use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use smallvec::{SmallVec, smallvec};
use tracing::debug;
use url::Url;

use crate::{
    findings_store::FindingsStore,
    origin::{Origin, OriginSet, get_repo_url},
};

const BASELINE_VERSION: u32 = 2;
const FINGERPRINT_ALGORITHM: &str = "kingfisher-v1";

type FingerprintForms = SmallVec<[u64; 2]>;

/// A baseline file. Files without `version` are the legacy v1 format.
///
/// Version 2 scopes findings to a canonical repository identifier. The legacy
/// `ExactFindings` field remains readable so existing files continue to work.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint_algorithm: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<RepositoryBaseline>,

    #[serde(rename = "ExactFindings", default, skip_serializing_if = "ExactFindings::is_empty")]
    pub exact_findings: ExactFindings,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryBaseline {
    pub id: String,

    #[serde(default)]
    pub findings: Vec<RepositoryBaselineFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryBaselineFinding {
    pub path: String,
    pub fingerprint: String,
    pub rule_id: String,
    pub line: usize,
    pub first_seen_at: String,
    pub last_updated_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactFindings {
    #[serde(default)]
    pub matches: Vec<BaselineFinding>,
}

impl ExactFindings {
    fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }
}

/// A finding in the unversioned v1 baseline format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineFinding {
    pub filepath: String,
    pub fingerprint: String,
    pub linenum: usize,
    pub lastupdated: String,
}

pub fn load_baseline(path: &Path) -> Result<BaselineFile> {
    let data = fs::read_to_string(path).context("read baseline file")?;
    let baseline: BaselineFile = serde_yaml::from_str(&data).context("parse baseline yaml")?;
    validate_baseline(&baseline)?;
    Ok(baseline)
}

fn validate_baseline(baseline: &BaselineFile) -> Result<()> {
    if let Some(version) = baseline.version
        && version != BASELINE_VERSION
    {
        bail!("unsupported baseline version {version}; this Kingfisher supports version 2");
    }

    if baseline.version == Some(BASELINE_VERSION) {
        match baseline.fingerprint_algorithm.as_deref() {
            Some(FINGERPRINT_ALGORITHM) => {}
            Some(algorithm) => bail!(
                "unsupported baseline fingerprint algorithm {algorithm:?}; expected {FINGERPRINT_ALGORITHM:?}"
            ),
            None => bail!(
                "baseline version 2 is missing fingerprint_algorithm; expected {FINGERPRINT_ALGORITHM:?}"
            ),
        }
    }

    Ok(())
}

/// Parse a baseline fingerprint string into its canonical u64 form(s).
///
/// Accepts either the decimal form users see in scan output (JSON/pretty/SARIF)
/// or the 16-char zero-padded hex form previously written by `--manage-baseline`.
/// Returns 0–2 canonical u64 interpretations: ambiguous 16-digit all-digit
/// strings — which could be either a decimal fingerprint or a legacy hex
/// fingerprint whose value happens to contain no `a-f` — yield both so either
/// form matches.
fn parse_fingerprint(s: &str) -> FingerprintForms {
    let trimmed = s.trim();
    if let Some(rest) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        return match u64::from_str_radix(rest, 16) {
            Ok(v) => smallvec![v],
            Err(_) => SmallVec::new(),
        };
    }
    if trimmed.len() == 16 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        if trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
            return match u64::from_str_radix(trimmed, 16) {
                Ok(v) => smallvec![v],
                Err(_) => SmallVec::new(),
            };
        }
        let mut out: FingerprintForms = SmallVec::new();
        if let Ok(v) = trimmed.parse::<u64>() {
            out.push(v);
        }
        if let Ok(v) = u64::from_str_radix(trimmed, 16)
            && !out.contains(&v)
        {
            out.push(v);
        }
        return out;
    }
    match trimmed.parse::<u64>() {
        Ok(v) => smallvec![v],
        Err(_) => SmallVec::new(),
    }
}

/// Atomically writes a baseline in the same directory as its destination.
pub fn save_baseline(path: &Path, baseline: &BaselineFile) -> Result<()> {
    validate_baseline(baseline)?;
    let data = serde_yaml::to_string(baseline).context("serialize baseline")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent).context("create temporary baseline")?;
    temp.write_all(data.as_bytes()).context("write temporary baseline")?;
    temp.as_file_mut().sync_all().context("sync temporary baseline")?;
    temp.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("replace baseline file {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FindingContext {
    repository_id: String,
    path: String,
}

#[derive(Debug, Clone)]
struct ScanScope {
    root: PathBuf,
    repository_id: String,
}

struct ScopeResolver {
    scopes: Vec<ScanScope>,
    repo_links: BTreeMap<PathBuf, String>,
}

impl ScopeResolver {
    fn new(store: &FindingsStore, roots: &[PathBuf]) -> Self {
        let repo_links: BTreeMap<_, _> =
            store.repo_links().iter().map(|(path, url)| (path.clone(), url.clone())).collect();
        let mut scopes: Vec<_> = roots
            .iter()
            .map(|root| ScanScope {
                root: root.clone(),
                repository_id: repository_id_for_root(root, &repo_links),
            })
            .collect();
        // Prefer the narrowest matching root when roots are nested.
        scopes.sort_by(|a, b| {
            b.root
                .components()
                .count()
                .cmp(&a.root.components().count())
                .then_with(|| a.root.cmp(&b.root))
        });
        scopes.dedup_by(|a, b| a.root == b.root);
        Self { scopes, repo_links }
    }

    fn scanned_repository_ids(&self) -> BTreeSet<String> {
        self.scopes.iter().map(|scope| scope.repository_id.clone()).collect()
    }

    fn contexts(&self, origins: &OriginSet) -> Vec<FindingContext> {
        let mut by_repository = BTreeMap::<String, String>::new();
        for origin in origins.iter() {
            if let Some(context) = self.context_for_origin(origin) {
                by_repository
                    .entry(context.repository_id)
                    .and_modify(|path| {
                        if context.path < *path {
                            *path = context.path.clone();
                        }
                    })
                    .or_insert(context.path);
            }
        }

        if by_repository.is_empty()
            && let Some(scope) = self.scopes.first()
        {
            by_repository.insert(scope.repository_id.clone(), String::new());
        }

        by_repository
            .into_iter()
            .map(|(repository_id, path)| FindingContext { repository_id, path })
            .collect()
    }

    fn context_for_origin(&self, origin: &Origin) -> Option<FindingContext> {
        match origin {
            Origin::GitRepo(git) => {
                let repository_id = repository_id_for_root(&git.repo_path, &self.repo_links);
                let path = git
                    .first_commit
                    .as_ref()
                    .map(|commit| normalize_path(Path::new(&commit.blob_path)))
                    .unwrap_or_default();
                Some(FindingContext { repository_id, path })
            }
            Origin::File(file) => self.context_for_path(&file.path),
            Origin::Extended(extended) => {
                extended.path().and_then(|path| self.context_for_path(path))
            }
        }
    }

    fn context_for_path(&self, path: &Path) -> Option<FindingContext> {
        if let Some(scope) = self.scopes.iter().find(|scope| path.starts_with(&scope.root)) {
            let relative = path.strip_prefix(&scope.root).unwrap_or(path);
            let relative = if relative.as_os_str().is_empty() {
                path.file_name().map(PathBuf::from).unwrap_or_default()
            } else {
                relative.to_path_buf()
            };
            return Some(FindingContext {
                repository_id: scope.repository_id.clone(),
                path: normalize_path(&relative),
            });
        }

        Some(FindingContext {
            repository_id: local_repository_id(path.parent().unwrap_or(path)),
            path: path
                .file_name()
                .map(PathBuf::from)
                .map_or_else(String::new, |p| normalize_path(&p)),
        })
    }
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn repository_id_for_root(root: &Path, repo_links: &BTreeMap<PathBuf, String>) -> String {
    if let Some(remote) = repo_links.get(root)
        && let Some(id) = canonical_remote_repository_id(remote)
    {
        return id;
    }
    if let Ok(remote) = get_repo_url(root)
        && let Some(id) = canonical_remote_repository_id(&remote)
    {
        return id;
    }
    local_repository_id(root)
}

fn local_repository_id(root: &Path) -> String {
    let normalized = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    format!("local://{}", normalize_path(&normalized))
}

fn canonical_remote_repository_id(raw: &str) -> Option<String> {
    let normalized = if let Some(rest) = raw.strip_prefix("git@") {
        let (host, path) = rest.split_once(':')?;
        format!("https://{host}/{path}")
    } else {
        raw.to_string()
    };
    let url = Url::parse(&normalized).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    let authority = url.port().map_or(host.clone(), |port| format!("{host}:{port}"));
    let mut path = url.path().trim_matches('/').to_string();
    if let Some(without_git) = path.strip_suffix(".git") {
        path = without_git.to_string();
    }
    if path.is_empty() {
        Some(format!("git://{authority}"))
    } else {
        Some(format!("git://{authority}/{path}"))
    }
}

fn legacy_fingerprints(baseline: &BaselineFile) -> HashSet<u64> {
    baseline
        .exact_findings
        .matches
        .iter()
        .flat_map(|finding| parse_fingerprint(&finding.fingerprint))
        .collect()
}

fn repository_fingerprints(baseline: &BaselineFile) -> BTreeMap<&str, HashSet<u64>> {
    baseline
        .repositories
        .iter()
        .map(|repository| {
            let fingerprints = repository
                .findings
                .iter()
                .flat_map(|finding| parse_fingerprint(&finding.fingerprint))
                .collect();
            (repository.id.as_str(), fingerprints)
        })
        .collect()
}

/// Applies an already-loaded baseline without writing it.
///
/// Legacy v1 fingerprints are global. Version 2 findings are suppressed only
/// when every repository represented by the finding contains that fingerprint.
pub fn apply_loaded_baseline(
    store: &mut FindingsStore,
    baseline: &BaselineFile,
    roots: &[PathBuf],
) -> Result<()> {
    validate_baseline(baseline)?;
    let legacy_known = legacy_fingerprints(baseline);
    let repository_known = repository_fingerprints(baseline);
    let resolver = ScopeResolver::new(store, roots);

    for arc_msg in store.get_matches_mut() {
        let (origins, _blob, finding) = Arc::make_mut(arc_msg);
        let fingerprint = finding.finding_fingerprint;
        let contexts = resolver.contexts(origins);
        let known = legacy_known.contains(&fingerprint)
            || (!contexts.is_empty()
                && contexts.iter().all(|context| {
                    repository_known
                        .get(context.repository_id.as_str())
                        .is_some_and(|known| known.contains(&fingerprint))
                }));
        if known {
            debug!("Skipping finding due to baseline (fingerprint {fingerprint})");
            finding.visible = false;
        }
    }
    Ok(())
}

/// Builds a v2 baseline from the successfully scanned roots.
///
/// Existing v2 repositories outside `roots` are preserved. Repositories in
/// `roots` are replaced with exactly the findings encountered in this scan.
/// Legacy entries are migrated to repository-scoped entries for the current
/// scan and removed from the resulting file.
pub fn build_managed_baseline(
    store: &FindingsStore,
    baseline: &BaselineFile,
    roots: &[PathBuf],
) -> Result<BaselineFile> {
    validate_baseline(baseline)?;
    let resolver = ScopeResolver::new(store, roots);
    let mut scanned = resolver.scanned_repository_ids();
    let mut observations = BTreeMap::<(String, u64), RepositoryBaselineFinding>::new();
    let now = Utc::now().to_rfc3339();

    let mut existing = BTreeMap::<(String, u64), RepositoryBaselineFinding>::new();
    for repository in &baseline.repositories {
        for finding in &repository.findings {
            for fingerprint in parse_fingerprint(&finding.fingerprint) {
                existing
                    .entry((repository.id.clone(), fingerprint))
                    .or_insert_with(|| finding.clone());
            }
        }
    }

    for message in store.get_matches() {
        let (origins, _blob, finding) = message.as_ref();
        for context in resolver.contexts(origins) {
            scanned.insert(context.repository_id.clone());
            let key = (context.repository_id, finding.finding_fingerprint);
            let candidate = RepositoryBaselineFinding {
                path: context.path,
                fingerprint: finding.finding_fingerprint.to_string(),
                rule_id: finding.rule.id().to_string(),
                line: finding.location.resolved_source_span().start.line,
                first_seen_at: now.clone(),
                last_updated_at: now.clone(),
            };

            observations
                .entry(key.clone())
                .and_modify(|current| {
                    if (&candidate.path, candidate.line, &candidate.rule_id)
                        < (&current.path, current.line, &current.rule_id)
                    {
                        *current = candidate.clone();
                    }
                })
                .or_insert(candidate);

            if let Some(previous) = existing.get(&key)
                && let Some(current) = observations.get_mut(&key)
            {
                current.first_seen_at = previous.first_seen_at.clone();
                if current.path == previous.path
                    && current.rule_id == previous.rule_id
                    && current.line == previous.line
                {
                    current.last_updated_at = previous.last_updated_at.clone();
                }
            }
        }
    }

    let mut repositories = BTreeMap::<String, Vec<RepositoryBaselineFinding>>::new();
    for repository in &baseline.repositories {
        if !scanned.contains(&repository.id) {
            repositories.insert(repository.id.clone(), repository.findings.clone());
        }
    }
    for ((repository_id, _fingerprint), finding) in observations {
        repositories.entry(repository_id).or_default().push(finding);
    }

    let repositories = repositories
        .into_iter()
        .filter_map(|(id, mut findings)| {
            findings.sort_by(|a, b| {
                a.path
                    .cmp(&b.path)
                    .then_with(|| a.line.cmp(&b.line))
                    .then_with(|| a.rule_id.cmp(&b.rule_id))
                    .then_with(|| a.fingerprint.cmp(&b.fingerprint))
            });
            findings.dedup_by(|a, b| a.fingerprint == b.fingerprint);
            (!findings.is_empty()).then_some(RepositoryBaseline { id, findings })
        })
        .collect();

    Ok(BaselineFile {
        version: Some(BASELINE_VERSION),
        fingerprint_algorithm: Some(FINGERPRINT_ALGORITHM.to_string()),
        repositories,
        exact_findings: ExactFindings::default(),
    })
}

/// Backward-compatible convenience API used by library callers and tests.
/// Scanner orchestration uses `apply_loaded_baseline` and
/// `build_managed_baseline` separately so parallel workers never write.
pub fn apply_baseline(
    store: &mut FindingsStore,
    baseline_path: &Path,
    manage: bool,
    roots: &[PathBuf],
) -> Result<()> {
    let baseline = if baseline_path.exists() {
        load_baseline(baseline_path)?
    } else {
        BaselineFile::default()
    };
    apply_loaded_baseline(store, &baseline, roots)?;
    if manage {
        let updated = build_managed_baseline(store, &baseline, roots)?;
        if updated != baseline || !baseline_path.exists() {
            save_baseline(baseline_path, &updated)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob::{BlobId, BlobMetadata},
        location::{Location, OffsetSpan, SourcePoint, SourceSpan},
        matcher::{Match, SerializableCapture, SerializableCaptures},
        origin::{Origin, OriginSet},
        rules::rule::{Confidence, Rule, RuleSyntax},
    };
    use anyhow::Result;
    use smallvec::SmallVec;
    use std::{path::Path, sync::Arc};
    use tempfile::TempDir;

    fn test_rule() -> Arc<Rule> {
        Arc::new(Rule::new(RuleSyntax {
            name: "test".to_string(),
            id: "test.rule".to_string(),
            pattern: "test".to_string(),
            min_entropy: 0.0,
            confidence: Confidence::Low,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        }))
    }

    fn empty_captures() -> SerializableCaptures {
        SerializableCaptures { captures: SmallVec::<[SerializableCapture; 2]>::new() }
    }

    fn make_store_with_match(fingerprint: u64, file_path: &Path) -> FindingsStore {
        let mut store = FindingsStore::new(PathBuf::from("."));
        let rule = test_rule();
        let match_item = Match {
            location: Location::with_source_span(
                OffsetSpan { start: 0, end: 1 },
                Some(SourceSpan {
                    start: SourcePoint { line: 1, column: 0 },
                    end: SourcePoint { line: 1, column: 1 },
                }),
            ),
            groups: empty_captures(),
            blob_id: BlobId::default(),
            finding_fingerprint: fingerprint,
            rule: Arc::clone(&rule),
            validation_response_body: None,
            validation_response_status: 0,
            validation_success: false,
            validation_outcome: kingfisher_core::ValidationOutcome::NotAttempted,
            calculated_entropy: 0.0,
            visible: true,
            is_base64: false,
            dependent_captures: std::collections::BTreeMap::new(),
        };

        let origin = OriginSet::from(Origin::from_file(file_path.to_path_buf()));
        let blob_meta = Arc::new(BlobMetadata {
            id: BlobId::default(),
            num_bytes: 0,
            mime_essence: None,
            language: None,
        });

        let entry = Arc::new((Arc::new(origin), blob_meta, match_item));
        store.get_matches_mut().push(entry);
        store
    }

    fn legacy_path(root: &Path, file: &Path) -> String {
        let mut expected = PathBuf::from(root.file_name().unwrap());
        if let Ok(stripped) = file.strip_prefix(root) {
            expected = expected.join(stripped);
        }
        normalize_path(&expected)
    }

    fn repository_id(remote: &str) -> String {
        canonical_remote_repository_id(remote).unwrap()
    }

    #[test]
    fn apply_baseline_writes_v2_and_filters_existing_fingerprints() -> Result<()> {
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let secret_file = tmp.path().join("secret.txt");
        fs::write(&secret_file, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        let fingerprint = 0x1234_u64;

        let mut store = make_store_with_match(fingerprint, &secret_file);
        store.register_repo_link(roots[0].clone(), "https://example.com/team/repo.git".into());
        apply_baseline(&mut store, &baseline_path, true, &roots)?;

        let baseline = load_baseline(&baseline_path)?;
        assert_eq!(baseline.version, Some(BASELINE_VERSION));
        assert!(baseline.exact_findings.matches.is_empty());
        assert_eq!(baseline.repositories.len(), 1);
        assert_eq!(baseline.repositories[0].id, "git://example.com/team/repo");
        let entry = &baseline.repositories[0].findings[0];
        assert_eq!(entry.fingerprint, fingerprint.to_string());
        assert_eq!(entry.path, "secret.txt");

        let (_, _, recorded) = store.get_matches()[0].as_ref();
        assert!(recorded.visible);

        let mut follow_up = make_store_with_match(fingerprint, &secret_file);
        follow_up.register_repo_link(roots[0].clone(), "https://example.com/team/repo.git".into());
        apply_baseline(&mut follow_up, &baseline_path, false, &roots)?;
        assert!(!follow_up.get_matches()[0].as_ref().2.visible);
        Ok(())
    }

    #[test]
    fn repository_scoping_does_not_suppress_another_repository() -> Result<()> {
        let tmp = TempDir::new()?;
        let root_a = tmp.path().join("a");
        let root_b = tmp.path().join("b");
        fs::create_dir_all(&root_a)?;
        fs::create_dir_all(&root_b)?;
        let fingerprint = 42;
        let baseline = BaselineFile {
            version: Some(BASELINE_VERSION),
            fingerprint_algorithm: Some(FINGERPRINT_ALGORITHM.into()),
            repositories: vec![RepositoryBaseline {
                id: repository_id("https://example.com/team/a.git"),
                findings: vec![RepositoryBaselineFinding {
                    path: "secret.txt".into(),
                    fingerprint: fingerprint.to_string(),
                    rule_id: "test.rule".into(),
                    line: 1,
                    first_seen_at: "now".into(),
                    last_updated_at: "now".into(),
                }],
            }],
            exact_findings: ExactFindings::default(),
        };

        let mut store_a = make_store_with_match(fingerprint, &root_a.join("secret.txt"));
        store_a.register_repo_link(root_a.clone(), "https://example.com/team/a.git".into());
        apply_loaded_baseline(&mut store_a, &baseline, std::slice::from_ref(&root_a))?;
        assert!(!store_a.get_matches()[0].as_ref().2.visible);

        let mut store_b = make_store_with_match(fingerprint, &root_b.join("secret.txt"));
        store_b.register_repo_link(root_b.clone(), "https://example.com/team/b.git".into());
        apply_loaded_baseline(&mut store_b, &baseline, std::slice::from_ref(&root_b))?;
        assert!(store_b.get_matches()[0].as_ref().2.visible);
        Ok(())
    }

    #[test]
    fn managed_update_preserves_unscanned_repositories() -> Result<()> {
        let tmp = TempDir::new()?;
        let root_a = tmp.path().join("a");
        fs::create_dir_all(&root_a)?;
        let mut store = make_store_with_match(1, &root_a.join("new.txt"));
        store.register_repo_link(root_a.clone(), "https://example.com/team/a.git".into());
        let untouched = RepositoryBaseline {
            id: repository_id("https://example.com/team/b.git"),
            findings: vec![RepositoryBaselineFinding {
                path: "old.txt".into(),
                fingerprint: "2".into(),
                rule_id: "test.rule".into(),
                line: 1,
                first_seen_at: "then".into(),
                last_updated_at: "then".into(),
            }],
        };
        let baseline = BaselineFile {
            version: Some(BASELINE_VERSION),
            fingerprint_algorithm: Some(FINGERPRINT_ALGORITHM.into()),
            repositories: vec![untouched.clone()],
            exact_findings: ExactFindings::default(),
        };

        let updated = build_managed_baseline(&store, &baseline, std::slice::from_ref(&root_a))?;
        assert!(updated.repositories.contains(&untouched));
        assert!(updated.repositories.iter().any(|repo| {
            repo.id == repository_id("https://example.com/team/a.git")
                && repo.findings.iter().any(|finding| finding.fingerprint == "1")
        }));
        Ok(())
    }

    #[test]
    fn managed_update_groups_same_fingerprint_by_repository() -> Result<()> {
        let tmp = TempDir::new()?;
        let root_a = tmp.path().join("a");
        let root_b = tmp.path().join("b");
        fs::create_dir_all(&root_a)?;
        fs::create_dir_all(&root_b)?;
        let fingerprint = 7;

        let mut store = make_store_with_match(fingerprint, &root_a.join("secret.txt"));
        let store_b = make_store_with_match(fingerprint, &root_b.join("secret.txt"));
        store.get_matches_mut().extend(store_b.get_matches().iter().cloned());
        store.register_repo_link(root_a.clone(), "https://example.com/team/a.git".into());
        store.register_repo_link(root_b.clone(), "https://example.com/team/b.git".into());

        let roots = [root_a, root_b];
        let updated = build_managed_baseline(&store, &BaselineFile::default(), &roots)?;
        assert_eq!(updated.repositories.len(), 2);
        assert!(updated.repositories.iter().all(|repository| {
            repository.findings.len() == 1 && repository.findings[0].fingerprint == "7"
        }));
        assert_ne!(updated.repositories[0].id, updated.repositories[1].id);
        Ok(())
    }

    #[test]
    fn managing_legacy_baseline_migrates_to_v2() -> Result<()> {
        let tmp = TempDir::new()?;
        let root = tmp.path().to_path_buf();
        let file = root.join("secret.txt");
        let fingerprint = 99;
        let mut store = make_store_with_match(fingerprint, &file);
        store.register_repo_link(root.clone(), "https://example.com/team/repo.git".into());
        let legacy = BaselineFile {
            exact_findings: ExactFindings {
                matches: vec![BaselineFinding {
                    filepath: legacy_path(&root, &file),
                    fingerprint: fingerprint.to_string(),
                    linenum: 1,
                    lastupdated: "then".into(),
                }],
            },
            ..BaselineFile::default()
        };

        apply_loaded_baseline(&mut store, &legacy, std::slice::from_ref(&root))?;
        assert!(!store.get_matches()[0].as_ref().2.visible);
        let migrated = build_managed_baseline(&store, &legacy, std::slice::from_ref(&root))?;
        assert_eq!(migrated.version, Some(BASELINE_VERSION));
        assert!(migrated.exact_findings.matches.is_empty());
        assert_eq!(migrated.repositories[0].findings[0].fingerprint, "99");
        Ok(())
    }

    #[test]
    fn managing_baseline_is_idempotent() -> Result<()> {
        let tmp = TempDir::new()?;
        let roots = [tmp.path().to_path_buf()];
        let secret_file = tmp.path().join("secret.txt");
        fs::write(&secret_file, "dummy")?;
        let baseline_path = tmp.path().join("baseline.yaml");
        let fingerprint = 0xfeed_beef_dade_f00d_u64;

        let mut initial = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut initial, &baseline_path, true, &roots)?;
        let baseline_before = fs::read_to_string(&baseline_path)?;

        let mut rerun = make_store_with_match(fingerprint, &secret_file);
        apply_baseline(&mut rerun, &baseline_path, true, &roots)?;
        let baseline_after = fs::read_to_string(&baseline_path)?;
        assert_eq!(baseline_before, baseline_after);
        assert!(!rerun.get_matches()[0].as_ref().2.visible);
        Ok(())
    }

    #[test]
    fn parse_fingerprint_accepts_all_forms() {
        let value: u64 = 0xfeed_beef_dade_f00d;
        assert_eq!(parse_fingerprint(&format!("{:016x}", value)).as_slice(), &[value]);
        assert_eq!(parse_fingerprint(&format!("0x{:016x}", value)).as_slice(), &[value]);
        assert_eq!(parse_fingerprint(&format!("0X{:X}", value)).as_slice(), &[value]);
        assert_eq!(parse_fingerprint(&value.to_string()).as_slice(), &[value]);
        assert_eq!(parse_fingerprint("  42  ").as_slice(), &[42]);
        assert_eq!(parse_fingerprint("0").as_slice(), &[0]);
        assert!(parse_fingerprint("").is_empty());
        assert!(parse_fingerprint("notahex").is_empty());
    }

    #[test]
    fn parse_fingerprint_all_digit_16_chars_is_ambiguous() {
        let value = "1234567890123456";
        let parsed = parse_fingerprint(value);
        assert!(parsed.contains(&1234567890123456_u64));
        assert!(parsed.contains(&u64::from_str_radix(value, 16).unwrap()));
    }

    #[test]
    fn legacy_decimal_and_hex_fingerprints_still_match() -> Result<()> {
        let tmp = TempDir::new()?;
        let root = tmp.path().to_path_buf();
        let file = root.join("secret.txt");
        let decimal = 0xfeed_beef_dade_f00d_u64;
        let hex = 0x1a2b_3c4d_5e6f_7890_u64;

        for fingerprint in [decimal.to_string(), format!("{hex:016x}")] {
            let value = parse_fingerprint(&fingerprint)[0];
            let legacy = BaselineFile {
                exact_findings: ExactFindings {
                    matches: vec![BaselineFinding {
                        filepath: legacy_path(&root, &file),
                        fingerprint,
                        linenum: 1,
                        lastupdated: "then".into(),
                    }],
                },
                ..BaselineFile::default()
            };
            let mut store = make_store_with_match(value, &file);
            apply_loaded_baseline(&mut store, &legacy, std::slice::from_ref(&root))?;
            assert!(!store.get_matches()[0].as_ref().2.visible);
        }
        Ok(())
    }

    #[test]
    fn canonical_repository_ids_ignore_transport_and_git_suffix() {
        assert_eq!(
            canonical_remote_repository_id("https://Example.COM/team/repo.git"),
            Some("git://example.com/team/repo".into())
        );
        assert_eq!(
            canonical_remote_repository_id("git@example.com:team/repo.git"),
            Some("git://example.com/team/repo".into())
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let baseline = BaselineFile { version: Some(3), ..BaselineFile::default() };
        assert!(validate_baseline(&baseline).is_err());
    }

    #[test]
    fn version_two_requires_supported_fingerprint_algorithm() {
        let missing = BaselineFile { version: Some(2), ..BaselineFile::default() };
        assert!(validate_baseline(&missing).is_err());

        let unknown = BaselineFile {
            version: Some(2),
            fingerprint_algorithm: Some("kingfisher-v99".into()),
            ..BaselineFile::default()
        };
        assert!(validate_baseline(&unknown).is_err());
    }
}
