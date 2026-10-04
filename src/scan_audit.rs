//! Repository coverage auditing for multi-asset scans.

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use regex::Regex;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::json;
use tracing::debug;
use uuid::Uuid;

use crate::{
    cli::commands::{github::GitHistoryMode, scan},
    matcher::MatcherStats,
};

const AUDIT_SCHEMA: &str = "kingfisher.repository-audit.v1";

pub type SharedScanAudit = Arc<Mutex<ScanAuditCollector>>;

#[derive(Serialize, JsonSchema, Clone, Debug, Default)]
pub struct RepositoryAuditSummary {
    pub discovered: usize,
    pub fetch_succeeded: usize,
    pub fetch_failed: usize,
    pub scan_succeeded: usize,
    pub scan_partial: usize,
    pub scan_failed: usize,
    pub pending: usize,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct ScanAuditManifest {
    pub schema: String,
    pub run_id: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<f64>,
    pub summary: RepositoryAuditSummary,
    pub repositories: Vec<RepositoryAuditRecord>,
}

impl ScanAuditManifest {
    pub fn for_repository(&self, repository_key: &str) -> Self {
        let repositories = self
            .repositories
            .iter()
            .filter(|record| record.key == repository_key)
            .cloned()
            .collect::<Vec<_>>();
        let summary = summarize(&repositories);
        Self {
            schema: self.schema.clone(),
            run_id: self.run_id.clone(),
            started_at: self.started_at.clone(),
            completed_at: self.completed_at.clone(),
            duration_seconds: self.duration_seconds,
            summary,
            repositories,
        }
    }
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct RepositoryAuditRecord {
    /// Stable normalized key used to correlate lifecycle events.
    pub key: String,
    /// Canonical remote URL, or a local path for directly supplied repositories.
    pub repository: String,
    pub source: String,
    pub discovered_at: String,
    pub fetch: AuditPhase,
    pub scan: AuditPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<GitAuditSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<RepositoryScanStats>,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct AuditPhase {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuditPhase {
    fn pending() -> Self {
        Self {
            status: "pending".to_string(),
            started_at: None,
            completed_at: None,
            duration_seconds: None,
            method: None,
            error: None,
        }
    }

    fn not_applicable() -> Self {
        Self { status: "not_applicable".to_string(), ..Self::pending() }
    }
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct GitAuditSnapshot {
    pub scope: String,
    pub tip_ref: String,
    /// Inclusive committer timestamp bounds (Unix seconds) for --since-hours.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusive_root_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusive_root_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clone_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shallow: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetched_commit_count: Option<u64>,
    /// Individual snapshots when one repository was scanned for multiple
    /// selectors, such as several GitHub event commits or branches.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub target_snapshots: Vec<GitAuditTargetSnapshot>,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct GitAuditTargetSnapshot {
    pub selector: String,
    pub snapshot: Box<GitAuditSnapshot>,
}

#[derive(Serialize, JsonSchema, Clone, Debug, Default)]
pub struct RepositoryScanStats {
    pub findings: usize,
    pub blobs_scanned: u64,
    pub bytes_scanned: u64,
}

pub struct ScanAuditCollector {
    manifest: ScanAuditManifest,
    records: BTreeMap<String, RepositoryAuditRecord>,
    roots: HashMap<PathBuf, String>,
    fetch_started: HashMap<String, Instant>,
    scan_started: HashMap<String, Instant>,
    run_started: Instant,
    log_writer: Option<BufWriter<File>>,
    log_error: Option<String>,
}

impl ScanAuditCollector {
    pub fn new(started_at: String, audit_log: Option<&Path>) -> Result<Self> {
        let run_id = Uuid::new_v4().to_string();
        let log_writer = match audit_log {
            Some(path) => {
                Some(BufWriter::new(crate::util::create_no_follow(path).with_context(|| {
                    format!("Failed to create repository audit log {}", path.display())
                })?))
            }
            None => None,
        };
        let started_at = chrono::DateTime::parse_from_rfc3339(&started_at)
            .map(|timestamp| timestamp.with_timezone(&chrono::Utc).to_rfc3339())
            .unwrap_or(started_at);
        let manifest = ScanAuditManifest {
            schema: AUDIT_SCHEMA.to_string(),
            run_id,
            started_at,
            completed_at: None,
            duration_seconds: None,
            summary: RepositoryAuditSummary::default(),
            repositories: Vec::new(),
        };
        let mut collector = Self {
            manifest,
            records: BTreeMap::new(),
            roots: HashMap::new(),
            fetch_started: HashMap::new(),
            scan_started: HashMap::new(),
            run_started: Instant::now(),
            log_writer,
            log_error: None,
        };
        collector.write_event("run_started", None);
        Ok(collector)
    }

    pub fn discover_remote(&mut self, repository: &str) {
        let key = normalize_remote_key(repository);
        if self.records.contains_key(&key) {
            return;
        }
        let record = RepositoryAuditRecord {
            key: key.clone(),
            repository: repository.trim_end_matches(".git").to_string(),
            source: "remote".to_string(),
            discovered_at: now(),
            fetch: AuditPhase::pending(),
            scan: AuditPhase::pending(),
            git: None,
            stats: None,
        };
        self.records.insert(key.clone(), record);
        self.write_event("repository_discovered", Some(&key));
    }

    pub fn discover_local(&mut self, root: &Path) {
        let normalized_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        let key = format!("local:{}", normalized_root.display());
        self.roots.insert(root.to_path_buf(), key.clone());
        if self.records.contains_key(&key) {
            return;
        }
        let record = RepositoryAuditRecord {
            key: key.clone(),
            repository: normalized_root.display().to_string(),
            source: "local".to_string(),
            discovered_at: now(),
            fetch: AuditPhase::not_applicable(),
            scan: AuditPhase::pending(),
            git: None,
            stats: None,
        };
        self.records.insert(key.clone(), record);
        self.write_event("repository_discovered", Some(&key));
    }

    pub fn fetch_started(&mut self, repository: &str) {
        let key = normalize_remote_key(repository);
        self.fetch_started.insert(key.clone(), Instant::now());
        if let Some(record) = self.records.get_mut(&key) {
            record.fetch.status = "running".to_string();
            record.fetch.started_at = Some(now());
        }
        self.write_event("repository_fetch_started", Some(&key));
    }

    pub fn fetch_completed(&mut self, repository: &str, root: &Path, method: &str) {
        let key = normalize_remote_key(repository);
        self.roots.insert(root.to_path_buf(), key.clone());
        let elapsed =
            self.fetch_started.remove(&key).map(|started| started.elapsed().as_secs_f64());
        if let Some(record) = self.records.get_mut(&key) {
            record.fetch.status = "completed".to_string();
            record.fetch.completed_at = Some(now());
            record.fetch.duration_seconds = elapsed;
            record.fetch.method = Some(method.to_string());
            record.fetch.error = None;
        }
        self.write_event("repository_fetch_completed", Some(&key));
    }

    pub fn fetch_failed(&mut self, repository: &str, error: &str) {
        let key = normalize_remote_key(repository);
        let elapsed =
            self.fetch_started.remove(&key).map(|started| started.elapsed().as_secs_f64());
        if let Some(record) = self.records.get_mut(&key) {
            record.fetch.status = "failed".to_string();
            record.fetch.completed_at = Some(now());
            record.fetch.duration_seconds = elapsed;
            record.fetch.error = Some(sanitize_error(error));
            record.scan.status = "not_run".to_string();
        }
        self.write_event("repository_fetch_failed", Some(&key));
    }

    /// Applies a scan-start event using a git snapshot gathered beforehand.
    ///
    /// Callers that share the audit collector across scan workers should
    /// gather the snapshot with [`git_snapshot`] *before* taking the audit
    /// mutex: `git_snapshot` traverses Git history, and holding the
    /// lock during traversal serializes worker startup across the scan. Pass
    /// `None` for roots that are not Git repositories so no git boundary is
    /// recorded for them.
    pub fn scan_started_with_snapshot(
        &mut self,
        root: &Path,
        snapshot: Option<GitAuditSnapshot>,
    ) -> Option<String> {
        // Artifact fetchers produce ordinary directories (Docker, cloud exports, etc.).
        // Register them on entry so their failures and completion count toward coverage.
        if !self.roots.contains_key(root) {
            self.discover_local(root);
        }
        let key = self.roots.get(root)?.clone();
        self.scan_started.insert(key.clone(), Instant::now());
        if let Some(record) = self.records.get_mut(&key) {
            record.scan.status = "running".to_string();
            record.scan.started_at = Some(now());
            record.git = snapshot;
        }
        self.write_event("repository_scan_started", Some(&key));
        Some(key)
    }

    pub fn scan_partial(&mut self, key: &str, stats: RepositoryScanStats, error: &str) {
        let elapsed = self.scan_started.remove(key).map(|started| started.elapsed().as_secs_f64());
        if let Some(record) = self.records.get_mut(key) {
            record.scan.status = "partial".to_string();
            record.scan.completed_at = Some(now());
            record.scan.duration_seconds = elapsed;
            record.scan.error = Some(sanitize_error(error));
            record.stats = Some(stats);
        }
        self.write_event("repository_scan_partial", Some(key));
    }

    pub fn scan_completed(&mut self, key: &str, stats: RepositoryScanStats) {
        let elapsed = self.scan_started.remove(key).map(|started| started.elapsed().as_secs_f64());
        if let Some(record) = self.records.get_mut(key) {
            record.scan.status = "completed".to_string();
            record.scan.completed_at = Some(now());
            record.scan.duration_seconds = elapsed;
            record.scan.error = None;
            record.stats = Some(stats);
        }
        self.write_event("repository_scan_completed", Some(key));
    }

    pub fn scan_failed(&mut self, key: &str, error: &str) {
        let elapsed = self.scan_started.remove(key).map(|started| started.elapsed().as_secs_f64());
        if let Some(record) = self.records.get_mut(key) {
            if record.scan.status == "completed" {
                return;
            }
            record.scan.status = "failed".to_string();
            record.scan.completed_at = Some(now());
            record.scan.duration_seconds = elapsed;
            record.scan.error = Some(sanitize_error(error));
        }
        self.write_event("repository_scan_failed", Some(key));
    }

    /// Mark already-streamed records as an incomplete run after discovery fails.
    pub fn run_failed(&mut self) {
        self.write_event("run_failed", None);
    }

    pub fn finish(&mut self) -> Result<ScanAuditManifest> {
        if self.manifest.completed_at.is_none() {
            self.manifest.completed_at = Some(now());
            self.manifest.duration_seconds = Some(self.run_started.elapsed().as_secs_f64());
            self.refresh_manifest();
            self.write_event("run_completed", None);
        }
        if let Some(writer) = self.log_writer.as_mut()
            && let Err(error) = writer.flush()
        {
            self.log_error.get_or_insert_with(|| error.to_string());
        }
        if let Some(error) = &self.log_error {
            anyhow::bail!("Failed to write repository audit log: {error}");
        }
        Ok(self.manifest.clone())
    }

    pub fn snapshot(&mut self) -> ScanAuditManifest {
        self.refresh_manifest();
        self.manifest.clone()
    }

    fn refresh_manifest(&mut self) {
        self.manifest.repositories = self.records.values().cloned().collect();
        self.manifest.summary = summarize(&self.manifest.repositories);
    }

    fn write_event(&mut self, event: &str, repository_key: Option<&str>) {
        let Some(writer) = self.log_writer.as_mut() else {
            return;
        };
        if self.log_error.is_some() {
            return;
        }
        let repository = repository_key.and_then(|key| self.records.get(key)).cloned();
        let payload = json!({
            "schema": AUDIT_SCHEMA,
            "event": event,
            "run_id": self.manifest.run_id,
            "timestamp": now(),
            "repository": repository,
            "summary": if matches!(event, "run_completed" | "run_failed") { Some(summarize(&self.records.values().cloned().collect::<Vec<_>>())) } else { None },
        });
        let result = serde_json::to_writer(&mut *writer, &payload)
            .and_then(|_| writer.write_all(b"\n").map_err(serde_json::Error::io))
            .and_then(|_| writer.flush().map_err(serde_json::Error::io));
        if let Err(error) = result {
            self.log_error = Some(error.to_string());
        }
    }
}

impl From<&MatcherStats> for RepositoryScanStats {
    fn from(stats: &MatcherStats) -> Self {
        Self { findings: 0, blobs_scanned: stats.blobs_scanned, bytes_scanned: stats.bytes_scanned }
    }
}

fn summarize(records: &[RepositoryAuditRecord]) -> RepositoryAuditSummary {
    let mut summary = RepositoryAuditSummary { discovered: records.len(), ..Default::default() };
    for record in records {
        match record.fetch.status.as_str() {
            "completed" => summary.fetch_succeeded += 1,
            "failed" => summary.fetch_failed += 1,
            _ => {}
        }
        match record.scan.status.as_str() {
            "completed" => summary.scan_succeeded += 1,
            "partial" => summary.scan_partial += 1,
            "failed" => summary.scan_failed += 1,
            "pending" | "running" => summary.pending += 1,
            _ => {}
        }
    }
    summary
}

fn normalize_remote_key(repository: &str) -> String {
    repository.trim().trim_end_matches('/').trim_end_matches(".git").to_string()
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

static URL_CREDENTIAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(https?://)[^/@\s]+@").expect("valid URL credential regex"));
static AUTHORIZATION_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(authorization:\s*)(?:(?:bearer|basic)\s+)?[^\s,;]+")
        .expect("valid authorization header regex")
});

fn sanitize_error(error: &str) -> String {
    let compact = error.split_whitespace().collect::<Vec<_>>().join(" ");
    let compact = URL_CREDENTIAL_RE.replace_all(&compact, "$1***@");
    let compact = AUTHORIZATION_HEADER_RE.replace_all(&compact, "$1***");
    compact.chars().take(2048).collect()
}

/// Gathers the git boundary information for a repository scan.
///
/// This reads repository metadata and must be called *outside* any lock
/// shared with other scan workers (see [`ScanAuditCollector::scan_started_with_snapshot`]).
/// Operations share the repository timeout from `args`; zero or `--no-limits` disables it.
pub fn git_snapshot(root: &Path, args: &scan::ScanArgs, fetched: bool) -> GitAuditSnapshot {
    let deadline = if args.content_filtering_args.no_limits || args.git_repo_timeout == 0 {
        None
    } else {
        Instant::now().checked_add(Duration::from_secs(args.git_repo_timeout))
    };
    // Open once for all metadata queries. Isolated options match the scanner and
    // avoid consulting unrelated user/system configuration or executing helpers.
    let pack_cache_bytes =
        crate::input::gix_pack_cache_bytes_for_threads(rayon::current_num_threads());
    let options = gix::open::Options::isolated()
        .config_overrides([format!("gitoxide.core.deltaBaseCacheLimit={pack_cache_bytes}")]);
    let repository = gix::discover_opts(root, Default::default(), options)
        .map_err(|error| debug!("Failed to open audit repository {}: {error}", root.display()))
        .ok();
    let repository = repository.as_ref().filter(|_| audit_before_deadline(deadline));
    let input = &args.input_specifier_args;
    let branch_root_enabled = input.branch_root || input.branch_root_commit.is_some();
    let scope = if input.staged {
        "staged_tree_diff"
    } else if input.since_hours.is_some() {
        "commit_time_range"
    } else if input.since_commit.is_some() {
        if input.git_history == GitHistoryMode::Full { "commit_range" } else { "tree_diff" }
    } else if branch_root_enabled {
        "inclusive_root_tree_diff"
    } else if input.branch.is_some() {
        if input.git_history == GitHistoryMode::Full { "branch_history" } else { "git_tree" }
    } else if input.git_history == GitHistoryMode::None {
        "working_tree"
    } else {
        "all_fetched_git_objects"
    };

    // Mirror the enumerator's staged resolution (enumerate_git_diff_repo): the
    // scanned tip is a synthesized staged-snapshot commit whose SHA cannot be
    // known here without creating objects, and the base is the explicit
    // --since-commit or the auto-detected HEAD (falling back to the empty tree
    // when the repository has no commits).
    let (tip_ref, tip_sha, base_ref) = if input.staged {
        let base = input.since_commit.clone().or_else(|| {
            let repository = repository?;
            repository.head_id().ok().map(|id| id.to_hex().to_string()).or_else(|| {
                audit_before_deadline(deadline)
                    .then(|| repository.object_hash().empty_tree().to_hex().to_string())
            })
        });
        ("(staged index)".to_string(), None, base)
    } else if (input.since_commit.is_some() || input.since_hours.is_some())
        && input.git_history == GitHistoryMode::Full
        && input.branch.is_none()
        && !branch_root_enabled
    {
        ("(all refs and HEAD)".to_string(), None, input.since_commit.clone())
    } else {
        // With --branch <ref> --branch-root (and no explicit
        // --branch-root-commit), the enumerator diffs <ref>'s parent tree
        // against HEAD, so the scanned tip is HEAD and <ref> is only the
        // inclusive root boundary.
        let tip_ref = if branch_root_enabled && input.branch_root_commit.is_none() {
            "HEAD".to_string()
        } else {
            input.branch.clone().unwrap_or_else(|| "HEAD".to_string())
        };
        let tip_sha = repository.and_then(|repo| git_commit_sha(repo, deadline, &tip_ref));
        (tip_ref, tip_sha, input.since_commit.clone())
    };
    let inclusive_root_ref = if branch_root_enabled {
        input.branch_root_commit.clone().or_else(|| input.branch.clone())
    } else {
        None
    };
    let clone_mode = fetched.then(|| {
        if input.git_history == GitHistoryMode::None {
            "checkout".to_string()
        } else {
            input.git_clone.to_string()
        }
    });
    let fetched_commit_count = if scope == "all_fetched_git_objects" {
        repository.and_then(|repo| git_commit_count(repo, deadline, None))
    } else if scope == "branch_history" {
        repository.zip(tip_sha.as_deref()).and_then(|(repo, tip)| {
            let tip = gix::ObjectId::from_hex(tip.as_bytes()).ok()?;
            git_commit_count(repo, deadline, Some(tip))
        })
    } else {
        None
    };
    let history_time_range = input.resolved_history_time_range();
    GitAuditSnapshot {
        scope: scope.to_string(),
        tip_sha,
        tip_ref,
        since_timestamp: history_time_range.map(|(start, _)| start),
        until_timestamp: history_time_range.map(|(_, end)| end),
        base_sha: base_ref
            .as_ref()
            .and_then(|value| repository.and_then(|repo| git_commit_sha(repo, deadline, value))),
        base_ref,
        inclusive_root_sha: inclusive_root_ref
            .as_ref()
            .and_then(|value| repository.and_then(|repo| git_commit_sha(repo, deadline, value))),
        inclusive_root_ref,
        clone_mode,
        shallow: repository
            .filter(|_| audit_before_deadline(deadline))
            .map(gix::Repository::is_shallow),
        fetched_commit_count,
        target_snapshots: Vec::new(),
    }
}

/// Combines the snapshots for all selectors scanned from one repository.
///
/// A single selector keeps the compact historical shape. Multiple selectors
/// use an explicit union marker and retain every individual boundary so the
/// manifest never presents one selector's tip as the scope of all work.
pub fn combine_git_snapshots(
    snapshots: Vec<(String, GitAuditSnapshot)>,
) -> Option<GitAuditSnapshot> {
    match snapshots.as_slice() {
        [] => None,
        [(_, snapshot)] => Some(snapshot.clone()),
        _ => Some(GitAuditSnapshot {
            scope: "multiple_targets".to_string(),
            tip_ref: "(multiple targets)".to_string(),
            since_timestamp: None,
            until_timestamp: None,
            tip_sha: None,
            base_ref: None,
            base_sha: None,
            inclusive_root_ref: None,
            inclusive_root_sha: None,
            clone_mode: None,
            shallow: None,
            fetched_commit_count: None,
            target_snapshots: snapshots
                .into_iter()
                .map(|(selector, snapshot)| GitAuditTargetSnapshot {
                    selector,
                    snapshot: Box::new(snapshot),
                })
                .collect(),
        }),
    }
}

/// Resolves one revision to a commit, preserving the scanner's local and
/// remote-tracking candidate order. Ranges and non-commit objects are rejected.
fn git_commit_sha(
    repository: &gix::Repository,
    deadline: Option<Instant>,
    ref_name: &str,
) -> Option<String> {
    crate::scanner::reference_candidates(ref_name).into_iter().find_map(|candidate| {
        if !audit_before_deadline(deadline) {
            return None;
        }
        let commit = repository
            .rev_parse_single(candidate.as_bytes())
            .ok()?
            .object()
            .ok()?
            .peel_to_commit()
            .ok()?;
        audit_before_deadline(deadline).then(|| commit.id.to_hex().to_string())
    })
}

fn audit_before_deadline(deadline: Option<Instant>) -> bool {
    deadline.is_none_or(|deadline| Instant::now() < deadline)
}

/// Match `rev-list --all`: this worktree's refs plus HEAD, including the main
/// and linked worktrees' detached HEADs, but excluding reflog-only objects.
fn git_count_tips(
    repository: &gix::Repository,
    deadline: Option<Instant>,
) -> Option<Vec<gix::ObjectId>> {
    let mut tips = gix::hashtable::HashSet::default();
    let references = repository.references().ok()?;
    for reference in references.all().ok()?.peeled().ok()? {
        if !audit_before_deadline(deadline) {
            return None;
        }
        let reference = reference.ok()?;
        let object = reference.id().object().ok()?;
        // Git permits tags and other refs to point to trees or blobs.
        if object.kind == gix::object::Kind::Commit {
            tips.insert(object.id);
        }
    }
    let mut add_head = |repo: &gix::Repository| -> Option<()> {
        if !audit_before_deadline(deadline) {
            return None;
        }
        if let Some(id) = repo.head().ok()?.try_peel_to_id().ok()?
            && id.object().ok()?.kind == gix::object::Kind::Commit
        {
            tips.insert(id.detach());
        }
        Some(())
    };
    add_head(repository)?;
    if repository.git_dir() != repository.common_dir() {
        add_head(&repository.main_repo().ok()?)?;
    }
    // Locked or removed checkouts still have countable HEADs in their private
    // git directories. If that metadata cannot be read, keep the count unknown
    // rather than silently reporting an incomplete total.
    for worktree in repository
        .worktrees()
        .inspect_err(|error| debug!(%error, "Cannot enumerate worktrees for audit commit count"))
        .ok()?
    {
        if !audit_before_deadline(deadline) {
            return None;
        }
        if worktree.git_dir() != repository.git_dir() {
            let repo = worktree
                .into_repo_with_possibly_inaccessible_worktree()
                .inspect_err(|error| debug!(%error, "Cannot open worktree for audit commit count"))
                .ok()?;
            add_head(&repo)?;
        }
    }
    Some(tips.into_iter().collect())
}

fn git_commit_count(
    repository: &gix::Repository,
    deadline: Option<Instant>,
    tip: Option<gix::ObjectId>,
) -> Option<u64> {
    if !audit_before_deadline(deadline) {
        return None;
    }
    let tips = match tip {
        Some(tip) => vec![tip],
        None => git_count_tips(repository, deadline)?,
    };
    let mut count = 0;
    if let Some(shallow) = repository.shallow_commits().ok()? {
        // gix's walker skips shallow parents globally, which can hide history
        // still reachable from another tip or merge parent. Stop only the edges
        // of each shallow commit, as Git does.
        let mut pending = tips;
        let mut seen = gix::hashtable::HashSet::default();
        while let Some(id) = pending.pop() {
            if !audit_before_deadline(deadline) {
                return None;
            }
            if !seen.insert(id) {
                continue;
            }
            let commit = repository.find_commit(id).ok()?;
            count += 1;
            if shallow.binary_search(&id).is_err() {
                pending.extend(commit.parent_ids().map(|parent| parent.detach()));
            }
        }
    } else {
        // Keep the walk streaming and let gix use the commit-graph cache when
        // present. Counting never needs tree/blob data or full commit metadata.
        let mut commits = repository.rev_walk(tips).all().ok()?;
        loop {
            if !audit_before_deadline(deadline) {
                return None;
            }
            let Some(commit) = commits.next() else { break };
            commit.ok()?;
            count += 1;
        }
    }
    audit_before_deadline(deadline).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn audit_commit_resolution_handles_refs_tags_and_invalid_input() {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = git2::Repository::init(&root).unwrap();
        let signature = git2::Signature::now("tester", "tester@example.com").unwrap();
        let tree_id = repo.index().unwrap().write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let commit =
            repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[]).unwrap();
        let object = repo.find_object(commit, None).unwrap();
        repo.tag("release", &object, &signature, "annotated tag", false).unwrap();
        repo.reference("refs/remotes/origin/feature", commit, false, "remote branch").unwrap();
        let deadline = Some(Instant::now() + Duration::from_secs(30));

        for reference in ["HEAD", "release", "feature", "origin/feature", &commit.to_string()] {
            assert_eq!(
                git_commit_sha(&gix::open(&root).unwrap(), deadline, reference),
                Some(commit.to_string()),
                "failed to resolve {reference}"
            );
        }
        for reference in ["missing", "--all", "--help", "HEAD..HEAD", &tree_id.to_string()] {
            assert_eq!(
                git_commit_sha(&gix::open(&root).unwrap(), deadline, reference),
                None,
                "unexpected commit for {reference}"
            );
        }
    }

    #[test]
    fn unlimited_repository_timeouts_preserve_audit_boundaries() {
        use clap::Parser;

        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = git2::Repository::init(&root).unwrap();
        let signature = git2::Signature::now("tester", "tester@example.com").unwrap();
        let tree_id = repo.index().unwrap().write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let commit =
            repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[]).unwrap();

        for options in [
            vec!["--git-repo-timeout=30"],
            vec!["--git-repo-timeout=0"],
            vec!["--git-repo-timeout=1", "--no-limits"],
            vec!["--git-repo-timeout=0", "--no-limits"],
        ] {
            let command = crate::cli::CommandLineArgs::try_parse_from(
                ["kingfisher", "scan", "."].into_iter().chain(options.iter().copied()),
            )
            .unwrap();
            let crate::cli::global::Command::Scan(command) = command.command else { panic!() };
            let crate::cli::commands::scan::ScanOperation::Scan(args) =
                command.into_operation().unwrap()
            else {
                panic!()
            };
            let snapshot = git_snapshot(&root, &args, false);
            assert_eq!(snapshot.tip_sha, Some(commit.to_string()), "options={options:?}");
            assert_eq!(snapshot.shallow, Some(false), "options={options:?}");
            assert_eq!(snapshot.fetched_commit_count, Some(1), "options={options:?}");
        }
    }

    fn scan_args(options: &[&str]) -> scan::ScanArgs {
        use clap::Parser;

        let command = crate::cli::CommandLineArgs::try_parse_from(
            ["kingfisher", "scan", "."].into_iter().chain(options.iter().copied()),
        )
        .unwrap();
        let crate::cli::global::Command::Scan(command) = command.command else { panic!() };
        let crate::cli::commands::scan::ScanOperation::Scan(args) =
            command.into_operation().unwrap()
        else {
            panic!()
        };
        args
    }

    fn commit(repo: &git2::Repository, parents: &[git2::Oid]) -> git2::Oid {
        let signature = git2::Signature::now("tester", "tester@example.com").unwrap();
        let tree_id = repo.treebuilder(None).unwrap().write().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let parents: Vec<_> = parents.iter().map(|id| repo.find_commit(*id).unwrap()).collect();
        let parent_refs: Vec<_> = parents.iter().collect();
        repo.commit(None, &signature, &signature, "audit fixture", &tree, &parent_refs).unwrap()
    }

    fn git_value(root: &Path, args: &[&str]) -> String {
        let output =
            std::process::Command::new("git").current_dir(root).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn assert_count_matches_git(root: &Path, branch: Option<&str>, expected: u64) {
        let args = match branch {
            Some(branch) => scan_args(&["--branch", branch]),
            None => scan_args(&[]),
        };
        let snapshot = git_snapshot(root, &args, false);
        let git_count = match branch {
            Some(branch) => git_value(root, &["rev-list", "--count", branch]),
            None => git_value(root, &["rev-list", "--all", "--count"]),
        };
        assert_eq!(git_count.parse::<u64>().unwrap(), expected);
        assert_eq!(snapshot.fetched_commit_count, Some(expected));
        assert_eq!(
            snapshot.shallow,
            Some(git_value(root, &["rev-parse", "--is-shallow-repository"]) == "true")
        );
    }

    #[test]
    fn audit_counts_unique_reachable_commits_and_peels_packed_tags() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let repo = git2::Repository::init(root).unwrap();
        let initial = commit(&repo, &[]);
        let left = commit(&repo, &[initial]);
        // Distinguish sibling commits even when written in the same second.
        let signature = git2::Signature::now("tester", "tester@example.com").unwrap();
        let tree = repo.find_commit(left).unwrap().tree().unwrap();
        let right = repo
            .commit(
                None,
                &signature,
                &signature,
                "other branch",
                &tree,
                &[&repo.find_commit(initial).unwrap()],
            )
            .unwrap();
        let merge = commit(&repo, &[left, right]);
        let tag_only = commit(&repo, &[right]);
        let detached = commit(&repo, &[initial, left]);
        let unreachable = commit(&repo, &[merge]);
        repo.reference("refs/heads/main", merge, true, "main").unwrap();
        repo.reference("refs/remotes/origin/feature", right, true, "remote").unwrap();
        repo.tag(
            "release",
            &repo.find_object(tag_only, None).unwrap(),
            &signature,
            "tag-only history",
            false,
        )
        .unwrap();
        repo.tag_lightweight("tree-only", tree.as_object(), false).unwrap();
        let blob = repo.blob(b"not a commit").unwrap();
        repo.tag_lightweight("blob-only", &repo.find_object(blob, None).unwrap(), false).unwrap();
        repo.set_head_detached(unreachable).unwrap();
        repo.set_head_detached(detached).unwrap();

        assert_count_matches_git(root, None, 6);
        assert_count_matches_git(root, Some("main"), 4);
        assert_count_matches_git(root, Some("release"), 3);
        let gix_repo = gix::open(root).unwrap();
        assert_eq!(git_commit_sha(&gix_repo, None, "release"), Some(tag_only.to_string()));
        assert_eq!(git_commit_sha(&gix_repo, None, "main~1"), Some(left.to_string()));
        assert_eq!(git_commit_sha(&gix_repo, None, "HEAD^2"), Some(left.to_string()));
        assert_eq!(
            git_commit_sha(&gix_repo, None, &merge.to_string()[..10]),
            Some(merge.to_string())
        );
        assert_eq!(git_commit_sha(&gix_repo, None, "blob-only"), None);
        assert_eq!(git_commit_sha(&gix_repo, None, "tree-only"), None);

        git_value(root, &["pack-refs", "--all", "--prune"]);
        git_value(root, &["repack", "-ad"]);
        git_value(root, &["commit-graph", "write", "--reachable"]);
        assert_count_matches_git(root, None, 6);
        assert_count_matches_git(root, Some("main"), 4);
        assert_count_matches_git(root, Some("release"), 3);
    }

    #[test]
    fn audit_shallow_counts_stop_only_at_the_boundary_commits() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let repo = git2::Repository::init(root).unwrap();
        let initial = commit(&repo, &[]);
        let middle = commit(&repo, &[initial]);
        let shallow_tip = commit(&repo, &[middle]);
        let merge = commit(&repo, &[shallow_tip, middle]);
        repo.reference("refs/heads/main", merge, true, "main").unwrap();
        repo.reference("refs/heads/boundary", shallow_tip, true, "shallow tip").unwrap();
        repo.set_head("refs/heads/main").unwrap();
        std::fs::write(repo.path().join("shallow"), format!("{shallow_tip}\n")).unwrap();
        assert_count_matches_git(root, None, 4);
        assert_count_matches_git(root, Some("main"), 4);
        assert_count_matches_git(root, Some("boundary"), 1);

        // A genuine truncated clone: the boundary's parent need not exist.
        repo.set_head("refs/heads/boundary").unwrap();
        repo.find_reference("refs/heads/main").unwrap().delete().unwrap();
        let middle_hex = middle.to_string();
        std::fs::remove_file(
            repo.path().join("objects").join(&middle_hex[..2]).join(&middle_hex[2..]),
        )
        .unwrap();
        assert_count_matches_git(root, None, 1);
    }

    #[test]
    fn audit_counts_worktree_heads_and_private_refs_from_either_worktree() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let repo = git2::Repository::init(root).unwrap();
        let initial = commit(&repo, &[]);
        let main_detached = commit(&repo, &[initial]);
        let linked_detached = commit(&repo, &[main_detached]);
        let private_tip = commit(&repo, &[linked_detached]);
        repo.reference("refs/heads/main", initial, true, "main").unwrap();
        repo.set_head("refs/heads/main").unwrap();
        let linked = root.join("linked worktree");
        repo.worktree("linked", &linked, None).unwrap();
        let linked_repo = git2::Repository::open(&linked).unwrap();
        linked_repo.set_head_detached(linked_detached).unwrap();
        linked_repo.reference("refs/worktree/private", private_tip, true, "private ref").unwrap();
        repo.set_head_detached(main_detached).unwrap();
        // --all includes other worktree HEADs, but only the current worktree's
        // private refs.
        assert_count_matches_git(root, None, 3);
        assert_count_matches_git(&linked, None, 4);
        // Main HEAD must still be counted when it is the only reference to a commit.
        git_value(&linked, &["update-ref", "-d", "refs/worktree/private"]);
        linked_repo.set_head_detached(initial).unwrap();
        assert_count_matches_git(&linked, None, 2);
    }

    #[test]
    fn audit_counts_heads_of_locked_and_removed_worktrees() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let repo = git2::Repository::init(root).unwrap();
        let initial = commit(&repo, &[]);
        let detached = commit(&repo, &[initial]);
        repo.reference("refs/heads/main", initial, true, "main").unwrap();
        repo.set_head("refs/heads/main").unwrap();
        let linked = root.join("linked worktree");
        let worktree = repo.worktree("linked", &linked, None).unwrap();
        let linked_repo = git2::Repository::open(&linked).unwrap();
        linked_repo.set_head_detached(detached).unwrap();
        worktree.lock(Some("offline worktree")).unwrap();
        assert_count_matches_git(root, None, 2);

        // Close handles before removing the checkout, especially on Windows.
        drop(linked_repo);
        drop(worktree);
        std::fs::remove_dir_all(&linked).unwrap();
        // Its private git directory still has a HEAD that Git counts.
        assert_count_matches_git(root, None, 2);
    }

    #[test]
    fn audit_handles_bare_empty_missing_and_nested_repositories() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("bare repository");
        let repo = git2::Repository::init_bare(&root).unwrap();
        assert_count_matches_git(&root, None, 0);
        let snapshot = git_snapshot(&root, &scan_args(&["--staged"]), false);
        assert_eq!(snapshot.base_ref.as_deref(), Some("4b825dc642cb6eb9a060e54bf8d69288fbee4904"));
        assert!(snapshot.base_sha.is_none());
        assert!(snapshot.tip_sha.is_none());
        let initial = commit(&repo, &[]);
        repo.reference("refs/heads/main", initial, true, "main").unwrap();
        repo.set_head("refs/heads/main").unwrap();
        assert_count_matches_git(&root, None, 1);
        let staged = git_snapshot(&root, &scan_args(&["--staged"]), false);
        assert_eq!(staged.base_ref, Some(initial.to_string()));
        assert_eq!(staged.base_sha, Some(initial.to_string()));
        assert!(staged.fetched_commit_count.is_none());

        let working = temp.path().join("working repository");
        let working_repo = git2::Repository::init(&working).unwrap();
        let initial = commit(&working_repo, &[]);
        working_repo.reference("refs/heads/main", initial, true, "main").unwrap();
        working_repo.set_head("refs/heads/main").unwrap();
        let nested = working.join("subdirectory");
        std::fs::create_dir(&nested).unwrap();
        assert_count_matches_git(&nested, None, 1);

        let missing = git_snapshot(temp.path(), &scan_args(&[]), false);
        assert!(missing.tip_sha.is_none());
        assert!(missing.shallow.is_none());
        assert!(missing.fetched_commit_count.is_none());
    }

    #[test]
    fn audit_preserves_explicit_boundaries_and_snapshot_scopes() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let repo = git2::Repository::init(root).unwrap();
        let initial = commit(&repo, &[]);
        let tip = commit(&repo, &[initial]);
        repo.reference("refs/heads/main", tip, true, "main").unwrap();
        repo.reference("refs/remotes/origin/base", initial, true, "base").unwrap();
        repo.set_head("refs/heads/main").unwrap();
        for options in [
            vec!["--since-commit", "base"],
            vec!["--branch", "main", "--since-commit", "base"],
            vec!["--staged", "--since-commit", "base"],
        ] {
            let snapshot = git_snapshot(root, &scan_args(&options), false);
            assert_eq!(snapshot.base_ref.as_deref(), Some("base"));
            assert_eq!(snapshot.base_sha, Some(initial.to_string()));
            assert!(snapshot.fetched_commit_count.is_none());
        }
        let snapshot =
            git_snapshot(root, &scan_args(&["--branch", "base", "--branch-root"]), false);
        assert_eq!(snapshot.tip_sha, Some(tip.to_string()));
        assert_eq!(snapshot.inclusive_root_sha, Some(initial.to_string()));
        let snapshot = git_snapshot(root, &scan_args(&["--git-history", "none"]), true);
        assert_eq!(snapshot.clone_mode.as_deref(), Some("checkout"));
        assert!(snapshot.fetched_commit_count.is_none());
    }

    #[test]
    fn audit_snapshot_works_without_git_on_path() {
        let temp = tempdir().unwrap();
        let repo = git2::Repository::init(temp.path()).unwrap();
        let initial = commit(&repo, &[]);
        repo.reference("refs/heads/main", initial, true, "main").unwrap();
        repo.set_head("refs/heads/main").unwrap();
        let empty_path = temp.path().join("empty path");
        std::fs::create_dir(&empty_path).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "scan_audit::tests::audit_without_git_child", "--nocapture"])
            .env("PATH", &empty_path)
            .env("KF_TEST_AUDIT_REPO", temp.path())
            .env("KF_TEST_AUDIT_COMMIT", initial.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child audit failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn audit_without_git_child() {
        let Some(root) = std::env::var_os("KF_TEST_AUDIT_REPO") else { return };
        assert!(std::process::Command::new("git").arg("--version").output().is_err());
        let snapshot = git_snapshot(Path::new(&root), &scan_args(&[]), false);
        assert_eq!(snapshot.tip_sha, Some(std::env::var("KF_TEST_AUDIT_COMMIT").unwrap()));
        assert_eq!(snapshot.fetched_commit_count, Some(1));
        assert_eq!(snapshot.shallow, Some(false));
    }

    #[test]
    fn audit_does_not_report_partial_counts_or_expired_metadata() {
        let temp = tempdir().unwrap();
        let repo = git2::Repository::init(temp.path()).unwrap();
        let initial = commit(&repo, &[]);
        let tip = commit(&repo, &[initial]);
        repo.reference("refs/heads/main", tip, true, "main").unwrap();
        repo.set_head("refs/heads/main").unwrap();
        let gix_repo = gix::open(temp.path()).unwrap();
        let expired = Some(Instant::now() - Duration::from_secs(1));
        assert!(git_commit_sha(&gix_repo, expired, "HEAD").is_none());
        assert!(git_commit_count(&gix_repo, expired, None).is_none());
        let initial_hex = initial.to_string();
        std::fs::remove_file(
            repo.path().join("objects").join(&initial_hex[..2]).join(&initial_hex[2..]),
        )
        .unwrap();
        assert!(git_commit_count(&gix_repo, None, None).is_none());
        let snapshot = git_snapshot(temp.path(), &scan_args(&[]), false);
        assert_eq!(snapshot.tip_sha, Some(tip.to_string()));
        assert!(snapshot.fetched_commit_count.is_none());
        assert_eq!(snapshot.shallow, Some(false));
    }

    #[test]
    fn manifest_summary_counts_repository_outcomes() {
        let mut collector = ScanAuditCollector::new("2026-01-01T00:00:00Z".into(), None).unwrap();
        collector.discover_remote("https://github.com/acme/one.git");
        collector.discover_remote("https://github.com/acme/two.git");
        collector.fetch_failed("https://github.com/acme/two.git", "permission denied\nwith detail");
        let manifest = collector.finish().unwrap();
        assert_eq!(manifest.summary.discovered, 2);
        assert_eq!(manifest.summary.fetch_failed, 1);
        assert_eq!(
            manifest.repositories[1].fetch.error.as_deref(),
            Some("permission denied with detail")
        );
    }

    #[test]
    fn local_repositories_are_not_fetch_successes() {
        let mut collector = ScanAuditCollector::new("2026-01-01T00:00:00Z".into(), None).unwrap();
        collector.discover_local(Path::new("/tmp/repo"));
        let manifest = collector.finish().unwrap();
        assert_eq!(manifest.summary.discovered, 1);
        assert_eq!(manifest.summary.fetch_succeeded, 0);
        assert_eq!(manifest.summary.fetch_failed, 0);
    }

    #[test]
    fn streamed_non_git_roots_have_terminal_coverage() {
        for partial in [false, true] {
            let mut collector =
                ScanAuditCollector::new("2026-01-01T00:00:00Z".into(), None).unwrap();
            let root = tempfile::tempdir().unwrap();
            let key = collector.scan_started_with_snapshot(root.path(), None).unwrap();
            let stats = RepositoryScanStats { findings: 0, blobs_scanned: 1, bytes_scanned: 42 };
            if partial {
                collector.scan_partial(&key, stats, "unreadable input");
            } else {
                collector.scan_completed(&key, stats);
            }
            let manifest = collector.finish().unwrap();
            assert!(manifest.completed_at.is_some());
            assert_eq!(manifest.summary.discovered, 1);
            assert_eq!(manifest.summary.pending, 0);
            assert_eq!(manifest.summary.scan_partial, usize::from(partial));
            assert_eq!(manifest.summary.scan_succeeded, usize::from(!partial));
            assert!(manifest.repositories[0].git.is_none());
        }
    }

    #[test]
    fn started_at_is_normalized_to_utc() {
        let collector = ScanAuditCollector::new("2026-01-01T12:00:00-08:00".into(), None).unwrap();
        assert_eq!(collector.manifest.started_at, "2026-01-01T20:00:00+00:00");
    }

    #[test]
    fn audit_errors_redact_url_credentials_and_authorization_headers() {
        let error = "clone https://user:token@example.com/acme/repo failed Authorization: Bearer very-secret";
        let sanitized = sanitize_error(error);
        assert_eq!(sanitized, "clone https://***@example.com/acme/repo failed Authorization: ***");
    }

    #[cfg(unix)]
    #[test]
    fn audit_log_refuses_symlinked_path() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("target.jsonl");
        std::fs::write(&target, b"ORIGINAL_CONTENT").unwrap();

        // A symlink planted at the audit-log path must be refused instead of
        // followed, leaving its target untouched.
        let link = temp.path().join("repository-audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = ScanAuditCollector::new("2026-01-01T00:00:00Z".into(), Some(&link));
        assert!(result.is_err(), "audit log must refuse a symlinked output path");
        assert_eq!(std::fs::read(&target).unwrap(), b"ORIGINAL_CONTENT");
    }

    #[test]
    fn discovery_failure_marks_streamed_audit_records_incomplete() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("audit.jsonl");
        let mut collector =
            ScanAuditCollector::new("2026-01-01T00:00:00Z".into(), Some(&path)).unwrap();
        collector.discover_remote("https://github.com/acme/first.git");
        collector.run_failed();
        let text = std::fs::read_to_string(path).unwrap();
        let events: Vec<serde_json::Value> =
            text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(events.last().unwrap()["event"], "run_failed");
        assert!(!events.iter().any(|event| event["event"] == "run_completed"));
    }

    #[test]
    fn incremental_log_flushes_lifecycle_events() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("repository-audit.jsonl");
        let mut collector =
            ScanAuditCollector::new("2026-01-01T00:00:00Z".into(), Some(&path)).unwrap();
        let repository = "https://github.com/acme/example.git";
        collector.discover_remote(repository);
        collector.fetch_started(repository);
        collector.fetch_failed(repository, "permission denied");
        collector.finish().unwrap();

        let events = std::fs::read_to_string(path).unwrap();
        assert!(events.contains("\"event\":\"run_started\""));
        assert!(events.contains("\"event\":\"repository_discovered\""));
        assert!(events.contains("\"event\":\"repository_fetch_failed\""));
        assert!(events.contains("\"event\":\"run_completed\""));
    }
}
