//! Repository coverage auditing for multi-asset scans.

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::json;
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
    /// mutex: `git_snapshot` runs blocking Git subprocesses, and holding the
    /// lock while they run serializes worker startup across the scan. Pass
    /// `None` for roots that are not Git repositories so no git boundary is
    /// recorded for them.
    pub fn scan_started_with_snapshot(
        &mut self,
        root: &Path,
        snapshot: Option<GitAuditSnapshot>,
    ) -> Option<String> {
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
            "summary": if event == "run_completed" { Some(summarize(&self.records.values().cloned().collect::<Vec<_>>())) } else { None },
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

fn sanitize_error(error: &str) -> String {
    let compact = error.split_whitespace().collect::<Vec<_>>().join(" ");
    let compact = regex::Regex::new(r"(?i)(https?://)[^/@\s]+@")
        .expect("valid URL credential regex")
        .replace_all(&compact, "$1***@");
    let compact = regex::Regex::new(r"(?i)(authorization:\s*)(?:(?:bearer|basic)\s+)?[^\s,;]+")
        .expect("valid authorization header regex")
        .replace_all(&compact, "$1***");
    compact.chars().take(2048).collect()
}

/// Gathers the git boundary information for a repository scan.
///
/// This runs blocking Git subprocesses and must be called *outside* any lock
/// shared with other scan workers (see [`ScanAuditCollector::scan_started_with_snapshot`]).
/// Each command is bounded by the repository timeout from `args`.
pub fn git_snapshot(root: &Path, args: &scan::ScanArgs, fetched: bool) -> GitAuditSnapshot {
    let deadline = Instant::now() + Duration::from_secs(args.git_repo_timeout);
    let input = &args.input_specifier_args;
    let branch_root_enabled = input.branch_root || input.branch_root_commit.is_some();
    let scope = if input.staged {
        "staged_tree_diff"
    } else if input.since_commit.is_some() {
        "tree_diff"
    } else if branch_root_enabled {
        "inclusive_root_tree_diff"
    } else if input.branch.is_some() {
        "git_tree"
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
            git_output(root, deadline, &["rev-parse", "--verify", "HEAD"])
                .or_else(|| git_output(root, deadline, &["hash-object", "-t", "tree", "/dev/null"]))
        });
        ("(staged index)".to_string(), None, base)
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
        let tip_sha = git_output(
            root,
            deadline,
            &["rev-parse", "--verify", &format!("{tip_ref}^{{commit}}")],
        );
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
        git_output(root, deadline, &["rev-list", "--all", "--count"])
            .and_then(|value| value.parse().ok())
    } else {
        None
    };
    GitAuditSnapshot {
        scope: scope.to_string(),
        tip_sha,
        tip_ref,
        base_sha: base_ref.as_ref().and_then(|value| {
            git_output(root, deadline, &["rev-parse", "--verify", &format!("{value}^{{commit}}")])
        }),
        base_ref,
        inclusive_root_sha: inclusive_root_ref.as_ref().and_then(|value| {
            git_output(root, deadline, &["rev-parse", "--verify", &format!("{value}^{{commit}}")])
        }),
        inclusive_root_ref,
        clone_mode,
        shallow: git_output(root, deadline, &["rev-parse", "--is-shallow-repository"])
            .map(|value| value == "true"),
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

fn git_output(root: &Path, deadline: Instant, args: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    if root.join("HEAD").is_file() && root.join("objects").is_dir() {
        command.arg("--git-dir").arg(root);
    } else {
        command.arg("-C").arg(root);
    }
    command.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().ok()?;

    // Poll for completion so a wedged Git subprocess cannot outlive the
    // repository timeout (plain `output()` would block without bound). Every
    // audited command produces tiny output, so the pipe cannot fill while we
    // poll; an unexpected chatty command would simply hit the deadline.
    let mut backoff = Duration::from_millis(1);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    };
    if !status.success() {
        return None;
    }
    let output = child.wait_with_output().ok()?;
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
