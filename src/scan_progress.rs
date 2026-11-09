//! Live CLI progress and opt-in snapshots for the native wizard's child process.
//! No report content or credentials are written to either channel.
use std::{
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use thousands::Separable;

#[derive(Default)]
struct Counters {
    claimed: AtomicBool,
    enabled: AtomicBool,
    include_hidden: AtomicBool,
    bytes: AtomicU64,
    blobs: AtomicU64,
    findings: AtomicU64,
    phase: Mutex<Phase>,
    terminal: Mutex<Option<ProgressBar>>,
    completed: AtomicU64,
    total: AtomicU64,
}

impl Counters {
    fn reportable(&self, visible: bool) -> bool {
        visible || self.include_hidden.load(Ordering::Relaxed)
    }

    fn found(&self, visibility: impl Iterator<Item = bool>, origins: u64) {
        let include_hidden = self.include_hidden.load(Ordering::Relaxed);
        let count = visibility.filter(|visible| *visible || include_hidden).count() as u64;
        self.findings.fetch_add(count * origins, Ordering::Relaxed);
    }

    fn enter(&self, kind: PhaseKind, total: u64, now: Instant) {
        let mut phase = self.phase.lock().unwrap();
        self.total.fetch_add(total, Ordering::Relaxed);
        phase.activity(kind, true, now);
    }

    fn snapshot(&self, now: Instant) -> Snapshot {
        let phase = self.phase.lock().unwrap();
        Snapshot {
            bytes: self.bytes.load(Ordering::Relaxed),
            blobs: self.blobs.load(Ordering::Relaxed),
            findings: self.findings.load(Ordering::Relaxed),
            phase: phase.label.clone(),
            kind: phase.kind,
            scan_seconds: phase.scan_seconds(now),
            completed: self.completed.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PhaseKind {
    #[default]
    Other,
    Scan,
    Validation,
}

#[derive(Default)]
struct Phase {
    kind: PhaseKind,
    label: String,
    scan_started: Option<Instant>,
    scan_elapsed: Duration,
    active_scans: usize,
    active_validations: usize,
}
impl Phase {
    fn set(&mut self, label: &str, kind: PhaseKind, now: Instant) {
        if let Some(started) = self.scan_started.take() {
            self.scan_elapsed += now.saturating_duration_since(started);
        }
        self.label = label.to_owned();
        self.kind = kind;
        if kind == PhaseKind::Scan {
            self.scan_started = Some(now);
        }
    }

    fn activity(&mut self, kind: PhaseKind, entering: bool, now: Instant) {
        let active = match kind {
            PhaseKind::Scan => &mut self.active_scans,
            PhaseKind::Validation => &mut self.active_validations,
            PhaseKind::Other => return,
        };
        if entering {
            *active += 1;
        } else {
            debug_assert!(*active > 0, "scan progress activities must be paired");
            *active = active.saturating_sub(1);
        }
        // Repository scans and validation can overlap. Keep one aggregate line, with
        // scanning taking precedence until the last active scanner has finished.
        let (label, kind) = if self.active_scans > 0 {
            ("Scanning files and Git history", PhaseKind::Scan)
        } else if self.active_validations > 0 {
            ("Validating credentials", PhaseKind::Validation)
        } else {
            ("Processing findings", PhaseKind::Other)
        };
        if self.kind != kind {
            self.set(label, kind, now);
        }
    }

    fn scan_seconds(&self, now: Instant) -> f64 {
        (self.scan_elapsed
            + self
                .scan_started
                .map(|start| now.saturating_duration_since(start))
                .unwrap_or_default())
        .as_secs_f64()
    }
}

#[derive(serde::Serialize)]
struct Snapshot {
    bytes: u64,
    blobs: u64,
    findings: u64,
    phase: String,
    kind: PhaseKind,
    scan_seconds: f64,
    completed: u64,
    total: u64,
}

impl Snapshot {
    fn message(&self, elapsed: Duration) -> String {
        let seconds = elapsed.as_secs();
        let elapsed = format!("{:02}:{:02}", seconds / 60, seconds % 60);
        match self.kind {
            PhaseKind::Scan => {
                let rate = if self.scan_seconds > 0.0 {
                    self.bytes as f64 / self.scan_seconds
                } else {
                    0.0
                };
                format!(
                    "scanning {} inputs · {} · {}/s · {} findings (incl. duplicates) · {elapsed}",
                    self.blobs.separate_with_commas(),
                    format_bytes(self.bytes as f64),
                    format_bytes(rate),
                    self.findings.separate_with_commas(),
                )
            }
            PhaseKind::Validation => format!(
                "validating {}/{} findings checked · {} findings (incl. duplicates) · {elapsed}",
                self.completed.separate_with_commas(),
                self.total.separate_with_commas(),
                self.findings.separate_with_commas(),
            ),
            PhaseKind::Other => format!("{} · {elapsed}", self.phase),
        }
    }
}

fn format_bytes(bytes: f64) -> String {
    if bytes >= 1024_f64.powi(3) {
        format!("{:.2} GB", bytes / 1024_f64.powi(3))
    } else if bytes >= 1024_f64.powi(2) {
        format!("{:.1} MB", bytes / 1024_f64.powi(2))
    } else if bytes >= 1024.0 {
        format!("{:.1} KB", bytes / 1024.0)
    } else {
        format!("{bytes:.0} B")
    }
}

static COUNTERS: LazyLock<Arc<Counters>> = LazyLock::new(|| Arc::new(Counters::default()));

pub(crate) struct ProgressGuard {
    sender: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for ProgressGuard {
    fn drop(&mut self) {
        if let Some(sender) = &self.sender {
            let _ = sender.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        finish_terminal();
        COUNTERS.enabled.store(false, Ordering::Relaxed);
        COUNTERS.claimed.store(false, Ordering::Release);
    }
}

pub(crate) fn start(terminal_enabled: bool, include_hidden: bool) -> Option<ProgressGuard> {
    let path = std::env::var_os("KINGFISHER_PROGRESS_FILE");
    if !terminal_enabled && path.is_none() {
        return None;
    }
    let counters = Arc::clone(&COUNTERS);
    // A second scan must not reset another guard's counters or later clear its
    // terminal. The original guard owns progress until its snapshot writer exits.
    if counters.claimed.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
    {
        return None;
    }
    counters.bytes.store(0, Ordering::Relaxed);
    counters.blobs.store(0, Ordering::Relaxed);
    counters.findings.store(0, Ordering::Relaxed);
    counters.completed.store(0, Ordering::Relaxed);
    counters.total.store(0, Ordering::Relaxed);
    counters.include_hidden.store(include_hidden, Ordering::Relaxed);
    *counters.phase.lock().unwrap() = Phase::default();
    counters.enabled.store(true, Ordering::Relaxed);
    phase("Preparing scan", 0, PhaseKind::Other);

    let terminal = terminal_enabled.then(|| {
        let counters = Arc::clone(&counters);
        let style = ProgressStyle::with_template("{spinner} {status}")
            .expect("progress template should compile")
            .with_key("status", move |state: &ProgressState, writer: &mut dyn std::fmt::Write| {
                let _ =
                    writer.write_str(&counters.snapshot(Instant::now()).message(state.elapsed()));
            });
        let pb = ProgressBar::new_spinner().with_style(style);
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    });
    *counters.terminal.lock().unwrap() = terminal.clone();
    let (sender, thread) = if let Some(path) = path {
        let (sender, receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut finished = false;
            loop {
                let snapshot = counters.snapshot(Instant::now());
                // A reader may catch an incomplete write; it keeps the previous valid snapshot.
                let _ = std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap());
                if finished {
                    break;
                }
                finished = !matches!(
                    receiver.recv_timeout(Duration::from_millis(500)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                );
            }
        });
        (Some(sender), Some(thread))
    } else {
        (None, None)
    };
    Some(ProgressGuard { sender, thread })
}

pub(crate) fn terminal() -> Option<ProgressBar> {
    COUNTERS.terminal.lock().unwrap().clone()
}

/// Stop terminal rendering before reports/summaries, but keep wizard snapshots alive.
pub(crate) fn finish_terminal() {
    if let Some(terminal) = COUNTERS.terminal.lock().unwrap().take() {
        terminal.finish_and_clear();
    }
}

/// Streaming per-repository reports can overlap other scans. Pause the one shared
/// renderer for the entire atomic stdout write, rather than clearing another line.
pub(crate) fn suspend<T>(write: impl FnOnce() -> T) -> T {
    if let Some(terminal) = terminal() { terminal.suspend(write) } else { write() }
}

pub(crate) fn enabled() -> bool {
    COUNTERS.enabled.load(Ordering::Relaxed)
}

pub(crate) fn scanned(bytes: u64) {
    if COUNTERS.enabled.load(Ordering::Relaxed) {
        COUNTERS.bytes.fetch_add(bytes, Ordering::Relaxed);
        COUNTERS.blobs.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn found(visibility: impl Iterator<Item = bool>, origins: u64) {
    if COUNTERS.enabled.load(Ordering::Relaxed) {
        COUNTERS.found(visibility, origins);
    }
}

pub(crate) fn reportable(visible: bool) -> bool {
    COUNTERS.reportable(visible)
}

pub(crate) struct ActivityGuard {
    counters: Option<Arc<Counters>>,
    kind: PhaseKind,
}
impl ActivityGuard {
    pub(crate) fn advance(&self, count: u64) {
        if let Some(counters) = &self.counters {
            counters.completed.fetch_add(count, Ordering::Relaxed);
        }
    }
}
impl Drop for ActivityGuard {
    fn drop(&mut self) {
        if let Some(counters) = &self.counters {
            counters.phase.lock().unwrap().activity(self.kind, false, Instant::now());
        }
    }
}

fn activity(kind: PhaseKind, total: u64) -> ActivityGuard {
    let counters = COUNTERS.enabled.load(Ordering::Relaxed).then(|| Arc::clone(&COUNTERS));
    if let Some(counters) = &counters {
        counters.enter(kind, total, Instant::now());
    }
    ActivityGuard { counters, kind }
}

pub(crate) fn scanning() -> ActivityGuard {
    activity(PhaseKind::Scan, 0)
}

pub(crate) fn validating(total: u64) -> ActivityGuard {
    activity(PhaseKind::Validation, total)
}

pub(crate) fn phase(label: &str, total: u64, kind: PhaseKind) {
    if COUNTERS.enabled.load(Ordering::Relaxed) {
        let mut phase = COUNTERS.phase.lock().unwrap();
        if phase.active_scans == 0 && phase.active_validations == 0 {
            phase.set(label, kind, Instant::now());
            if kind != PhaseKind::Other {
                COUNTERS.completed.store(0, Ordering::Relaxed);
                COUNTERS.total.store(total, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_can_finish_before_snapshot_guard_and_nested_start_cannot_replace_it() {
        let guard = start(true, false).expect("first progress owner");
        scanned(42);
        assert!(start(true, true).is_none());
        assert_eq!(COUNTERS.snapshot(Instant::now()).bytes, 42);
        finish_terminal();
        assert!(terminal().is_none());
        assert!(enabled(), "snapshot counters remain active during report output");
        scanned(8);
        assert_eq!(COUNTERS.snapshot(Instant::now()).bytes, 50);
        drop(guard);
        assert!(!enabled());
        assert!(!COUNTERS.claimed.load(Ordering::Acquire));
    }

    #[test]
    fn scan_clock_excludes_preparation_validation_and_reporting() {
        let start = Instant::now();
        let mut phase = Phase::default();
        phase.set("Preparing scan", PhaseKind::Other, start);
        phase.set(
            "Inspecting files and Git history",
            PhaseKind::Scan,
            start + Duration::from_secs(10),
        );
        assert_eq!(phase.scan_seconds(start + Duration::from_secs(12)), 2.);
        phase.set("Checking credentials", PhaseKind::Validation, start + Duration::from_secs(15));
        assert_eq!(phase.scan_seconds(start + Duration::from_secs(60)), 5.);
        phase.set(
            "Checking dependent credentials",
            PhaseKind::Validation,
            start + Duration::from_secs(65),
        );
        phase.set("Writing report", PhaseKind::Other, start + Duration::from_secs(90));
        assert_eq!(phase.scan_seconds(start + Duration::from_secs(100)), 5.);
    }

    #[test]
    fn findings_aggregate_occurrences_without_counting_hidden_helpers() {
        let counters = Counters::default();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| counters.found([true, false, true].into_iter(), 3));
            }
        });
        assert_eq!(counters.snapshot(Instant::now()).findings, 24);
        counters.include_hidden.store(true, Ordering::Relaxed);
        counters.found([true, false, true].into_iter(), 2);
        assert_eq!(counters.snapshot(Instant::now()).findings, 30);
    }

    #[test]
    fn overlapping_activities_preserve_validation_totals_and_scan_clock() {
        let counters = Arc::new(Counters::default());
        let start = Instant::now();
        counters.enter(PhaseKind::Scan, 0, start);
        counters.enter(PhaseKind::Scan, 0, start + Duration::from_secs(1));
        counters.enter(PhaseKind::Validation, 10, start + Duration::from_secs(2));
        counters.enter(PhaseKind::Validation, 20, start + Duration::from_secs(3));
        let progress =
            ActivityGuard { counters: Some(Arc::clone(&counters)), kind: PhaseKind::Validation };
        progress.advance(7);
        counters.phase.lock().unwrap().activity(
            PhaseKind::Scan,
            false,
            start + Duration::from_secs(4),
        );
        let scanning = counters.snapshot(start + Duration::from_secs(5));
        assert!(scanning.kind == PhaseKind::Scan);
        assert_eq!(scanning.scan_seconds, 5.);
        counters.phase.lock().unwrap().activity(
            PhaseKind::Scan,
            false,
            start + Duration::from_secs(6),
        );
        let validating = counters.snapshot(start + Duration::from_secs(10));
        assert!(validating.kind == PhaseKind::Validation);
        assert_eq!((validating.completed, validating.total), (7, 30));
        assert_eq!(validating.scan_seconds, 6.);
        drop(progress);
        let remaining = counters.snapshot(start + Duration::from_secs(11));
        assert!(remaining.kind == PhaseKind::Validation);
        assert_eq!((remaining.completed, remaining.total), (7, 30));
    }

    #[test]
    fn dropping_activity_guards_balances_phase_counts() {
        let counters = Arc::new(Counters::default());
        for kind in [PhaseKind::Scan, PhaseKind::Validation] {
            counters.enter(kind, 0, Instant::now());
            drop(ActivityGuard { counters: Some(Arc::clone(&counters)), kind });
        }
        let phase = counters.phase.lock().unwrap();
        assert_eq!(phase.active_scans, 0);
        assert_eq!(phase.active_validations, 0);
        assert!(phase.kind == PhaseKind::Other);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "scan progress activities must be paired")]
    fn unbalanced_activities_have_an_explicit_debug_invariant() {
        Phase::default().activity(PhaseKind::Scan, false, Instant::now());
    }

    #[test]
    fn live_messages_label_duplicate_inclusive_findings_and_reportable_validation_progress() {
        let mut snapshot = Snapshot {
            bytes: 1024 * 1024 * 1024,
            blobs: 663_204,
            findings: 103_411,
            phase: String::new(),
            kind: PhaseKind::Scan,
            scan_seconds: 2.,
            completed: 1_188,
            total: 1_235,
        };
        assert_eq!(
            snapshot.message(Duration::from_secs(31)),
            "scanning 663,204 inputs · 1.00 GB · 512.0 MB/s · 103,411 findings (incl. duplicates) · 00:31"
        );
        snapshot.kind = PhaseKind::Validation;
        snapshot.findings = 137_799;
        assert_eq!(
            snapshot.message(Duration::from_secs(114)),
            "validating 1,188/1,235 findings checked · 137,799 findings (incl. duplicates) · 01:54"
        );
    }
}
