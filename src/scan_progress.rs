//! Lightweight, opt-in progress snapshots for the native wizard's child process.
//! No report content or credentials are written to this channel.
use std::{
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Counters {
    bytes: AtomicU64,
    blobs: AtomicU64,
    phase: Mutex<Phase>,
    completed: AtomicU64,
    total: AtomicU64,
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
    fn scan_seconds(&self, now: Instant) -> f64 {
        (self.scan_elapsed
            + self
                .scan_started
                .map(|start| now.saturating_duration_since(start))
                .unwrap_or_default())
        .as_secs_f64()
    }
}
static COUNTERS: LazyLock<Option<Arc<Counters>>> = LazyLock::new(|| {
    std::env::var_os("KINGFISHER_PROGRESS_FILE").map(|_| Arc::new(Counters::default()))
});

pub(crate) struct ProgressGuard(mpsc::Sender<()>, Option<thread::JoinHandle<()>>);
impl Drop for ProgressGuard {
    fn drop(&mut self) {
        let _ = self.0.send(());
        if let Some(thread) = self.1.take() {
            let _ = thread.join();
        }
    }
}
pub(crate) fn start() -> Option<ProgressGuard> {
    let counters = COUNTERS.as_ref()?.clone();
    let path = std::env::var_os("KINGFISHER_PROGRESS_FILE")?;
    phase("Preparing scan", 0, PhaseKind::Other);
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let mut finished = false;
        loop {
            let phase = counters.phase.lock().unwrap();
            let snapshot = serde_json::json!({
                "bytes": counters.bytes.load(Ordering::Relaxed),
                "blobs": counters.blobs.load(Ordering::Relaxed),
                "phase": phase.label,
                "kind": phase.kind,
                "scan_seconds": phase.scan_seconds(Instant::now()),
                "completed": counters.completed.load(Ordering::Relaxed),
                "total": counters.total.load(Ordering::Relaxed),
            });
            drop(phase);
            // A reader may catch an incomplete write; it keeps the previous valid snapshot.
            let _ = std::fs::write(&path, snapshot.to_string());
            if finished {
                break;
            }
            finished = !matches!(
                receiver.recv_timeout(Duration::from_millis(500)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
        }
    });
    Some(ProgressGuard(sender, Some(thread)))
}
pub(crate) fn scanned(bytes: u64) {
    if let Some(counters) = COUNTERS.as_ref() {
        counters.bytes.fetch_add(bytes, Ordering::Relaxed);
        counters.blobs.fetch_add(1, Ordering::Relaxed);
    }
}
pub(crate) fn phase(label: &str, total: u64, kind: PhaseKind) {
    if let Some(counters) = COUNTERS.as_ref() {
        let mut phase = counters.phase.lock().unwrap();
        phase.set(label, kind, Instant::now());
        counters.completed.store(0, Ordering::Relaxed);
        counters.total.store(total, Ordering::Relaxed);
    }
}
pub(crate) fn advance() {
    if let Some(counters) = COUNTERS.as_ref() {
        counters.completed.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
