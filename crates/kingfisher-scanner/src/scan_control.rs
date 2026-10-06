//! Per-call cooperative deadlines and cancellation, independent of scanner configuration.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// A reusable, thread-safe cancellation signal. Cancellation is permanent for this token.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Permanently signal cancellation to every clone of this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Return whether cancellation has been signalled.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Why a scan stopped. Interrupted scans return an error, never partial findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScanAborted {
    #[error("scan cancelled")]
    /// The caller signalled cancellation.
    Cancelled,
    #[error("scan deadline exceeded")]
    /// The configured deadline was reached.
    TimedOut,
}

/// Optional limits for one scan. Existing scan methods use unlimited controls.
///
/// Checks run between matching/filtering operations and in Vectorscan callbacks.
/// Individual native operations, file reads and decoding cannot be preempted, so
/// a deadline is cooperative rather than a hard wall-clock execution limit.
#[derive(Clone, Debug, Default)]
pub struct ScanControl {
    deadline: Option<Instant>,
    cancellation: Option<CancellationToken>,
    #[cfg(test)]
    observer: Option<CheckObserver>,
}

#[cfg(test)]
#[derive(Clone)]
struct CheckObserver(Arc<CheckCallback>);
#[cfg(test)]
type CheckCallback =
    dyn Fn(&'static std::panic::Location<'static>) -> Result<(), ScanAborted> + Send + Sync;
#[cfg(test)]
impl std::fmt::Debug for CheckObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckObserver")
    }
}

impl ScanControl {
    /// Set an absolute deadline, shared across all phases of a scan.
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Set a deadline relative to now. An unrepresentable duration is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if the duration overflows the platform's monotonic clock.
    pub fn with_timeout(self, timeout: Duration) -> anyhow::Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| anyhow::anyhow!("scan timeout is too large"))?;
        Ok(self.with_deadline(deadline))
    }

    /// Attach a cancellation token; all its clones can interrupt this call.
    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.cancellation = Some(token);
        self
    }

    pub(crate) fn is_limited(&self) -> bool {
        #[cfg(test)]
        if self.observer.is_some() {
            return true;
        }
        self.deadline.is_some() || self.cancellation.is_some()
    }

    #[cfg(test)]
    pub(crate) fn with_check_observer(
        mut self,
        observer: impl Fn(&'static std::panic::Location<'static>) -> Result<(), ScanAborted>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.observer = Some(CheckObserver(Arc::new(observer)));
        self
    }

    /// Check the cancellation signal and deadline without performing scan work.
    ///
    /// # Errors
    ///
    /// Returns [`ScanAborted::Cancelled`] if cancelled, otherwise
    /// [`ScanAborted::TimedOut`] if the deadline was reached.
    #[inline]
    #[cfg_attr(test, track_caller)]
    pub fn check(&self) -> Result<(), ScanAborted> {
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            (observer.0)(std::panic::Location::caller())?;
        }
        if self.cancellation.as_ref().is_some_and(CancellationToken::is_cancelled) {
            return Err(ScanAborted::Cancelled);
        }
        if self.deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ScanAborted::TimedOut);
        }
        Ok(())
    }
}
