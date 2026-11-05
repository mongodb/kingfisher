use std::{
    future::Future,
    sync::{Arc, OnceLock},
    time::Duration,
};

use kingfisher_scanner::{CancellationToken, ScanAborted, ScanControl};
use napi::{Error, Result, Status};
use napi_derive::napi;
use tokio::sync::Semaphore;

pub(crate) fn failure(code: &str, message: &str) -> Error {
    Error::new(Status::GenericFailure, format!("{code}: {message}"))
}

pub(crate) fn invalid(message: &str) -> Error {
    Error::new(Status::InvalidArg, format!("KF_INVALID_ARGUMENT: {message}"))
}

pub(crate) fn interrupted(reason: ScanAborted) -> Error {
    match reason {
        ScanAborted::Cancelled => failure("KF_CANCELLED", "operation cancelled"),
        ScanAborted::TimedOut => failure("KF_TIMEOUT", "operation deadline exceeded"),
    }
}

pub(crate) fn scan_error(error: anyhow::Error) -> Error {
    if let Some(reason) = error.downcast_ref::<ScanAborted>() {
        interrupted(*reason)
    } else if error.is::<std::io::Error>() {
        failure("KF_IO", "input could not be read")
    } else {
        // Filters, parsers and provider errors can contain secret-bearing values.
        // Never put their unfiltered Display representation into JavaScript errors.
        failure("KF_SCAN", "native scanning or input processing failed")
    }
}

pub(crate) fn duration(milliseconds: f64, allow_zero: bool) -> Result<Duration> {
    let duration = Duration::try_from_secs_f64(milliseconds / 1000.0)
        .map_err(|_| invalid("timeoutMs must be finite and nonnegative"))?;
    if duration.is_zero() && !allow_zero {
        return Err(invalid("timeoutMs must be positive"));
    }
    Ok(duration)
}

/// Regex compilation can recurse deeply. Keep its cold path off the smaller
/// default Windows/Tokio stacks without replacing the reusable scanning pool.
pub(crate) fn compilation_stack<T: Send>(
    operation: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("kingfisher-rule-compiler".into())
            .stack_size(8 * 1024 * 1024)
            .spawn_scoped(scope, operation)
            .map_err(|_| failure("KF_NATIVE", "rule compiler worker could not start"))?
            .join()
            .map_err(|_| failure("KF_NATIVE", "rule compiler worker failed"))?
    })
}

#[napi]
#[derive(Default)]
pub struct NativeCancellationToken {
    pub(crate) token: CancellationToken,
}

#[napi]
impl NativeCancellationToken {
    #[napi(constructor, catch_unwind)]
    pub fn new() -> Self {
        Self { token: CancellationToken::default() }
    }

    #[napi(catch_unwind)]
    pub fn cancel(&self) {
        self.token.cancel();
    }

    #[napi(getter, catch_unwind)]
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

pub(crate) fn control(
    timeout_ms: Option<f64>,
    token: Option<&NativeCancellationToken>,
) -> Result<ScanControl> {
    let mut control = ScanControl::default();
    if let Some(milliseconds) = timeout_ms {
        control = control
            .with_timeout(duration(milliseconds, false)?)
            .map_err(|_| invalid("timeoutMs exceeds the monotonic clock range"))?;
    }
    if let Some(token) = token {
        control = control.with_cancellation(token.token.clone());
    }
    control.check().map_err(interrupted)?;
    Ok(control)
}

/// Async work does not cancel merely because JavaScript drops its Promise.
pub(crate) async fn controlled<T>(
    control: &ScanControl,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    control.check().map_err(interrupted)?;
    tokio::pin!(future);
    loop {
        tokio::select! {
            // Completion wins when both branches are ready. In particular, a
            // confirmed mutation must not become "outcome unknown" merely
            // because its response was observed at the deadline boundary.
            biased;
            result = &mut future => return result,
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                control.check().map_err(interrupted)?;
            }
        }
    }
}

/// Bound CPU/native work across scanners and Node worker environments. Keep the
/// permit in the blocking closure, even if its async caller is dropped.
pub(crate) async fn blocking<T: Send + 'static>(
    control: ScanControl,
    operation: impl FnOnce(&ScanControl) -> Result<T> + Send + 'static,
) -> Result<T> {
    static WORKERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let workers = WORKERS
        .get_or_init(|| {
            let count = std::thread::available_parallelism().map_or(2, usize::from).clamp(1, 4);
            Arc::new(Semaphore::new(count))
        })
        .clone();
    let permit = controlled(&control, async {
        workers.acquire_owned().await.map_err(|_| failure("KF_CLOSED", "worker pool closed"))
    })
    .await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        control.check().map_err(interrupted)?;
        // The scanner owns its final control check and successful dedup commit.
        // Do not reject a completed scan afterward and leave a committed cache
        // entry behind an apparent cancellation. Other operations check before
        // returning at their own completion boundary.
        operation(&control)
    })
    .await
    .map_err(|_| failure("KF_NATIVE", "native worker failed"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_operations_are_not_relabelled_by_late_controls() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        runtime.block_on(async {
            let control = ScanControl::default().with_timeout(Duration::from_millis(1)).unwrap();
            let result = controlled(&control, async {
                // A completed side effect may return on the same poll in which
                // the deadline passes; its successful result is authoritative.
                std::thread::sleep(Duration::from_millis(5));
                Ok(7)
            })
            .await
            .unwrap();
            assert_eq!(result, 7);

            let token = CancellationToken::default();
            let control = ScanControl::default().with_cancellation(token.clone());
            let result = controlled(&control, async {
                token.cancel();
                Ok(9)
            })
            .await
            .unwrap();
            assert_eq!(result, 9);
        });
    }
}
