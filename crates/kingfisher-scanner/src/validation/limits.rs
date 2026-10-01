//! Network resource policy scoped to one future, never to the process.
//!
//! A scope follows the future across executor threads. Spawned tasks must be
//! scoped explicitly; unrelated concurrent callers retain their own defaults.
use std::{
    future::{Future, IntoFuture},
    time::Duration,
};

tokio::task_local! {
    static POLICY: NetworkLimits;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NetworkLimits {
    pub no_timeouts: bool,
    pub unlimited_response: bool,
    pub unlimited_results: bool,
}

impl NetworkLimits {
    pub fn current() -> Self {
        POLICY.try_with(|value| *value).unwrap_or_default()
    }

    pub async fn scope<F: Future>(self, future: F) -> F::Output {
        POLICY.scope(self, future).await
    }

    pub fn sync_scope<T>(self, work: impl FnOnce() -> T) -> T {
        POLICY.sync_scope(self, work)
    }
}

pub async fn timeout<F: IntoFuture>(
    duration: Duration,
    work: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    if duration.is_zero() || NetworkLimits::current().no_timeouts {
        Ok(work.await)
    } else {
        tokio::time::timeout(duration, work.into_future()).await
    }
}

/// Apply a timeout only when the enclosing operation has a finite budget.
pub trait ResourceTimeout: Sized {
    fn resource_timeout(self, duration: Duration) -> Self;
}
impl ResourceTimeout for reqwest::ClientBuilder {
    fn resource_timeout(self, duration: Duration) -> Self {
        if duration.is_zero() || NetworkLimits::current().no_timeouts {
            self
        } else {
            self.timeout(duration)
        }
    }
}
impl ResourceTimeout for reqwest::RequestBuilder {
    fn resource_timeout(self, duration: Duration) -> Self {
        if duration.is_zero() || NetworkLimits::current().no_timeouts {
            self
        } else {
            self.timeout(duration)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unlimited_timeout_is_scoped_and_preserves_other_tasks() {
        let work = || async {
            timeout(Duration::from_millis(1), async {
                tokio::time::sleep(Duration::from_millis(25)).await;
                42
            })
            .await
        };
        let (unlimited, bounded) = tokio::join!(
            NetworkLimits { no_timeouts: true, ..Default::default() }.scope(work()),
            work(),
        );
        assert_eq!(unlimited.unwrap(), 42);
        assert!(bounded.is_err());
        assert!(!NetworkLimits::current().no_timeouts);
    }
}
