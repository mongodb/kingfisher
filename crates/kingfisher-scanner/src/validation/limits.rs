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

/// Apply a connection timeout only when the enclosing operation has a finite budget.
pub trait ResourceConnectTimeout: Sized {
    fn resource_connect_timeout(self, duration: Duration) -> Self;
}
impl ResourceConnectTimeout for reqwest::ClientBuilder {
    fn resource_connect_timeout(self, duration: Duration) -> Self {
        if duration.is_zero() || NetworkLimits::current().no_timeouts {
            self
        } else {
            self.connect_timeout(duration)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unlimited_client_waits_for_response_without_affecting_bounded_clients() {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                "complete"
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let work = || async {
            reqwest::Client::builder()
                .no_proxy()
                .resource_connect_timeout(Duration::from_secs(1))
                .resource_timeout(Duration::from_millis(5))
                .build()
                .unwrap()
                .get(&url)
                .send()
                .await
        };
        let (unlimited, bounded) = tokio::join!(
            NetworkLimits { no_timeouts: true, ..Default::default() }.scope(work()),
            work(),
        );
        assert_eq!(unlimited.unwrap().text().await.unwrap(), "complete");
        assert!(bounded.unwrap_err().is_timeout());
        assert!(!NetworkLimits::current().no_timeouts);
        server.abort();
    }

    #[tokio::test]
    async fn unlimited_timeout_is_scoped_and_preserves_other_tasks() {
        let (release, receiver) = tokio::sync::oneshot::channel();
        let unlimited = NetworkLimits { no_timeouts: true, ..Default::default() }
            .scope(timeout(Duration::from_millis(1), async { receiver.await.unwrap() }));
        tokio::pin!(unlimited);
        // Start the scoped future while its work remains under our control.
        std::future::poll_fn(|context| {
            assert!(unlimited.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        // Pending work cannot win a delayed timer poll, unlike two short sleeps
        // that may both be ready under coarse Windows timers or executor load.
        let bounded = tokio::time::timeout(
            Duration::from_secs(10),
            timeout(Duration::from_millis(1), std::future::pending::<()>()),
        )
        .await
        .expect("the unrelated future must retain its finite timeout");
        assert!(bounded.is_err());
        // Its nominal deadline has now passed, but the unlimited scope still
        // waits for the value instead of inheriting the other caller's budget.
        std::future::poll_fn(|context| {
            assert!(unlimited.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        release.send(42).unwrap();
        assert_eq!(unlimited.await.unwrap(), 42);
        assert!(!NetworkLimits::current().no_timeouts);
    }
}
