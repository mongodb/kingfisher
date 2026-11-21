use std::{sync::LazyLock, time::Duration};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use tracing::debug;

use crate::validation::GLOBAL_USER_AGENT;

pub(super) const LAST_USED_SOURCE: &str = "JFrog Access token activity";

#[derive(Deserialize)]
struct TokenUsage {
    last_used: Option<i64>,
}

/// Shared by Artifactory and Xray lookups. Unlike the mapper clients, this one never follows
/// redirects, so the token cannot be forwarded to another origin.
static ACTIVITY_CLIENT: LazyLock<reqwest::Result<Client>> = LazyLock::new(|| {
    Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .build()
});

/// Runs before the mapper's own requests so they cannot replace the timestamp being read.
pub(super) async fn fetch_token_last_used(token: &str, base_url: &str) -> Option<String> {
    fetch_token_usage(token, base_url).await.unwrap_or_else(|err| {
        debug!("JFrog access-map: token activity unavailable: {err}");
        None
    })
}

async fn fetch_token_usage(token: &str, base_url: &str) -> Result<Option<String>> {
    let mut url = Url::parse(base_url).context("Invalid JFrog instance URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid JFrog instance URL"
    );
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("Invalid JFrog instance URL"))?
        .pop_if_empty()
        .extend(["access", "api", "v1", "tokens", "me"]);

    let client = ACTIVITY_CLIENT
        .as_ref()
        .map_err(|_| anyhow::anyhow!("Could not build JFrog token activity client"))?;
    let response = client
        .get(url)
        .bearer_auth(token)
        .header(header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .context("JFrog token activity request failed")?;
    let status = response.status();
    ensure!(status.is_success(), "JFrog token activity lookup returned HTTP {status}");
    let usage = response.json::<TokenUsage>().await.context("Invalid JFrog token activity JSON")?;

    Ok(usage
        .last_used
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Secs, true)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::super::{artifactory, xray};
    use super::LAST_USED_SOURCE;

    #[tokio::test]
    async fn both_jfrog_mappers_use_the_exact_token_activity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access/api/v1/tokens/me"))
            .and(header("authorization", "Bearer example-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"last_used": 1704067200})),
            )
            .expect(2)
            .mount(&server)
            .await;
        for (route, response) in [
            ("/artifactory/api/security/current", json!({"name": "example"})),
            ("/artifactory/api/repositories", json!([])),
            ("/xray/api/v1/system/ping", json!({})),
            ("/xray/api/v1/binMgr/default/repos", json!([])),
            ("/xray/api/v1/policies", json!([])),
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .mount(&server)
                .await;
        }

        let artifactory =
            artifactory::map_access_from_token_and_url("example-token", &server.uri())
                .await
                .unwrap();
        let xray =
            xray::map_access_from_token_and_url("example-token", &server.uri()).await.unwrap();
        for result in [artifactory, xray] {
            assert_eq!(
                result.token_details.unwrap().last_used_at.as_deref(),
                Some("2024-01-01T00:00:00Z")
            );
            assert_eq!(
                result.provider_metadata.unwrap().credential_last_used_source.as_deref(),
                Some(LAST_USED_SOURCE)
            );
        }
    }

    #[tokio::test]
    async fn redirected_activity_lookup_preserves_the_access_map() {
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/access/api/v1/tokens/me"))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", destination.uri()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/artifactory/api/security/current"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "example"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/artifactory/api/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let result = artifactory::map_access_from_token_and_url("example-token", &server.uri())
            .await
            .unwrap();
        assert_eq!(result.identity.id, "example");
        assert!(result.token_details.unwrap().last_used_at.is_none());
        assert!(result.provider_metadata.is_none());
        assert!(destination.received_requests().await.unwrap().is_empty());
    }
}
