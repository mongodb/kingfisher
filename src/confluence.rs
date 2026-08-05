use anyhow::{Context, Result, bail};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::PathBuf};
use url::Url;

/// Number of results requested per page; Confluence caps this at 100.
const CONFLUENCE_PAGE_SIZE: usize = 100;

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfluencePage {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub body: Option<ConfluenceBody>,
    #[serde(rename = "_links")]
    pub links: ConfluenceLinks,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfluenceBody {
    #[serde(default)]
    pub storage: Option<ConfluenceStorage>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfluenceStorage {
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfluenceLinks {
    pub webui: String,
}

#[derive(Debug, Deserialize)]
struct ConfluenceSearchResponse {
    results: Vec<ConfluencePage>,
    #[serde(rename = "_links")]
    links: ConfluenceResultLinks,
}

#[derive(Debug, Deserialize)]
struct ConfluenceResultLinks {
    next: Option<String>,
}

/// Adds Confluence Cloud's `/wiki` context path, which Server/Data Center does
/// not use. Without it Cloud answers `404 No endpoint GET
/// /rest/api/content/search`. Only a root path is rewritten, so a deliberate
/// context path is left alone.
fn normalize_confluence_base(confluence_url: &Url) -> Url {
    let is_cloud = confluence_url.host_str().is_some_and(|host| host.ends_with(".atlassian.net"));
    let path_is_root = matches!(confluence_url.path(), "" | "/");
    if !is_cloud || !path_is_root {
        return confluence_url.clone();
    }

    let mut url = confluence_url.clone();
    url.set_path("/wiki");
    url
}

/// Re-anchors the pagination state from `_links.next` onto our own API URL.
/// Cloud returns `next` without the `/wiki` prefix, so resolving it against the
/// site URL would drop that segment.
fn next_page_url(api_url: &Url, next: &str, cql: &str, limit: usize) -> Option<Url> {
    let query = next.split_once('?').map(|(_, query)| query)?;

    let mut url = api_url.clone();
    url.set_query(Some(query));

    let present: HashSet<String> = url.query_pairs().map(|(key, _)| key.into_owned()).collect();

    // A `next` without pagination state would re-request the first page forever.
    if !present.contains("cursor") && !present.contains("start") {
        return None;
    }

    // `next` does not always echo every parameter back; dropping
    // `expand=body.storage` would blank page bodies and hide secrets.
    {
        let mut pairs = url.query_pairs_mut();
        if !present.contains("cql") {
            pairs.append_pair("cql", cql);
        }
        if !present.contains("limit") {
            pairs.append_pair("limit", &limit.to_string());
        }
        if !present.contains("expand") {
            pairs.append_pair("expand", "body.storage");
        }
    }

    Some(url)
}

pub async fn search_pages(
    confluence_url: Url,
    cql: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<ConfluencePage>> {
    let token = std::env::var("KF_CONFLUENCE_TOKEN")
        .context("KF_CONFLUENCE_TOKEN environment variable must be set")?;
    let user = std::env::var("KF_CONFLUENCE_USER").ok();
    if let Some(ref u) = user
        && !u.contains('@')
    {
        bail!("KF_CONFLUENCE_USER must be an email address");
    }

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")?;

    let site_url = normalize_confluence_base(&confluence_url);
    let base = site_url.as_str().trim_end_matches('/');
    let api_url = Url::parse(&format!("{}/rest/api/content/search", base))?;
    let limit = std::cmp::min(CONFLUENCE_PAGE_SIZE, max_results);

    let mut pages = Vec::new();

    // Cloud dropped offset pagination here in 2020; following `_links.next`
    // works for both deployments.
    let mut next_url = if max_results == 0 {
        None
    } else {
        let mut url = api_url.clone();
        url.query_pairs_mut()
            .append_pair("cql", cql)
            .append_pair("limit", &limit.to_string())
            .append_pair("expand", "body.storage");
        Some(url)
    };

    while let Some(url) = next_url.take() {
        let req = client.get(url);
        let req = if let Some(user) = &user {
            req.basic_auth(user, Some(&token))
        } else {
            req.bearer_auth(&token)
        };
        let resp = req.send().await.context("Failed to send Confluence request")?;

        let status = resp.status();
        if !status.is_success() {
            let location = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let body =
                resp.text().await.unwrap_or_else(|e| format!("Failed to read response: {}", e));

            if let Some(loc) = location {
                bail!(
                    "Confluence API request returned {} redirect to {}. Check KF_CONFLUENCE_TOKEN and KF_CONFLUENCE_USER",
                    status,
                    loc
                );
            } else {
                bail!("Confluence API request failed with status {}: {}", status, body);
            }
        }

        let body: ConfluenceSearchResponse =
            resp.json().await.context("Failed to parse Confluence response")?;
        let received = body.results.len();
        for p in body.results {
            pages.push(p);
            if pages.len() >= max_results {
                break;
            }
        }

        // Cloud can return an empty page alongside a `next` link; stopping here
        // is what keeps the loop bounded.
        if pages.len() >= max_results || received == 0 {
            break;
        }

        next_url =
            body.links.next.as_deref().and_then(|next| next_page_url(&api_url, next, cql, limit));
    }
    Ok(pages)
}

pub async fn download_pages_to_dir(
    confluence_url: Url,
    cql: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<(PathBuf, String)>> {
    std::fs::create_dir_all(output_dir)?;
    let pages = search_pages(confluence_url.clone(), cql, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    // `webui` is relative to the same context path as the API.
    let site_url = normalize_confluence_base(&confluence_url);
    let web_base = site_url.as_str().trim_end_matches('/').to_string();
    for page in pages {
        let file = output_dir.join(format!("{}.json", page.id));
        std::fs::write(&file, serde_json::to_vec(&page)?)?;
        let link = format!("{}{}", web_base, page.links.webui);
        paths.push((file, link));
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::{next_page_url, normalize_confluence_base, search_pages};
    use serde_json::json;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param, query_param_is_missing},
    };

    async fn with_confluence_token<T>(future: impl std::future::Future<Output = T>) -> T {
        temp_env::async_with_vars(
            [("KF_CONFLUENCE_TOKEN", Some("test-token")), ("KF_CONFLUENCE_USER", None)],
            future,
        )
        .await
    }

    fn api_url() -> Url {
        Url::parse("https://example.atlassian.net/wiki/rest/api/content/search").expect("API URL")
    }

    #[test]
    fn normalize_confluence_base_adds_the_cloud_wiki_context_path() {
        let normalized =
            normalize_confluence_base(&Url::parse("https://example.atlassian.net").unwrap());
        assert_eq!(normalized.as_str(), "https://example.atlassian.net/wiki");

        let with_slash =
            normalize_confluence_base(&Url::parse("https://example.atlassian.net/").unwrap());
        assert_eq!(with_slash.as_str(), "https://example.atlassian.net/wiki");
    }

    #[test]
    fn normalize_confluence_base_does_not_double_the_wiki_segment() {
        let normalized =
            normalize_confluence_base(&Url::parse("https://example.atlassian.net/wiki").unwrap());
        assert_eq!(normalized.as_str(), "https://example.atlassian.net/wiki");
    }

    #[test]
    fn normalize_confluence_base_leaves_self_hosted_and_explicit_paths_alone() {
        let server =
            normalize_confluence_base(&Url::parse("https://confluence.example.com").unwrap());
        assert_eq!(server.as_str(), "https://confluence.example.com/");

        let context =
            normalize_confluence_base(&Url::parse("https://example.com/confluence").unwrap());
        assert_eq!(context.as_str(), "https://example.com/confluence");

        let explicit =
            normalize_confluence_base(&Url::parse("https://example.atlassian.net/other").unwrap());
        assert_eq!(explicit.as_str(), "https://example.atlassian.net/other");
    }

    #[test]
    fn next_page_url_keeps_the_wiki_context_path() {
        let next = next_page_url(
            &api_url(),
            "/rest/api/content/search?cql=label+%3D+secret&cursor=abc123&limit=25&expand=body.storage",
            "label = secret",
            25,
        )
        .expect("next URL should be built");

        assert_eq!(next.path(), "/wiki/rest/api/content/search");
        assert_eq!(next.host_str(), Some("example.atlassian.net"));
        assert!(next.query().expect("query").contains("cursor=abc123"));
    }

    #[test]
    fn next_page_url_restores_parameters_the_server_dropped() {
        // Atlassian's own documented `next` example omits `expand`.
        let next = next_page_url(
            &api_url(),
            "/rest/api/content/search?limit=25&cursor=abc123",
            "label = secret",
            25,
        )
        .expect("next URL should be built");

        let pairs: Vec<(String, String)> =
            next.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        assert!(pairs.contains(&("expand".to_string(), "body.storage".to_string())));
        assert!(pairs.contains(&("cql".to_string(), "label = secret".to_string())));
        assert!(pairs.contains(&("cursor".to_string(), "abc123".to_string())));
        assert_eq!(pairs.iter().filter(|(k, _)| k == "limit").count(), 1);
    }

    #[test]
    fn next_page_url_accepts_server_data_center_offset_links() {
        let next = next_page_url(
            &api_url(),
            "/rest/api/content/search?cql=label+%3D+secret&start=25&limit=25",
            "label = secret",
            25,
        )
        .expect("next URL should be built");

        assert!(next.query().expect("query").contains("start=25"));
    }

    #[test]
    fn next_page_url_rejects_links_without_pagination_state() {
        assert!(
            next_page_url(&api_url(), "/rest/api/content/search?cql=x", "x", 25).is_none(),
            "links without pagination state must not be followed"
        );
        assert!(
            next_page_url(&api_url(), "/rest/api/content/search", "x", 25).is_none(),
            "links without a query string must not be followed"
        );
    }

    #[tokio::test]
    async fn search_pages_follows_cursor_based_next_link() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/content/search"))
            .and(query_param("cql", "label = secret"))
            .and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"id": "1", "title": "first", "_links": {"webui": "/pages/1"}}
                ],
                "_links": {
                    "next": "/rest/api/content/search?cql=label+%3D+secret&cursor=abc123&limit=1&expand=body.storage"
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/api/content/search"))
            .and(query_param("cursor", "abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"id": "2", "title": "second", "_links": {"webui": "/pages/2"}}
                ],
                "_links": {}
            })))
            .mount(&server)
            .await;

        let confluence_url = Url::parse(&server.uri()).expect("server URL");
        let pages =
            with_confluence_token(search_pages(confluence_url, "label = secret", 10, false))
                .await
                .expect("pages should be fetched");

        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].id, "1");
        assert_eq!(pages[1].id, "2");
    }

    #[tokio::test]
    async fn search_pages_preserves_wiki_context_path_on_cloud() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        // Cloud returns `next` without the `/wiki` the request needs.
        Mock::given(method("GET"))
            .and(path("/wiki/rest/api/content/search"))
            .and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"id": "1", "title": "first", "_links": {"webui": "/pages/1"}}
                ],
                "_links": {
                    "next": "/rest/api/content/search?cql=label+%3D+secret&cursor=abc123&limit=1&expand=body.storage"
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/wiki/rest/api/content/search"))
            .and(query_param("cursor", "abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"id": "2", "title": "second", "_links": {"webui": "/pages/2"}}
                ],
                "_links": {}
            })))
            .mount(&server)
            .await;

        let confluence_url = Url::parse(&format!("{}/wiki", server.uri())).expect("server URL");
        let pages =
            with_confluence_token(search_pages(confluence_url, "label = secret", 10, false))
                .await
                .expect("pages should be fetched");

        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].id, "1");
        assert_eq!(pages[1].id, "2");
    }

    #[tokio::test]
    async fn search_pages_stops_on_an_empty_page_that_still_advertises_next() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/content/search"))
            .and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"id": "1", "title": "first", "_links": {"webui": "/pages/1"}}
                ],
                "_links": {"next": "/rest/api/content/search?cursor=abc123"}
            })))
            .mount(&server)
            .await;

        // The cursor never changes, so the mock may only be hit once.
        Mock::given(method("GET"))
            .and(path("/rest/api/content/search"))
            .and(query_param("cursor", "abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [],
                "_links": {"next": "/rest/api/content/search?cursor=abc123"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let confluence_url = Url::parse(&server.uri()).expect("server URL");
        let pages =
            with_confluence_token(search_pages(confluence_url, "label = secret", 50, false))
                .await
                .expect("pages should be fetched");

        assert_eq!(pages.len(), 1);
    }

    #[tokio::test]
    async fn search_pages_stops_once_max_results_reached_without_following_next() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/content/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"id": "1", "title": "first", "_links": {"webui": "/pages/1"}},
                    {"id": "2", "title": "second", "_links": {"webui": "/pages/2"}}
                ],
                "_links": {
                    "next": "/rest/api/content/search?cursor=should-not-be-fetched"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let confluence_url = Url::parse(&server.uri()).expect("server URL");
        let pages = with_confluence_token(search_pages(confluence_url, "label = secret", 1, false))
            .await
            .expect("pages should be fetched");

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].id, "1");
    }
}
