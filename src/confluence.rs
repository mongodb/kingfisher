use anyhow::{Context, Result, bail};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

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

    let base = confluence_url.as_str().trim_end_matches('/');
    let api_base = format!("{}/rest/api/content/search", base);

    let mut pages = Vec::new();

    // Confluence Cloud removed offset-based `start` pagination for this
    // endpoint in 2020 in favor of a server-issued cursor; Server/Data Center
    // still returns a `_links.next` URL too, so following it works for both.
    let mut next_url = if max_results == 0 {
        None
    } else {
        let mut url = Url::parse(&api_base)?;
        let limit = std::cmp::min(100, max_results);
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
        for p in body.results {
            pages.push(p);
            if pages.len() >= max_results {
                break;
            }
        }
        if pages.len() >= max_results {
            break;
        }
        next_url = body.links.next.as_deref().and_then(|next| confluence_url.join(next).ok());
    }
    Ok(pages)
}

#[cfg(test)]
mod tests {
    use super::search_pages;
    use serde_json::json;
    use std::ffi::OsString;
    use tokio::sync::Mutex;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param, query_param_is_missing},
    };

    static CONFLUENCE_ENV: Mutex<()> = Mutex::const_new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[tokio::test]
    async fn search_pages_follows_cursor_based_next_link() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let _lock = CONFLUENCE_ENV.lock().await;
        let _token = EnvVarGuard::set("KF_CONFLUENCE_TOKEN", "test-token");
        let _user = EnvVarGuard::unset("KF_CONFLUENCE_USER");

        let server = MockServer::start().await;

        // Confluence Cloud paginates this endpoint via a cursor embedded in
        // `_links.next`, not via a repeated/incrementing `start` parameter.
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
        let pages = search_pages(confluence_url, "label = secret", 10, false)
            .await
            .expect("pages should be fetched");

        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].id, "1");
        assert_eq!(pages[1].id, "2");
    }

    #[tokio::test]
    async fn search_pages_stops_once_max_results_reached_without_following_next() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let _lock = CONFLUENCE_ENV.lock().await;
        let _token = EnvVarGuard::set("KF_CONFLUENCE_TOKEN", "test-token");
        let _user = EnvVarGuard::unset("KF_CONFLUENCE_USER");

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
        let pages = search_pages(confluence_url, "label = secret", 1, false)
            .await
            .expect("pages should be fetched");

        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].id, "1");
    }
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
    let base = confluence_url.as_str().trim_end_matches('/');
    let web_base = base.to_string();
    for page in pages {
        let file = output_dir.join(format!("{}.json", page.id));
        std::fs::write(&file, serde_json::to_vec(&page)?)?;
        let link = format!("{}{}", web_base, page.links.webui);
        paths.push((file, link));
    }
    Ok(paths)
}
