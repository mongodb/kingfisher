use anyhow::{Context, Result};
use futures::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tracing::warn;
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct SlackMessage {
    pub permalink: String,
    pub text: Option<String>,
    pub ts: String,
    pub channel: SlackChannel,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct SlackChannel {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackPagination {
    page: Option<u32>,
    page_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SlackMessages {
    matches: Vec<SlackMessage>,
    pagination: Option<SlackPagination>,
}

#[derive(Debug, Deserialize)]
struct SlackSearchResponse {
    ok: bool,
    error: Option<String>,
    messages: Option<SlackMessages>,
}

#[derive(Debug, Deserialize)]
pub struct SlackFile {
    pub id: String,
    pub name: Option<String>,
    pub title: Option<String>,
    pub permalink: Option<String>,
    pub url_private: Option<String>,
    pub url_private_download: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackFiles {
    matches: Vec<SlackFile>,
    pagination: Option<SlackPagination>,
}

#[derive(Debug, Deserialize)]
struct SlackFileSearchResponse {
    ok: bool,
    error: Option<String>,
    files: Option<SlackFiles>,
}

fn next_slack_page(pagination: Option<&SlackPagination>, current_page: u32) -> Option<u32> {
    let pagination = pagination?;
    let page_count = pagination.page_count?;
    let next_page = pagination.page.unwrap_or(current_page).saturating_add(1);
    (next_page <= page_count).then_some(next_page)
}

fn slack_file_permalink(file: &SlackFile) -> Option<String> {
    file.permalink.as_ref().filter(|permalink| !permalink.trim().is_empty()).cloned()
}

fn slack_token() -> Result<String> {
    std::env::var("KF_SLACK_TOKEN").context("KF_SLACK_TOKEN environment variable must be set")
}

fn slack_client(ignore_certs: bool) -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")
}

fn slack_api_error(error: Option<String>) -> anyhow::Error {
    let error = error.unwrap_or_else(|| "unknown".to_string());
    match error.as_str() {
        "not_allowed_token_type" => anyhow::anyhow!(
            "Slack API error: not_allowed_token_type - use a user token with the `search:read` \
             scope"
        ),
        "missing_scope" => anyhow::anyhow!(
            "Slack API error: missing_scope - Slack search requires `search:read` and file \
             downloads require `files:read`"
        ),
        _ => anyhow::anyhow!("Slack API error: {error}"),
    }
}

pub async fn search_messages(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<SlackMessage>> {
    if !kingfisher_scanner::validation::limits::NetworkLimits::current().unlimited_results
        && max_results == 0
    {
        return Ok(Vec::new());
    }

    let token = slack_token()?;
    let client = slack_client(ignore_certs)?;
    let mut page = 1u32;
    let mut messages = Vec::new();

    loop {
        let url = api_url.join("search.messages").context("Failed to build Slack API URL")?;

        let resp = client
            .get(url)
            .bearer_auth(&token)
            .query(&[("query", query), ("count", "100"), ("page", &page.to_string())])
            .send()
            .await
            .context("Failed to send Slack request")?;

        let body: SlackSearchResponse =
            resp.json().await.context("Failed to parse Slack response")?;

        if !body.ok {
            return Err(slack_api_error(body.error));
        }

        let Some(msgs) = body.messages else {
            break;
        };
        for m in msgs.matches {
            messages.push(m);
            if !kingfisher_scanner::validation::limits::NetworkLimits::current().unlimited_results
                && messages.len() >= max_results
            {
                return Ok(messages);
            }
        }
        let Some(next_page) = next_slack_page(msgs.pagination.as_ref(), page) else {
            break;
        };
        page = next_page;
    }

    Ok(messages)
}

pub async fn search_files(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<SlackFile>> {
    if !kingfisher_scanner::validation::limits::NetworkLimits::current().unlimited_results
        && max_results == 0
    {
        return Ok(Vec::new());
    }

    let token = slack_token()?;
    let client = slack_client(ignore_certs)?;
    let mut page = 1u32;
    let mut files = Vec::new();

    loop {
        let url = api_url.join("search.files").context("Failed to build Slack API URL")?;

        let resp = client
            .get(url)
            .bearer_auth(&token)
            .query(&[("query", query), ("count", "100"), ("page", &page.to_string())])
            .send()
            .await
            .context("Failed to send Slack file search request")?;

        let body: SlackFileSearchResponse =
            resp.json().await.context("Failed to parse Slack file search response")?;

        if !body.ok {
            return Err(slack_api_error(body.error));
        }

        let Some(file_results) = body.files else {
            break;
        };
        for file in file_results.matches {
            files.push(file);
            if !kingfisher_scanner::validation::limits::NetworkLimits::current().unlimited_results
                && files.len() >= max_results
            {
                return Ok(files);
            }
        }
        let Some(next_page) = next_slack_page(file_results.pagination.as_ref(), page) else {
            break;
        };
        page = next_page;
    }

    Ok(files)
}

fn sanitize_filename_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();

    let trimmed = sanitized.trim_matches([' ', '.']);
    if trimmed.is_empty() { "file".to_string() } else { trimmed.to_string() }
}

pub async fn download_messages_to_dir(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<(PathBuf, String)>> {
    tokio::fs::create_dir_all(output_dir).await?;
    let messages = search_messages(api_url, query, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    for msg in messages {
        let ts = msg.ts.replace('.', "_");
        let file = output_dir.join(format!("{}_{}.json", msg.channel.id, ts));
        tokio::fs::write(&file, serde_json::to_vec(&msg)?).await?;
        paths.push((file, msg.permalink));
    }
    Ok(paths)
}

pub async fn download_files_to_dir(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
    max_file_size: Option<u64>,
) -> Result<Vec<(PathBuf, String)>> {
    tokio::fs::create_dir_all(output_dir).await?;
    let files = search_files(api_url, query, max_results, ignore_certs).await?;
    let token = slack_token()?;
    let client = slack_client(ignore_certs)?;
    let mut paths = Vec::new();

    for file in files {
        let Some(download_url) =
            file.url_private_download.as_deref().or(file.url_private.as_deref())
        else {
            warn!("Skipping Slack file {} because it has no downloadable URL", file.id);
            continue;
        };

        let response = client
            .get(download_url)
            .bearer_auth(&token)
            .send()
            .await
            .with_context(|| format!("Failed to download Slack file {}", file.id))?
            .error_for_status()
            .with_context(|| {
                format!(
                    "Failed to download Slack file {}; ensure the token has the `files:read` scope",
                    file.id
                )
            })?;

        if let Some(limit) = max_file_size
            && let Some(content_length) = response.content_length()
            && content_length > limit
        {
            warn!(
                "Skipping Slack file {} because its download size is {} bytes, exceeding the \
                 max file size limit of {} bytes",
                file.id, content_length, limit
            );
            continue;
        }

        let original_name = file.name.as_deref().or(file.title.as_deref()).unwrap_or("file");
        let filename = format!(
            "{}_{}",
            sanitize_filename_component(&file.id),
            sanitize_filename_component(original_name)
        );
        let path = output_dir.join(filename);
        let mut output = tokio::fs::File::create(&path)
            .await
            .with_context(|| format!("Failed to create Slack file download {}", path.display()))?;
        let mut body = response.bytes_stream();
        let mut downloaded = 0u64;
        let mut exceeded_limit = None;
        while let Some(chunk) = body.next().await {
            let chunk = chunk
                .with_context(|| format!("Failed while downloading Slack file {}", file.id))?;
            let next_size = downloaded.saturating_add(chunk.len() as u64);
            if let Some(limit) = max_file_size
                && next_size > limit
            {
                exceeded_limit = Some(limit);
                break;
            }
            output.write_all(&chunk).await.with_context(|| {
                format!("Failed to write Slack file download {}", path.display())
            })?;
            downloaded = next_size;
        }

        if let Some(limit) = exceeded_limit {
            drop(output);
            let _ = tokio::fs::remove_file(&path).await;
            warn!(
                "Skipping Slack file {} because its streamed download exceeded the max file size \
                 limit of {} bytes",
                file.id, limit
            );
            continue;
        }
        output
            .flush()
            .await
            .with_context(|| format!("Failed to flush Slack file download {}", path.display()))?;

        if let Some(permalink) = slack_file_permalink(&file) {
            paths.push((path, permalink));
        }
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::{
        SlackFile, SlackPagination, download_files_to_dir, next_slack_page,
        sanitize_filename_component,
    };
    use axum::{
        Router,
        body::{Body, Bytes},
        http::{Response, StatusCode, header},
        response::IntoResponse,
        routing::get,
    };
    use futures::{Future, stream};
    use std::{convert::Infallible, ffi::OsString};
    use tempfile::TempDir;
    use tokio::sync::Mutex;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    static SLACK_TOKEN_ENV: Mutex<()> = Mutex::const_new(());

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
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    async fn with_slack_token<T>(future: impl Future<Output = T>) -> T {
        let _lock = SLACK_TOKEN_ENV.lock().await;
        let _token = EnvVarGuard::set("KF_SLACK_TOKEN", "xoxp-test");
        future.await
    }

    #[test]
    fn sanitize_filename_component_prevents_path_traversal() {
        assert_eq!(sanitize_filename_component("../../secrets.txt"), "_.._secrets.txt");
        assert_eq!(sanitize_filename_component(".."), "file");
        assert_eq!(sanitize_filename_component("a:b\\c"), "a_b_c");
    }

    #[test]
    fn next_slack_page_requires_pagination_metadata() {
        assert_eq!(next_slack_page(None, 1), None);
        assert_eq!(
            next_slack_page(Some(&SlackPagination { page: Some(1), page_count: None }), 1),
            None
        );
    }

    #[test]
    fn next_slack_page_advances_until_last_page() {
        assert_eq!(
            next_slack_page(Some(&SlackPagination { page: Some(1), page_count: Some(3) }), 1),
            Some(2)
        );
        assert_eq!(
            next_slack_page(Some(&SlackPagination { page: None, page_count: Some(3) }), 2),
            Some(3)
        );
        assert_eq!(
            next_slack_page(Some(&SlackPagination { page: Some(3), page_count: Some(3) }), 3),
            None
        );
    }

    #[test]
    fn slack_file_permalink_ignores_missing_or_blank_links() {
        let mut file = SlackFile {
            id: "F123".to_string(),
            name: Some("credentials.txt".to_string()),
            title: None,
            permalink: None,
            url_private: None,
            url_private_download: None,
        };
        assert_eq!(super::slack_file_permalink(&file), None);

        file.permalink = Some("   ".to_string());
        assert_eq!(super::slack_file_permalink(&file), None);

        file.permalink = Some("https://example.slack.com/files/U123/F123/credentials.txt".into());
        assert_eq!(
            super::slack_file_permalink(&file).as_deref(),
            Some("https://example.slack.com/files/U123/F123/credentials.txt")
        );
    }

    #[tokio::test]
    async fn download_files_to_dir_skips_file_when_content_length_exceeds_limit() {
        let server = MockServer::start().await;
        let file_response = serde_json::json!({
            "ok": true,
            "files": {
                "matches": [{
                    "id": "F123",
                    "name": "large.txt",
                    "title": "large.txt",
                    "permalink": "https://example.slack.com/files/F123/large.txt",
                    "url_private_download": format!("{}/files/F123/download", server.uri())
                }],
                "pagination": {"page": 1, "page_count": 1}
            }
        });

        Mock::given(method("GET"))
            .and(path("/search.files"))
            .respond_with(ResponseTemplate::new(200).set_body_json(file_response))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/F123/download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Length", "31")
                    .set_body_string("this body should not be written"),
            )
            .mount(&server)
            .await;

        let output = TempDir::new().expect("create temp dir");
        let output_dir = output.path().to_path_buf();
        let paths = with_slack_token(download_files_to_dir(
            Url::parse(&format!("{}/", server.uri())).expect("server URL"),
            "secret",
            1,
            false,
            &output_dir,
            Some(8),
        ))
        .await
        .expect("download should skip oversized file without failing");

        assert!(paths.is_empty());
        assert!(std::fs::read_dir(&output_dir).expect("read output dir").next().is_none());
    }

    #[tokio::test]
    async fn download_files_to_dir_removes_partial_file_when_stream_exceeds_limit() {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind test server");
        let base_url = format!("http://{}/", listener.local_addr().expect("server addr"));
        let file_response = format!(
            r#"{{
                "ok": true,
                "files": {{
                    "matches": [{{
                        "id": "F456",
                        "name": "streamed.txt",
                        "title": "streamed.txt",
                        "permalink": "https://example.slack.com/files/F456/streamed.txt",
                        "url_private_download": "{base_url}files/F456/download"
                    }}],
                    "pagination": {{"page": 1, "page_count": 1}}
                }}
            }}"#
        );
        let app = Router::new()
            .route(
                "/search.files",
                get(move || {
                    let file_response = file_response.clone();
                    async move {
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "application/json")],
                            file_response,
                        )
                            .into_response()
                    }
                }),
            )
            .route(
                "/files/F456/download",
                get(|| async {
                    let chunks = stream::iter([
                        Ok::<_, Infallible>(Bytes::from_static(b"12345")),
                        Ok::<_, Infallible>(Bytes::from_static(b"67890")),
                    ]);
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from_stream(chunks))
                        .expect("streaming response")
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server should run");
        });

        let output = TempDir::new().expect("create temp dir");
        let output_dir = output.path().to_path_buf();
        let paths = with_slack_token(download_files_to_dir(
            Url::parse(&base_url).expect("server URL"),
            "secret",
            1,
            false,
            &output_dir,
            Some(8),
        ))
        .await
        .expect("download should skip oversized stream without failing");
        server.abort();

        assert!(paths.is_empty());
        assert!(std::fs::read_dir(&output_dir).expect("read output dir").next().is_none());
    }
}
