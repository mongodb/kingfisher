use anyhow::{Context, Result, bail};
use kingfisher_scanner::validation::limits::NetworkLimits;
use reqwest::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

// Re-export the Issue type from gouqi so callers don't depend on the crate.
pub use gouqi::Issue as JiraIssue;

const JIRA_COMMENTS_PAGE_SIZE: u32 = 1000;
// Bound decoded bytes, not Content-Length: Jira responses may be compressed.
// This is per API page, not a total artifact/result limit.
const MAX_JIRA_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Field selector sent with every JQL search. Left unset, Jira Cloud returns
/// only `id`, `key`, `summary`, and `status`, silently dropping issue
/// descriptions from the scan.
const JIRA_SEARCH_FIELDS: &str = "*all";

/// Issues per search request; `--max-results` is a total, not a page size.
const JIRA_ISSUES_PAGE_SIZE: usize = 100;

#[derive(Clone, Copy, Debug, Default)]
pub struct DownloadIssueArtifactsOptions {
    pub include_comments: bool,
    pub include_changelog: bool,
}

/// Recursively extracts plain text from an Atlassian Document Format (ADF) node.
///
/// Jira Cloud API v3 returns issue descriptions as ADF — a nested JSON structure
/// rather than a plain string. This function walks the content tree and writes
/// leaf `"type": "text"` node values into a single output buffer so extraction
/// remains linear in the size of the final text.
fn extract_adf_text(node: &serde_json::Value) -> String {
    struct PendingSeparator<'a> {
        separator: &'a str,
        previous_ended_whitespace: bool,
    }

    struct TextAccumulator {
        text: String,
        last_char_is_whitespace: bool,
    }

    impl TextAccumulator {
        fn new() -> Self {
            Self { text: String::new(), last_char_is_whitespace: true }
        }

        fn len(&self) -> usize {
            self.text.len()
        }

        fn ends_with_newline(&self) -> bool {
            self.text.ends_with('\n')
        }

        fn last_char_is_whitespace(&self) -> bool {
            self.last_char_is_whitespace
        }

        fn write_text(
            &mut self,
            text: &str,
            pending_separator: &mut Option<PendingSeparator<'_>>,
        ) -> bool {
            if text.is_empty() {
                return false;
            }

            if let Some(pending_separator) = pending_separator.take() {
                let starts_non_whitespace =
                    text.chars().next().map(|ch| !ch.is_whitespace()).unwrap_or(false);
                if !pending_separator.previous_ended_whitespace && starts_non_whitespace {
                    self.text.push_str(pending_separator.separator);
                    if let Some(last_char) = pending_separator.separator.chars().last() {
                        self.last_char_is_whitespace = last_char.is_whitespace();
                    }
                }
            }

            self.text.push_str(text);
            if let Some(last_char) = text.chars().last() {
                self.last_char_is_whitespace = last_char.is_whitespace();
            }
            true
        }

        fn write_char(
            &mut self,
            ch: char,
            pending_separator: &mut Option<PendingSeparator<'_>>,
        ) -> bool {
            if let Some(pending_separator) = pending_separator.take()
                && !pending_separator.previous_ended_whitespace
                && !ch.is_whitespace()
            {
                self.text.push_str(pending_separator.separator);
                if let Some(last_char) = pending_separator.separator.chars().last() {
                    self.last_char_is_whitespace = last_char.is_whitespace();
                }
            }

            self.text.push(ch);
            self.last_char_is_whitespace = ch.is_whitespace();
            true
        }
    }

    fn write_adf_text(
        node: &serde_json::Value,
        output: &mut TextAccumulator,
        pending_separator: &mut Option<PendingSeparator<'_>>,
    ) -> bool {
        match node {
            serde_json::Value::Object(map) => {
                let node_type = map.get("type").and_then(|v| v.as_str());
                if node_type == Some("text") {
                    return output.write_text(
                        map.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                        pending_separator,
                    );
                }
                if node_type == Some("hardBreak") {
                    return output.write_char('\n', pending_separator);
                }

                let start_len = output.len();
                if let Some(children) = map.get("content").and_then(|v| v.as_array()) {
                    let separator = match node_type {
                        Some("table") => Some("\n"),
                        Some("tableRow") => Some(" "),
                        _ => None,
                    };
                    let mut wrote_child_text = false;
                    let mut previous_ended_whitespace = true;
                    for child in children {
                        let mut child_pending_separator = if wrote_child_text {
                            separator.map(|separator| PendingSeparator {
                                separator,
                                previous_ended_whitespace,
                            })
                        } else {
                            pending_separator.take()
                        };
                        let child_wrote_text =
                            write_adf_text(child, output, &mut child_pending_separator);
                        if !wrote_child_text && !child_wrote_text {
                            *pending_separator = child_pending_separator;
                        }
                        if child_wrote_text {
                            wrote_child_text = true;
                            previous_ended_whitespace = output.last_char_is_whitespace();
                        }
                    }
                }

                if matches!(
                    node_type,
                    Some(
                        "paragraph"
                            | "heading"
                            | "blockquote"
                            | "listItem"
                            | "codeBlock"
                            | "tableRow"
                            | "table"
                    )
                ) && output.len() > start_len
                    && !output.ends_with_newline()
                {
                    output.text.push('\n');
                    output.last_char_is_whitespace = true;
                }

                output.len() > start_len
            }
            serde_json::Value::Array(arr) => {
                let start_len = output.len();
                let mut wrote_child_text = false;
                for child in arr {
                    let mut child_pending_separator =
                        if wrote_child_text { None } else { pending_separator.take() };
                    let child_wrote_text =
                        write_adf_text(child, output, &mut child_pending_separator);
                    if !wrote_child_text && !child_wrote_text {
                        *pending_separator = child_pending_separator;
                    }
                    if child_wrote_text {
                        wrote_child_text = true;
                    }
                }
                output.len() > start_len
            }
            _ => false,
        }
    }

    let mut output = TextAccumulator::new();
    let mut pending_separator = None;
    write_adf_text(node, &mut output, &mut pending_separator);
    output.text
}

/// Returns true if the value looks like an ADF document root.
fn is_adf(value: &serde_json::Value) -> bool {
    value.get("type").and_then(|v| v.as_str()).map(|t| t == "doc").unwrap_or(false)
}

fn flatten_adf_fields(issue_value: &mut serde_json::Value) {
    // Jira Cloud API v3 returns descriptions as Atlassian Document Format (ADF),
    // a nested JSON tree whose leaf text nodes contain the actual content.
    // Flatten ADF to a plain string so the secret scanner can match against it.
    if let Some(desc) = issue_value.pointer("/fields/description")
        && is_adf(desc)
    {
        let plain_text = extract_adf_text(desc);
        if let Some(fields) =
            issue_value.pointer_mut("/fields").and_then(|value| value.as_object_mut())
        {
            fields.insert(
                "description".to_string(),
                serde_json::Value::String(plain_text.trim_end_matches('\n').to_string()),
            );
        }
    }

    // Apply the same ADF flattening to comment bodies.
    if let Some(comments) = issue_value.pointer_mut("/fields/comment/comments")
        && let Some(arr) = comments.as_array_mut()
    {
        for comment in arr.iter_mut() {
            let plain_text = comment
                .get("body")
                .and_then(|body| if is_adf(body) { Some(extract_adf_text(body)) } else { None });
            if let Some(plain_text) = plain_text
                && let Some(comment_obj) = comment.as_object_mut()
            {
                comment_obj.insert(
                    "body".to_string(),
                    serde_json::Value::String(plain_text.trim_end_matches('\n').to_string()),
                );
            }
        }
    }
}

fn flatten_comment_bodies(comments: &mut [serde_json::Value]) {
    for comment in comments {
        let plain_text = comment
            .get("body")
            .and_then(|body| if is_adf(body) { Some(extract_adf_text(body)) } else { None });
        if let Some(plain_text) = plain_text
            && let Some(comment_obj) = comment.as_object_mut()
        {
            comment_obj.insert(
                "body".to_string(),
                serde_json::Value::String(plain_text.trim_end_matches('\n').to_string()),
            );
        }
    }
}

fn build_http_client(ignore_certs: bool) -> Result<Client> {
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(ignore_certs);
    if !ignore_certs {
        // reqwest 0.13 defaults to platform certificate verification. Preserve
        // Jira's existing Mozilla roots (including on hosts without a CA bundle)
        // and HTTP/1.1 behavior of the former reqwest 0.12 client. Use the same
        // maintained AWS-LC provider as the rest of the CLI when none is installed.
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| rustls::crypto::aws_lc_rs::default_provider().into());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("Failed to configure Jira TLS")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        builder = builder.tls_backend_preconfigured(tls);
    }
    if !kingfisher_scanner::validation::limits::NetworkLimits::current().no_timeouts {
        builder = builder.timeout(Duration::from_secs(30));
    }
    builder.build().context("Failed to build HTTP client")
}

async fn jira_response_body(mut response: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("Failed to read Jira response body")? {
        anyhow::ensure!(
            NetworkLimits::current().unlimited_response
                || body.len().saturating_add(chunk.len()) <= max_bytes,
            "Jira response exceeded the {max_bytes}-byte decoded body limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn jira_json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let body = jira_response_body(response, MAX_JIRA_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body).context("Invalid Jira JSON response")
}

/// Preserve explicit API roots and reverse-proxy context paths.
fn jira_api_url(jira_url: &Url, endpoint: &str) -> Result<Url> {
    anyhow::ensure!(
        jira_url.query().is_none() && jira_url.fragment().is_none(),
        "Jira --url must not contain query parameters or a fragment; pass the search expression with --jql"
    );
    let base = jira_url.as_str().trim_end_matches('/');
    let api = if base.contains("/rest/api/") {
        base.to_owned()
    } else if jira_url.host_str().is_some_and(|host| host.ends_with(".atlassian.net")) {
        format!("{base}/rest/api/3")
    } else {
        format!("{base}/rest/api/latest")
    };
    Url::parse(&format!("{api}/{endpoint}")).context("Invalid Jira API URL")
}

async fn jira_get(client: &Client, auth: &JiraAuth, url: Url) -> Result<reqwest::Response> {
    for attempt in 0..=3 {
        let response = auth
            .apply(client.get(url.clone()))
            .send()
            .await
            .context("Cannot reach Jira API; check --url and network connectivity")?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
            let delay = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(|secs| Duration::from_secs(secs.min(30)))
                .unwrap_or_else(|| Duration::from_millis(250 * (1 << attempt)));
            tokio::time::sleep(delay).await;
            continue;
        }
        match response.status().as_u16() {
            200..=299 => return Ok(response),
            401 | 403 => bail!(
                "Jira authentication or permission check failed (HTTP {}); check KF_JIRA_TOKEN and KF_JIRA_USER",
                response.status()
            ),
            429 => bail!("Jira rate limit persisted after 3 retries (HTTP 429)"),
            status => bail!("Jira API returned HTTP {status}; check --url and API permissions"),
        }
    }
    unreachable!("bounded retry loop returns")
}

/// Fail before acquiring issue artifacts when a URL or credentials are invalid.
pub async fn check_access(jira_url: &Url, ignore_certs: bool) -> Result<()> {
    let auth = JiraAuth::from_env()?;
    let endpoint = if matches!(auth, JiraAuth::Anonymous) { "serverInfo" } else { "myself" };
    let response =
        jira_get(&build_http_client(ignore_certs)?, &auth, jira_api_url(jira_url, endpoint)?)
            .await?;
    let body: serde_json::Value = jira_json(response)
        .await
        .context("Jira access check returned invalid JSON; check --url")?;
    anyhow::ensure!(
        body.is_object(),
        "Jira access check did not return an API object; check --url"
    );
    Ok(())
}

/// Add safe project exclusions to the same JQL search used for all discovery.
pub fn excluding_projects(jql: &str, projects: &[String]) -> Result<String> {
    if projects.is_empty() {
        return Ok(jql.to_owned());
    }
    let mut keys = Vec::new();
    for key in projects {
        anyhow::ensure!(
            !key.is_empty()
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "Invalid Jira project key for --skip-project"
        );
        keys.push(format!("\"{}\"", key.to_ascii_uppercase()));
    }
    // ORDER BY belongs after the predicate, not inside parenthesized JQL.
    let ordering = regex::Regex::new(r"(?i)\border\s+by\b").expect("constant JQL pattern");
    let mut candidates = ordering.find_iter(jql).peekable();
    let mut quote = None;
    let mut escaped = false;
    let mut split = jql.len();
    for (index, ch) in jql.char_indices() {
        if candidates.peek().is_some_and(|candidate| candidate.start() == index) {
            candidates.next();
            if quote.is_none() {
                split = index;
                break;
            }
        }
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
        }
    }
    let predicate = jql[..split].trim();
    let predicate =
        if predicate.is_empty() { String::new() } else { format!("({predicate}) AND ") };
    Ok(format!("{predicate}project NOT IN ({}) {}", keys.join(", "), &jql[split..])
        .trim_end()
        .to_owned())
}

/// Jira authentication resolved from the environment. Cloud API tokens need
/// Basic auth with the account email; Bearer is for OAuth 2.0 tokens and
/// Server/Data Center PATs. Search and comment fetching both resolve auth here
/// so the two cannot drift apart.
#[derive(Clone, PartialEq, Eq)]
enum JiraAuth {
    Basic { user: String, token: String },
    Bearer(String),
    Anonymous,
}

// Hand-written so a token cannot reach logs or a failed assertion's output.
// The account email is kept: it is not a credential and is the useful part
// when diagnosing which identity was picked up.
impl std::fmt::Debug for JiraAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic { user, .. } => {
                f.debug_struct("Basic").field("user", user).field("token", &"<redacted>").finish()
            }
            Self::Bearer(_) => f.debug_tuple("Bearer").field(&"<redacted>").finish(),
            Self::Anonymous => f.write_str("Anonymous"),
        }
    }
}

impl JiraAuth {
    fn from_env() -> Result<Self> {
        match (std::env::var("KF_JIRA_USER").ok(), std::env::var("KF_JIRA_TOKEN").ok()) {
            (Some(user), Some(token)) => {
                if !user.contains('@') {
                    bail!("KF_JIRA_USER must be an email address");
                }
                Ok(Self::Basic { user, token })
            }
            (Some(_), None) => bail!(
                "KF_JIRA_USER is set but KF_JIRA_TOKEN is not; Jira Cloud Basic auth requires both"
            ),
            (None, Some(token)) => Ok(Self::Bearer(token)),
            (None, None) => Ok(Self::Anonymous),
        }
    }

    fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match self {
            Self::Basic { user, token } => request.basic_auth(user, Some(token)),
            Self::Bearer(token) => request.bearer_auth(token),
            Self::Anonymous => request,
        }
    }
}

fn normalize_issue(issue: &JiraIssue) -> Result<serde_json::Value> {
    let mut issue_value = serde_json::to_value(issue)?;
    flatten_adf_fields(&mut issue_value);
    Ok(issue_value)
}

fn extract_embedded_comments(issue: &JiraIssue) -> Result<Option<(Vec<serde_json::Value>, bool)>> {
    let Some(comments) = issue.comments() else {
        return Ok(None);
    };

    let is_complete = comments.start_at + comments.comments.len() as u32 >= comments.total;
    let mut comments_json = comments
        .comments
        .into_iter()
        .map(serde_json::to_value)
        .collect::<serde_json::Result<Vec<_>>>()?;
    flatten_comment_bodies(&mut comments_json);
    Ok(Some((comments_json, is_complete)))
}

fn issue_artifact_dir(output_dir: &Path, issue_key: &str) -> PathBuf {
    output_dir.join(issue_key)
}

#[derive(serde::Deserialize)]
struct JiraCommentsPage {
    comments: Vec<serde_json::Value>,
    #[serde(rename = "startAt")]
    start_at: u32,
    total: u32,
}

pub async fn fetch_issues(
    jira_url: &Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<JiraIssue>> {
    let client = build_http_client(ignore_certs)?;
    let auth = JiraAuth::from_env()?;
    let cloud = jira_api_url(jira_url, "")?.path().trim_end_matches('/').ends_with("/3");
    let endpoint = if cloud { "search/jql" } else { "search" };
    let mut seen_cursors = HashSet::new();

    let mut issues: Vec<JiraIssue> = Vec::new();
    // Cloud paginates by cursor, Server/Data Center by offset; both report
    // `is_last_page`.
    let mut start_at: u64 = 0;
    let mut next_page_token: Option<String> = None;

    while kingfisher_scanner::validation::limits::NetworkLimits::current().unlimited_results
        || issues.len() < max_results
    {
        let page_size =
            if kingfisher_scanner::validation::limits::NetworkLimits::current().unlimited_results {
                JIRA_ISSUES_PAGE_SIZE
            } else {
                std::cmp::min(JIRA_ISSUES_PAGE_SIZE, max_results - issues.len())
            };

        let mut url = jira_api_url(jira_url, endpoint)?;
        url.query_pairs_mut()
            .append_pair("jql", jql)
            .append_pair("maxResults", &page_size.to_string())
            .append_pair("fields", JIRA_SEARCH_FIELDS);
        let used_cursor = next_page_token.is_some();
        if let Some(token) = &next_page_token {
            url.query_pairs_mut().append_pair("nextPageToken", token);
        } else if start_at > 0 {
            url.query_pairs_mut().append_pair("startAt", &start_at.to_string());
        }

        // Errors propagate: a rate limit partway through must not look like
        // "no more issues". This is why `stream()` is unused — it maps a failed
        // page to end-of-stream.
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SearchPage {
            issues: Vec<JiraIssue>,
            total: Option<u64>,
            is_last: Option<bool>,
            #[serde(alias = "next_page_token")]
            next_page_token: Option<String>,
        }
        let results: SearchPage = jira_json(jira_get(&client, &auth, url).await?)
            .await
            .context("Failed to parse Jira search response")?;
        let received = results.issues.len();
        issues.extend(results.issues);

        // An empty page keeps the loop bounded if the server keeps advertising
        // more.
        if received == 0
            || results.is_last == Some(true)
            || results.total.is_some_and(|total| issues.len() as u64 >= total)
        {
            break;
        }

        match results.next_page_token {
            Some(token) => {
                anyhow::ensure!(
                    seen_cursors.insert(token.clone()),
                    "Jira search repeated a pagination cursor"
                );
                next_page_token = Some(token);
            }
            // Reusing a spent cursor re-requests the same page forever, and an
            // offset means nothing to a cursor API.
            None if used_cursor || cloud => break,
            None => start_at += received as u64,
        }
    }

    if !kingfisher_scanner::validation::limits::NetworkLimits::current().unlimited_results {
        issues.truncate(max_results);
    }
    Ok(issues)
}

fn validate_issue_key(issue_key: &str) -> Result<()> {
    // Project keys may contain underscores. This guards path/URL syntax, not the
    // administrator-configurable project-key grammar or numeric-ID resolution.
    anyhow::ensure!(
        !issue_key.is_empty()
            && issue_key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "Invalid Jira issue key"
    );
    Ok(())
}

pub async fn fetch_comments(
    jira_url: &Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<Vec<serde_json::Value>> {
    validate_issue_key(issue_key)?;

    let client = build_http_client(ignore_certs)?;
    let auth = JiraAuth::from_env()?;
    let mut start_at = 0;
    let mut all_comments = Vec::new();

    loop {
        let url = jira_api_url(
            jira_url,
            &format!(
                "issue/{issue_key}/comment?startAt={start_at}&maxResults={JIRA_COMMENTS_PAGE_SIZE}"
            ),
        )?;
        let response = jira_get(&client, &auth, url).await?;
        let page: JiraCommentsPage =
            jira_json(response).await.context("Failed to parse Jira comments JSON")?;
        let received = page.comments.len() as u32;
        all_comments.extend(page.comments);

        if received == 0 || start_at + received >= page.total {
            break;
        }

        let next = page.start_at.saturating_add(received);
        anyhow::ensure!(next > start_at, "Jira comments pagination did not advance");
        start_at = next;
    }

    flatten_comment_bodies(&mut all_comments);
    Ok(all_comments)
}

pub async fn fetch_changelog(
    jira_url: &Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<gouqi::Changelog> {
    validate_issue_key(issue_key)?;
    let url = jira_api_url(jira_url, &format!("issue/{issue_key}/changelog"))?;
    jira_json(jira_get(&build_http_client(ignore_certs)?, &JiraAuth::from_env()?, url).await?)
        .await
        .context("Failed to parse Jira changelog response")
}

pub async fn download_issues_to_dir(
    jira_url: &Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
    options: DownloadIssueArtifactsOptions,
) -> Result<Vec<PathBuf>> {
    check_access(jira_url, ignore_certs).await?;
    std::fs::create_dir_all(output_dir)?;
    let issues = fetch_issues(jira_url, jql, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    for issue in issues {
        validate_issue_key(&issue.key)?;
        let issue_dir = issue_artifact_dir(output_dir, &issue.key);
        std::fs::create_dir_all(&issue_dir)?;

        let issue_value = normalize_issue(&issue)?;
        let file = issue_dir.join("issue.json");
        std::fs::write(&file, serde_json::to_vec(&issue_value)?)?;
        paths.push(file);

        if options.include_comments {
            let comments = match extract_embedded_comments(&issue)? {
                Some((comments, true)) => comments,
                Some((_, false)) | None => {
                    fetch_comments(jira_url, &issue.key, ignore_certs).await?
                }
            };
            let file = issue_dir.join("comments.json");
            std::fs::write(&file, serde_json::to_vec(&comments)?)?;
            paths.push(file);
        }

        if options.include_changelog {
            let changelog = fetch_changelog(jira_url, &issue.key, ignore_certs).await?;
            let file = issue_dir.join("changelog.json");
            std::fs::write(&file, serde_json::to_vec(&changelog)?)?;
            paths.push(file);
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn compressed_response_limits_count_decoded_bytes_and_obey_content_policy() {
        use std::io::Write;
        let server = MockServer::start().await;
        let value = json!({"description": "x".repeat(1024)});
        let decoded = serde_json::to_vec(&value).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&decoded).unwrap();
        let encoded = encoder.finish().unwrap();
        assert!(encoded.len() < 64 && decoded.len() > 64);
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(encoded),
            )
            .expect(3)
            .mount(&server)
            .await;
        for limits in [
            NetworkLimits::default(),
            NetworkLimits { no_timeouts: true, ..Default::default() },
            NetworkLimits { unlimited_response: true, ..Default::default() },
        ] {
            let result = limits
                .scope(async {
                    let response = super::build_http_client(false)
                        .unwrap()
                        .get(server.uri())
                        .send()
                        .await
                        .unwrap();
                    super::jira_response_body(response, 64).await
                })
                .await;
            if limits.unlimited_response {
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&result.unwrap()).unwrap(),
                    value
                );
            } else {
                assert!(result.unwrap_err().to_string().contains("decoded body limit"));
            }
        }
    }

    #[tokio::test]
    async fn decoded_response_limit_accepts_exactly_the_limit_and_keeps_json_errors() {
        let response = http::Response::builder().body(vec![b'x'; 64]).unwrap().into();
        assert_eq!(super::jira_response_body(response, 64).await.unwrap(), vec![b'x'; 64]);
        let response = http::Response::builder().body(vec![b'x'; 65]).unwrap().into();
        assert!(super::jira_response_body(response, 64).await.is_err());
        let response = http::Response::builder().body("not JSON").unwrap().into();
        let error = super::jira_json::<serde_json::Value>(response).await.unwrap_err();
        assert!(error.to_string().contains("Invalid Jira JSON response"));
    }

    #[tokio::test]
    async fn comments_and_changelog_accept_underscored_project_keys() {
        let server = MockServer::start().await;
        for (suffix, body) in [
            ("comment", json!({"startAt":0,"total":1,"comments":[{"body":"preserved"}]})),
            ("changelog", json!({"values":[]})),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/rest/api/latest/issue/MY_EXAMPLE_PROJECT-1/{suffix}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let base = Url::parse(&server.uri()).unwrap();
        let comments =
            without_jira_credentials(fetch_comments(&base, "MY_EXAMPLE_PROJECT-1", false))
                .await
                .unwrap();
        assert_eq!(comments[0]["body"], "preserved");
        without_jira_credentials(super::fetch_changelog(&base, "MY_EXAMPLE_PROJECT-1", false))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn shared_http_client_preserves_strict_and_insecure_tls_modes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for ignore_certs in [false, true] {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(
                rustls::crypto::aws_lc_rs::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let Ok(mut stream) = acceptor.accept(socket).await else { return false };
                let mut buffer = [0; 4096];
                assert!(stream.read(&mut buffer).await.unwrap() > 0);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
                true
            });
            let response = super::build_http_client(ignore_certs)
                .unwrap()
                .get(format!("https://{address}/"))
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;
            if ignore_certs {
                assert_eq!(response.unwrap().text().await.unwrap(), "{}");
            } else {
                assert!(response.unwrap_err().is_connect());
            }
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(5), server)
                    .await
                    .unwrap()
                    .unwrap(),
                ignore_certs
            );
        }
    }

    #[tokio::test]
    async fn shared_http_client_preserves_jira_artifacts_and_authentication() {
        let server = wiremock::MockServer::start().await;
        let issue = serde_json::json!({
            "self": format!("{}/jira/rest/api/latest/issue/TEST-1", server.uri()),
            "key": "TEST-1",
            "id": "10000",
            "fields": {
                "summary": "example",
                "customfield_123": {"nested": ["keep", 42, true]},
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": "description"}]}]
                }
            }
        });
        let changelog = serde_json::json!({"values": [{
            "author": {
                "accountId": "user-1", "active": true, "avatarUrls": null,
                "displayName": "Example", "emailAddress": null, "key": null,
                "name": null, "self": "https://jira.example.com/user/1", "timeZone": null
            },
            "created": "2026-10-18T00:00:00.000+0000",
            "items": [{"field": "description", "from": null, "fromString": "before", "to": null, "toString": "after"}]
        }]});
        for (endpoint, body) in [
            ("myself", serde_json::json!({"accountId": "user-1"})),
            ("search", serde_json::json!({"issues": [issue.clone()], "total": 1})),
            (
                "issue/TEST-1/comment",
                serde_json::json!({"startAt": 0, "total": 1, "comments": [{
                    "id": "1", "custom": "preserved",
                    "body": {"type": "doc", "version": 1, "content": [{
                        "type": "paragraph", "content": [{"type": "text", "text": "comment"}]
                    }]}
                }]}),
            ),
            ("issue/TEST-1/changelog", changelog.clone()),
        ] {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path(format!("/jira/rest/api/latest/{endpoint}")))
                .and(wiremock::matchers::basic_auth("user@example.com", "test-token"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_env::async_with_vars(
            [("KF_JIRA_USER", Some("user@example.com")), ("KF_JIRA_TOKEN", Some("test-token"))],
            super::download_issues_to_dir(
                &url::Url::parse(&format!("{}/jira", server.uri())).unwrap(),
                "project = TEST",
                10,
                false,
                &dir.path().to_path_buf(),
                super::DownloadIssueArtifactsOptions {
                    include_comments: true,
                    include_changelog: true,
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(paths.len(), 3);
        let read = |name| -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(dir.path().join("TEST-1").join(name)).unwrap())
                .unwrap()
        };
        let mut expected_issue = issue;
        expected_issue["fields"]["description"] = serde_json::json!("description");
        assert_eq!(read("issue.json"), expected_issue);
        assert_eq!(
            read("comments.json"),
            serde_json::json!([{"id": "1", "custom": "preserved", "body": "comment"}])
        );
        assert_eq!(read("changelog.json"), changelog);
    }

    #[test]
    fn project_exclusions_are_case_insensitive_and_keep_ordering() {
        assert_eq!(
            super::excluding_projects(
                "project = APP ORDER BY updated DESC",
                &["arChive".into(), "test".into()]
            )
            .unwrap(),
            "(project = APP) AND project NOT IN (\"ARCHIVE\", \"TEST\") ORDER BY updated DESC"
        );
        assert!(
            super::excluding_projects("project = APP", &["bad\" OR project = APP".into()]).is_err()
        );
        assert_eq!(
            super::excluding_projects(
                "summary ~ '\" order by \"' ORDER\nBY updated",
                &["archived".into()]
            )
            .unwrap(),
            "(summary ~ '\" order by \"') AND project NOT IN (\"ARCHIVED\") ORDER\nBY updated"
        );
    }

    #[test]
    fn api_paths_preserve_context_and_explicit_versions() {
        for (base, expected) in [
            ("https://jira.example.com/jira", "/jira/rest/api/latest/search"),
            ("https://jira.example.com/proxy/rest/api/2", "/proxy/rest/api/2/search"),
            ("https://example.atlassian.net", "/rest/api/3/search"),
        ] {
            assert_eq!(
                super::jira_api_url(&url::Url::parse(base).unwrap(), "search").unwrap().path(),
                expected
            );
        }
        for url in ["https://jira.example.com/?x=1", "https://jira.example.com/jira#fragment"] {
            let error = super::jira_api_url(&url::Url::parse(url).unwrap(), "search").unwrap_err();
            assert!(error.to_string().contains("--url must not contain"));
        }
    }

    #[tokio::test]
    async fn access_checks_fail_before_issue_acquisition() {
        for status in [401, 403, 404, 302] {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/jira/rest/api/latest/myself"))
                .respond_with(wiremock::ResponseTemplate::new(status))
                .expect(1)
                .mount(&server)
                .await;
            let base = url::Url::parse(&format!("{}/jira", server.uri())).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let result = temp_env::async_with_vars(
                [("KF_JIRA_TOKEN", Some("test-token")), ("KF_JIRA_USER", None)],
                super::download_issues_to_dir(
                    &base,
                    "project = APP",
                    10,
                    false,
                    &dir.path().to_path_buf(),
                    Default::default(),
                ),
            )
            .await;
            assert!(result.is_err());
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn rate_limits_retry_and_then_stop_with_a_clear_error() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .expect(4)
            .mount(&server)
            .await;
        let result = without_jira_credentials(super::fetch_issues(
            &url::Url::parse(&server.uri()).unwrap(),
            "project = APP",
            10,
            false,
        ))
        .await;
        assert!(result.unwrap_err().to_string().contains("after 3 retries"));
    }
    use super::{
        JIRA_COMMENTS_PAGE_SIZE, JiraAuth, extract_adf_text, extract_embedded_comments,
        fetch_comments, fetch_issues, flatten_adf_fields, flatten_comment_bodies, is_adf,
    };
    use kingfisher_scanner::validation::limits::NetworkLimits;
    use serde_json::json;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param, query_param_is_missing},
    };

    async fn without_jira_credentials<T>(future: impl std::future::Future<Output = T>) -> T {
        temp_env::async_with_vars([("KF_JIRA_USER", None::<&str>), ("KF_JIRA_TOKEN", None)], future)
            .await
    }

    #[test]
    fn jira_auth_uses_basic_for_cloud_email_and_token() {
        temp_env::with_vars(
            [("KF_JIRA_USER", Some("user@example.com")), ("KF_JIRA_TOKEN", Some("test-token"))],
            || {
                assert_eq!(
                    JiraAuth::from_env().expect("should accept email and token"),
                    JiraAuth::Basic {
                        user: "user@example.com".to_string(),
                        token: "test-token".to_string(),
                    }
                );
            },
        );
    }

    #[test]
    fn jira_auth_debug_never_reveals_the_token() {
        // `assert_eq!` prints the value on failure, so a derived Debug would
        // put credentials in test output and in any log that formats them.
        let basic = JiraAuth::Basic {
            user: "user@example.com".to_string(),
            token: "super-secret-token".to_string(),
        };
        let rendered = format!("{:?} {:?}", basic, JiraAuth::Bearer("super-secret-token".into()));

        assert!(!rendered.contains("super-secret-token"), "token leaked into Debug: {rendered}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("user@example.com"));
    }

    #[test]
    fn jira_auth_uses_bearer_when_user_is_unset() {
        temp_env::with_vars(
            [("KF_JIRA_USER", None), ("KF_JIRA_TOKEN", Some("test-token"))],
            || {
                assert_eq!(
                    JiraAuth::from_env().expect("should accept a bare token"),
                    JiraAuth::Bearer("test-token".to_string())
                );
            },
        );
    }

    #[test]
    fn jira_auth_rejects_user_without_token() {
        temp_env::with_vars(
            [("KF_JIRA_USER", Some("user@example.com")), ("KF_JIRA_TOKEN", None)],
            || {
                let err = JiraAuth::from_env().expect_err("should reject user without token");
                assert!(err.to_string().contains("KF_JIRA_TOKEN"));
            },
        );
    }

    #[test]
    fn jira_auth_rejects_user_that_is_not_an_email() {
        temp_env::with_vars(
            [("KF_JIRA_USER", Some("not-an-email")), ("KF_JIRA_TOKEN", Some("test-token"))],
            || {
                let err = JiraAuth::from_env().expect_err("should reject non-email user");
                assert!(err.to_string().contains("email address"));
            },
        );
    }

    #[test]
    fn jira_auth_is_anonymous_without_credentials() {
        temp_env::with_vars([("KF_JIRA_USER", None::<&str>), ("KF_JIRA_TOKEN", None)], || {
            assert_eq!(
                JiraAuth::from_env().expect("should allow anonymous access"),
                JiraAuth::Anonymous
            );
        });
    }

    #[test]
    fn is_adf_detects_doc_root() {
        let doc = json!({"type": "doc", "version": 1, "content": []});
        assert!(is_adf(&doc));
        assert!(!is_adf(&json!({"type": "paragraph"})));
        assert!(!is_adf(&json!("not-a-doc")));
    }

    #[test]
    fn extract_adf_text_concatenates_adjacent_text_nodes() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "sk-"},
                    {"type": "text", "text": "proj-123"}
                ]
            }]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "sk-proj-123");
    }

    #[test]
    fn extract_adf_text_preserves_hard_breaks() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "foo"},
                    {"type": "hardBreak"},
                    {"type": "text", "text": "bar"}
                ]
            }]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "foo\nbar");
    }

    #[test]
    fn extract_adf_text_adds_paragraph_separator() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": "first"}]},
                {"type": "paragraph", "content": [{"type": "text", "text": "second"}]}
            ]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "first\nsecond");
    }

    #[test]
    fn extract_adf_text_returns_empty_for_non_adf_values() {
        let value = json!("plain description string");
        let text = extract_adf_text(&value);
        assert_eq!(text, "");

        let number_value = json!(42);
        let number_text = extract_adf_text(&number_value);
        assert_eq!(number_text, "");

        let null_value = json!(null);
        let null_text = extract_adf_text(&null_value);
        assert_eq!(null_text, "");
    }

    #[test]
    fn extract_adf_text_handles_missing_content_fields() {
        let doc_without_content = json!({
            "type": "doc",
            "version": 1
        });
        let text = extract_adf_text(&doc_without_content);
        assert_eq!(text, "");

        let paragraph_without_content = json!({
            "type": "paragraph"
        });
        let para_text = extract_adf_text(&paragraph_without_content);
        assert_eq!(para_text, "");
    }

    #[test]
    fn extract_adf_text_handles_empty_doc() {
        let empty_doc = json!({
            "type": "doc",
            "version": 1,
            "content": []
        });
        let text = extract_adf_text(&empty_doc);
        assert_eq!(text, "");
    }

    #[test]
    fn extract_adf_text_handles_lists_and_code_blocks() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "bulletList",
                    "content": [
                        {
                            "type": "listItem",
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": "item1"}]
                            }]
                        },
                        {
                            "type": "listItem",
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": "item2"}]
                            }]
                        }
                    ]
                },
                {
                    "type": "codeBlock",
                    "content": [{"type": "text", "text": "code"}]
                }
            ]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "item1\nitem2\ncode");
    }

    #[test]
    fn extract_adf_text_preserves_table_row_whitespace_rules() {
        let value = json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "tableRow",
                "content": [
                    {"type": "text", "text": "foo"},
                    {"type": "text", "text": "bar"},
                    {"type": "text", "text": " baz"}
                ]
            }]
        });
        let text = extract_adf_text(&value);
        assert_eq!(text.trim_end(), "foo bar baz");
    }

    #[test]
    fn flatten_adf_fields_converts_comment_bodies() {
        let mut issue_value = json!({
            "fields": {
                "comment": {
                    "comments": [
                        {
                            "body": {
                                "type": "doc",
                                "version": 1,
                                "content": [{
                                    "type": "paragraph",
                                    "content": [{"type": "text", "text": "secret"}]
                                }]
                            }
                        }
                    ]
                }
            }
        });
        flatten_adf_fields(&mut issue_value);
        let body = issue_value
            .pointer("/fields/comment/comments/0/body")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(body, "secret");
    }

    #[test]
    fn flatten_adf_fields_converts_description() {
        let mut issue_value = json!({
            "fields": {
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{"type": "text", "text": "desc"}]
                    }]
                }
            }
        });
        flatten_adf_fields(&mut issue_value);
        let desc =
            issue_value.pointer("/fields/description").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(desc, "desc");
    }

    #[test]
    fn flatten_adf_fields_leaves_plain_description() {
        let mut issue_value = json!({
            "fields": {
                "description": "plain description"
            }
        });
        flatten_adf_fields(&mut issue_value);
        let desc =
            issue_value.pointer("/fields/description").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(desc, "plain description");
    }

    #[test]
    fn flatten_adf_fields_handles_missing_description() {
        let mut issue_value = json!({
            "fields": {
                "summary": "no description here"
            }
        });
        flatten_adf_fields(&mut issue_value);
        assert!(issue_value.pointer("/fields/description").is_none());
    }

    #[test]
    fn flatten_comment_bodies_converts_adf_comment_bodies() {
        let mut comments = vec![json!({
            "id": "1",
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "ghp_test_secret"}]
                }]
            }
        })];

        flatten_comment_bodies(&mut comments);

        assert_eq!(comments[0].pointer("/body"), Some(&json!("ghp_test_secret")));
    }

    #[test]
    fn extract_embedded_comments_preserves_empty_comment_arrays() {
        let issue: super::JiraIssue = serde_json::from_value(json!({
            "self": "https://jira.example.com/rest/api/latest/issue/TEST-1",
            "key": "TEST-1",
            "id": "10000",
            "fields": {
                "comment": {
                    "comments": [],
                    "self": "https://jira.example.com/rest/api/latest/issue/TEST-1/comment",
                    "maxResults": 0,
                    "total": 0,
                    "startAt": 0
                }
            }
        }))
        .expect("issue should deserialize");

        let (comments, is_complete) = extract_embedded_comments(&issue)
            .expect("embedded comments should serialize")
            .expect("comment wrapper should deserialize");

        assert!(comments.is_empty());
        assert!(is_complete);
    }

    #[test]
    fn extract_embedded_comments_marks_partial_comment_pages_incomplete() {
        let issue: super::JiraIssue = serde_json::from_value(json!({
            "self": "https://jira.example.com/rest/api/latest/issue/TEST-1",
            "key": "TEST-1",
            "id": "10000",
            "fields": {
                "comment": {
                    "comments": [
                        {
                            "self": "https://jira.example.com/rest/api/latest/issue/TEST-1/comment/1",
                            "id": "1",
                            "body": "first"
                        }
                    ],
                    "self": "https://jira.example.com/rest/api/latest/issue/TEST-1/comment",
                    "maxResults": 1,
                    "total": 2,
                    "startAt": 0
                }
            }
        }))
        .expect("issue should deserialize");

        let (_comments, is_complete) = extract_embedded_comments(&issue)
            .expect("embedded comments should serialize")
            .expect("comment wrapper should deserialize");

        assert!(!is_complete);
    }

    #[test]
    fn issue_key_validation_accepts_keys_and_numeric_issue_ids() {
        for issue_key in [
            "TEST-1",
            "project42-123",
            "12345",
            "PRODUCT_2013-123",
            "MY_EXAMPLE_PROJECT-1",
            "A_20_A091-15",
        ] {
            super::validate_issue_key(issue_key).expect("valid Jira issue key or ID");
        }
    }

    #[tokio::test]
    async fn comments_and_changelog_reject_invalid_issue_keys_without_echoing_input() {
        let jira_url = Url::parse("https://jira.example.com").unwrap();
        for issue_key in [
            "",
            "../TEST-1",
            "TEST-1/comment",
            "TEST-1?token=secret",
            "TEST-1#fragment",
            "TÉST-1",
            "TEST-1\nforged-log-entry",
            "TEST-1%2Fcomment",
        ] {
            let comments_error = fetch_comments(&jira_url, issue_key, false)
                .await
                .expect_err("invalid issue key must be rejected before making a request");
            let changelog_error = super::fetch_changelog(&jira_url, issue_key, false)
                .await
                .expect_err("invalid issue key must be rejected before making a request");
            assert_eq!(comments_error.to_string(), "Invalid Jira issue key");
            assert_eq!(changelog_error.to_string(), "Invalid Jira issue key");
        }
    }

    #[tokio::test]
    async fn fetch_comments_paginates_all_pages() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/latest/issue/TEST-1/comment"))
            .and(query_param("startAt", "0"))
            .and(query_param("maxResults", JIRA_COMMENTS_PAGE_SIZE.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "comments": [
                    {"id": "1", "body": "first"},
                    {"id": "2", "body": "second"}
                ],
                "startAt": 0,
                "maxResults": JIRA_COMMENTS_PAGE_SIZE,
                "total": 3
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/api/latest/issue/TEST-1/comment"))
            .and(query_param("startAt", "2"))
            .and(query_param("maxResults", JIRA_COMMENTS_PAGE_SIZE.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "comments": [
                    {"id": "3", "body": "third"}
                ],
                "startAt": 2,
                "maxResults": JIRA_COMMENTS_PAGE_SIZE,
                "total": 3
            })))
            .mount(&server)
            .await;

        let comments = without_jira_credentials(fetch_comments(
            &Url::parse(&server.uri()).expect("server URL"),
            "TEST-1",
            false,
        ))
        .await
        .expect("comments should be fetched");

        assert_eq!(comments.len(), 3);
        assert_eq!(comments[0].pointer("/body"), Some(&json!("first")));
        assert_eq!(comments[2].pointer("/body"), Some(&json!("third")));
    }

    #[tokio::test]
    async fn fetch_comments_preserves_base_path() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/jira/rest/api/latest/issue/TEST-1/comment"))
            .and(query_param("startAt", "0"))
            .and(query_param("maxResults", JIRA_COMMENTS_PAGE_SIZE.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "comments": [
                    {"id": "1", "body": "first"}
                ],
                "startAt": 0,
                "maxResults": JIRA_COMMENTS_PAGE_SIZE,
                "total": 1
            })))
            .mount(&server)
            .await;

        let jira_url = Url::parse(&format!("{}/jira", server.uri())).expect("server URL");
        let comments = without_jira_credentials(fetch_comments(&jira_url, "TEST-1", false))
            .await
            .expect("comments should be fetched");

        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].pointer("/body"), Some(&json!("first")));
    }

    fn issue_page(first_id: usize, count: usize) -> Vec<serde_json::Value> {
        (first_id..first_id + count)
            .map(|n| {
                json!({
                    "self": format!("https://jira.example.com/rest/api/latest/issue/TEST-{n}"),
                    "key": format!("TEST-{n}"),
                    "id": n.to_string(),
                    "fields": {"summary": format!("issue {n}")}
                })
            })
            .collect()
    }

    #[tokio::test]
    async fn fetch_issues_pages_beyond_a_single_request() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param_is_missing("startAt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 150,
                "maxResults": 100,
                "startAt": 0,
                "issues": issue_page(1, 100)
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param("startAt", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 150,
                "maxResults": 50,
                "startAt": 100,
                "issues": issue_page(101, 50)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let jira_url = Url::parse(&server.uri()).expect("server URL");
        let issues =
            without_jira_credentials(fetch_issues(&jira_url, "project = TEST", 150, false))
                .await
                .expect("issues should be fetched");

        assert_eq!(issues.len(), 150);
        assert_eq!(issues[0].key, "TEST-1");
        assert_eq!(issues[149].key, "TEST-150");
    }

    #[tokio::test]
    async fn fetch_issues_stops_when_the_cursor_dries_up() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param_is_missing("nextPageToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 10_000,
                "maxResults": 100,
                "startAt": 0,
                "issues": issue_page(1, 100),
                "next_page_token": "abc123"
            })))
            .expect(1)
            .mount(&server)
            .await;

        // The cursor dries up without a "last page" flag, so the mock may only
        // be hit once: reusing the spent token would loop here forever.
        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param("nextPageToken", "abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 10_000,
                "maxResults": 100,
                "startAt": 0,
                "issues": issue_page(101, 50)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let jira_url = Url::parse(&server.uri()).expect("server URL");
        let issues =
            without_jira_credentials(fetch_issues(&jira_url, "project = TEST", usize::MAX, false))
                .await
                .expect("issues should be fetched");

        assert_eq!(issues.len(), 150);
    }

    #[tokio::test]
    async fn fetch_issues_unbounded_stops_on_the_last_page() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        // `--all` passes usize::MAX: only "last page" may stop the loop.
        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param_is_missing("startAt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 130,
                "maxResults": 100,
                "startAt": 0,
                "issues": issue_page(1, 100)
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param("startAt", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 130,
                "maxResults": 100,
                "startAt": 100,
                "issues": issue_page(101, 30)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let jira_url = Url::parse(&server.uri()).expect("server URL");
        let issues =
            without_jira_credentials(fetch_issues(&jira_url, "project = TEST", usize::MAX, false))
                .await
                .expect("issues should be fetched");

        assert_eq!(issues.len(), 130);
        assert_eq!(issues[129].key, "TEST-130");
    }

    #[tokio::test]
    async fn fetch_issues_stops_at_max_results() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param("maxResults", "40"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 500,
                "maxResults": 40,
                "startAt": 0,
                "issues": issue_page(1, 40)
            })))
            .expect(1)
            .mount(&server)
            .await;

        let jira_url = Url::parse(&server.uri()).expect("server URL");
        let issues = without_jira_credentials(fetch_issues(&jira_url, "project = TEST", 40, false))
            .await
            .expect("issues should be fetched");

        assert_eq!(issues.len(), 40);
    }

    #[tokio::test]
    async fn fetch_issues_propagates_errors_instead_of_truncating() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param_is_missing("startAt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 150,
                "maxResults": 100,
                "startAt": 0,
                "issues": issue_page(1, 100)
            })))
            .mount(&server)
            .await;

        // Returning the first page as the whole result set would under-report
        // findings with no signal to the user.
        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param("startAt", "100"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let jira_url = Url::parse(&server.uri()).expect("server URL");
        let result =
            without_jira_credentials(fetch_issues(&jira_url, "project = TEST", 150, false)).await;

        assert!(result.is_err(), "a mid-pagination failure must not be reported as success");
    }

    #[tokio::test]
    async fn fetch_issues_requests_all_fields() {
        if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
            return;
        }
        let server = MockServer::start().await;

        // Unset, Cloud substitutes a minimal field set and drops descriptions.
        Mock::given(method("GET"))
            .and(path("/rest/api/latest/search"))
            .and(query_param("fields", "*all"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 1,
                "maxResults": 50,
                "startAt": 0,
                "issues": [{
                    "self": "https://jira.example.com/rest/api/latest/issue/TEST-1",
                    "key": "TEST-1",
                    "id": "10000",
                    "fields": {
                        "summary": "example",
                        "description": "AKIAIOSFODNN7EXAMPLE"
                    }
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let jira_url = Url::parse(&server.uri()).expect("server URL");
        let issues = without_jira_credentials(fetch_issues(&jira_url, "project = TEST", 50, false))
            .await
            .expect("issues should be fetched");

        assert_eq!(issues.len(), 1);
        // Must survive into the scanned artifact, not just the HTTP response.
        let issue_value = super::normalize_issue(&issues[0]).expect("issue should normalize");
        assert_eq!(
            issue_value.pointer("/fields/description").and_then(|v| v.as_str()),
            Some("AKIAIOSFODNN7EXAMPLE")
        );
    }
}
