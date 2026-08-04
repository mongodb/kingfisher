use anyhow::{Context, Result, bail};
use gouqi::{Credentials, SearchOptions, r#async::Jira};
use reqwest_0_12::{Client, RequestBuilder};
use std::path::{Path, PathBuf};
use url::Url;

// Re-export the Issue type from gouqi so callers don't depend on the crate.
pub use gouqi::Issue as JiraIssue;

const JIRA_COMMENTS_PAGE_SIZE: u32 = 1000;

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
    Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")
}

/// Jira authentication resolved from the environment. Cloud API tokens need
/// Basic auth with the account email; Bearer is for OAuth 2.0 tokens and
/// Server/Data Center PATs. Search and comment fetching both resolve auth here
/// so the two cannot drift apart.
#[derive(Clone, Debug, PartialEq, Eq)]
enum JiraAuth {
    Basic { user: String, token: String },
    Bearer(String),
    Anonymous,
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

    fn credentials(self) -> Credentials {
        match self {
            Self::Basic { user, token } => Credentials::Basic(user, token),
            Self::Bearer(token) => Credentials::Bearer(token),
            Self::Anonymous => Credentials::Anonymous,
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

fn build_jira_client(jira_url: &Url, ignore_certs: bool) -> Result<Jira> {
    let base = jira_url.as_str().trim_end_matches('/');
    let client = build_http_client(ignore_certs)?;
    let credentials = JiraAuth::from_env()?.credentials();
    Ok(Jira::from_client(base.to_string(), credentials, client)?)
}

fn jira_relative_base_url(jira_url: &Url) -> Url {
    let mut base_url = jira_url.clone();
    if !base_url.path().ends_with('/') {
        let new_path = if base_url.path().is_empty() {
            "/".to_string()
        } else {
            format!("{}/", base_url.path())
        };
        base_url.set_path(&new_path);
    }
    base_url
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
    let jira = build_jira_client(jira_url, ignore_certs)?;

    let mut issues: Vec<JiraIssue> = Vec::new();
    // Cloud paginates by cursor, Server/Data Center by offset; both report
    // `is_last_page`.
    let mut start_at: u64 = 0;
    let mut next_page_token: Option<String> = None;

    while issues.len() < max_results {
        let page_size = std::cmp::min(JIRA_ISSUES_PAGE_SIZE, max_results - issues.len());

        let mut options = SearchOptions::builder();
        options.max_results(page_size as u64).fields(vec![JIRA_SEARCH_FIELDS]);
        if let Some(token) = &next_page_token {
            options.next_page_token(token);
        } else if start_at > 0 {
            options.start_at(start_at);
        }

        // Errors propagate: a rate limit partway through must not look like
        // "no more issues". This is why `stream()` is unused — it maps a failed
        // page to end-of-stream.
        let results = jira.search().list(jql, &options.build()).await?;
        let received = results.issues.len();
        issues.extend(results.issues);

        // An empty page keeps the loop bounded if the server keeps advertising
        // more.
        if received == 0 || results.is_last_page == Some(true) {
            break;
        }

        match results.next_page_token {
            Some(token) => next_page_token = Some(token),
            None => start_at += received as u64,
        }
    }

    issues.truncate(max_results);
    Ok(issues)
}

pub async fn fetch_comments(
    jira_url: &Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<Vec<serde_json::Value>> {
    if !issue_key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        anyhow::bail!("Invalid Jira issue key: {issue_key}");
    }

    let client = build_http_client(ignore_certs)?;
    let auth = JiraAuth::from_env()?;
    let mut start_at = 0;
    let mut all_comments = Vec::new();
    let base_url = jira_relative_base_url(jira_url);

    loop {
        let url = base_url
            .join(&format!(
                "rest/api/latest/issue/{issue_key}/comment?startAt={start_at}&maxResults={JIRA_COMMENTS_PAGE_SIZE}"
            ))
            .context("Failed to construct Jira comments URL")?;

        let request = auth.apply(client.get(url));

        let response = request.send().await.context("Failed to fetch Jira comments")?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Jira comments API returned HTTP {status}: {}",
                body.chars().take(500).collect::<String>()
            );
        }

        let page = response
            .json::<JiraCommentsPage>()
            .await
            .context("Failed to parse Jira comments JSON")?;
        let received = page.comments.len() as u32;
        all_comments.extend(page.comments);

        if received == 0 || start_at + received >= page.total {
            break;
        }

        start_at = page.start_at + received;
    }

    flatten_comment_bodies(&mut all_comments);
    Ok(all_comments)
}

pub async fn fetch_changelog(
    jira_url: &Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<gouqi::Changelog> {
    let jira = build_jira_client(jira_url, ignore_certs)?;
    Ok(jira.issues().changelog(issue_key).await?)
}

pub async fn download_issues_to_dir(
    jira_url: &Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
    options: DownloadIssueArtifactsOptions,
) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(output_dir)?;
    let issues = fetch_issues(jira_url, jql, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    for issue in issues {
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
    use super::{
        JIRA_COMMENTS_PAGE_SIZE, JiraAuth, extract_adf_text, extract_embedded_comments,
        fetch_comments, fetch_issues, flatten_adf_fields, flatten_comment_bodies, is_adf,
    };
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
