use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use chrono::{Local, Utc};
use http::StatusCode;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use schemars::JsonSchema;
use serde::Serialize;
use url::Url;

use kingfisher_scanner::validation::http_validation::is_auto_provided_request_var;

use crate::{
    access_map::{
        AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata, ResourceExposure,
    },
    blob::BlobMetadata,
    bstring_escape::Escaped,
    cli,
    cli::global::GlobalArgs,
    finding_data, findings_store,
    matcher::{Match, compute_finding_fingerprint},
    origin::{Origin, OriginSet},
    rules::Revocation,
    rules::rule::Confidence,
    template_vars::extract_template_vars,
    validation_body::{self, ValidationResponseBody},
};
mod bson_format;
mod html_format;
mod json_format;
mod pretty_format;
mod sarif_format;
pub mod styles;
mod toon_format;
use std::io::IsTerminal;

use styles::{StyledObject, Styles};

use crate::{
    cli::commands::output::ReportOutputFormat,
    location::SourceSpan,
    origin::{GitRepoOrigin, get_repo_url},
};

/// Shell-escape a string for safe command-line usage using single quotes.
fn escape_for_shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn required_vars_for_validation(validation: &crate::rules::Validation) -> BTreeSet<String> {
    use crate::rules::Validation;
    let mut vars = BTreeSet::new();

    match validation {
        Validation::Http(http) => {
            vars.extend(extract_template_vars(&http.request.url));
            for (k, v) in &http.request.headers {
                vars.extend(extract_template_vars(k));
                vars.extend(extract_template_vars(v));
            }
            if let Some(body) = &http.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        Validation::Grpc(grpc) => {
            vars.extend(extract_template_vars(&grpc.request.url));
            for (k, v) in &grpc.request.headers {
                vars.extend(extract_template_vars(k));
                vars.extend(extract_template_vars(v));
            }
            if let Some(body) = &grpc.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        Validation::AWS => {
            vars.insert("AKID".to_string());
            vars.insert("TOKEN".to_string());
        }
        Validation::GCP => {
            vars.insert("TOKEN".to_string());
        }
        Validation::MongoDB
        | Validation::MySQL
        | Validation::Postgres
        | Validation::Jdbc
        | Validation::JWT => {
            vars.insert("TOKEN".to_string());
        }
        Validation::AzureStorage => {
            vars.insert("TOKEN".to_string());
            vars.insert("AZURENAME".to_string());
        }
        Validation::Coinbase => {
            vars.insert("TOKEN".to_string());
            vars.insert("CRED_NAME".to_string());
        }
        Validation::Raw(raw) => {
            vars.extend(kingfisher_scanner::validation::raw::required_vars(raw));
        }
    }

    vars.retain(|var| !is_auto_provided_request_var(var));

    vars
}

fn is_sensitive_arg_key(key: &str) -> bool {
    let normalized = key.trim_start_matches('-').to_ascii_lowercase();
    let exact = [
        "arg",
        "var",
        "token",
        "secret",
        "password",
        "pass",
        "key",
        "api-key",
        "apikey",
        "auth",
        "oauth-token",
        "pat",
        "credential",
        "credentials",
    ];
    if exact.iter().any(|candidate| *candidate == normalized) {
        return true;
    }

    let contains = ["token", "secret", "password", "apikey", "api-key", "auth", "credential"];
    contains.iter().any(|candidate| normalized.contains(candidate))
}

fn sanitize_command_line_args(args: &[String]) -> Vec<String> {
    let mut sanitized = Vec::with_capacity(args.len());
    let mut redact_next = false;

    for arg in args {
        if redact_next {
            sanitized.push("***REDACTED***".to_string());
            redact_next = false;
            continue;
        }

        let Some(stripped) = arg.strip_prefix('-') else {
            sanitized.push(arg.clone());
            continue;
        };

        if stripped.is_empty() {
            sanitized.push(arg.clone());
            continue;
        }

        let key_value_split = arg.split_once('=');
        if let Some((key, _)) = key_value_split {
            if is_sensitive_arg_key(key) {
                sanitized.push(format!("{key}=***REDACTED***"));
            } else {
                sanitized.push(arg.clone());
            }
            continue;
        }

        if is_sensitive_arg_key(arg) {
            sanitized.push(arg.clone());
            redact_next = true;
            continue;
        }

        sanitized.push(arg.clone());
    }

    sanitized
}

fn required_vars_for_revocation(revocation: &Revocation) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();

    match revocation {
        Revocation::AWS => {
            vars.insert("AKID".to_string());
            vars.insert("TOKEN".to_string());
        }
        Revocation::GCP => {
            vars.insert("TOKEN".to_string());
        }
        Revocation::Http(http) => {
            vars.extend(extract_template_vars(&http.request.url));
            for (k, v) in &http.request.headers {
                vars.extend(extract_template_vars(k));
                vars.extend(extract_template_vars(v));
            }
            if let Some(body) = &http.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        Revocation::HttpMultiStep(multi) => {
            for step in &multi.steps {
                vars.extend(extract_template_vars(&step.request.url));
                for (k, v) in &step.request.headers {
                    vars.extend(extract_template_vars(k));
                    vars.extend(extract_template_vars(v));
                }
                if let Some(body) = &step.request.body {
                    vars.extend(extract_template_vars(body));
                }
            }
        }
    }

    vars
}

/// Build the --var arguments string from dependent captures, but only for variables that are
/// required by the validation/revocation templates.
fn build_var_args(
    dependent_captures: &std::collections::BTreeMap<String, String>,
    akid_from_captures: Option<&str>,
    akid_from_validation_body: Option<&str>,
    required_vars: &BTreeSet<String>,
) -> String {
    let mut var_args = Vec::new();

    // Add AKID if available (for AWS)
    if let Some(akid) = akid_from_captures.or(akid_from_validation_body)
        && !akid.is_empty()
        && required_vars.contains("AKID")
        && !dependent_captures.contains_key("AKID")
    {
        var_args.push(format!("--var AKID={}", escape_for_shell(akid)));
    }

    // Add dependent captures only when required by the templates.
    // This avoids generating commands like `--var BODY=...` for tokens whose named captures
    // are just internal parsing aids (e.g., checksum payloads).
    for (name, value) in dependent_captures {
        let name_upper = name.to_ascii_uppercase();
        if required_vars.contains(&name_upper) && !name.eq_ignore_ascii_case("TOKEN") {
            var_args.push(format!("--var {}={}", name, escape_for_shell(value)));
        }
    }

    if var_args.is_empty() { String::new() } else { format!("{} ", var_args.join(" ")) }
}

/// Generate a kingfisher revoke command for an active credential if the rule supports revocation.
///
/// Returns `None` if:
/// - The credential is not active
/// - The rule doesn't have revocation configured
/// - Required data (like AWS AKID) cannot be determined
fn build_revoke_command(
    rule_id: &str,
    revocation: &Revocation,
    snippet: &str,
    dependent_captures: &std::collections::BTreeMap<String, String>,
    akid_from_captures: Option<&str>,
    akid_from_validation_body: Option<&str>,
) -> Option<String> {
    let required_vars = required_vars_for_revocation(revocation);

    let var_args = build_var_args(
        dependent_captures,
        akid_from_captures,
        akid_from_validation_body,
        &required_vars,
    );

    match revocation {
        Revocation::AWS => {
            // AWS needs the access key ID (AKID) in addition to the secret
            // Try to get it from captures first, then from validation response body
            let akid = akid_from_captures.or(akid_from_validation_body)?;
            if akid.is_empty() {
                return None;
            }
            Some(format!(
                "kingfisher revoke --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Revocation::GCP => {
            // GCP revocation uses the service account JSON key (which is the snippet)
            Some(format!(
                "kingfisher revoke --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Revocation::Http(_) => {
            // HTTP-based revocation with dependent variables
            Some(format!(
                "kingfisher revoke --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Revocation::HttpMultiStep(_) => {
            // Multi-step HTTP revocation with dependent variables
            Some(format!(
                "kingfisher revoke --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
    }
}

/// Generate a kingfisher validate command for a finding.
///
/// Returns `None` if the rule doesn't have validation configured or required data is missing.
fn build_validate_command(
    rule_id: &str,
    validation: &crate::rules::Validation,
    snippet: &str,
    dependent_captures: &std::collections::BTreeMap<String, String>,
    akid_from_captures: Option<&str>,
    akid_from_validation_body: Option<&str>,
) -> Option<String> {
    use crate::rules::Validation;

    let required_vars = required_vars_for_validation(validation);

    let var_args = build_var_args(
        dependent_captures,
        akid_from_captures,
        akid_from_validation_body,
        &required_vars,
    );

    match validation {
        Validation::AWS => {
            // AWS needs the access key ID (AKID) in addition to the secret
            let akid = akid_from_captures.or(akid_from_validation_body)?;
            if akid.is_empty() {
                return None;
            }
            Some(format!(
                "kingfisher validate --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Validation::GCP => {
            // GCP validation uses the service account JSON key
            Some(format!(
                "kingfisher validate --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Validation::Http(_) => {
            // HTTP-based validation with dependent variables
            Some(format!(
                "kingfisher validate --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Validation::Grpc(_) => {
            // gRPC-based validation with dependent variables
            Some(format!(
                "kingfisher validate --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Validation::MongoDB
        | Validation::MySQL
        | Validation::Postgres
        | Validation::Jdbc
        | Validation::JWT
        | Validation::AzureStorage
        | Validation::Coinbase
        | Validation::Raw(_) => {
            // These validators with dependent variables
            Some(format!(
                "kingfisher validate --rule {} {}{}",
                rule_id,
                var_args,
                escape_for_shell(snippet)
            ))
        }
    }
}

/// Extract AWS Access Key ID from validation response body if present.
fn extract_akid_from_validation_body(body: &ValidationResponseBody) -> Option<String> {
    static AKID_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?xi)\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b",
        )
        .expect("AKID regex should compile")
    });

    let text = validation_body::clone_as_string(body);
    AKID_RE.find(&text).map(|m| m.as_str().to_string())
}

const BITBUCKET_FRAGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'|');

const AZURE_QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'|');

fn build_git_urls(
    repo_url: &str,
    commit_id: &str,
    file_path: &str,
    line: usize,
) -> (String, String, String) {
    let repo_url = repo_url.trim_end_matches('/');
    let mut repository_url = repo_url.to_string();
    let mut commit_url = format!("{repo_url}/commit/{commit_id}");
    let mut file_url = format!("{repo_url}/blob/{commit_id}/{file_path}#L{line}",);

    if let Ok(parsed) = Url::parse(repo_url) {
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or_default();
        let segments: Vec<&str> = parsed
            .path_segments()
            .map(|segments| segments.filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();

        let format_anchor = |path: &str| {
            let normalized = path.replace('\\', "/");
            utf8_percent_encode(normalized.trim_start_matches('/'), BITBUCKET_FRAGMENT_ENCODE_SET)
                .to_string()
        };

        if host.eq_ignore_ascii_case("bitbucket.org") {
            let joined = segments.join("/");
            let base = if joined.is_empty() {
                format!("{scheme}://{host}")
            } else {
                format!("{scheme}://{host}/{joined}")
            };
            let anchor = format_anchor(file_path);
            repository_url = base.clone();
            commit_url = format!("{base}/commits/{commit_id}");
            file_url = format!("{base}/commits/{commit_id}#L{anchor}F{line}");
        } else if host.contains("bitbucket") {
            if segments.len() >= 3 && segments[0].eq_ignore_ascii_case("scm") {
                let project = segments[1];
                let repo = segments[2];
                let base = format!("{scheme}://{host}/projects/{project}/repos/{repo}");
                let anchor = format_anchor(file_path);
                repository_url = base.clone();
                commit_url = format!("{base}/commits/{commit_id}");
                file_url = format!("{base}/commits/{commit_id}#L{anchor}F{line}");
            }
        } else if host.eq_ignore_ascii_case("dev.azure.com") || host.ends_with(".visualstudio.com")
        {
            let normalized = file_path.replace('\\', "/");
            let trimmed = normalized.trim_start_matches('/');
            let encoded_path = utf8_percent_encode(trimmed, AZURE_QUERY_ENCODE_SET).to_string();
            repository_url = repo_url.to_string();
            commit_url = format!("{repo_url}/commit/{commit_id}");
            if line > 0 {
                file_url =
                    format!("{repo_url}/commit/{commit_id}?path=/{}&line={line}", encoded_path);
            } else {
                file_url = format!("{repo_url}/commit/{commit_id}?path=/{}", encoded_path);
            }
        }
    }

    (repository_url, commit_url, file_url)
}

pub fn run(
    global_args: &GlobalArgs,
    ds: Arc<Mutex<findings_store::FindingsStore>>,
    args: &cli::commands::scan::ScanArgs,
    audit_context: Option<ScanAuditContext>,
) -> Result<()> {
    let writer = args.output_args.get_writer()?;
    run_with_writer(global_args, ds, args, audit_context, writer)
}

/// Same as [`run`], but writes into a caller-provided `Write` instead of
/// constructing one from `args.output_args`. Useful when the caller wants
/// to render into an in-memory buffer first (e.g. so a stdout lock can be
/// held only around the final atomic emit, not around the report's CPU
/// work).
pub fn run_with_writer<W: std::io::Write>(
    global_args: &GlobalArgs,
    ds: Arc<Mutex<findings_store::FindingsStore>>,
    args: &cli::commands::scan::ScanArgs,
    audit_context: Option<ScanAuditContext>,
    writer: W,
) -> Result<()> {
    global_args.use_color(std::io::stdout());
    let stdout_is_tty = std::io::stdout().is_terminal();
    let use_color = stdout_is_tty && !args.output_args.has_output();
    let styles = Styles::new(use_color);

    let ds_clone = Arc::clone(&ds);
    let reporter =
        DetailsReporter { datastore: ds_clone, styles, only_valid: args.only_valid, audit_context };
    reporter.report(args.output_args.format, writer, args)
}
pub struct DetailsReporter {
    pub datastore: Arc<Mutex<findings_store::FindingsStore>>,
    pub styles: Styles,
    pub only_valid: bool,
    pub audit_context: Option<ScanAuditContext>,
}

#[derive(Clone, Debug)]
pub struct ScanAuditContext {
    pub scan_timestamp: Option<String>,
    pub scan_duration_seconds: Option<f64>,
    pub rules_applied: Option<usize>,
    pub successful_validations: Option<usize>,
    pub failed_validations: Option<usize>,
    pub skipped_validations: Option<usize>,
    pub blobs_scanned: Option<u64>,
    pub bytes_scanned: Option<u64>,
    pub running_version: Option<String>,
    pub latest_version: Option<String>,
    pub update_check_status: Option<String>,
}

impl DetailsReporter {
    pub fn extract_git_metadata(
        &self,
        prov: &GitRepoOrigin,
        source_span: &SourceSpan,
    ) -> Option<serde_json::Value> {
        let repo_url = get_repo_url(&prov.repo_path)
            .unwrap_or_else(|_| prov.repo_path.to_string_lossy().to_string().into());
        let repo_url = repo_url.trim_end_matches(".git").to_string();
        if let Some(cs) = &prov.first_commit {
            let cmd = &cs.commit_metadata;
            let commit_id = cmd.commit_id.to_string();
            let (repository_url, commit_url, file_url) =
                build_git_urls(&repo_url, &commit_id, &cs.blob_path, source_span.start.line);
            // let msg =
            //     String::from_utf8_lossy(cmd.message.lines().next().unwrap_or(&[],),).
            // into_owned();

            let atime = cmd
                .committer_timestamp
                .format(gix::date::time::format::SHORT)
                .unwrap_or_else(|_| cmd.committer_timestamp.seconds.to_string());

            let git_metadata = serde_json::json!({
                "repository_url": repository_url,
                "commit": {
                    "id": commit_id,
                    "url": commit_url,
                    "date": atime,
                    "committer": {
                        "name": &cmd.committer_name,
                        "email": &cmd.committer_email,
                    },
                    // "author": {
                    //     "name": String::from_utf8_lossy(&cmd.author_name),
                    //     "email": String::from_utf8_lossy(&cmd.author_email),
                    // },
                    // "message": msg,
                },
                "file": {
                    "path": &cs.blob_path,
                    "url": file_url,
                    "git_command": format!(
                        "git -C {} show {}:{}",
                        prov.repo_path.display(),
                        cmd.commit_id,
                        &cs.blob_path
                    )
                }
            });
            Some(git_metadata)
        } else {
            None
        }
    }

    /// If the given file path corresponds to a Jira issue downloaded to disk,
    /// return the online Jira URL for that issue.
    fn jira_issue_url(
        &self,
        path: &std::path::Path,
        args: &cli::commands::scan::ScanArgs,
    ) -> Option<String> {
        // drop any trailing slash so we don’t end up with “//browse/…”
        let jira_url = args.input_specifier_args.jira_url.as_ref()?.as_str().trim_end_matches('/');

        let ds = self.datastore.lock().ok()?;
        let root = ds.clone_root();
        let jira_dir = root.join("jira_issues");
        if path.starts_with(&jira_dir) {
            let relative = path.strip_prefix(&jira_dir).ok()?;
            let mut components = relative.components();
            let key = if components.clone().count() > 1 {
                components
                    .next()
                    .and_then(|component| component.as_os_str().to_str())
                    .filter(|segment| !segment.is_empty())
                    .map(std::borrow::Cow::from)
            } else {
                None
            }
            .or_else(|| path.file_stem().map(|stem| stem.to_string_lossy()))?;
            Some(format!("{}/browse/{}", jira_url, key))
        } else {
            None
        }
    }

    fn normalized_finding_fingerprint(m: &Match, origin: &OriginSet) -> u64 {
        // EXTERNAL FINGERPRINT: Use get(1).or_else(get(0)) for backward compatibility.
        //
        // This indexing is intentionally different from the internal `validation_dedup_key()`
        // (which uses get(0)) to maintain stable external fingerprints and consistent
        // reporting output. Changing this would break historical baselines and alter
        // finding appearance.
        let finding_value = m
            .groups
            .captures
            .get(1)
            .or_else(|| m.groups.captures.first())
            .map(|capture| capture.raw_value())
            .unwrap_or("");
        let offset_start = m.location.offset_span.start as u64;
        let offset_end = m.location.offset_span.end as u64;
        let has_file = origin.iter().any(|o| matches!(o, Origin::File(_)));
        let has_git = origin.iter().any(|o| matches!(o, Origin::GitRepo(_)));
        let origin_key = if has_file || has_git { "file_git" } else { "ext" };
        compute_finding_fingerprint(finding_value, origin_key, offset_start, offset_end)
    }

    fn origin_set_contains_git(origin: &OriginSet) -> bool {
        origin.iter().any(|o| matches!(o, Origin::GitRepo(_)))
    }

    fn merge_origins_for_dedup(mut existing: ReportMatch, incoming: ReportMatch) -> ReportMatch {
        let existing_has_git = Self::origin_set_contains_git(&existing.origin);
        let incoming_has_git = Self::origin_set_contains_git(&incoming.origin);
        let prefer_git = existing_has_git || incoming_has_git;

        if incoming_has_git && !existing_has_git {
            existing = incoming.clone();
        }

        let mut origins = Vec::new();
        let mut push_unique = |origin: &Origin| {
            if !origins.iter().any(|existing| existing == origin) {
                origins.push(origin.clone());
            }
        };

        for origin in existing.origin.iter().chain(incoming.origin.iter()) {
            push_unique(origin);
        }

        if prefer_git {
            origins.retain(|origin| matches!(origin, Origin::GitRepo(_)));
        }

        if let Some(origin_set) = OriginSet::try_from_iter(origins) {
            existing.origin = origin_set;
        }

        existing
    }

    /// If the given file path corresponds to a Confluence page downloaded to disk,
    /// return the URL for that page.
    fn confluence_page_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.confluence_links().get(path).cloned()
    }

    /// If the given file path corresponds to a Slack message downloaded to disk,
    /// return the permalink for that message.
    fn slack_message_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.slack_links().get(path).cloned()
    }

    fn teams_message_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.teams_links().get(path).cloned()
    }

    fn postman_resource_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.postman_links().get(path).cloned()
    }

    fn repo_artifact_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.repo_links().get(path).cloned()
    }

    fn s3_display_path(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        for (dir, bucket) in ds.s3_buckets().iter() {
            if path.starts_with(dir) {
                let rel = path.strip_prefix(dir).ok()?;
                return Some(format!("s3://{}/{}", bucket, rel.display()));
            }
        }
        None
    }

    fn docker_display_path(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        for (dir, image) in ds.docker_images().iter() {
            if path.starts_with(dir) {
                let rel = path.strip_prefix(dir).ok()?;
                let mut rel_str = rel.display().to_string();
                rel_str = rel_str.replace(".decomp.tar!", ".tar.gz | ");
                rel_str = rel_str.replace(".tar!", ".tar | ");
                rel_str = rel_str.replace('!', " | ");
                return Some(format!("{} | {}", image, rel_str));
            }
        }
        None
    }

    fn process_matches(&self, only_valid: bool, filter_visible: bool) -> Result<Vec<ReportMatch>> {
        let datastore = self.datastore.lock().unwrap();
        Ok(datastore
            .get_matches()
            .iter()
            .filter(|msg| {
                let (_origin, _blob_metadata, match_item) = &***msg;
                if only_valid {
                    // If filter_visible is true, require the match to be visible.
                    if filter_visible {
                        match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                            && match_item.visible
                    } else {
                        // Do not filter by visibility when not needed (for validation)
                        match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                    }
                } else {
                    // When not filtering by only_valid, use visibility if desired.
                    if filter_visible { match_item.visible } else { true }
                }
            })
            .map(|msg| {
                let (origin, blob_metadata, match_item) = &**msg;
                ReportMatch {
                    origin: (**origin).clone(),
                    blob_metadata: (**blob_metadata).clone(),
                    m: match_item.clone(),
                    comment: None,
                    visible: match_item.visible,
                    match_confidence: match_item.rule.confidence(),
                    validation_response_body: match_item.validation_response_body.clone(),
                    validation_response_status: match_item.validation_response_status,
                    validation_success: match_item.validation_success,
                }
            })
            .collect())
    }

    pub fn get_filtered_matches(&self) -> Result<Vec<ReportMatch>> {
        self.process_matches(self.only_valid, true)
    }

    pub fn get_unfiltered_matches(&self, only_valid: Option<bool>) -> Result<Vec<ReportMatch>> {
        self.process_matches(only_valid.unwrap_or(self.only_valid), false)
    }

    pub fn deduplicate_matches(
        &self,
        matches: Vec<ReportMatch>,
        no_dedup: bool,
    ) -> Vec<ReportMatch> {
        if no_dedup {
            return matches;
        }

        use std::collections::HashMap;
        let mut by_fp: HashMap<(u64, String), ReportMatch> = HashMap::new();

        for rm in matches {
            let key = (
                Self::normalized_finding_fingerprint(&rm.m, &rm.origin),
                rm.m.rule.id().to_string(),
            );
            if let Some(existing) = by_fp.get_mut(&key) {
                *existing = Self::merge_origins_for_dedup(existing.clone(), rm);
                continue;
            }
            by_fp.insert(key, rm);
        }
        by_fp.into_values().collect()
    }

    fn matches_for_output(&self, args: &cli::commands::scan::ScanArgs) -> Result<Vec<ReportMatch>> {
        let mut matches = self.get_filtered_matches()?;
        if !args.no_dedup {
            matches = self.deduplicate_matches(matches, args.no_dedup);
        }
        if args.no_dedup {
            let mut expanded = Vec::new();
            for rm in matches {
                if rm.origin.len() > 1 {
                    for origin in rm.origin.iter() {
                        let mut single = rm.clone();
                        single.origin = OriginSet::new(origin.clone(), Vec::new());
                        expanded.push(single);
                    }
                } else {
                    expanded.push(rm);
                }
            }
            matches = expanded;
        }
        matches.sort_by(|a, b| {
            let path_a = a
                .origin
                .first()
                .full_path()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let path_b = b
                .origin
                .first()
                .full_path()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            path_a
                .cmp(&path_b)
                .then_with(|| {
                    a.m.location
                        .resolved_source_span()
                        .start
                        .line
                        .cmp(&b.m.location.resolved_source_span().start.line)
                })
                .then_with(|| {
                    a.m.location
                        .resolved_source_span()
                        .start
                        .column
                        .cmp(&b.m.location.resolved_source_span().start.column)
                })
        });
        Ok(matches)
    }

    pub fn build_finding_record(
        &self,
        rm: &ReportMatch,
        args: &cli::commands::scan::ScanArgs,
    ) -> FindingReporterRecord {
        let source_span = rm.m.location.resolved_source_span();
        let line_num = source_span.start.line;

        // Prefer the named TOKEN capture (when present) for display + validate/revoke commands.
        // This avoids cases like Modal CLI pairs where capture(0) is an ID and TOKEN is the secret.
        let snippet_capture =
            rm.m.groups
                .captures
                .iter()
                .find(|c| c.name.map(|n| n.eq_ignore_ascii_case("TOKEN")).unwrap_or(false))
                .or_else(|| rm.m.groups.captures.first());

        // Get raw snippet value (for revoke/validate command) and display snippet (for output)
        let (raw_snippet, snippet) = if let Some(capture) = snippet_capture {
            let raw = capture.raw_value().to_string();
            let displayed = capture.display_value();
            (raw, Escaped(displayed.as_ref().as_bytes()).to_string())
        } else {
            (String::new(), String::new())
        };

        let validation_status = if rm.validation_success {
            "Active Credential".to_string()
        } else if rm.validation_response_status == StatusCode::PRECONDITION_REQUIRED.as_u16()
            && validation_body::as_str(&rm.validation_response_body)
                .starts_with("(skip list entry)")
        {
            "Canary Token (Skipped)".to_string()
        } else if matches!(
            rm.validation_response_status,
            status if status == StatusCode::CONTINUE.as_u16()
                || status == StatusCode::PRECONDITION_REQUIRED.as_u16()
        ) {
            "Not Attempted".to_string()
        } else {
            "Inactive Credential".to_string()
        };

        let validation_body_str = validation_body::as_str(&rm.validation_response_body);
        let response_body = if args.full_validation_response {
            validation_body_str.to_string()
        } else {
            const MAX_RESPONSE_LENGTH: usize = 512;
            let truncated_body: String =
                validation_body_str.chars().take(MAX_RESPONSE_LENGTH).collect();
            let ellipsis =
                if validation_body_str.chars().count() > MAX_RESPONSE_LENGTH { "..." } else { "" };
            format!("{}{}", truncated_body, ellipsis)
        };

        let git_metadata_val = rm
            .origin
            .iter()
            .filter_map(|origin| {
                if let Origin::GitRepo(e) = origin {
                    self.extract_git_metadata(e, &source_span)
                } else {
                    None
                }
            })
            .next();

        let file_path = rm
            .origin
            .iter()
            .find_map(|origin| self.origin_display_path(origin, args))
            .or_else(|| {
                rm.origin.iter().find_map(|origin| {
                    origin
                        .blob_path()
                        .map(|p| p.display().to_string())
                        .and_then(Self::non_empty_string)
                })
            })
            .or_else(|| self.git_object_fallback_path(rm))
            .unwrap_or_else(|| format!("blob:{}", rm.blob_metadata.id.hex()));

        // Generate validate/revoke commands only if not redacting (they contain the secret)
        let (validate_command, revoke_command) = if args.redact {
            (None, None)
        } else {
            // Try to find AKID from captures (for AWS)
            let akid_from_captures: Option<String> =
                rm.m.groups
                    .captures
                    .iter()
                    .find(|c| c.name == Some("AKID") || c.name == Some("akid"))
                    .map(|c| c.raw_value().to_string());

            // Try to extract AKID from validation response body (fallback for AWS)
            let akid_from_body = extract_akid_from_validation_body(&rm.validation_response_body);

            // Generate validate command for findings with validation support
            let validate_cmd = if let Some(validation) = &rm.m.rule.syntax().validation {
                // Merge dependent captures with named regex captures so the generated command is runnable.
                // (E.g., Modal needs TOKEN_ID, which is a named capture on the same rule.)
                let mut merged_vars = rm.m.dependent_captures.clone();
                for cap in rm.m.groups.captures.iter() {
                    let Some(name) = cap.name else { continue };
                    if name.eq_ignore_ascii_case("TOKEN") {
                        continue;
                    }
                    merged_vars
                        .entry(name.to_uppercase())
                        .or_insert_with(|| cap.raw_value().to_string());
                }

                build_validate_command(
                    rm.m.rule.id(),
                    validation,
                    &raw_snippet,
                    &merged_vars,
                    akid_from_captures.as_deref(),
                    akid_from_body.as_deref(),
                )
            } else {
                None
            };

            // Generate revoke command for active credentials with revocation support
            let revoke_cmd = if rm.validation_success {
                if let Some(revocation) = &rm.m.rule.syntax().revocation {
                    // Merge dependent captures with named regex captures so the generated command is runnable.
                    // (Some rules capture required revocation parameters directly in the match.)
                    let mut merged_vars = rm.m.dependent_captures.clone();
                    for cap in rm.m.groups.captures.iter() {
                        let Some(name) = cap.name else { continue };
                        if name.eq_ignore_ascii_case("TOKEN") {
                            continue;
                        }
                        merged_vars
                            .entry(name.to_uppercase())
                            .or_insert_with(|| cap.raw_value().to_string());
                    }
                    build_revoke_command(
                        rm.m.rule.id(),
                        revocation,
                        &raw_snippet,
                        &merged_vars,
                        akid_from_captures.as_deref(),
                        akid_from_body.as_deref(),
                    )
                } else {
                    None
                }
            } else {
                None
            };

            (validate_cmd, revoke_cmd)
        };

        FindingReporterRecord {
            rule: RuleMetadata {
                name: rm.m.rule.name().to_string(),
                id: rm.m.rule.id().to_string(),
            },
            finding: FindingRecordData {
                snippet,
                fingerprint: rm.m.finding_fingerprint.to_string(),
                confidence: rm.match_confidence.to_string(),
                entropy: format!("{:.2}", rm.m.calculated_entropy),
                validation: ValidationInfo { status: validation_status, response: response_body },
                language: rm
                    .blob_metadata
                    .language
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                line: line_num as u32,
                column_start: source_span.start.column as u32,
                column_end: source_span.end.column as u32,
                path: file_path,
                encoding: if rm.m.is_base64 { Some("base64".to_string()) } else { None },
                git_metadata: git_metadata_val,
                validate_command,
                revoke_command,
            },
        }
    }

    fn origin_display_path(
        &self,
        origin: &Origin,
        args: &cli::commands::scan::ScanArgs,
    ) -> Option<String> {
        match origin {
            Origin::File(e) => self
                .repo_artifact_url(&e.path)
                .and_then(Self::non_empty_string)
                .or_else(|| self.jira_issue_url(&e.path, args).and_then(Self::non_empty_string))
                .or_else(|| self.confluence_page_url(&e.path).and_then(Self::non_empty_string))
                .or_else(|| self.slack_message_url(&e.path).and_then(Self::non_empty_string))
                .or_else(|| self.teams_message_url(&e.path).and_then(Self::non_empty_string))
                .or_else(|| self.postman_resource_url(&e.path).and_then(Self::non_empty_string))
                .or_else(|| self.s3_display_path(&e.path).and_then(Self::non_empty_string))
                .or_else(|| self.docker_display_path(&e.path).and_then(Self::non_empty_string))
                .or_else(|| Self::non_empty_string(e.path.display().to_string())),
            Origin::GitRepo(e) => {
                e.first_commit.as_ref().and_then(|c| Self::non_empty_string(c.blob_path.clone()))
            }
            Origin::Extended(e) => {
                e.path().map(|p| p.display().to_string()).and_then(Self::non_empty_string)
            }
        }
    }

    fn git_object_fallback_path(&self, rm: &ReportMatch) -> Option<String> {
        let blob_hex = rm.blob_metadata.id.hex();
        rm.origin.iter().find_map(|origin| {
            if let Origin::GitRepo(repo_origin) = origin {
                let (prefix, suffix) = blob_hex.split_at(2);
                let repo_path = repo_origin.repo_path.as_ref();
                let git_dir_objects = repo_path.join(".git").join("objects");
                let objects_dir = if git_dir_objects.is_dir() {
                    git_dir_objects
                } else {
                    repo_path.join("objects")
                };
                let fallback_path = objects_dir.join(prefix).join(suffix);
                Self::non_empty_string(fallback_path.display().to_string())
            } else {
                None
            }
        })
    }

    fn non_empty_string(value: String) -> Option<String> {
        if value.trim().is_empty() { None } else { Some(value) }
    }

    pub fn build_finding_records(
        &self,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<Vec<FindingReporterRecord>> {
        let matches = self.matches_for_output(args)?;
        Ok(matches.iter().map(|rm| self.build_finding_record(rm, args)).collect())
    }

    pub fn build_report_envelope(
        &self,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<ReportEnvelope> {
        let findings = self.build_finding_records(args)?;
        let access_map = self.build_access_map_records(args);
        let metadata = self.build_report_metadata(args, &findings, access_map.as_ref());

        Ok(ReportEnvelope { findings, access_map, metadata: Some(metadata) })
    }

    fn build_report_metadata(
        &self,
        args: &cli::commands::scan::ScanArgs,
        findings: &[FindingReporterRecord],
        access_map: Option<&Vec<AccessMapEntry>>,
    ) -> ScanReportMetadata {
        let mut active_findings = 0usize;
        let mut inactive_findings = 0usize;
        let mut unknown_validation_findings = 0usize;

        for record in findings {
            let status = record.finding.validation.status.to_ascii_lowercase();
            if status.contains("inactive") {
                inactive_findings += 1;
            } else if status.contains("active") {
                active_findings += 1;
            } else {
                unknown_validation_findings += 1;
            }
        }

        let command_line_args: Vec<String> = std::env::args().collect();
        let sanitized_command_line_args = sanitize_command_line_args(&command_line_args);
        let scan_timestamp = self.audit_context.as_ref().and_then(|ctx| ctx.scan_timestamp.clone());
        let generated_at = generated_at_for_scan_timezone(scan_timestamp.as_deref());
        let scan_timestamp = scan_timestamp.unwrap_or_else(|| generated_at.clone());

        ScanReportMetadata {
            generated_at: generated_at.clone(),
            scan_timestamp,
            target: derive_scan_target(args),
            command_line_args: sanitized_command_line_args,
            kingfisher_version: self
                .audit_context
                .as_ref()
                .and_then(|ctx| ctx.running_version.clone())
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
            latest_version_available: self
                .audit_context
                .as_ref()
                .and_then(|ctx| ctx.latest_version.clone()),
            update_check_status: self
                .audit_context
                .as_ref()
                .and_then(|ctx| ctx.update_check_status.clone()),
            summary: ScanReportSummary {
                findings: findings.len(),
                active_findings,
                inactive_findings,
                unknown_validation_findings,
                access_map_identities: access_map.map_or(0, Vec::len),
                rules_applied: self.audit_context.as_ref().and_then(|ctx| ctx.rules_applied),
                confidence_level: args.confidence.to_string(),
                custom_rules_used: !args.rules.rules_path.is_empty() || !args.rules.load_builtins,
                successful_validations: self
                    .audit_context
                    .as_ref()
                    .and_then(|ctx| ctx.successful_validations),
                failed_validations: self
                    .audit_context
                    .as_ref()
                    .and_then(|ctx| ctx.failed_validations),
                skipped_validations: self
                    .audit_context
                    .as_ref()
                    .and_then(|ctx| ctx.skipped_validations),
                blobs_scanned: self.audit_context.as_ref().and_then(|ctx| ctx.blobs_scanned),
                bytes_scanned: self.audit_context.as_ref().and_then(|ctx| ctx.bytes_scanned),
                scan_duration_seconds: self
                    .audit_context
                    .as_ref()
                    .and_then(|ctx| ctx.scan_duration_seconds),
            },
        }
    }

    fn build_access_map_records(
        &self,
        args: &cli::commands::scan::ScanArgs,
    ) -> Option<Vec<AccessMapEntry>> {
        if !args.access_map {
            return None;
        }

        let ds = self.datastore.lock().unwrap();
        let raw_results = ds.access_map_results();

        if raw_results.is_empty() {
            return None;
        }

        let mut entries = Vec::new();
        for result in raw_results {
            let account = summarize_account(&result.identity);
            let mut grouped: BTreeMap<Vec<String>, Vec<String>> = BTreeMap::new();

            if result.resources.is_empty() {
                grouped.insert(Vec::new(), vec![result.identity.id.clone()]);
            } else {
                for resource in &result.resources {
                    let resource_name = format_resource(resource);
                    let permissions = normalize_permissions(&result.cloud, &resource.permissions);
                    grouped.entry(permissions).or_default().push(resource_name);
                }
            }

            let mut groups: Vec<AccessMapResourceGroup> = grouped
                .into_iter()
                .map(|(permissions, mut resources)| {
                    resources.sort();
                    AccessMapResourceGroup { resources, permissions }
                })
                .collect();

            groups.sort_by(|a, b| a.resources.cmp(&b.resources));

            let permissions_by_severity =
                if result.permissions.is_empty() { None } else { Some(result.permissions.clone()) };
            let context = AccessIdentityContext::from_summary(&result.identity);

            entries.push(AccessMapEntry {
                provider: result.cloud.clone(),
                account: account.clone(),
                groups,
                token_details: result.token_details.clone(),
                provider_metadata: result.provider_metadata.clone(),
                fingerprint: result.fingerprint.clone(),
                permissions_by_severity,
                context,
            });
        }

        Some(entries)
    }

    fn style_finding_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_finding_heading.apply_to(val)
    }

    fn style_finding_active_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_finding_active_heading.apply_to(val)
    }

    #[expect(dead_code)]
    fn style_rule<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_rule.apply_to(val)
    }

    fn style_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_heading.apply_to(val)
    }

    fn style_match<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_match.apply_to(val)
    }

    fn style_metadata<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_metadata.apply_to(val)
    }

    fn style_active_creds<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_active_creds.apply_to(val)
    }
}

fn normalize_permissions(cloud: &str, permissions: &[String]) -> Vec<String> {
    if cloud.eq_ignore_ascii_case("aws") {
        return Vec::new();
    }

    let mut set = BTreeSet::new();
    for perm in permissions {
        let normalized = perm.trim();
        if !normalized.is_empty() {
            set.insert(normalized.to_string());
        }
    }

    set.into_iter().collect()
}

fn summarize_account(identity: &AccessSummary) -> Option<String> {
    identity
        .account_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| identity.project.clone().filter(|s| !s.trim().is_empty()))
        .or_else(|| identity.tenant.clone().filter(|s| !s.trim().is_empty()))
        .or_else(|| Some(identity.id.clone()).filter(|s| !s.trim().is_empty()))
}

fn format_resource(resource: &ResourceExposure) -> String {
    let name = resource.name.trim();
    if name.is_empty() {
        return resource.resource_type.clone();
    }

    let resource_type = resource.resource_type.trim();
    if resource_type.is_empty() { name.to_string() } else { format!("{}:{}", resource_type, name) }
}
/// A trait for things that can be output as a document.
///
/// This trait is used to factor output-related code, such as friendly handling
/// of buffering, into one place.
pub trait Reportable {
    type Format;
    fn report<W: std::io::Write>(
        &self,
        format: Self::Format,
        writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()>;
}
impl Reportable for DetailsReporter {
    type Format = ReportOutputFormat;

    fn report<W: std::io::Write>(
        &self,
        format: Self::Format,
        writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        match format {
            ReportOutputFormat::Pretty => self.pretty_format(writer, args),
            ReportOutputFormat::Json => self.json_format(writer, args),
            ReportOutputFormat::Jsonl => self.jsonl_format(writer, args),
            ReportOutputFormat::Bson => self.bson_format(writer, args),
            ReportOutputFormat::Toon => self.toon_format(writer, args),
            ReportOutputFormat::Sarif => self.sarif_format(writer, args.no_dedup, args),
            ReportOutputFormat::Html => self.html_format(writer, args),
        }
    }
}

fn generated_at_for_scan_timezone(scan_timestamp: Option<&str>) -> String {
    if let Some(scan_timestamp) = scan_timestamp
        && let Ok(scan_dt) = chrono::DateTime::parse_from_rfc3339(scan_timestamp)
    {
        return Utc::now().with_timezone(scan_dt.offset()).to_rfc3339();
    }
    Local::now().to_rfc3339()
}

fn derive_scan_target(args: &cli::commands::scan::ScanArgs) -> Option<String> {
    let mut targets = Vec::new();
    let input_args = &args.input_specifier_args;

    for path in &input_args.path_inputs {
        targets.push(path.display().to_string());
    }
    for git in &input_args.git_url {
        targets.push(git.to_string());
    }
    if let Some(bucket) = &input_args.s3_bucket {
        targets.push(format!("s3://{bucket}"));
    }
    if let Some(bucket) = &input_args.gcs_bucket {
        targets.push(format!("gcs://{bucket}"));
    }
    for image in &input_args.docker_image {
        targets.push(format!("docker://{image}"));
    }
    for archive in &input_args.docker_archive {
        targets.push(format!("docker-archive://{}", archive.display()));
    }
    if input_args.jira_url.is_some() {
        targets.push("jira".to_string());
    }
    if input_args.confluence_url.is_some() {
        targets.push("confluence".to_string());
    }
    if input_args.slack_query.is_some() {
        targets.push("slack".to_string());
    }

    if targets.is_empty() {
        return None;
    }
    if targets.len() == 1 {
        return targets.pop();
    }
    Some(format!("{} targets", targets.len()))
}

/// A match produced by one of kingfisher's rules.
/// This corresponds to a single location.
#[derive(Serialize, JsonSchema, Clone)]
pub struct ReportMatch {
    pub origin: OriginSet,

    #[serde(rename = "blob_metadata")]
    pub blob_metadata: BlobMetadata,

    #[serde(flatten)]
    pub m: Match,

    /// An optional comment assigned to the match
    pub comment: Option<String>,

    /// The confidence level of the match
    pub match_confidence: Confidence,

    /// Whether the match is visible in the output
    pub visible: bool,

    /// Validation Body
    #[serde(
        default,
        serialize_with = "validation_body::serialize",
        deserialize_with = "validation_body::deserialize"
    )]
    #[schemars(schema_with = "validation_body::schema")]
    pub validation_response_body: ValidationResponseBody,

    /// Validation Status Code
    pub validation_response_status: u16,

    /// Validation Success
    pub validation_success: bool,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct FindingReporterRecord {
    pub rule: RuleMetadata,
    pub finding: FindingRecordData,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct AccessMapEntry {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub groups: Vec<AccessMapResourceGroup>,
    #[serde(default)]
    pub token_details: Option<AccessTokenDetails>,
    #[serde(default)]
    pub provider_metadata: Option<ProviderMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Permissions classified by severity (admin / privilege_escalation / risky / read_only).
    /// Same shape as PermissionSummary; aggregated across all groups for this identity.
    /// Absent when the underlying provider didn't classify (e.g., imported reports).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_by_severity: Option<PermissionSummary>,
    /// Discriminator context to tell duplicate-named identities apart in the UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<AccessIdentityContext>,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct AccessMapResourceGroup {
    pub resources: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
}

/// Optional identity context (project, tenant, account, host) used by the
/// viewer to disambiguate duplicate-named identities.
#[derive(Serialize, JsonSchema, Clone, Debug, Default)]
pub struct AccessIdentityContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_type: Option<String>,
}

impl AccessIdentityContext {
    fn from_summary(identity: &AccessSummary) -> Option<Self> {
        let project = identity.project.clone().filter(|s| !s.trim().is_empty());
        let tenant = identity.tenant.clone().filter(|s| !s.trim().is_empty());
        let account_id = identity.account_id.clone().filter(|s| !s.trim().is_empty());
        let id = identity.id.clone();
        let identity_id = if id.trim().is_empty() { None } else { Some(id) };
        let access_type = if identity.access_type.trim().is_empty() {
            None
        } else {
            Some(identity.access_type.clone())
        };

        if project.is_none()
            && tenant.is_none()
            && account_id.is_none()
            && identity_id.is_none()
            && access_type.is_none()
        {
            return None;
        }

        Some(Self { project, tenant, account_id, identity_id, access_type })
    }
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct ReportEnvelope {
    pub findings: Vec<FindingReporterRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_map: Option<Vec<AccessMapEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ScanReportMetadata>,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct ScanReportMetadata {
    pub generated_at: String,
    pub scan_timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub command_line_args: Vec<String>,
    pub kingfisher_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_version_available: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_check_status: Option<String>,
    pub summary: ScanReportSummary,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct ScanReportSummary {
    pub findings: usize,
    pub active_findings: usize,
    pub inactive_findings: usize,
    pub unknown_validation_findings: usize,
    pub access_map_identities: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_applied: Option<usize>,
    pub confidence_level: String,
    pub custom_rules_used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successful_validations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_validations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_validations: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blobs_scanned: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_scanned: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_duration_seconds: Option<f64>,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct RuleMetadata {
    pub name: String,
    pub id: String,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct ValidationInfo {
    pub status: String,
    pub response: String,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct FindingRecordData {
    pub snippet: String,
    pub fingerprint: String,
    pub confidence: String,
    pub entropy: String,
    pub validation: ValidationInfo,
    pub language: String,
    pub line: u32,
    pub column_start: u32,
    pub column_end: u32,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validate_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_command: Option<String>,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::{
        blob::{BlobId, BlobMetadata},
        cli::commands::inputs::{ContentFilteringArgs, InputSpecifierArgs},
        cli::commands::output::OutputArgs,
        cli::commands::scan::{ConfidenceLevel, ScanArgs},
        cli::commands::{
            azure::AzureRepoType,
            bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
            gitea::GiteaRepoType,
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            gitlab::GitLabRepoType,
            rules::{RuleCacheArgs, RuleSpecifierArgs},
        },
        git_commit_metadata::CommitMetadata,
        location::{Location, OffsetSpan, SourcePoint, SourceSpan},
        matcher::{SerializableCapture, SerializableCaptures},
        origin::{Origin, OriginSet},
        rules::rule::{Confidence, Rule, RuleSyntax},
    };
    use gix::{ObjectId, date::Time};
    use smallvec::SmallVec;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn build_var_args_ignores_unrequired_named_captures() {
        let dependent = BTreeMap::from([
            ("BODY".to_string(), "payload-part".to_string()),
            ("CHECKSUM".to_string(), "abc123".to_string()),
        ]);
        let required = BTreeSet::from(["TOKEN".to_string()]);

        let args = build_var_args(&dependent, None, None, &required);
        assert_eq!(args, "");
    }

    #[test]
    fn build_validate_command_omits_body_checksum_vars_for_vercel_like_http_rule() {
        let validation = crate::rules::Validation::Http(crate::rules::HttpValidation {
            request: crate::rules::HttpRequest {
                method: "GET".to_string(),
                url: "https://api.vercel.com/v2/user".to_string(),
                headers: BTreeMap::from([(
                    "Authorization".to_string(),
                    "Bearer {{TOKEN}}".to_string(),
                )]),
                body: None,
                response_matcher: None,
                multipart: None,
                response_is_html: false,
            },
            multipart: None,
        });
        let dependent = BTreeMap::from([
            ("BODY".to_string(), "payload-part".to_string()),
            ("CHECKSUM".to_string(), "abc123".to_string()),
        ]);

        let cmd = build_validate_command(
            "kingfisher.vercel.1",
            &validation,
            "vcp_testtoken",
            &dependent,
            None,
            None,
        )
        .expect("validate command should be generated");

        assert!(!cmd.contains("--var BODY="), "command should not include BODY var: {}", cmd);
        assert!(
            !cmd.contains("--var CHECKSUM="),
            "command should not include CHECKSUM var: {}",
            cmd
        );
        assert!(cmd.contains("kingfisher validate --rule kingfisher.vercel.1"));
    }

    #[test]
    fn extract_template_vars_includes_filter_argument_vars() {
        let text = "Basic {{ NEXT_PUBLIC_VERCEL_APP_CLIENT_ID | default: VERCEL_APP_CLIENT_ID | append: ':' | append: VERCEL_APP_CLIENT_SECRET | b64enc }}";
        let vars = extract_template_vars(text);

        assert!(vars.contains("NEXT_PUBLIC_VERCEL_APP_CLIENT_ID"));
        assert!(vars.contains("VERCEL_APP_CLIENT_ID"));
        assert!(vars.contains("VERCEL_APP_CLIENT_SECRET"));
        assert!(!vars.contains("APPEND"));
        assert!(!vars.contains("DEFAULT"));
        assert!(!vars.contains("B64ENC"));
    }

    #[test]
    fn build_revoke_command_is_emitted_when_required_vars_missing() {
        // Revocation template requires ACCOUNTIDENTIFIER, but the finding doesn't have it.
        let revocation = Revocation::Http(crate::rules::HttpValidation {
            request: crate::rules::HttpRequest {
                method: "DELETE".to_string(),
                url: "https://example.com/revoke?accountIdentifier={{ ACCOUNTIDENTIFIER }}&token={{ TOKEN }}"
                    .to_string(),
                headers: BTreeMap::new(),
                body: None,
                response_matcher: None,
                multipart: None,
                response_is_html: false,
            },
            multipart: None,
        });

        let cmd = build_revoke_command(
            "kingfisher.example.1",
            &revocation,
            "secret",
            &BTreeMap::new(),
            None,
            None,
        );

        let cmd = cmd.expect("command should still be emitted when vars are missing");
        assert!(cmd.contains("kingfisher revoke --rule kingfisher.example.1"));
        assert!(cmd.contains("'secret'"));
    }

    fn sample_scan_args() -> ScanArgs {
        ScanArgs {
            num_jobs: 1,
            rules: RuleSpecifierArgs::default(),
            rule_cache: RuleCacheArgs::default(),
            input_specifier_args: InputSpecifierArgs {
                path_inputs: Vec::new(),
                git_url: Vec::new(),
                git_clone_dir: None,
                keep_clones: false,
                repo_clone_limit: None,
                include_contributors: false,
                github_user: Vec::new(),
                github_organization: Vec::new(),
                github_exclude: Vec::new(),
                all_github_organizations: false,
                github_api_url: Url::parse("https://api.github.com/").unwrap(),
                github_repo_type: GitHubRepoType::Source,
                gitlab_user: Vec::new(),
                gitlab_group: Vec::new(),
                gitlab_exclude: Vec::new(),
                all_gitlab_groups: false,
                gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
                gitlab_repo_type: GitLabRepoType::All,
                gitlab_include_subgroups: false,
                huggingface_user: Vec::new(),
                huggingface_organization: Vec::new(),
                huggingface_model: Vec::new(),
                huggingface_dataset: Vec::new(),
                huggingface_space: Vec::new(),
                huggingface_exclude: Vec::new(),
                gitea_user: Vec::new(),
                gitea_organization: Vec::new(),
                gitea_exclude: Vec::new(),
                all_gitea_organizations: false,
                gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
                gitea_repo_type: GiteaRepoType::Source,
                bitbucket_user: Vec::new(),
                bitbucket_workspace: Vec::new(),
                bitbucket_project: Vec::new(),
                bitbucket_exclude: Vec::new(),
                all_bitbucket_workspaces: false,
                bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/").unwrap(),
                bitbucket_repo_type: BitbucketRepoType::Source,
                bitbucket_auth: BitbucketAuthArgs::default(),
                azure_organization: Vec::new(),
                azure_project: Vec::new(),
                azure_exclude: Vec::new(),
                all_azure_projects: false,
                azure_base_url: Url::parse("https://dev.azure.com/").unwrap(),
                azure_repo_type: AzureRepoType::Source,
                jira_url: None,
                jql: None,
                jira_include_comments: false,
                jira_include_changelog: false,
                confluence_url: None,
                cql: None,
                slack_query: None,
                slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
                teams_query: None,
                teams_api_url: Url::parse("https://graph.microsoft.com/").unwrap(),
                postman_workspaces: Vec::new(),
                postman_collections: Vec::new(),
                postman_environments: Vec::new(),
                postman_all: false,
                postman_include_mocks_monitors: false,
                postman_api_url: Url::parse("https://api.getpostman.com/").unwrap(),
                max_results: 100,
                s3_bucket: None,
                s3_prefix: None,
                role_arn: None,
                aws_local_profile: None,
                gcs_bucket: None,
                gcs_prefix: None,
                gcs_service_account: None,
                docker_image: Vec::new(),
                docker_archive: Vec::new(),
                git_clone: GitCloneMode::Bare,
                git_history: GitHistoryMode::Full,
                commit_metadata: true,
                repo_artifacts: false,
                scan_nested_repos: true,
                since_commit: None,
                branch: None,
                branch_root: false,
                branch_root_commit: None,
                staged: false,
            },
            extra_ignore_comments: Vec::new(),
            content_filtering_args: ContentFilteringArgs {
                max_file_size_mb: 256.0,
                exclude: Vec::new(),
                no_extract_archives: false,
                extraction_depth: 2,
                no_binary: false,
            },
            confidence: ConfidenceLevel::Medium,
            no_validate: false,
            access_map: false,
            only_valid: false,
            min_entropy: None,
            rule_stats: false,
            no_dedup: false,
            view_report: false,
            redact: false,
            no_base64: false,
            turbo: false,
            git_repo_timeout: 1_800,
            output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
            baseline_file: None,
            manage_baseline: false,
            skip_regex: Vec::new(),
            skip_word: Vec::new(),
            skip_aws_account: Vec::new(),
            skip_aws_account_file: None,
            no_inline_ignore: false,
            no_ignore_if_contains: false,
            view_report_port: 7890,
            view_report_address: "127.0.0.1".to_string(),
            validation_timeout: 10,
            validation_retries: 1,
            validation_rps: None,
            validation_rps_rule: Vec::new(),
            full_validation_response: false,
            max_validation_response_length: 2048,
            alert_webhook: Vec::new(),
            alert_format: None,
            alert_on: crate::alerts::AlertOn::Findings,
            alert_min_confidence: cli::commands::scan::ConfidenceLevel::Medium,
            alert_include_secret: false,
            alert_report_url: None,
            alert_detail: crate::alerts::AlertDetail::Auto,
            config_webhook_overrides: Vec::new(),
        }
    }

    fn sample_report_match(
        validation_body: &str,
        validation_status: u16,
        validation_success: bool,
    ) -> (ReportMatch, String) {
        let repo_path = Arc::new(PathBuf::from("/tmp/repo"));
        let commit_metadata = Arc::new(CommitMetadata {
            commit_id: ObjectId::from_hex(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            committer_name: "Alice".into(),
            committer_email: "alice@exmple.com".into(),
            committer_timestamp: Time::new(0, 0),
        });
        let blob_path = "path/in/history.txt".to_string();
        let origin = OriginSet::new(
            Origin::from_git_repo_with_first_commit(repo_path, commit_metadata, blob_path.clone()),
            vec![],
        );

        let rule = Arc::new(Rule::new(RuleSyntax {
            name: "Test Rule".into(),
            id: "test.rule".into(),
            pattern: ".*".into(),
            min_entropy: 0.0,
            confidence: Confidence::Medium,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
        }));

        let blob_id = BlobId::new(b"blob-data");
        let validation_body_stored = validation_body::from_string(validation_body);
        let report_match = ReportMatch {
            origin,
            blob_metadata: BlobMetadata {
                id: blob_id,
                num_bytes: 42,
                mime_essence: None,
                language: Some("Unknown".into()),
            },
            m: Match {
                location: Location::with_source_span(
                    OffsetSpan { start: 0, end: 10 },
                    Some(SourceSpan {
                        start: SourcePoint { line: 19, column: 0 },
                        end: SourcePoint { line: 19, column: 10 },
                    }),
                ),
                groups: SerializableCaptures {
                    captures: SmallVec::<[SerializableCapture; 2]>::new(),
                },
                blob_id,
                finding_fingerprint: 123,
                rule: Arc::clone(&rule),
                validation_response_body: validation_body_stored.clone(),
                validation_response_status: validation_status,
                validation_success,
                calculated_entropy: 5.29,
                visible: true,
                is_base64: false,
                dependent_captures: std::collections::BTreeMap::new(),
            },
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: validation_body_stored,
            validation_response_status: validation_status,
            validation_success,
        };

        (report_match, blob_path)
    }

    fn build_validation_response(validation_body: &str, full_response: bool) -> String {
        let temp = tempdir().unwrap();
        let datastore =
            Arc::new(Mutex::new(findings_store::FindingsStore::new(temp.path().to_path_buf())));
        let reporter = DetailsReporter {
            datastore,
            styles: Styles::new(false),
            only_valid: false,
            audit_context: None,
        };

        let (report_match, _) = sample_report_match(validation_body, StatusCode::OK.as_u16(), true);
        let mut scan_args = sample_scan_args();
        scan_args.full_validation_response = full_response;

        let record = reporter.build_finding_record(&report_match, &scan_args);
        record.finding.validation.response
    }

    #[test]
    fn build_finding_record_uses_git_blob_path() {
        let temp = tempdir().unwrap();
        let datastore =
            Arc::new(Mutex::new(findings_store::FindingsStore::new(temp.path().to_path_buf())));
        let reporter = DetailsReporter {
            datastore,
            styles: Styles::new(false),
            only_valid: false,
            audit_context: None,
        };

        let (report_match, blob_path) =
            sample_report_match("Bad credentials", StatusCode::UNAUTHORIZED.as_u16(), false);

        let scan_args = sample_scan_args();

        let record = reporter.build_finding_record(&report_match, &scan_args);
        assert_eq!(record.finding.path, blob_path);
        let git_file_path = record
            .finding
            .git_metadata
            .as_ref()
            .and_then(|git| git.get("file"))
            .and_then(|file| file.get("path"))
            .and_then(|path| path.as_str())
            .unwrap();
        assert_eq!(git_file_path, "path/in/history.txt");
    }

    #[test]
    fn skip_list_matches_surface_skip_reason() {
        let temp = tempdir().unwrap();
        let datastore =
            Arc::new(Mutex::new(findings_store::FindingsStore::new(temp.path().to_path_buf())));
        let reporter = DetailsReporter {
            datastore,
            styles: Styles::new(false),
            only_valid: false,
            audit_context: None,
        };

        let (report_match, _) = sample_report_match(
            "(skip list entry) AWS validation not attempted for account 111122223333.",
            StatusCode::PRECONDITION_REQUIRED.as_u16(),
            false,
        );
        let scan_args = sample_scan_args();

        let record = reporter.build_finding_record(&report_match, &scan_args);
        assert_eq!(record.finding.validation.status, "Canary Token (Skipped)");
        assert_eq!(
            record.finding.validation.response,
            "(skip list entry) AWS validation not attempted for account 111122223333."
        );
    }

    #[test]
    fn validation_response_truncates_when_flag_off() {
        let body = "a".repeat(513);
        let response = build_validation_response(&body, false);
        assert_eq!(response, format!("{}...", "a".repeat(512)));
    }

    #[test]
    fn validation_response_full_when_flag_on() {
        let body = "a".repeat(513);
        let response = build_validation_response(&body, true);
        assert_eq!(response, body);
    }

    #[test]
    fn validation_response_truncation_counts_chars() {
        let body = "é".repeat(513);
        let response = build_validation_response(&body, false);

        assert!(response.ends_with("..."));
        assert_eq!(response.chars().count(), 515);
        assert!(response.chars().take(512).all(|ch| ch == 'é'));
    }

    #[test]
    fn sanitize_command_line_args_redacts_secret_values() {
        let input = vec![
            "kingfisher".to_string(),
            "scan".to_string(),
            "--token".to_string(),
            "abcd".to_string(),
            "--output=report.html".to_string(),
            "--arg=TOP_SECRET".to_string(),
            "--var".to_string(),
            "TOKEN=inline".to_string(),
            "--path".to_string(),
            "./repo".to_string(),
        ];
        let sanitized = sanitize_command_line_args(&input);

        assert_eq!(sanitized[2], "--token");
        assert_eq!(sanitized[3], "***REDACTED***");
        assert_eq!(sanitized[4], "--output=report.html");
        assert_eq!(sanitized[5], "--arg=***REDACTED***");
        assert_eq!(sanitized[6], "--var");
        assert_eq!(sanitized[7], "***REDACTED***");
    }

    #[test]
    fn report_envelope_contains_audit_metadata() {
        let temp = tempdir().unwrap();
        let datastore =
            Arc::new(Mutex::new(findings_store::FindingsStore::new(temp.path().to_path_buf())));
        let reporter = DetailsReporter {
            datastore,
            styles: Styles::new(false),
            only_valid: false,
            audit_context: None,
        };

        let mut args = sample_scan_args();
        args.input_specifier_args.path_inputs.push(PathBuf::from("/tmp/project"));

        let envelope = reporter.build_report_envelope(&args).expect("build envelope");
        let metadata = envelope.metadata.expect("metadata should be present");

        assert_eq!(metadata.summary.findings, 0);
        assert_eq!(metadata.summary.active_findings, 0);
        assert_eq!(metadata.summary.inactive_findings, 0);
        assert_eq!(metadata.summary.access_map_identities, 0);
        assert_eq!(metadata.target.as_deref(), Some("/tmp/project"));
        assert_eq!(metadata.kingfisher_version, env!("CARGO_PKG_VERSION"));
    }

    use super::build_git_urls;

    #[test]
    fn azure_commit_links_use_query_paths() {
        let (repo_url, commit_url, file_url) = build_git_urls(
            "https://dev.azure.com/org/project/_git/repo",
            "0123456789abcdef",
            "dir/file.txt",
            7,
        );

        assert_eq!(repo_url, "https://dev.azure.com/org/project/_git/repo");
        assert_eq!(
            commit_url,
            "https://dev.azure.com/org/project/_git/repo/commit/0123456789abcdef"
        );
        assert_eq!(
            file_url,
            "https://dev.azure.com/org/project/_git/repo/commit/0123456789abcdef?path=/dir/file.txt&line=7"
        );
    }
}

impl From<finding_data::FindingDataEntry> for ReportMatch {
    fn from(e: finding_data::FindingDataEntry) -> Self {
        ReportMatch {
            origin: e.origin,
            blob_metadata: e.blob_metadata,
            m: e.match_val,
            comment: e.match_comment,
            visible: e.visible,
            match_confidence: e.match_confidence,
            validation_response_body: e.validation_response_body.clone(),
            validation_response_status: e.validation_response_status,
            validation_success: e.validation_success,
        }
    }
}
