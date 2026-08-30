use std::{collections::HashSet, env, time::Duration};

use anyhow::{Context, Result, anyhow};
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use reqwest::{StatusCode, Url, header::LINK};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use tracing::{debug, warn};

use crate::{git_url::GitUrl, validation::GLOBAL_USER_AGENT};

const HUGGINGFACE_ENDPOINT: &str = "https://huggingface.co/";
const HUGGINGFACE_API: &str = "https://huggingface.co/api/";
const HUGGINGFACE_PATH_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC.remove(b'/');

#[derive(Debug, Clone, Default)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub organization: Vec<String>,
    pub model: Vec<String>,
    pub dataset: Vec<String>,
    pub space: Vec<String>,
    pub bucket: Vec<String>,
    pub exclude: Vec<String>,
}

impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty()
            && self.organization.is_empty()
            && self.model.is_empty()
            && self.dataset.is_empty()
            && self.space.is_empty()
            && self.bucket.is_empty()
    }
}

#[derive(Clone, Default)]
pub struct AuthConfig {
    token: Option<String>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field(
                "token",
                &self
                    .token
                    .as_ref()
                    .map(|token| format!("{}…", token.chars().take(4).collect::<String>())),
            )
            .finish()
    }
}

impl AuthConfig {
    pub fn from_env() -> Self {
        let token = env::var("KF_HUGGINGFACE_TOKEN").ok().filter(|t| !t.trim().is_empty());
        Self { token }
    }

    pub(crate) fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.token { request.bearer_auth(token) } else { request }
    }

    pub(crate) fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum ResourceKind {
    Model,
    Dataset,
    Space,
    Bucket,
}

impl ResourceKind {
    fn api_path(self) -> &'static str {
        match self {
            ResourceKind::Model => "models",
            ResourceKind::Dataset => "datasets",
            ResourceKind::Space => "spaces",
            ResourceKind::Bucket => "buckets",
        }
    }

    fn git_url(self, slug: &str) -> Option<String> {
        match self {
            ResourceKind::Model => Some(format!("https://huggingface.co/{slug}.git")),
            ResourceKind::Dataset => Some(format!("https://huggingface.co/datasets/{slug}.git")),
            ResourceKind::Space => Some(format!("https://huggingface.co/spaces/{slug}.git")),
            ResourceKind::Bucket => None,
        }
    }

    fn canonical_prefix(self) -> &'static str {
        match self {
            ResourceKind::Model => "model",
            ResourceKind::Dataset => "dataset",
            ResourceKind::Space => "space",
            ResourceKind::Bucket => "bucket",
        }
    }

    fn display_name_singular(self) -> &'static str {
        match self {
            ResourceKind::Model => "model",
            ResourceKind::Dataset => "dataset",
            ResourceKind::Space => "space",
            ResourceKind::Bucket => "bucket",
        }
    }

    fn display_name_plural(self) -> &'static str {
        match self {
            ResourceKind::Model => "models",
            ResourceKind::Dataset => "datasets",
            ResourceKind::Space => "spaces",
            ResourceKind::Bucket => "buckets",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct ResourceRef {
    kind: ResourceKind,
    slug: String,
}

impl ResourceRef {
    fn new(kind: ResourceKind, slug: String) -> Self {
        Self { kind, slug }
    }

    fn canonical_key(&self) -> String {
        format!("{}:{}", self.kind.canonical_prefix(), self.slug.to_lowercase())
    }

    fn git_url(&self) -> Option<String> {
        self.kind.git_url(&self.slug)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct BucketTarget {
    bucket_id: String,
    prefix: Option<String>,
}

impl BucketTarget {
    fn new(bucket_id: String, prefix: Option<String>) -> Self {
        Self { bucket_id, prefix: prefix.filter(|prefix| !prefix.is_empty()) }
    }

    pub fn bucket_id(&self) -> &str {
        &self.bucket_id
    }

    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    pub fn uri(&self) -> String {
        match &self.prefix {
            Some(prefix) => format!("hf://buckets/{}/{prefix}", self.bucket_id),
            None => format!("hf://buckets/{}", self.bucket_id),
        }
    }

    pub fn object_uri(&self, path: &str) -> String {
        format!("hf://buckets/{}/{}", self.bucket_id, path.trim_start_matches('/'))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct BucketInfo {
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct BucketTreeEntry {
    #[serde(rename = "type")]
    entry_type: String,
    path: String,
    #[serde(default)]
    size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HuggingFaceItem {
    Id {
        id: String,
    },
    ModelId {
        #[serde(rename = "modelId")]
        model_id: String,
    },
}

impl HuggingFaceItem {
    fn into_identifier(self) -> String {
        match self {
            HuggingFaceItem::Id { id } => id,
            HuggingFaceItem::ModelId { model_id } => model_id,
        }
    }
}

#[derive(Default)]
struct ExcludeSet {
    typed: HashSet<String>,
    untyped: HashSet<String>,
}

impl ExcludeSet {
    fn from_list(values: &[String]) -> Self {
        let mut typed = HashSet::new();
        let mut untyped = HashSet::new();
        for raw in values {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((prefix, rest)) = trimmed.split_once(':') {
                match normalize_kind(prefix) {
                    Some(kind) => {
                        if let Some(slug) = parse_slug_for_kind(kind, rest) {
                            typed.insert(format!(
                                "{}:{}",
                                kind.canonical_prefix(),
                                slug.to_lowercase()
                            ));
                        } else {
                            warn!(
                                "Ignoring invalid Hugging Face exclusion '{raw}' (expected owner/name)"
                            );
                        }
                    }
                    None => warn!("Ignoring invalid Hugging Face exclusion '{raw}' (unknown type)"),
                }
            } else if let Some(slug) = normalize_untyped_slug(trimmed) {
                untyped.insert(slug);
            } else {
                warn!("Ignoring invalid Hugging Face exclusion '{raw}' (expected owner/name)");
            }
        }
        Self { typed, untyped }
    }

    fn should_exclude(&self, kind: ResourceKind, slug: &str) -> bool {
        let typed_key = format!("{}:{}", kind.canonical_prefix(), slug.to_lowercase());
        if self.typed.contains(&typed_key) {
            return true;
        }
        self.untyped.contains(&slug.to_lowercase())
    }
}

fn normalize_kind(raw: &str) -> Option<ResourceKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "model" | "models" => Some(ResourceKind::Model),
        "dataset" | "datasets" => Some(ResourceKind::Dataset),
        "space" | "spaces" => Some(ResourceKind::Space),
        "bucket" | "buckets" => Some(ResourceKind::Bucket),
        _ => None,
    }
}

fn normalize_untyped_slug(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let segments: Vec<&str> = trimmed.split('/').filter(|segment| !segment.is_empty()).collect();
    normalize_untyped_segments(&segments)
}

fn normalize_untyped_segments(segments: &[&str]) -> Option<String> {
    if segments.is_empty() {
        return None;
    }
    let mut parts: Vec<&str> = segments.to_vec();
    if let Some(first) = parts.first() {
        let lowered = first.trim().to_ascii_lowercase();
        if matches!(
            lowered.as_str(),
            "models" | "model" | "datasets" | "dataset" | "spaces" | "space" | "buckets" | "bucket"
        ) {
            parts.remove(0);
        }
    }
    if parts.len() < 2 {
        return None;
    }
    let owner = parts[0].trim();
    let binding = parts[1..].join("/");
    let name = binding.trim_end_matches(".git").trim();

    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some(format!("{}/{}", owner, name).to_lowercase())
}

fn parse_slug_for_kind(kind: ResourceKind, raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let url = Url::parse(trimmed).ok()?;
        let segments: Vec<&str> = url
            .path_segments()
            .map(|segments| segments.filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        return parse_slug_segments(kind, &segments);
    }
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    parse_slug_segments(kind, &segments)
}

fn parse_slug_segments(kind: ResourceKind, segments: &[&str]) -> Option<String> {
    if segments.is_empty() {
        return None;
    }
    let mut parts: Vec<&str> = segments.to_vec();
    if let Some(first) = parts.first() {
        let lowered = first.trim().to_ascii_lowercase();
        let should_trim = match kind {
            ResourceKind::Model => matches!(lowered.as_str(), "models" | "model"),
            ResourceKind::Dataset => matches!(lowered.as_str(), "datasets" | "dataset"),
            ResourceKind::Space => matches!(lowered.as_str(), "spaces" | "space"),
            ResourceKind::Bucket => matches!(lowered.as_str(), "buckets" | "bucket"),
        };
        if should_trim {
            parts.remove(0);
        }
    }
    if parts.len() < 2 {
        return None;
    }
    let owner = parts[0].trim();
    let binding = parts[1..].join("/");
    let name = binding.trim_end_matches(".git").trim();

    if owner.is_empty() || name.is_empty() {
        return None;
    }
    Some(format!("{owner}/{name}"))
}

fn parse_bucket_target(raw: &str) -> Option<BucketTarget> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (segments, strip_web_route) = if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("hf://")
    {
        let url = Url::parse(trimmed).ok()?;
        let mut segments: Vec<String> = url
            .path_segments()
            .map(|segments| {
                segments
                    .filter(|segment| !segment.is_empty())
                    .map(|segment| percent_decode_str(segment).decode_utf8_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();

        if url.scheme() == "hf" {
            if url.host_str() != Some("buckets") {
                return None;
            }
            (segments, false)
        } else if matches!(
            url.host_str().map(|host| host.to_ascii_lowercase()),
            Some(host) if matches!(host.as_str(), "huggingface.co" | "www.huggingface.co" | "hf.co")
        ) && segments.first().map(String::as_str) == Some("buckets")
        {
            segments.remove(0);
            (segments, true)
        } else {
            return None;
        }
    } else {
        let mut segments: Vec<String> = trimmed
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(ToString::to_string)
            .collect();
        if matches!(segments.first().map(String::as_str), Some("bucket" | "buckets")) {
            segments.remove(0);
        }
        (segments, false)
    };

    if segments.len() < 2 {
        return None;
    }

    let bucket_id = format!("{}/{}", segments[0], segments[1]);
    let mut prefix_parts = segments[2..].to_vec();
    // Browser URLs insert a route marker between the bucket ID and object path. In an hf:// URI
    // or a plain bucket handle, these are valid object-directory names and must be preserved.
    if strip_web_route
        && matches!(prefix_parts.first().map(String::as_str), Some("tree" | "blob" | "resolve"))
    {
        prefix_parts.remove(0);
    }
    let prefix = if prefix_parts.is_empty() { None } else { Some(prefix_parts.join("/")) };
    Some(BucketTarget::new(bucket_id, prefix))
}

fn parse_next_link(value: &str) -> Option<Url> {
    value.split(',').find_map(|part| {
        let part = part.trim();
        let (url_part, params) = part.split_once('>')?;
        if params.contains("rel=\"next\"") {
            let url = url_part.trim_start_matches('<').trim();
            Url::parse(url).ok()
        } else {
            None
        }
    })
}

const BODY_SNIPPET_LIMIT: usize = 200;

async fn fetch_paginated<T>(
    client: &reqwest::Client,
    mut current_url: Url,
    auth: &AuthConfig,
    context: &str,
) -> Result<Vec<T>>
where
    T: DeserializeOwned,
{
    let mut items = Vec::new();
    loop {
        let mut request =
            client.get(current_url.clone()).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        request = auth.apply(request);
        let response = request.send().await?;
        let status = response.status();
        let link_header = response
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            let mut message = format!(
                "Hugging Face API request failed while enumerating {context} ({status}): {body}"
            );
            if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
                && !auth.has_token()
            {
                message.push_str(
                    "\nProvide a Hugging Face access token via the KF_HUGGINGFACE_TOKEN environment variable.",
                );
            }
            return Err(anyhow!(message));
        }
        let body = response.bytes().await?;
        let value: Value = serde_json::from_slice(&body).map_err(|err| {
            let snippet = body_snippet(&body);
            anyhow!(
                "Failed to parse Hugging Face response while enumerating {context}: {err}. Body snippet: {snippet}",
                context = context,
                err = err,
                snippet = snippet
            )
        })?;

        let array = value.as_array().ok_or_else(|| {
            let snippet = body_snippet(&body);
            anyhow!(
                "Unexpected Hugging Face response format while enumerating {context} (expected array). Body snippet: {snippet}",
                context = context,
                snippet = snippet
            )
        })?;

        let mut page = Vec::new();
        for (index, element) in array.iter().enumerate() {
            match serde_json::from_value::<T>(element.clone()) {
                Ok(item) => page.push(item),
                Err(err) => {
                    let snippet = value_snippet(element);
                    warn!(
                        "Skipping Hugging Face item at index {index} while enumerating {context}: {err}. Item snippet: {snippet}"
                    );
                }
            }
        }
        items.append(&mut page);
        if let Some(link_value) = link_header
            && let Some(next_url) = parse_next_link(&link_value)
        {
            current_url = next_url;
            continue;
        }
        break;
    }
    Ok(items)
}

fn body_snippet(body: &[u8]) -> String {
    truncate_for_display(&String::from_utf8_lossy(body), BODY_SNIPPET_LIMIT)
}

fn value_snippet(value: &Value) -> String {
    let text = value.to_string();
    truncate_for_display(&text, BODY_SNIPPET_LIMIT)
}

fn truncate_for_display(text: &str, limit: usize) -> String {
    let mut snippet: String = text.chars().take(limit).collect();
    if text.chars().count() > limit {
        snippet.push('…');
    }
    snippet
}

async fn fetch_resources_for_owner(
    client: &reqwest::Client,
    base_url: &Url,
    owner: &str,
    label: &str,
    auth: &AuthConfig,
    progress: Option<&ProgressBar>,
) -> Result<Vec<ResourceRef>> {
    let mut resources = Vec::new();
    for kind in [ResourceKind::Model, ResourceKind::Dataset, ResourceKind::Space] {
        if let Some(pb) = progress {
            pb.set_message(format!(
                "Enumerating Hugging Face {label} {}",
                kind.display_name_plural()
            ));
        }
        let mut url = base_url.join(kind.api_path())?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("author", owner);
            pairs.append_pair("limit", "100");
        }
        let context = format!("{} for {label}", kind.display_name_plural());
        match fetch_paginated::<HuggingFaceItem>(client, url, auth, &context).await {
            Ok(items) => {
                for item in items {
                    let identifier = item.into_identifier();
                    if let Some(slug) = parse_slug_for_kind(kind, &identifier) {
                        resources.push(ResourceRef::new(kind, slug));
                    } else {
                        warn!(
                            "Skipping Hugging Face {} with unexpected identifier '{}'",
                            kind.display_name_singular(),
                            identifier
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    "Failed to enumerate Hugging Face {} for {label}: {err}",
                    kind.display_name_plural()
                );
            }
        }
    }
    Ok(resources)
}

fn append_explicit_resources(specifiers: &RepoSpecifiers, resources: &mut Vec<ResourceRef>) {
    for model in &specifiers.model {
        if let Some(slug) = parse_slug_for_kind(ResourceKind::Model, model) {
            resources.push(ResourceRef::new(ResourceKind::Model, slug));
        } else {
            warn!("Ignoring invalid Hugging Face model identifier '{model}'");
        }
    }
    for dataset in &specifiers.dataset {
        if let Some(slug) = parse_slug_for_kind(ResourceKind::Dataset, dataset) {
            resources.push(ResourceRef::new(ResourceKind::Dataset, slug));
        } else {
            warn!("Ignoring invalid Hugging Face dataset identifier '{dataset}'");
        }
    }
    for space in &specifiers.space {
        if let Some(slug) = parse_slug_for_kind(ResourceKind::Space, space) {
            resources.push(ResourceRef::new(ResourceKind::Space, slug));
        } else {
            warn!("Ignoring invalid Hugging Face space identifier '{space}'");
        }
    }
}

async fn fetch_buckets_for_owner(
    client: &reqwest::Client,
    base_url: &Url,
    owner: &str,
    label: &str,
    auth: &AuthConfig,
    progress: Option<&ProgressBar>,
) -> Result<Vec<BucketTarget>> {
    if let Some(pb) = progress {
        pb.set_message(format!("Enumerating Hugging Face {label} buckets"));
    }
    let mut url = base_url.join(&format!("buckets/{owner}"))?;
    url.query_pairs_mut().append_pair("limit", "100");
    let context = format!("buckets for {label}");
    let buckets = fetch_paginated::<BucketInfo>(client, url, auth, &context).await?;
    Ok(buckets.into_iter().filter_map(|bucket| parse_bucket_target(&bucket.id)).collect())
}

pub async fn enumerate_repo_urls(
    specifiers: &RepoSpecifiers,
    auth: &AuthConfig,
    ignore_certs: bool,
    progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(ignore_certs)
        .build()?;
    let base_url = Url::parse(HUGGINGFACE_API)?;
    let excludes = ExcludeSet::from_list(&specifiers.exclude);
    let mut collected = Vec::new();

    for user in &specifiers.user {
        let label = format!("user {user}");
        if let Some(pb) = progress.as_ref() {
            pb.set_message(format!("Enumerating Hugging Face {label}"));
        }
        match fetch_resources_for_owner(&client, &base_url, user, &label, auth, progress.as_deref())
            .await
        {
            Ok(mut resources) => collected.append(&mut resources),
            Err(err) => warn!("Failed to enumerate Hugging Face user {user}: {err}"),
        }
    }

    for org in &specifiers.organization {
        let label = format!("organization {org}");
        if let Some(pb) = progress.as_ref() {
            pb.set_message(format!("Enumerating Hugging Face {label}"));
        }
        match fetch_resources_for_owner(&client, &base_url, org, &label, auth, progress.as_deref())
            .await
        {
            Ok(mut resources) => collected.append(&mut resources),
            Err(err) => warn!("Failed to enumerate Hugging Face organization {org}: {err}"),
        }
    }

    append_explicit_resources(specifiers, &mut collected);

    let mut seen = HashSet::new();
    let mut urls = Vec::new();
    for resource in collected {
        if excludes.should_exclude(resource.kind, &resource.slug) {
            debug!(
                "Skipping Hugging Face {} {} due to exclusion",
                resource.kind.display_name_singular(),
                resource.slug
            );
            continue;
        }
        let key = resource.canonical_key();
        if seen.insert(key)
            && let Some(url) = resource.git_url()
        {
            urls.push(url);
        }
    }
    urls.sort();
    urls.dedup();
    Ok(urls)
}

pub async fn enumerate_bucket_targets(
    specifiers: &RepoSpecifiers,
    auth: &AuthConfig,
    ignore_certs: bool,
    progress: Option<&mut ProgressBar>,
) -> Result<Vec<BucketTarget>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(ignore_certs)
        .build()?;
    let base_url = Url::parse(HUGGINGFACE_API)?;
    let excludes = ExcludeSet::from_list(&specifiers.exclude);
    let mut collected = Vec::new();

    for user in &specifiers.user {
        let label = format!("user {user}");
        match fetch_buckets_for_owner(&client, &base_url, user, &label, auth, progress.as_deref())
            .await
        {
            Ok(mut buckets) => collected.append(&mut buckets),
            Err(err) => warn!("Failed to enumerate Hugging Face buckets for user {user}: {err}"),
        }
    }

    for org in &specifiers.organization {
        let label = format!("organization {org}");
        match fetch_buckets_for_owner(&client, &base_url, org, &label, auth, progress.as_deref())
            .await
        {
            Ok(mut buckets) => collected.append(&mut buckets),
            Err(err) => {
                warn!("Failed to enumerate Hugging Face buckets for organization {org}: {err}")
            }
        }
    }

    for raw in &specifiers.bucket {
        if let Some(bucket) = parse_bucket_target(raw) {
            collected.push(bucket);
        } else {
            warn!("Ignoring invalid Hugging Face bucket identifier '{raw}'");
        }
    }

    collected.retain(|bucket| !excludes.should_exclude(ResourceKind::Bucket, bucket.bucket_id()));
    collected.sort_by(|a, b| a.bucket_id.cmp(&b.bucket_id).then_with(|| a.prefix.cmp(&b.prefix)));
    collected.dedup();

    let root_buckets: HashSet<String> = collected
        .iter()
        .filter(|bucket| bucket.prefix.is_none())
        .map(|bucket| bucket.bucket_id.clone())
        .collect();
    collected
        .retain(|bucket| bucket.prefix.is_none() || !root_buckets.contains(bucket.bucket_id()));

    Ok(collected)
}

fn build_exclude_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern)?);
    }
    Ok(Some(builder.build()?))
}

fn bucket_tree_url(api_base: &Url, bucket: &BucketTarget) -> Result<Url> {
    let mut url = api_base.join(&format!("buckets/{}/tree", bucket.bucket_id()))?;
    if let Some(prefix) = bucket.prefix() {
        let encoded = encode_bucket_path(prefix);
        url = Url::parse(&format!("{url}/{encoded}"))?;
    }
    url.query_pairs_mut().append_pair("recursive", "true");
    Ok(url)
}

fn bucket_download_url(endpoint: &Url, bucket_id: &str, path: &str) -> Result<Url> {
    let encoded = encode_bucket_path(path);
    Ok(Url::parse(&format!("{endpoint}buckets/{bucket_id}/resolve/{encoded}"))?)
}

fn encode_bucket_path(path: &str) -> String {
    utf8_percent_encode(path, HUGGINGFACE_PATH_ENCODE_SET).to_string()
}

pub async fn visit_bucket_objects<F>(
    targets: &[BucketTarget],
    auth: &AuthConfig,
    ignore_certs: bool,
    max_file_size: Option<u64>,
    exclude_patterns: &[String],
    mut visitor: F,
) -> Result<u64>
where
    F: FnMut(&BucketTarget, String, Vec<u8>) -> Result<()>,
{
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .danger_accept_invalid_certs(ignore_certs)
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()?;
    let api_base = Url::parse(HUGGINGFACE_API)?;
    let endpoint = Url::parse(HUGGINGFACE_ENDPOINT)?;
    let exclude_globset = build_exclude_globset(exclude_patterns)?;
    let mut visited = 0;

    for bucket in targets {
        let tree_url = bucket_tree_url(&api_base, bucket)?;
        let context = format!("files in bucket {}", bucket.bucket_id());
        let entries = fetch_paginated::<BucketTreeEntry>(&client, tree_url, auth, &context).await?;

        for entry in entries {
            if entry.entry_type != "file" {
                continue;
            }
            if exclude_globset.as_ref().is_some_and(|set| set.is_match(&entry.path)) {
                debug!("Skipping excluded Hugging Face bucket object {}", entry.path);
                continue;
            }
            if max_file_size.is_some_and(|limit| entry.size > limit) {
                debug!(
                    "Skipping Hugging Face bucket object {} ({} bytes exceeds configured limit)",
                    entry.path, entry.size
                );
                continue;
            }

            let bytes = if entry.size == 0 {
                Vec::new()
            } else {
                let url = bucket_download_url(&endpoint, bucket.bucket_id(), &entry.path)?;
                let response = auth.apply(client.get(url)).send().await.with_context(|| {
                    format!(
                        "Failed to fetch Hugging Face bucket object {}/{}",
                        bucket.bucket_id(),
                        entry.path
                    )
                })?;
                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    return Err(anyhow!(
                        "Hugging Face bucket object download failed for {}/{} ({status}): {}",
                        bucket.bucket_id(),
                        entry.path,
                        truncate_for_display(&body, BODY_SNIPPET_LIMIT)
                    ));
                }
                response.bytes().await?.to_vec()
            };

            visitor(bucket, entry.path, bytes)?;
            visited += 1;
        }
    }

    Ok(visited)
}

pub async fn list_repositories(
    specifiers: &RepoSpecifiers,
    auth: &AuthConfig,
    ignore_certs: bool,
    progress_enabled: bool,
) -> Result<()> {
    let mut progress = if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner()
            .with_style(style)
            .with_message("Enumerating Hugging Face resources");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let mut targets =
        enumerate_repo_urls(specifiers, auth, ignore_certs, Some(&mut progress)).await?;
    targets.extend(
        enumerate_bucket_targets(specifiers, auth, ignore_certs, Some(&mut progress))
            .await?
            .into_iter()
            .map(|bucket| bucket.uri()),
    );
    targets.sort();
    targets.dedup();
    for target in targets {
        println!("{target}");
    }
    progress.finish_and_clear();
    Ok(())
}

pub fn wiki_url(_repo_url: &GitUrl) -> Option<GitUrl> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_model_slug_from_plain() {
        assert_eq!(
            parse_slug_for_kind(ResourceKind::Model, "user/model"),
            Some("user/model".to_string())
        );
    }

    #[test]
    fn parse_dataset_slug_with_prefix() {
        assert_eq!(
            parse_slug_for_kind(ResourceKind::Dataset, "datasets/user/data.git"),
            Some("user/data".to_string())
        );
    }

    #[test]
    fn parse_space_slug_from_url() {
        assert_eq!(
            parse_slug_for_kind(ResourceKind::Space, "https://huggingface.co/spaces/user/demo"),
            Some("user/demo".to_string())
        );
    }

    #[test]
    fn parse_bucket_targets() {
        assert_eq!(
            parse_bucket_target("owner/checkpoints"),
            Some(BucketTarget::new("owner/checkpoints".into(), None))
        );
        assert_eq!(
            parse_bucket_target("hf://buckets/owner/checkpoints/logs/run-1"),
            Some(BucketTarget::new("owner/checkpoints".into(), Some("logs/run-1".into())))
        );
        assert_eq!(
            parse_bucket_target("https://huggingface.co/buckets/owner/checkpoints/tree/logs"),
            Some(BucketTarget::new("owner/checkpoints".into(), Some("logs".into())))
        );
        assert_eq!(parse_bucket_target("https://example.com/buckets/owner/checkpoints"), None);
    }

    #[test]
    fn bucket_uri_preserves_prefixes_named_like_web_routes() {
        assert_eq!(
            parse_bucket_target("hf://buckets/owner/checkpoints/tree/run-1"),
            Some(BucketTarget::new("owner/checkpoints".into(), Some("tree/run-1".into())))
        );
        assert_eq!(
            parse_bucket_target("owner/checkpoints/resolve/output"),
            Some(BucketTarget::new("owner/checkpoints".into(), Some("resolve/output".into())))
        );
        assert_eq!(
            parse_bucket_target("https://huggingface.co/buckets/owner/checkpoints/tree/run-1"),
            Some(BucketTarget::new("owner/checkpoints".into(), Some("run-1".into())))
        );
    }

    #[test]
    fn bucket_urls_preserve_nested_paths() {
        let api_base = Url::parse(HUGGINGFACE_API).unwrap();
        let endpoint = Url::parse(HUGGINGFACE_ENDPOINT).unwrap();
        let bucket = BucketTarget::new("owner/checkpoints".into(), Some("logs/run-1".into()));

        assert_eq!(
            bucket_tree_url(&api_base, &bucket).unwrap().as_str(),
            "https://huggingface.co/api/buckets/owner/checkpoints/tree/logs/run%2D1?recursive=true"
        );
        assert_eq!(
            bucket_download_url(&endpoint, bucket.bucket_id(), "logs/run-1/output file.txt")
                .unwrap()
                .as_str(),
            "https://huggingface.co/buckets/owner/checkpoints/resolve/logs/run%2D1/output%20file%2Etxt"
        );
    }

    #[test]
    fn exclude_set_matches_typed_and_untyped() {
        let excludes = ExcludeSet::from_list(&[
            "model:user/model".into(),
            "datasets/user/data".into(),
            "bucket:user/cache".into(),
        ]);
        assert!(excludes.should_exclude(ResourceKind::Model, "user/model"));
        assert!(excludes.should_exclude(ResourceKind::Dataset, "user/data"));
        assert!(excludes.should_exclude(ResourceKind::Bucket, "user/cache"));
        assert!(!excludes.should_exclude(ResourceKind::Space, "user/space"));
    }

    #[test]
    fn parse_link_header() {
        let header = "<https://huggingface.co/api/models?cursor=abc>; rel=\"next\"";
        let url = parse_next_link(header).expect("next link");
        assert_eq!(url.as_str(), "https://huggingface.co/api/models?cursor=abc");
    }

    #[test]
    fn truncate_for_display_adds_ellipsis() {
        assert_eq!(truncate_for_display("abcdef", 3), "abc…");
        assert_eq!(truncate_for_display("abc", 5), "abc");
    }
}
