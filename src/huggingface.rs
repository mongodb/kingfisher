use kingfisher_scanner::validation::limits::ResourceTimeout;
use std::{
    collections::{BTreeMap, HashSet},
    env,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use reqwest::{StatusCode, Url, header::LINK};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use tracing::{debug, warn};

use crate::{git_url::GitUrl, validation::GLOBAL_USER_AGENT};
use crate::{
    object_cache::{ObjectCache, ObjectVersion},
    path_selection::PathSelection,
};

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
    #[serde(default, rename = "xetHash", alias = "xet_hash")]
    xet_hash: Option<String>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    etag: Option<String>,
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
    let initial_url = current_url.clone();
    let mut visited = HashSet::new();
    loop {
        check_pagination_origin(&initial_url, &current_url)?;
        anyhow::ensure!(
            visited.insert(current_url.as_str().to_owned()),
            "Hugging Face API repeated a pagination link"
        );
        let mut request =
            client.get(current_url.clone()).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        request = auth.apply(request);
        let response = request.send().await?;
        let response = check_api_status(response, auth, context).await?;
        let link_header = response
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let body = response.bytes().await?;
        items.extend(parse_response_items::<T>(&body, context)?);
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

fn check_pagination_origin(initial: &Url, next: &Url) -> Result<()> {
    anyhow::ensure!(
        next.origin() == initial.origin()
            && next.username().is_empty()
            && next.password().is_none(),
        "Hugging Face pagination left its configured origin"
    );
    Ok(())
}

async fn check_api_status(
    mut response: reqwest::Response,
    auth: &AuthConfig,
    context: &str,
) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    // Error diagnostics need only a small prefix, even for unlimited-content scans.
    let body = crate::github::retry::read_body_prefix(&mut response, 512).await.unwrap_or_default();
    let body = String::from_utf8_lossy(&body);
    let mut message =
        format!("Hugging Face API request failed while enumerating {context} ({status}): {body}");
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) && !auth.has_token() {
        message.push_str("\nProvide a Hugging Face access token via the KF_HUGGINGFACE_TOKEN environment variable.");
    }
    Err(anyhow!(message))
}

fn parse_response_items<T: DeserializeOwned>(body: &[u8], context: &str) -> Result<Vec<T>> {
    let value: Value = serde_json::from_slice(body).map_err(|err| {
        anyhow!("Failed to parse Hugging Face response while enumerating {context}: {err}. Body snippet: {}", body_snippet(body))
    })?;
    let array = value.as_array().ok_or_else(|| {
        anyhow!("Unexpected Hugging Face response format while enumerating {context} (expected array). Body snippet: {}", body_snippet(body))
    })?;
    let mut items = Vec::new();
    for (index, element) in array.iter().enumerate() {
        match serde_json::from_value::<T>(element.clone()) {
            Ok(item) => items.push(item),
            Err(err) => warn!(
                "Skipping Hugging Face item at index {index} while enumerating {context}: {err}. Item snippet: {}",
                value_snippet(element)
            ),
        }
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
        .resource_timeout(Duration::from_secs(30))
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
        .resource_timeout(Duration::from_secs(30))
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
    visitor: F,
) -> Result<u64>
where
    F: FnMut(&BucketTarget, String, Vec<u8>) -> Result<()>,
{
    visit_bucket_objects_selected(
        targets,
        auth,
        ignore_certs,
        max_file_size,
        exclude_patterns,
        &PathSelection::default(),
        None,
        visitor,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn visit_bucket_objects_selected<F>(
    targets: &[BucketTarget],
    auth: &AuthConfig,
    ignore_certs: bool,
    max_file_size: Option<u64>,
    exclude_patterns: &[String],
    selection: &PathSelection,
    cache_dir: Option<&Path>,
    visitor: F,
) -> Result<u64>
where
    F: FnMut(&BucketTarget, String, Vec<u8>) -> Result<()>,
{
    let client = reqwest::Client::builder()
        .resource_timeout(Duration::from_secs(120))
        .danger_accept_invalid_certs(ignore_certs)
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()?;
    visit_bucket_objects_at(
        &client,
        &Url::parse(HUGGINGFACE_API)?,
        &Url::parse(HUGGINGFACE_ENDPOINT)?,
        targets,
        auth,
        max_file_size,
        exclude_patterns,
        selection,
        cache_dir,
        visitor,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn visit_bucket_objects_at<F>(
    client: &reqwest::Client,
    api_base: &Url,
    endpoint: &Url,
    targets: &[BucketTarget],
    auth: &AuthConfig,
    max_file_size: Option<u64>,
    exclude_patterns: &[String],
    selection: &PathSelection,
    cache_dir: Option<&Path>,
    mut visitor: F,
) -> Result<u64>
where
    F: FnMut(&BucketTarget, String, Vec<u8>) -> Result<()>,
{
    selection.check()?;
    let exclude_globset = build_exclude_globset(exclude_patterns)?;
    // Combine overlapping explicit bucket targets before enumerating any content.
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for target in targets {
        grouped
            .entry(target.bucket_id.clone())
            .or_default()
            .extend(selection.listing_prefixes(target.prefix()));
    }
    let mut visited = 0;
    for (bucket_id, prefixes) in grouped {
        if prefixes.is_empty() {
            continue;
        }
        let selected = PathSelection { include_prefixes: prefixes, ..selection.clone() };
        let selected = selected.within_prefix(None).expect("nonempty bucket selection");
        let bucket = BucketTarget::new(bucket_id, None);
        let policy = (&selected, max_file_size, exclude_patterns);
        let mut cache =
            cache_dir.map(|dir| ObjectCache::open(dir, &bucket.uri(), &policy)).transpose()?;
        let mut seen_objects = HashSet::new();
        if let Some(cache) = &cache {
            for key in cache.completed_objects() {
                visitor(&bucket, key.clone(), cache.read(&key)?)?;
                seen_objects.insert(key);
                visited += 1;
            }
        }
        let scopes = selected.listing_prefixes(None);
        for scope in scopes {
            if cache.as_ref().is_some_and(|cache| cache.scope_complete(&scope)) {
                continue;
            }
            let target = BucketTarget::new(
                bucket.bucket_id.clone(),
                (!scope.is_empty()).then(|| scope.trim_end_matches('/').to_owned()),
            );
            let initial = bucket_tree_url(api_base, &target)?;
            let mut current = cache
                .as_ref()
                .and_then(|cache| cache.continuation_token(&scope))
                .map(|token| Url::parse(&token))
                .transpose()?
                .unwrap_or_else(|| initial.clone());
            let mut seen_pages = HashSet::new();
            loop {
                check_pagination_origin(&initial, &current)?;
                anyhow::ensure!(
                    current.path() == initial.path(),
                    "Hugging Face pagination left its configured listing scope"
                );
                anyhow::ensure!(
                    seen_pages.insert(current.as_str().to_owned()),
                    "Hugging Face listing repeated a page link"
                );
                let response = auth
                    .apply(client.get(current.clone()))
                    .send()
                    .await
                    .context("Cannot list Hugging Face bucket objects")?;
                let context = format!("objects in bucket {}", bucket.bucket_id());
                let response = check_api_status(response, auth, &context).await?;
                let next = response
                    .headers()
                    .get(LINK)
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_next_link);
                if let Some(next) = &next {
                    check_pagination_origin(&initial, next)?;
                    anyhow::ensure!(
                        next.path() == initial.path(),
                        "Hugging Face pagination left its configured listing scope"
                    );
                }
                let body = response.bytes().await?;
                let entries = parse_response_items::<BucketTreeEntry>(&body, &context)?;
                for entry in entries {
                    if entry.entry_type != "file"
                        || !selected.matches(&entry.path)
                        || exclude_globset.as_ref().is_some_and(|set| set.is_match(&entry.path))
                        || max_file_size.is_some_and(|limit| entry.size > limit)
                        || seen_objects.contains(&entry.path)
                    {
                        continue;
                    }
                    let version = ObjectVersion {
                        identity: entry.xet_hash.or(entry.oid).or(entry.etag),
                        modified: None,
                        size: Some(entry.size),
                    };
                    let cached = cache
                        .as_ref()
                        .map(|cache| cache.cached(&entry.path, &version))
                        .transpose()?
                        .flatten();
                    let bytes = if let Some(bytes) = cached {
                        bytes
                    } else if entry.size == 0 {
                        Vec::new()
                    } else {
                        let url = bucket_download_url(endpoint, bucket.bucket_id(), &entry.path)?;
                        let response = auth
                            .apply(client.get(url))
                            .send()
                            .await
                            .context("Cannot download Hugging Face bucket object")?;
                        check_api_status(response, auth, "bucket object download")
                            .await?
                            .bytes()
                            .await?
                            .to_vec()
                    };
                    if let Some(cache) = &mut cache {
                        cache.store(&entry.path, version, &bytes)?;
                    }
                    visitor(&bucket, entry.path.clone(), bytes)?;
                    seen_objects.insert(entry.path);
                    visited += 1;
                }
                if let Some(cache) = &mut cache {
                    cache.finish_page(&scope, next.as_ref().map(ToString::to_string))?;
                }
                match next {
                    Some(next) => current = next,
                    None => break,
                }
            }
        }
        if let Some(cache) = &mut cache {
            cache.finish()?;
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
    #[tokio::test]
    async fn api_error_reads_only_a_bounded_prefix_without_waiting_for_eof() {
        use futures::StreamExt;
        use kingfisher_scanner::validation::limits::NetworkLimits;

        for unlimited_response in [false, true] {
            // The stream never ends, and bytes beyond the diagnostic prefix must not appear.
            let mut prefix = vec![b'x'; 512];
            prefix.extend_from_slice(b"must-not-appear");
            let stream = futures::stream::once(std::future::ready(Ok::<_, std::io::Error>(prefix)))
                .chain(futures::stream::pending());
            let response = http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(reqwest::Body::wrap_stream(stream))
                .unwrap()
                .into();
            let error =
                tokio::time::timeout(
                    Duration::from_secs(10),
                    NetworkLimits { unlimited_response, ..Default::default() }
                        .scope(check_api_status(response, &AuthConfig::default(), "buckets")),
                )
                .await
                .expect("diagnostic reading must stop at its prefix limit")
                .unwrap_err();
            let message = error.to_string();
            assert!(message.contains(&"x".repeat(512)));
            assert!(!message.contains("must-not-appear"));
            assert!(message.contains("401"));
            assert!(message.contains("KF_HUGGINGFACE_TOKEN"));
        }
    }

    #[tokio::test]
    async fn api_status_check_preserves_success_bodies_and_short_error_details() {
        let response = http::Response::builder().status(200).body("untouched").unwrap().into();
        let response = check_api_status(response, &AuthConfig::default(), "models").await.unwrap();
        assert_eq!(response.text().await.unwrap(), "untouched");

        let response =
            http::Response::builder().status(403).body("permission denied").unwrap().into();
        let error =
            check_api_status(response, &AuthConfig { token: Some("configured".into()) }, "models")
                .await
                .unwrap_err()
                .to_string();
        assert!(error.contains("permission denied"));
        assert!(!error.contains("KF_HUGGINGFACE_TOKEN"));
    }

    #[tokio::test]
    async fn bucket_listing_skips_malformed_entries_without_losing_valid_files() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
        let server = MockServer::start().await;
        let api = Url::parse(&format!("{}/api/", server.uri())).unwrap();
        let endpoint = Url::parse(&format!("{}/", server.uri())).unwrap();
        Mock::given(path("/api/buckets/owner/data/tree"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"type":"directory","path":"folder","size":null},
                {"type":"file","path":"invalid.env","size":null},
                {"type":"file","path":"valid.env","size":6},
                {"type":"file","path":"empty.env","size":0},
                {"path":"missing-type.env","size":6}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/buckets/owner/data/resolve/valid%2Eenv"))
            .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
            .expect(1)
            .mount(&server)
            .await;
        let mut objects = Vec::new();
        let visited = visit_bucket_objects_at(
            &reqwest::Client::new(),
            &api,
            &endpoint,
            &[BucketTarget::new("owner/data".into(), None)],
            &AuthConfig::default(),
            None,
            &[],
            &PathSelection::default(),
            None,
            |_, key, bytes| {
                objects.push((key, bytes));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(visited, 2);
        assert_eq!(
            objects,
            [("valid.env".into(), b"secret".to_vec()), ("empty.env".into(), vec![])]
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn bucket_auth_failures_explain_how_to_supply_a_missing_token() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let api = Url::parse(&format!("{}/api/", server.uri())).unwrap();
        let endpoint = Url::parse(&format!("{}/", server.uri())).unwrap();
        for status in [401, 403] {
            for token in [None, Some("configured-token".to_string())] {
                server.reset().await;
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(status))
                    .expect(1)
                    .mount(&server)
                    .await;
                let auth = AuthConfig { token };
                let error = visit_bucket_objects_at(
                    &reqwest::Client::new(),
                    &api,
                    &endpoint,
                    &[BucketTarget::new("owner/data".into(), None)],
                    &auth,
                    None,
                    &[],
                    &PathSelection::default(),
                    None,
                    |_, _, _| Ok(()),
                )
                .await
                .unwrap_err();
                assert_eq!(error.to_string().contains("KF_HUGGINGFACE_TOKEN"), !auth.has_token());
                assert!(error.to_string().contains(&status.to_string()));
                server.verify().await;
            }
        }
    }

    #[tokio::test]
    async fn resource_pagination_never_sends_tokens_to_another_origin() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let other = MockServer::start().await;
        let next = format!("<{}/api/models?cursor=next>; rel=\"next\"", other.uri());
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("link", next.as_str())
                    .set_body_json(serde_json::json!([])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(0)
            .mount(&other)
            .await;
        let error = fetch_paginated::<HuggingFaceItem>(
            &reqwest::Client::new(),
            Url::parse(&format!("{}/api/models", server.uri())).unwrap(),
            &AuthConfig { token: Some("must-not-leak".into()) },
            "models",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("configured origin"), "{error}");
        assert!(other.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn resource_pagination_follows_same_origin_links_and_rejects_cycles() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{path, query_param, query_param_is_missing},
        };
        let server = MockServer::start().await;
        let initial = Url::parse(&format!("{}/api/models", server.uri())).unwrap();
        let next = format!("<{initial}?cursor=next>; rel=\"next\"");
        Mock::given(path("/api/models"))
            .and(query_param_is_missing("cursor"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("link", next.as_str())
                    .set_body_json(serde_json::json!([{"id":"owner/first"}])),
            )
            .mount(&server)
            .await;
        Mock::given(query_param("cursor", "next"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"id":"owner/second"}])),
            )
            .mount(&server)
            .await;
        let items = fetch_paginated::<HuggingFaceItem>(
            &reqwest::Client::new(),
            initial.clone(),
            &AuthConfig::default(),
            "models",
        )
        .await
        .unwrap();
        assert_eq!(items.len(), 2);
        server.reset().await;
        let cycle = format!("<{initial}>; rel=\"next\"");
        Mock::given(path("/api/models"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("link", cycle.as_str())
                    .set_body_json(serde_json::json!([])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = fetch_paginated::<HuggingFaceItem>(
            &reqwest::Client::new(),
            initial,
            &AuthConfig::default(),
            "models",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("repeated a pagination link"));
    }

    #[test]
    fn pagination_origin_rejects_scheme_changes_and_embedded_credentials() {
        let initial = Url::parse("https://huggingface.co/api/models").unwrap();
        for next in [
            "http://huggingface.co/api/models",
            "https://huggingface.co:444/api/models",
            "https://user:password@huggingface.co/api/models",
            "https://untrusted.example/api/models",
        ] {
            assert!(check_pagination_origin(&initial, &Url::parse(next).unwrap()).is_err());
        }
    }

    #[tokio::test]
    async fn bucket_filters_scope_listing_and_skip_downloads_for_every_exclusion() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        let api = url::Url::parse(&format!("{}/api/", server.uri())).unwrap();
        let endpoint = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        Mock::given(method("GET"))
            .and(path("/api/buckets/owner/data/tree/configs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"type":"file","path":"configs/key.env","size":6,"xetHash":"v1"},
                {"type":"file","path":"configs/generated/key.env","size":6},
                {"type":"file","path":"configs/photo.png","size":6},
                {"type":"file","path":"configs/large.env","size":1000},
                {"type":"file","path":"configs/glob.env","size":6},
                {"type":"file","path":"outside/key.env","size":6}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/buckets/owner/data/resolve/configs/key%2Eenv"))
            .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
            .expect(1)
            .mount(&server)
            .await;
        let selection = super::PathSelection {
            include_prefixes: vec!["configs/".into(), "configs/nested/".into(), "outside/".into()],
            exclude_prefixes: vec!["configs/generated/".into()],
            include_extensions: vec!["env".into()],
            ..Default::default()
        };
        let targets = [
            super::BucketTarget::new("owner/data".into(), Some("configs/".into())),
            super::BucketTarget::new("owner/data".into(), Some("configs/nested/".into())),
        ];
        let mut keys = Vec::new();
        super::visit_bucket_objects_at(
            &reqwest::Client::new(),
            &api,
            &endpoint,
            &targets,
            &super::AuthConfig::default(),
            Some(100),
            &["**/glob.env".into()],
            &selection,
            None,
            |_, key, _| {
                keys.push(key);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(keys, ["configs/key.env"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn bucket_checkpoint_replays_completed_pages_and_reuses_unchanged_hashes() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path, query_param, query_param_is_missing},
        };
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let api = url::Url::parse(&format!("{}/api/", server.uri())).unwrap();
        let endpoint = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        let next = format!(
            "<{}/api/buckets/owner/data/tree/configs?recursive=true&cursor=next>; rel=\"next\"",
            server.uri()
        );
        let targets = [super::BucketTarget::new("owner/data".into(), Some("configs/".into()))];
        let selection = super::PathSelection::default();
        Mock::given(path("/api/buckets/owner/data/tree/configs")).and(query_param_is_missing("cursor"))
            .respond_with(ResponseTemplate::new(200).insert_header("link",next.as_str()).set_body_json(serde_json::json!([{"type":"file","path":"configs/first.env","size":6,"xetHash":"v1"}]))).expect(1).mount(&server).await;
        Mock::given(path("/buckets/owner/data/resolve/configs/first%2Eenv"))
            .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(query_param("cursor", "next"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            super::visit_bucket_objects_at(
                &reqwest::Client::new(),
                &api,
                &endpoint,
                &targets,
                &super::AuthConfig::default(),
                None,
                &[],
                &selection,
                Some(root.path()),
                |_, _, _| Ok(())
            )
            .await
            .is_err()
        );
        server.verify().await;
        server.reset().await;
        Mock::given(query_param("cursor","next")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{"type":"file","path":"configs/second.env","size":6,"xetHash":"v1"}]))).expect(1).mount(&server).await;
        Mock::given(path("/buckets/owner/data/resolve/configs/second%2Eenv"))
            .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
            .expect(1)
            .mount(&server)
            .await;
        let mut keys = Vec::new();
        super::visit_bucket_objects_at(
            &reqwest::Client::new(),
            &api,
            &endpoint,
            &targets,
            &super::AuthConfig::default(),
            None,
            &[],
            &selection,
            Some(root.path()),
            |_, key, _| {
                keys.push(key);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(keys, ["configs/first.env", "configs/second.env"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        server.verify().await;
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/api/buckets/owner/data/tree/configs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"type":"file","path":"configs/first.env","size":6,"xetHash":"v1"},
                {"type":"file","path":"configs/second.env","size":6,"xetHash":"v2"}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/buckets/owner/data/resolve/configs/second%2Eenv"))
            .respond_with(ResponseTemplate::new(200).set_body_string("changed"))
            .expect(1)
            .mount(&server)
            .await;
        let mut bodies = Vec::new();
        super::visit_bucket_objects_at(
            &reqwest::Client::new(),
            &api,
            &endpoint,
            &targets,
            &super::AuthConfig::default(),
            None,
            &[],
            &selection,
            Some(root.path()),
            |_, _, bytes| {
                bodies.push(bytes);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(bodies, [b"secret".to_vec(), b"changed".to_vec()]);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn bucket_pagination_cannot_repeat_or_leave_the_configured_origin() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let api = url::Url::parse(&format!("{}/api/", server.uri())).unwrap();
        let endpoint = url::Url::parse(&format!("{}/", server.uri())).unwrap();
        for target in [
            format!("{}/api/buckets/owner/data/tree?recursive=true", server.uri()),
            "https://untrusted.example/api/buckets/owner/data/tree".into(),
        ] {
            server.reset().await;
            let link = format!("<{target}>; rel=\"next\"");
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("link", link.as_str())
                        .set_body_json(serde_json::json!([])),
                )
                .expect(1)
                .mount(&server)
                .await;
            let error = super::visit_bucket_objects_at(
                &reqwest::Client::new(),
                &api,
                &endpoint,
                &[super::BucketTarget::new("owner/data".into(), None)],
                &super::AuthConfig::default(),
                None,
                &[],
                &super::PathSelection::default(),
                None,
                |_, _, _| Ok(()),
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("pagination") || error.to_string().contains("repeated")
            );
            server.verify().await;
        }
    }
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
