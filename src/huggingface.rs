use std::{collections::HashSet, env, time::Duration};

use anyhow::{Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{StatusCode, Url, header::LINK};
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, warn};

use crate::{git_url::GitUrl, validation::GLOBAL_USER_AGENT};

#[derive(Debug, Clone, Default)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub organization: Vec<String>,
    pub model: Vec<String>,
    pub dataset: Vec<String>,
    pub space: Vec<String>,
    pub exclude: Vec<String>,
}

impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty()
            && self.organization.is_empty()
            && self.model.is_empty()
            && self.dataset.is_empty()
            && self.space.is_empty()
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

    fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.token { request.bearer_auth(token) } else { request }
    }

    fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum ResourceKind {
    Model,
    Dataset,
    Space,
}

impl ResourceKind {
    fn api_path(self) -> &'static str {
        match self {
            ResourceKind::Model => "models",
            ResourceKind::Dataset => "datasets",
            ResourceKind::Space => "spaces",
        }
    }

    fn git_url(self, slug: &str) -> String {
        match self {
            ResourceKind::Model => format!("https://huggingface.co/{slug}.git"),
            ResourceKind::Dataset => format!("https://huggingface.co/datasets/{slug}.git"),
            ResourceKind::Space => format!("https://huggingface.co/spaces/{slug}.git"),
        }
    }

    fn canonical_prefix(self) -> &'static str {
        match self {
            ResourceKind::Model => "model",
            ResourceKind::Dataset => "dataset",
            ResourceKind::Space => "space",
        }
    }

    fn display_name_singular(self) -> &'static str {
        match self {
            ResourceKind::Model => "model",
            ResourceKind::Dataset => "dataset",
            ResourceKind::Space => "space",
        }
    }

    fn display_name_plural(self) -> &'static str {
        match self {
            ResourceKind::Model => "models",
            ResourceKind::Dataset => "datasets",
            ResourceKind::Space => "spaces",
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

    fn git_url(&self) -> String {
        self.kind.git_url(&self.slug)
    }
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
            "models" | "model" | "datasets" | "dataset" | "spaces" | "space"
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

async fn fetch_paginated(
    client: &reqwest::Client,
    mut current_url: Url,
    auth: &AuthConfig,
    context: &str,
) -> Result<Vec<HuggingFaceItem>> {
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
            match serde_json::from_value::<HuggingFaceItem>(element.clone()) {
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
        match fetch_paginated(client, url, auth, &context).await {
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
    let base_url = Url::parse("https://huggingface.co/api/")?;
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
        if seen.insert(key) {
            urls.push(resource.git_url());
        }
    }
    urls.sort();
    urls.dedup();
    Ok(urls)
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
            .with_message("Enumerating Hugging Face repositories");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let urls = enumerate_repo_urls(specifiers, auth, ignore_certs, Some(&mut progress)).await?;
    for url in urls {
        println!("{url}");
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
    fn exclude_set_matches_typed_and_untyped() {
        let excludes =
            ExcludeSet::from_list(&["model:user/model".into(), "datasets/user/data".into()]);
        assert!(excludes.should_exclude(ResourceKind::Model, "user/model"));
        assert!(excludes.should_exclude(ResourceKind::Dataset, "user/data"));
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
