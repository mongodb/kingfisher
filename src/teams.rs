use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct TeamsMessage {
    pub web_url: String,
    pub body_content: String,
    pub created_date_time: String,
    pub channel_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    value: Option<Vec<SearchResult>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchResult {
    hits_containers: Option<Vec<HitsContainer>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HitsContainer {
    hits: Option<Vec<Hit>>,
    more_results_available: Option<bool>,
    #[expect(dead_code)]
    total: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Hit {
    resource: Option<HitResource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HitResource {
    #[serde(rename = "webUrl")]
    web_url: Option<String>,
    body: Option<MessageBody>,
    created_date_time: Option<String>,
    channel_identity: Option<ChannelIdentity>,
}

#[derive(Debug, Deserialize)]
struct MessageBody {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelIdentity {
    channel_id: Option<String>,
}

const PAGE_SIZE: usize = 25;

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
    if trimmed.is_empty() { "unknown".to_string() } else { trimmed.to_string() }
}

pub async fn search_messages(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<TeamsMessage>> {
    let token = std::env::var("KF_TEAMS_TOKEN")
        .context("KF_TEAMS_TOKEN environment variable must be set")?;

    let client = Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")?;

    let mut from: usize = 0;
    let mut messages = Vec::new();

    loop {
        let url = api_url
            .join("v1.0/search/query")
            .context("Failed to build Microsoft Graph search URL")?;

        let body = serde_json::json!({
            "requests": [{
                "entityTypes": ["chatMessage"],
                "query": { "queryString": query },
                "from": from,
                "size": PAGE_SIZE
            }]
        });

        let resp = client
            .post(url)
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to send Microsoft Graph search request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Microsoft Graph API error (HTTP {}): {}", status, text));
        }

        let search_resp: SearchResponse =
            resp.json().await.context("Failed to parse Microsoft Graph search response")?;

        let results = search_resp.value.unwrap_or_default();
        let container = results
            .into_iter()
            .next()
            .and_then(|r| r.hits_containers)
            .and_then(|mut c| if c.is_empty() { None } else { Some(c.remove(0)) });

        let Some(container) = container else {
            break;
        };

        let hits = container.hits.unwrap_or_default();
        if hits.is_empty() {
            break;
        }

        for hit in hits {
            let Some(resource) = hit.resource else {
                continue;
            };
            let web_url = resource.web_url.unwrap_or_default();
            let body_content = resource.body.and_then(|b| b.content).unwrap_or_default();
            let created_date_time = resource.created_date_time.unwrap_or_default();
            let channel_id = resource.channel_identity.and_then(|ci| ci.channel_id);

            if web_url.is_empty() && body_content.is_empty() {
                continue;
            }

            messages.push(TeamsMessage { web_url, body_content, created_date_time, channel_id });

            if !kingfisher_scanner::validation::limits::NetworkLimits::current().unlimited_results
                && messages.len() >= max_results
            {
                return Ok(messages);
            }
        }

        let more = container.more_results_available.unwrap_or(false);
        if !more {
            break;
        }
        from += PAGE_SIZE;
    }

    Ok(messages)
}

pub async fn download_messages_to_dir(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<(PathBuf, String)>> {
    std::fs::create_dir_all(output_dir)?;
    let messages = search_messages(api_url, query, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    for (idx, msg) in messages.into_iter().enumerate() {
        let ts = msg.created_date_time.replace([':', '.', '-'], "_");
        let chan = sanitize_filename_component(msg.channel_id.as_deref().unwrap_or("unknown"));
        let file = output_dir.join(format!("{}_{}_{}.json", chan, ts, idx));
        std::fs::write(&file, serde_json::to_vec(&msg)?)?;
        paths.push((file, msg.web_url));
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::sanitize_filename_component;

    #[test]
    fn sanitize_filename_component_replaces_windows_invalid_characters() {
        assert_eq!(sanitize_filename_component("19:abc/def\\ghi"), "19_abc_def_ghi");
        assert_eq!(sanitize_filename_component(".."), "unknown");
    }
}
