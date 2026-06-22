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

    let api_url = Url::parse(&api_base)?;
    let mut pages = Vec::new();
    let mut start = 0usize;

    while pages.len() < max_results {
        let limit = std::cmp::min(100, max_results - pages.len());
        let url = api_url.clone();
        let req = client.get(url).query(&[
            ("cql", cql),
            ("limit", &limit.to_string()),
            ("start", &start.to_string()),
            ("expand", "body.storage"),
        ]);
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
        if pages.len() >= max_results || body.links.next.is_none() {
            break;
        }
        start += limit;
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
