use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use http::StatusCode;
use quick_xml::{events::Event, Reader};
use reqwest::{header::HeaderValue, Client};
use serde_json::Value as JsonValue;
use sha2::Sha256;

use crate::validation::{Cache, CachedResponse, VALIDATION_CACHE_SECONDS};

pub fn generate_azure_cache_key(azure_json: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(azure_json.as_bytes());
    format!("AZURE:{:x}", h.finalize())
}

/// Validate Azure Storage credentials without Azure SDK crates
pub async fn validate_azure_storage_credentials(
    azure_json: &str,
    cache: &Cache,
) -> Result<(bool, String)> {
    let cache_key = generate_azure_cache_key(azure_json);

    /* ── short-circuit cached result ───────────────────────────── */
    if let Some(e) = cache.get(&cache_key) {
        let c = e.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            return Ok((c.is_valid, c.body.clone()));
        }
    }

    /* ── pull account + key from caller JSON ──────────────────── */
    let tok: JsonValue = serde_json::from_str(azure_json)?;
    let storage_account = tok["storage_account"].as_str().unwrap_or("");
    let storage_key = tok["storage_key"].as_str().unwrap_or("");
    if storage_account.is_empty() || storage_key.is_empty() {
        let msg = "Missing storage_account or storage_key".to_string();
        cache.insert(cache_key, CachedResponse::new(msg.clone(), StatusCode::BAD_REQUEST, false));
        return Ok((false, msg));
    }

    /* ── build SignedKey GET /?comp=list ──────────────────────── */
    let now_rfc = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let url =
        format!("https://{account}.blob.core.windows.net/?comp=list", account = storage_account);

    // canonical string-to-sign per MSFT docs .
    let canon_headers = format!("x-ms-date:{now_rfc}\nx-ms-version:2023-11-03\n");
    let canon_resource = format!("/{account}/\ncomp:list", account = storage_account);
    let string_to_sign = format!(
        "GET\n\n\n\n\n\n\n\n\n\n\n\n{headers}{resource}",
        headers = canon_headers,
        resource = canon_resource
    );

    // HMAC-SHA256 -- Base64
    let key_bytes = b64.decode(storage_key)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key_bytes).map_err(|_| anyhow!("invalid key length"))?;
    mac.update(string_to_sign.as_bytes());
    let signature = b64.encode(mac.finalize().into_bytes());

    let mut hdrs = reqwest::header::HeaderMap::new();
    hdrs.insert("x-ms-date", HeaderValue::from_str(&now_rfc)?);
    hdrs.insert("x-ms-version", HeaderValue::from_static("2023-11-03"));
    hdrs.insert(
        "Authorization",
        HeaderValue::from_str(&format!(
            "SharedKey {account}:{sig}",
            account = storage_account,
            sig = signature
        ))?,
    );

    let client = Client::builder().build()?;
    let resp = client.get(&url).headers(hdrs).send().await?;

    /* ── capture status before `.text()` consumes resp ────────── */
    let status = resp.status();
    let body_txt = resp.text().await?;

    if !status.is_success() {
        let body = format!("Azure Storage validation failed (HTTP {}): {body_txt}", status);
        cache.insert(cache_key, CachedResponse::new(body.clone(), status, false));
        return Err(anyhow!(body));
    }

    // parse XML payload
    let mut reader = Reader::from_str(&body_txt);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut names = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) if e.name().as_ref().eq_ignore_ascii_case(b"name") => {
                let text = reader.read_text(e.name())?;
                names.push(text.into_owned());
            }
            Err(e) => return Err(anyhow!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    /* ── success ─────────────────────────────────────────────── */
    let body = format!("Account: {}; Containers: {:?}", storage_account, names);
    cache.insert(cache_key, CachedResponse::new(body.clone(), StatusCode::OK, true));
    Ok((true, body))
}
