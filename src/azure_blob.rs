//! Read-only Azure Blob Storage enumeration and downloads through the storage REST API.
//! Protocol references: <https://learn.microsoft.com/rest/api/storageservices/list-blobs>
//! and <https://learn.microsoft.com/rest/api/storageservices/authorize-with-shared-key>.
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{
    Client, Response, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue, IF_MATCH},
};
use serde::Deserialize;
use sha2::Sha256;
use tracing::{debug, warn};
use url::Url;

use crate::{
    object_cache::{ObjectCache, ObjectVersion},
    path_selection::PathSelection,
};

const API_VERSION: &str = "2023-11-03";
const MAX_LIST_BYTES: u64 = 32 * 1024 * 1024;

pub struct AzureBlobOptions<'a> {
    pub selection: &'a PathSelection,
    pub cache_dir: Option<&'a Path>,
    pub max_object_bytes: Option<u64>,
    pub ignore_certs: bool,
    pub no_timeouts: bool,
}

/// Container URLs contain no credentials; SAS credentials belong in the environment.
pub fn check_container_url(url: &Url) -> Result<()> {
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Azure Blob container URLs must not contain credentials, query parameters or fragments; use KF_AZURE_STORAGE_SAS for a SAS token"
    );
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    // This is an explicit operator-selected scan source (including Azurite), rather than
    // a rule-rendered validation destination; it does not need the validator's internal-IP opt-in.
    ensure!(
        url.host().is_some() && (url.scheme() == "https" || (url.scheme() == "http" && loopback)),
        "Azure Blob requires an HTTPS container URL (HTTP is allowed for loopback emulators)"
    );
    ensure!(!url.path().trim_matches('/').is_empty(), "Azure Blob URL must identify a container");
    Ok(())
}

// Intentionally has no Debug implementation: all variants can hold credentials.
enum StorageAuth {
    Anonymous,
    Sas(Vec<(String, String)>),
    SharedKey { account: String, key: Vec<u8> },
    Bearer(HeaderValue),
}

impl StorageAuth {
    fn from_env(url: &Url) -> Result<Self> {
        Self::from_values(url, |name| std::env::var(name).ok().filter(|v| !v.is_empty()))
    }

    fn from_values(url: &Url, get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let sas = get("KF_AZURE_STORAGE_SAS");
        let key = get("KF_AZURE_STORAGE_KEY");
        let token = get("KF_AZURE_STORAGE_TOKEN");
        ensure!(
            [sas.is_some(), key.is_some(), token.is_some()].into_iter().filter(|v| *v).count() <= 1,
            "Set only one of KF_AZURE_STORAGE_SAS, KF_AZURE_STORAGE_KEY or KF_AZURE_STORAGE_TOKEN"
        );
        if let Some(sas) = sas {
            let pairs: Vec<(String, String)> =
                url::form_urlencoded::parse(sas.trim_start_matches('?').as_bytes())
                    .into_owned()
                    .collect();
            ensure!(
                pairs.iter().any(|(name, value)| name == "sig" && !value.is_empty()),
                "KF_AZURE_STORAGE_SAS must be a SAS query string with a signature"
            );
            let mut names = HashSet::new();
            for (name, _) in &pairs {
                ensure!(
                    names.insert(name.to_ascii_lowercase())
                        && !matches!(
                            name.to_ascii_lowercase().as_str(),
                            "comp"
                                | "restype"
                                | "prefix"
                                | "marker"
                                | "maxresults"
                                | "delimiter"
                                | "include"
                                | "snapshot"
                                | "versionid"
                        ),
                    "KF_AZURE_STORAGE_SAS contains duplicate or reserved query parameters"
                );
            }
            return Ok(Self::Sas(pairs));
        }
        if let Some(key) = key {
            let account = get("KF_AZURE_STORAGE_ACCOUNT").or_else(|| {
                let host = url.host_str()?;
                // Custom domains and emulators require an explicit signing account.
                host.contains(".blob.core.").then(|| host.split('.').next().unwrap().trim_end_matches("-secondary").to_string())
            }).context("Set KF_AZURE_STORAGE_ACCOUNT when using a key with a custom endpoint or emulator")?;
            ensure!(
                !account.is_empty()
                    && account.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "Invalid KF_AZURE_STORAGE_ACCOUNT"
            );
            let key = STANDARD
                .decode(key)
                .map_err(|_| anyhow::anyhow!("KF_AZURE_STORAGE_KEY must be base64 encoded"))?;
            ensure!(!key.is_empty(), "KF_AZURE_STORAGE_KEY is empty");
            return Ok(Self::SharedKey { account, key });
        }
        if let Some(token) = token {
            let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| anyhow::anyhow!("Invalid KF_AZURE_STORAGE_TOKEN"))?;
            value.set_sensitive(true);
            return Ok(Self::Bearer(value));
        }
        Ok(Self::Anonymous)
    }

    fn headers(&self, url: &mut Url, etag: Option<&str>) -> Result<HeaderMap> {
        // List Blobs can expose a bare ETag; HTTP If-Match requires a quoted entity tag.
        // Preserve already-quoted tags and sign exactly the value sent on the wire.
        let etag = etag.map(|etag| {
            if etag.starts_with('"') || etag.starts_with("W/\"") {
                etag.to_owned()
            } else {
                format!("\"{etag}\"")
            }
        });
        let etag = etag.as_deref();
        let mut headers = HeaderMap::new();
        headers.insert("x-ms-version", HeaderValue::from_static(API_VERSION));
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        headers.insert("x-ms-date", HeaderValue::from_str(&date)?);
        if let Some(etag) = etag {
            headers
                .insert(IF_MATCH, HeaderValue::from_str(etag).context("Invalid Azure Blob ETag")?);
        }
        let authorization = match self {
            Self::Anonymous => None,
            Self::Sas(pairs) => {
                url.query_pairs_mut().extend_pairs(pairs);
                None
            }
            Self::Bearer(value) => Some(value.clone()),
            Self::SharedKey { account, key } => {
                let to_sign = signing_string(url, account, &date, etag);
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| anyhow::anyhow!("Invalid Azure Storage key"))?;
                mac.update(to_sign.as_bytes());
                let signature = STANDARD.encode(mac.finalize().into_bytes());
                Some(HeaderValue::from_str(&format!("SharedKey {account}:{signature}"))?)
            }
        };
        if let Some(mut value) = authorization {
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
        Ok(headers)
    }
}

// Only GET requests are issued, so all standard signing fields other than If-Match are empty.
fn signing_string(url: &Url, account: &str, date: &str, etag: Option<&str>) -> String {
    let mut fields = [""; 12];
    fields[0] = "GET";
    fields[8] = etag.unwrap_or("");
    let mut value = format!(
        "{}\nx-ms-date:{date}\nx-ms-version:{API_VERSION}\n/{account}{}",
        fields.join("\n"),
        url.path()
    );
    let mut query: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in url.query_pairs() {
        query.entry(name.to_ascii_lowercase()).or_default().push(value.into_owned());
    }
    for (name, mut values) in query {
        values.sort();
        value.push_str(&format!("\n{name}:{}", values.join(",")));
    }
    value
}

#[derive(Deserialize)]
#[serde(rename = "EnumerationResults")]
struct Listing {
    #[serde(rename = "Blobs")]
    blobs: Blobs,
    #[serde(rename = "NextMarker", default)]
    next_marker: String,
}

#[derive(Deserialize)]
struct Blobs {
    #[serde(rename = "Blob", default)]
    entries: Vec<BlobEntry>,
}

#[derive(Deserialize)]
struct BlobEntry {
    #[serde(rename = "Name")]
    name: BlobName,
    #[serde(rename = "Properties")]
    properties: BlobProperties,
}

#[derive(Deserialize)]
struct BlobName {
    #[serde(rename = "$text", default)]
    text: String,
    #[serde(rename = "@Encoded", default)]
    encoded: bool,
}

#[derive(Deserialize)]
struct BlobProperties {
    #[serde(rename = "Etag", alias = "ETag", default)]
    etag: Option<String>,
    #[serde(rename = "Last-Modified", default)]
    modified: Option<String>,
    #[serde(rename = "Content-Length", default)]
    size: Option<u64>,
    #[serde(rename = "ResourceType", default)]
    resource_type: Option<String>,
}

/// Append literal blob names without interpreting percent escapes, '?' or '#' as URL syntax.
pub fn blob_url(container: &Url, key: &str) -> Result<Url> {
    ensure!(
        !key.split('/').any(|part| matches!(part, "." | "..")),
        "Azure Blob name contains a dot path segment that cannot be represented safely by the HTTP client"
    );
    let mut url = container.clone();
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Invalid Azure Blob container URL"))?
        .pop_if_empty()
        .extend(key.split('/'));
    Ok(url)
}

async fn get(
    client: &Client,
    auth: &StorageAuth,
    url: Url,
    etag: Option<&str>,
) -> Result<Response> {
    check_response(get_response(client, auth, url, etag).await?)
}

fn check_response(response: Response) -> Result<Response> {
    let status = response.status();
    // Neither server bodies nor credential-bearing URLs belong in errors.
    ensure!(
        status == StatusCode::OK,
        "Azure Blob request failed (HTTP {status}); check container permissions and credentials"
    );
    Ok(response)
}

async fn get_response(
    client: &Client,
    auth: &StorageAuth,
    url: Url,
    etag: Option<&str>,
) -> Result<Response> {
    for attempt in 0..=3 {
        let mut url = url.clone();
        let headers = auth.headers(&mut url, etag)?;
        let response = client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("Azure Blob request failed")?;
        let status = response.status();
        if attempt < 3
            && matches!(status, StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE)
        {
            let delay = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(|s| Duration::from_secs(s.min(30)))
                .unwrap_or_else(|| Duration::from_millis(250 << attempt));
            drop(response);
            tokio::time::sleep(delay).await;
            continue;
        }
        return Ok(response);
    }
    unreachable!()
}

async fn read_body(mut response: Response, limit: Option<u64>) -> Result<Option<Vec<u8>>> {
    if limit.is_some_and(|limit| response.content_length().is_some_and(|len| len > limit)) {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)
        .context("Cannot read Azure Blob response")?
    {
        if limit.is_some_and(|limit| body.len() as u64 + chunk.len() as u64 > limit) {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

async fn download_blob(
    client: &Client,
    auth: &StorageAuth,
    container: &Url,
    key: &str,
    mut version: ObjectVersion,
    max_object_bytes: Option<u64>,
) -> Result<Option<(ObjectVersion, Vec<u8>)>> {
    let url = blob_url(container, key)?;
    let mut response = get_response(client, auth, url.clone(), version.identity.as_deref()).await?;
    if response.status() == StatusCode::PRECONDITION_FAILED {
        debug!(blob = %key, "Azure Blob changed after listing; fetching the current version");
        drop(response);
        // An unconditional GET returns one consistent current representation. Never
        // label those bytes with the stale listing ETag, even if headers are absent.
        response = get_response(client, auth, url, None).await?;
        version = ObjectVersion {
            identity: response
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            modified: response
                .headers()
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            size: response.content_length(),
        };
    }
    if response.status() == StatusCode::NOT_FOUND {
        warn!(blob = %key, "Azure Blob disappeared after listing; skipping it until the next scan");
        return Ok(None);
    }
    let response = check_response(response)?;
    Ok(read_body(response, max_object_bytes).await?.map(|data| (version, data)))
}

pub async fn visit_container_blobs<F>(
    container: &Url,
    options: AzureBlobOptions<'_>,
    visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    check_container_url(container)?;
    options.selection.check()?;
    let auth = StorageAuth::from_env(container)?;
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(options.ignore_certs)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd();
    if !options.no_timeouts {
        builder =
            builder.connect_timeout(Duration::from_secs(30)).read_timeout(Duration::from_secs(30));
    }
    visit_with_client(&builder.build()?, &auth, container, &options, visitor).await
}

async fn visit_with_client<F>(
    client: &Client,
    auth: &StorageAuth,
    container: &Url,
    options: &AzureBlobOptions<'_>,
    mut visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    let mut container = container.clone();
    container
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Invalid container URL"))?
        .pop_if_empty();
    let policy = (options.selection, options.max_object_bytes);
    let mut cache = options
        .cache_dir
        .map(|dir| ObjectCache::open(dir, container.as_str(), &policy))
        .transpose()?;
    if let Some(cache) = &cache {
        for key in cache.completed_objects() {
            visitor(key.clone(), cache.read(&key)?)?;
        }
    }
    // After an individual download fails, keep scanning but do not commit past that page.
    // Resuming then retries the incomplete page rather than reporting it as completed.
    let mut downloads_complete = true;
    for prefix in options.selection.listing_prefixes(None) {
        if cache.as_ref().is_some_and(|cache| cache.scope_complete(&prefix)) {
            continue;
        }
        let mut marker = cache.as_ref().and_then(|cache| cache.continuation_token(&prefix));
        let mut markers = HashSet::new();
        if let Some(marker) = &marker {
            markers.insert(marker.clone());
        }
        loop {
            let mut url = container.clone();
            url.query_pairs_mut()
                .append_pair("restype", "container")
                .append_pair("comp", "list")
                .append_pair("maxresults", "5000")
                .append_pair("prefix", &prefix);
            if let Some(marker) = &marker {
                url.query_pairs_mut().append_pair("marker", marker);
            }
            let response = get(client, auth, url, None).await?;
            let body = read_body(response, Some(MAX_LIST_BYTES))
                .await?
                .context("Azure Blob listing exceeds 32 MiB")?;
            let listing: Listing = quick_xml::de::from_reader(body.as_slice())
                .map_err(|_| anyhow::anyhow!("Invalid Azure Blob XML listing"))?;
            // Check before checkpointing or processing a repeated page.
            let next = (!listing.next_marker.is_empty()).then_some(listing.next_marker);
            if let Some(next) = &next {
                ensure!(
                    markers.insert(next.clone()),
                    "Azure Blob listing repeated a continuation marker"
                );
            }
            for entry in listing.blobs.entries {
                let key = if entry.name.encoded {
                    match percent_encoding::percent_decode_str(&entry.name.text).decode_utf8() {
                        Ok(key) => key.into_owned(),
                        Err(_) => {
                            warn!(
                                "Invalid encoded Azure Blob name; skipping it until the next scan"
                            );
                            downloads_complete = false;
                            continue;
                        }
                    }
                } else {
                    entry.name.text
                };
                let props = entry.properties;
                if key.is_empty()
                    || !options.selection.matches(&key)
                    || props.resource_type.as_deref() == Some("directory")
                    || (key.ends_with('/') && props.size == Some(0))
                    || options
                        .max_object_bytes
                        .is_some_and(|limit| props.size.is_some_and(|size| size > limit))
                {
                    continue;
                }
                if let Err(error) = blob_url(&container, &key) {
                    // Retrying cannot make a literal dot segment safe for this HTTP client.
                    // Treat unrepresentable names like other permanent selection skips so
                    // they do not prevent checkpointing otherwise completed pages.
                    warn!(blob = %key, error = %error, "Cannot represent Azure Blob name safely; permanently skipping it");
                    continue;
                }
                let mut version = ObjectVersion {
                    identity: props.etag.filter(|v| !v.is_empty()),
                    modified: props.modified,
                    size: props.size,
                };
                let cached =
                    cache.as_ref().map(|c| c.cached(&key, &version)).transpose()?.flatten();
                let data = if let Some(data) = cached {
                    data
                } else {
                    match download_blob(
                        client,
                        auth,
                        &container,
                        &key,
                        version.clone(),
                        options.max_object_bytes,
                    )
                    .await
                    {
                        Ok(Some((current_version, data))) => {
                            version = current_version;
                            data
                        }
                        Ok(None) => continue,
                        Err(error) => {
                            warn!(blob = %key, error = %error, "Cannot download Azure Blob; skipping it until the next scan");
                            downloads_complete = false;
                            continue;
                        }
                    }
                };
                if let Some(cache) = &mut cache {
                    cache.store(&key, version, &data)?;
                }
                visitor(key, data)?;
            }
            if downloads_complete && let Some(cache) = &mut cache {
                cache.finish_page(&prefix, next.clone())?;
            }
            match next {
                Some(next) => marker = Some(next),
                None => break,
            }
        }
    }
    if downloads_complete {
        if let Some(cache) = &mut cache {
            cache.finish()?;
        }
    } else {
        warn!(
            "Azure Blob scan is incomplete because some blobs could not be downloaded; incomplete pages were not checkpointed and will be retried on the next scan"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param, query_param_is_missing},
    };

    fn options<'a>(
        selection: &'a PathSelection,
        cache_dir: Option<&'a Path>,
    ) -> AzureBlobOptions<'a> {
        AzureBlobOptions {
            selection,
            cache_dir,
            max_object_bytes: Some(100),
            ignore_certs: false,
            no_timeouts: false,
        }
    }

    fn blob(name: &str, etag: &str, size: u64) -> String {
        format!(
            "<Blob><Name>{name}</Name><Properties><Etag>&quot;{etag}&quot;</Etag><Last-Modified>Wed, 14 Oct 2026 00:00:00 GMT</Last-Modified><Content-Length>{size}</Content-Length></Properties></Blob>"
        )
    }

    fn listing(blobs: &str, next: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(format!("<EnumerationResults><Blobs>{blobs}</Blobs><NextMarker>{next}</NextMarker></EnumerationResults>"))
    }

    fn client() -> Client {
        Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
    }

    #[test]
    fn validates_endpoints_and_keeps_literal_names_inside_container() {
        for good in [
            "https://account.blob.core.windows.net/container",
            "https://account.blob.core.usgovcloudapi.net/container/",
            "http://127.0.0.1:10000/devstoreaccount1/container",
            "http://[::1]:10000/devstoreaccount1/container",
        ] {
            check_container_url(&Url::parse(good).unwrap()).unwrap();
        }
        for bad in [
            "http://account.blob.core.windows.net/container",
            "https://user:secret@host/container",
            "https://host/container?sig=secret",
            "https://host/",
            "https://host/container#fragment",
            "ftp://host/container",
        ] {
            let err = check_container_url(&Url::parse(bad).unwrap()).unwrap_err().to_string();
            assert!(!err.contains("secret"));
        }
        let container = Url::parse("https://account.blob.core.windows.net/container").unwrap();
        assert_eq!(
            blob_url(&container, "//other.host/a ?#%&.env").unwrap().as_str(),
            "https://account.blob.core.windows.net/container///other.host/a%20%3F%23%25&.env"
        );
        assert!(blob_url(&container, "../outside").is_err());
    }

    #[test]
    fn canonical_get_signature_covers_query_encoding_and_condition() {
        let url = Url::parse("https://account.blob.core.windows.net/container/key%20name?prefix=a%2Fb%2B&comp=list&include=z&include=a").unwrap();
        let value =
            signing_string(&url, "account", "Wed, 14 Oct 2026 00:00:00 GMT", Some("\"etag\""));
        assert_eq!(
            value,
            "GET\n\n\n\n\n\n\n\n\"etag\"\n\n\n\nx-ms-date:Wed, 14 Oct 2026 00:00:00 GMT\nx-ms-version:2023-11-03\n/account/container/key%20name\ncomp:list\ninclude:a,z\nprefix:a/b+"
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(b"test-signing-key").unwrap();
        mac.update(value.as_bytes());
        assert_eq!(
            STANDARD.encode(mac.finalize().into_bytes()),
            "8OkXYyMIt52CAM5qWvSvmaGuv+ejYlZL5+Nvk76Xq4A="
        );
    }

    #[test]
    fn quoted_and_bare_etags_use_the_same_condition_and_signature() {
        let auth = StorageAuth::SharedKey { account: "account".into(), key: b"key".to_vec() };
        for etag in ["etag", "\"etag\""] {
            let mut url =
                Url::parse("https://account.blob.core.windows.net/container/key").unwrap();
            let headers = auth.headers(&mut url, Some(etag)).unwrap();
            assert_eq!(headers[IF_MATCH], "\"etag\"");
            let expected = signing_string(
                &url,
                "account",
                headers["x-ms-date"].to_str().unwrap(),
                Some("\"etag\""),
            );
            let mut mac = Hmac::<Sha256>::new_from_slice(b"key").unwrap();
            mac.update(expected.as_bytes());
            assert_eq!(
                headers[AUTHORIZATION],
                format!("SharedKey account:{}", STANDARD.encode(mac.finalize().into_bytes()))
            );
        }
    }

    #[test]
    fn auth_is_explicit_unambiguous_and_preserves_sas_signature() {
        let url = Url::parse("https://account-secondary.blob.core.windows.net/container").unwrap();
        let auth = StorageAuth::from_values(&url, |name| match name {
            "KF_AZURE_STORAGE_KEY" => Some(STANDARD.encode(b"key")),
            _ => None,
        })
        .unwrap();
        assert!(matches!(auth, StorageAuth::SharedKey { account, .. } if account == "account"));
        assert!(
            StorageAuth::from_values(
                &Url::parse("https://custom.host/container").unwrap(),
                |name| (name == "KF_AZURE_STORAGE_KEY").then(|| STANDARD.encode(b"key"))
            )
            .is_err()
        );
        assert!(StorageAuth::from_values(&url, |_| Some("value".to_string())).is_err());
        for sas in ["sig=secret&prefix=other", "sig=secret&sig=duplicate", "sv=version"] {
            let error = StorageAuth::from_values(&url, |name| {
                (name == "KF_AZURE_STORAGE_SAS").then(|| sas.to_string())
            })
            .err()
            .unwrap()
            .to_string();
            assert!(!error.contains("secret"));
        }
        let auth = StorageAuth::from_values(&url, |name| {
            (name == "KF_AZURE_STORAGE_SAS")
                .then(|| "?sv=version&sp=rl&sig=a%2Bb%2Fc%3D".to_string())
        })
        .unwrap();
        let mut request = url;
        request.query_pairs_mut().append_pair("comp", "list");
        let headers = auth.headers(&mut request, None).unwrap();
        assert!(!headers.contains_key(AUTHORIZATION));
        assert_eq!(request.query_pairs().find(|(k, _)| k == "sig").unwrap().1, "a+b/c=");
        let auth = StorageAuth::from_values(&request, |name| {
            (name == "KF_AZURE_STORAGE_TOKEN").then(|| "entra-token".to_string())
        })
        .unwrap();
        let headers = auth.headers(&mut request, None).unwrap();
        assert_eq!(headers[AUTHORIZATION], "Bearer entra-token");
        assert!(headers[AUTHORIZATION].is_sensitive());
    }

    #[tokio::test]
    async fn lists_disjoint_scopes_and_filters_before_downloading() {
        let server = MockServer::start().await;
        let container = Url::parse(&format!("{}/container", server.uri())).unwrap();
        let mut entries = blob("configs/key ?#%&amp;.ENV", "v1", 3);
        entries += &blob("configs/generated/skipped.env", "v1", 3);
        entries += &blob("configs/wrong.yaml", "v1", 3);
        entries += &blob("configs/large.env", "v1", 101);
        entries += "<Blob><Name>configs/folder.env</Name><Properties><ResourceType>directory</ResourceType></Properties></Blob>";
        entries += "<Blob><Name Encoded=\"true\">configs/non%EF%BF%BF.env</Name><Properties><Etag>&quot;v1&quot;</Etag><Content-Length>3</Content-Length></Properties></Blob>";
        Mock::given(method("GET"))
            .and(path("/container"))
            .and(query_param("comp", "list"))
            .and(query_param("prefix", "configs/"))
            .respond_with(listing(&entries, ""))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/container"))
            .and(query_param("prefix", "deploy/"))
            .respond_with(listing("", ""))
            .expect(1)
            .mount(&server)
            .await;
        for key in ["configs/key ?#%&.ENV", "configs/non\u{ffff}.env"] {
            let url = blob_url(&container, key).unwrap();
            Mock::given(method("GET"))
                .and(path(url.path()))
                .and(header("if-match", "\"v1\""))
                .respond_with(ResponseTemplate::new(200).set_body_string("key"))
                .expect(1)
                .mount(&server)
                .await;
        }
        let selection = PathSelection {
            include_prefixes: vec!["configs/".into(), "configs/nested/".into(), "deploy/".into()],
            exclude_prefixes: vec!["configs/generated/".into()],
            include_extensions: vec!["env".into()],
            ..Default::default()
        };
        let mut seen = Vec::new();
        visit_with_client(
            &client(),
            &StorageAuth::Anonymous,
            &container,
            &options(&selection, None),
            |key, data| {
                assert_eq!(data, b"key");
                seen.push(key);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(seen, ["configs/key ?#%&.ENV", "configs/non\u{ffff}.env"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn directory_markers_and_unsafe_names_do_not_block_page_checkpoints() {
        let server = MockServer::start().await;
        let container = Url::parse(&format!("{}/container", server.uri())).unwrap();
        let root = tempfile::tempdir().unwrap();
        let selection = PathSelection::default();
        let opts = options(&selection, Some(root.path()));
        let entries = blob("folder/", "v1", 0)
            + &blob("./unsafe.env", "v1", 3)
            + &blob("../unsafe.env", "v1", 3)
            + &blob("nested/../unsafe.env", "v1", 3)
            + &blob("content/", "v1", 3)
            + &blob("empty.env", "v1", 0);
        Mock::given(path("/container"))
            .and(query_param_is_missing("marker"))
            .respond_with(listing(&entries, "next"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container"))
            .and(query_param("marker", "next"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        for (key, body) in [("content/", "key"), ("empty.env", "")] {
            Mock::given(path(format!("/container/{key}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let mut seen = Vec::new();
        assert!(
            visit_with_client(&client(), &StorageAuth::Anonymous, &container, &opts, |key, _| {
                seen.push(key);
                Ok(())
            })
            .await
            .is_err()
        );
        assert_eq!(seen, ["content/", "empty.env"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
        {
            let cache = ObjectCache::open(
                root.path(),
                container.as_str(),
                &(opts.selection, opts.max_object_bytes),
            )
            .unwrap();
            assert_eq!(cache.continuation_token(""), Some("next".into()));
            assert_eq!(cache.completed_objects(), ["content/", "empty.env"]);
        }
        server.verify().await;
        server.reset().await;
        Mock::given(path("/container"))
            .and(query_param("marker", "next"))
            .respond_with(listing("", ""))
            .expect(1)
            .mount(&server)
            .await;
        seen.clear();
        visit_with_client(&client(), &StorageAuth::Anonymous, &container, &opts, |key, _| {
            seen.push(key);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(seen, ["content/", "empty.env"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resumes_pages_replays_complete_report_and_downloads_only_changed_etags() {
        let server = MockServer::start().await;
        let container = Url::parse(&format!("{}/container/", server.uri())).unwrap();
        let cache = tempfile::tempdir().unwrap();
        let selection = PathSelection::default();
        let opts = options(&selection, Some(cache.path()));
        let auth = StorageAuth::Sas(vec![("sig".into(), "secret-sas".into())]);
        Mock::given(path("/container"))
            .and(query_param_is_missing("marker"))
            .respond_with(listing(&blob("first.env", "v1", 3), "page&amp;2"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container"))
            .and(query_param("marker", "page&2"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container/first.env"))
            .and(query_param("sig", "secret-sas"))
            .and(header("if-match", "\"v1\""))
            .respond_with(ResponseTemplate::new(200).set_body_string("one"))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            visit_with_client(&client(), &auth, &container, &opts, |_, _| Ok(())).await.is_err()
        );
        server.verify().await;
        server.reset().await;
        Mock::given(path("/container"))
            .and(query_param("marker", "page&2"))
            .respond_with(listing(&blob("second.env", "v1", 3), ""))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container/second.env"))
            .respond_with(ResponseTemplate::new(200).set_body_string("two"))
            .expect(1)
            .mount(&server)
            .await;
        let mut seen = Vec::new();
        visit_with_client(&client(), &auth, &container, &opts, |key, data| {
            seen.push((key, data));
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            seen,
            [("first.env".into(), b"one".to_vec()), ("second.env".into(), b"two".to_vec())]
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        server.verify().await;
        server.reset().await;
        Mock::given(path("/container"))
            .and(query_param_is_missing("marker"))
            .respond_with(listing(&(blob("first.env", "v1", 3) + &blob("second.env", "v2", 3)), ""))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container/second.env"))
            .and(header("if-match", "\"v2\""))
            .respond_with(ResponseTemplate::new(200).set_body_string("new"))
            .expect(1)
            .mount(&server)
            .await;
        seen.clear();
        visit_with_client(&client(), &auth, &container, &opts, |key, data| {
            seen.push((key, data));
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            seen,
            [("first.env".into(), b"one".to_vec()), ("second.env".into(), b"new".to_vec())]
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        for dir in std::fs::read_dir(cache.path()).unwrap() {
            let manifest =
                std::fs::read_to_string(dir.unwrap().path().join("manifest.json")).unwrap();
            assert!(!manifest.contains("secret-sas"));
        }
    }

    #[tokio::test]
    async fn follows_empty_pages_and_rejects_marker_cycles_and_malformed_xml() {
        let server = MockServer::start().await;
        let container = Url::parse(&format!("{}/container", server.uri())).unwrap();
        let selection = PathSelection::default();
        Mock::given(path("/container"))
            .and(query_param_is_missing("marker"))
            .respond_with(listing("", "next"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container"))
            .and(query_param("marker", "next"))
            .respond_with(listing("", "next"))
            .expect(1)
            .mount(&server)
            .await;
        let error = visit_with_client(
            &client(),
            &StorageAuth::Anonymous,
            &container,
            &options(&selection, None),
            |_, _| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("repeated"));
        server.verify().await;
        server.reset().await;
        Mock::given(path("/container"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<html>secret-server-body</html>"),
            )
            .mount(&server)
            .await;
        let error = visit_with_client(
            &client(),
            &StorageAuth::Anonymous,
            &container,
            &options(&selection, None),
            |_, _| Ok(()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "Invalid Azure Blob XML listing");
    }

    #[tokio::test]
    async fn bounds_throttle_retries_and_never_follows_redirects_or_prints_credentials() {
        let server = MockServer::start().await;
        let url = Url::parse(&format!("{}/container", server.uri())).unwrap();
        let auth = StorageAuth::Sas(vec![("sig".into(), "secret-sas".into())]);
        Mock::given(path("/container"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "0")
                    .set_body_string("secret-body"),
            )
            .expect(4)
            .mount(&server)
            .await;
        let error = get(&client(), &auth, url.clone(), None).await.unwrap_err().to_string();
        assert!(error.contains("429"));
        assert!(!error.contains("secret"));
        server.verify().await;
        server.reset().await;
        Mock::given(path("/container"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/leak", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            get(&client(), &auth, url.clone(), None).await.unwrap_err().to_string().contains("302")
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.verify().await;
        server.reset().await;
        Mock::given(path("/container"))
            .respond_with(ResponseTemplate::new(412).set_body_string("secret-body"))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            get(&client(), &auth, url, Some("\"changed\""))
                .await
                .unwrap_err()
                .to_string()
                .contains("412")
        );
    }

    #[tokio::test]
    async fn enforces_download_size_even_if_listing_understates_length() {
        let server = MockServer::start().await;
        let container = Url::parse(&format!("{}/container", server.uri())).unwrap();
        let selection = PathSelection::default();
        Mock::given(path("/container"))
            .respond_with(listing(&blob("large.env", "v1", 1), ""))
            .mount(&server)
            .await;
        Mock::given(path("/container/large.env"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 101]))
            .mount(&server)
            .await;
        visit_with_client(
            &client(),
            &StorageAuth::Anonymous,
            &container,
            &options(&selection, None),
            |_, _| panic!("oversized body must not be visited"),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn individual_failures_skip_blobs_but_leave_the_failed_page_resumable() {
        let server = MockServer::start().await;
        let container = Url::parse(&format!("{}/container", server.uri())).unwrap();
        let root = tempfile::tempdir().unwrap();
        let selection = PathSelection::default();
        let opts = options(&selection, Some(root.path()));
        Mock::given(path("/container"))
            .and(query_param_is_missing("marker"))
            .respond_with(listing(&blob("first.env", "v1", 3), "next"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container"))
            .and(query_param("marker", "next"))
            .respond_with(listing(
                &(blob("../unsafe.env", "v1", 3)
                    + &blob("private.env", "v1", 3)
                    + &blob("later.env", "v1", 3)),
                "",
            ))
            .expect(1)
            .mount(&server)
            .await;
        for key in ["first.env", "later.env"] {
            Mock::given(path(format!("/container/{key}")))
                .respond_with(ResponseTemplate::new(200).set_body_string("key"))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(path("/container/private.env"))
            .respond_with(ResponseTemplate::new(403).set_body_string("sensitive server body"))
            .expect(1)
            .mount(&server)
            .await;
        let mut keys = Vec::new();
        visit_with_client(&client(), &StorageAuth::Anonymous, &container, &opts, |key, _| {
            keys.push(key);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(keys, ["first.env", "later.env"]);
        {
            let cache = ObjectCache::open(
                root.path(),
                container.as_str(),
                &(opts.selection, opts.max_object_bytes),
            )
            .unwrap();
            assert!(!cache.scope_complete(""));
            assert_eq!(cache.continuation_token(""), Some("next".into()));
            assert_eq!(cache.completed_objects(), ["first.env"]);
        }
        server.verify().await;
        server.reset().await;
        // The successful but uncheckpointed later blob is now gone. It must not survive finish().
        Mock::given(path("/container"))
            .and(query_param("marker", "next"))
            .respond_with(listing("", ""))
            .expect(1)
            .mount(&server)
            .await;
        let mut replayed = Vec::new();
        visit_with_client(&client(), &StorageAuth::Anonymous, &container, &opts, |key, _| {
            replayed.push(key);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(replayed, ["first.env"]);
        let cache = ObjectCache::open(
            root.path(),
            container.as_str(),
            &(opts.selection, opts.max_object_bytes),
        )
        .unwrap();
        assert!(
            cache
                .cached(
                    "later.env",
                    &ObjectVersion {
                        identity: Some("\"v1\"".into()),
                        modified: Some("Wed, 14 Oct 2026 00:00:00 GMT".into()),
                        size: Some(3)
                    }
                )
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn truncated_blob_body_is_skipped_without_committing_the_page() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let container =
            Url::parse(&format!("http://{}/container", listener.local_addr().unwrap())).unwrap();
        let xml = format!(
            "<EnumerationResults><Blobs>{}{}</Blobs><NextMarker /></EnumerationResults>",
            blob("truncated", "v1", 3),
            blob("stable", "v1", 3)
        );
        let responses = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}",
                xml.len()
            ),
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ncut".to_owned(),
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nkey".to_owned(),
        ];
        let server = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut buffer = [0; 1024];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                }
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let root = tempfile::tempdir().unwrap();
        let selection = PathSelection::default();
        let opts = options(&selection, Some(root.path()));
        let mut keys = Vec::new();
        visit_with_client(&client(), &StorageAuth::Anonymous, &container, &opts, |key, _| {
            keys.push(key);
            Ok(())
        })
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(keys, ["stable"]);
        let cache = ObjectCache::open(
            root.path(),
            container.as_str(),
            &(opts.selection, opts.max_object_bytes),
        )
        .unwrap();
        assert!(!cache.scope_complete(""));
        assert!(cache.completed_objects().is_empty());
    }

    #[tokio::test]
    async fn concurrent_replacement_refreshes_cache_identity_and_deletion_does_not_abort() {
        let server = MockServer::start().await;
        let container = Url::parse(&format!("{}/container", server.uri())).unwrap();
        let root = tempfile::tempdir().unwrap();
        let selection = PathSelection::default();
        let opts = options(&selection, Some(root.path()));
        let policy = (opts.selection, opts.max_object_bytes);
        let old_deleted = ObjectVersion { identity: Some("\"old\"".into()), ..Default::default() };
        {
            let mut cache = ObjectCache::open(root.path(), container.as_str(), &policy).unwrap();
            cache.store("deleted.env", old_deleted.clone(), b"old").unwrap();
            cache.finish_page("", None).unwrap();
            cache.finish().unwrap();
        }
        Mock::given(path("/container"))
            .respond_with(listing(
                &(blob("changing.env", "old", 3)
                    + &blob("deleted.env", "v1", 3)
                    + &blob("stable.env", "v1", 3)),
                "",
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container/changing.env"))
            .and(header("if-match", "\"old\""))
            .respond_with(ResponseTemplate::new(412))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container/changing.env"))
            .and(|request: &wiremock::Request| !request.headers.contains_key("if-match"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", "\"current\"")
                    .insert_header("Last-Modified", "Wed, 14 Oct 2026 00:00:00 GMT")
                    .set_body_string("new"),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container/deleted.env"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/container/stable.env"))
            .respond_with(ResponseTemplate::new(200).set_body_string("key"))
            .expect(1)
            .mount(&server)
            .await;
        let mut seen = Vec::new();
        visit_with_client(&client(), &StorageAuth::Anonymous, &container, &opts, |key, data| {
            seen.push((key, data));
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            seen,
            [("changing.env".into(), b"new".to_vec()), ("stable.env".into(), b"key".to_vec())]
        );
        {
            let cache = ObjectCache::open(root.path(), container.as_str(), &policy).unwrap();
            assert!(cache.cached("deleted.env", &old_deleted).unwrap().is_none());
        }
        server.verify().await;
        server.reset().await;
        // A new listing must reuse the replacement under its current identity, never "old".
        Mock::given(path("/container"))
            .respond_with(listing(
                &(blob("changing.env", "current", 3) + &blob("stable.env", "v1", 3)),
                "",
            ))
            .expect(1)
            .mount(&server)
            .await;
        let mut keys = Vec::new();
        visit_with_client(&client(), &StorageAuth::Anonymous, &container, &opts, |key, _| {
            keys.push(key);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(keys, ["changing.env", "stable.env"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
