use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, defaults, meta::region::RegionProviderChain};
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    Client,
    error::ProvideErrorMetadata,                    // for .code()
    operation::list_objects_v2::ListObjectsV2Error, // modeled service error
};
use aws_types::region::Region;
use reqwest; // HTTP client for HEAD fallback
use std::{collections::HashSet, path::Path};
use tracing::warn;

use crate::object_cache::{ObjectCache, ObjectVersion};
pub use crate::path_selection::PathSelection as S3ObjectFilters;

fn object_version(object: &aws_sdk_s3::types::Object) -> ObjectVersion {
    ObjectVersion {
        identity: object.e_tag.clone(),
        modified: object.last_modified.map(|time| time.to_string()),
        size: object.size.and_then(|size| u64::try_from(size).ok()),
    }
}

pub async fn visit_bucket_objects<F>(
    bucket: &str,
    prefix: Option<&str>,
    role_arn: Option<&str>,
    profile: Option<&str>,
    visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    let filters = S3ObjectFilters {
        include_prefixes: prefix.map(str::to_owned).into_iter().collect(),
        ..Default::default()
    };
    visit_bucket_objects_filtered(bucket, &filters, role_arn, profile, visitor).await
}

/// List only included scopes and download objects that pass all configured filters.
pub async fn visit_bucket_objects_filtered<F>(
    bucket: &str,
    filters: &S3ObjectFilters,
    role_arn: Option<&str>,
    profile: Option<&str>,
    visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    visit_bucket_objects_cached(bucket, filters, role_arn, profile, None, None, visitor).await
}

/// Optionally persist listing progress and content to resume interrupted scans
/// and avoid downloading unchanged objects. Cached objects are still scanned.
pub async fn visit_bucket_objects_cached<F>(
    bucket: &str,
    filters: &S3ObjectFilters,
    role_arn: Option<&str>,
    profile: Option<&str>,
    state_dir: Option<&Path>,
    max_object_bytes: Option<u64>,
    visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    filters.check()?;
    // Helper to build ConfigLoader with profile/creds/no_credentials
    let build_loader = || {
        let mut loader = defaults(BehaviorVersion::latest());
        if kingfisher_scanner::validation::limits::NetworkLimits::current().no_timeouts {
            loader = loader
                .timeout_config(aws_sdk_s3::config::timeout::TimeoutConfig::disabled())
                .stalled_stream_protection(
                    aws_sdk_s3::config::StalledStreamProtectionConfig::disabled(),
                );
        }
        if let Some(p) = profile {
            loader = loader.profile_name(p);
        }
        if let (Ok(k), Ok(s)) = (std::env::var("KF_AWS_KEY"), std::env::var("KF_AWS_SECRET")) {
            let session_token = std::env::var("KF_AWS_SESSION_TOKEN").ok();
            loader =
                loader.credentials_provider(Credentials::new(k, s, session_token, None, "kf_env"));
        }
        if profile.is_none() && std::env::var("KF_AWS_KEY").is_err() && role_arn.is_none() {
            loader = loader.no_credentials();
        }
        loader
    };

    // Initial client in default→us-east-1
    let default_region = RegionProviderChain::default_provider().or_else("us-east-1");
    let config = build_loader().region(default_region).load().await;
    let endpoint = configured_endpoint(&config);
    let client = if let Some(role) = role_arn {
        let assume = aws_config::sts::AssumeRoleProvider::builder(role.to_string())
            .session_name("kingfisher")
            .configure(&config)
            .build()
            .await;
        let conf = aws_sdk_s3::config::Builder::from(&config).credentials_provider(assume).build();
        Client::from_conf(conf)
    } else {
        Client::new(&config)
    };

    visit_with_client_cached(
        client,
        bucket,
        filters,
        state_dir,
        max_object_bytes,
        endpoint.as_deref(),
        visitor,
    )
    .await
}

// Match the SDK's endpoint override precedence, including service-specific profile settings.
fn configured_endpoint(config: &aws_types::SdkConfig) -> Option<String> {
    if config.get_origin("endpoint_url").is_client_config() {
        return config.endpoint_url().map(str::to_owned);
    }
    let key = aws_types::service_config::ServiceConfigKey::builder()
        .service_id("S3")
        .env("AWS_ENDPOINT_URL")
        .profile("endpoint_url")
        .build()
        .expect("all service config key fields are set");
    config
        .service_config()
        .and_then(|config| config.load_config(key))
        .or_else(|| config.endpoint_url().map(str::to_owned))
}

fn cache_source(bucket: &str, endpoint: Option<&str>) -> String {
    match endpoint {
        // Persist no credentials or query strings that an endpoint override might contain.
        Some(endpoint) => {
            format!("s3://{bucket}?endpoint={}", blake3::hash(endpoint.as_bytes()).to_hex())
        }
        None => format!("s3://{bucket}"),
    }
}

#[cfg(test)]
async fn visit_with_client<F>(
    client: Client,
    bucket: &str,
    filters: &S3ObjectFilters,
    visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    visit_with_client_cached(client, bucket, filters, None, None, None, visitor).await
}

async fn visit_with_client_cached<F>(
    mut client: Client,
    bucket: &str,
    filters: &S3ObjectFilters,
    state_dir: Option<&Path>,
    max_object_bytes: Option<u64>,
    endpoint: Option<&str>,
    mut visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    filters.check()?;
    let mut state = state_dir
        .map(|dir| {
            ObjectCache::open(dir, &cache_source(bucket, endpoint), &(filters, max_object_bytes))
        })
        .transpose()?;
    if let Some(state) = &state {
        // Replay completed pages into this run's findings before continuing the listing.
        for key in state.completed_objects() {
            visitor(key.clone(), state.read(&key)?)?;
        }
    }
    let mut region_redirected = false;
    for prefix in filters.listing_prefixes(None) {
        if state.as_ref().is_some_and(|state| state.scope_complete(&prefix)) {
            continue;
        }
        let mut continuation_token =
            state.as_ref().and_then(|state| state.continuation_token(&prefix));
        let mut seen_tokens = HashSet::new();
        if let Some(token) = &continuation_token {
            seen_tokens.insert(token.clone());
        }
        loop {
            let mut req = client.list_objects_v2().bucket(bucket);
            if !prefix.is_empty() {
                req = req.prefix(&prefix);
            }
            if let Some(ref token) = continuation_token {
                req = req.continuation_token(token);
            }

            let resp = match req.send().await {
                Ok(r) => r,

                // On error, extract the modeled service error
                Err(err) => {
                    let svc_err: ListObjectsV2Error = err.into_service_error(); // from SdkError

                    // If the bucket must be addressed at another region...
                    if svc_err.code() == Some("PermanentRedirect") && !region_redirected {
                        region_redirected = true;
                        // HEAD request to get x-amz-bucket-region header
                        let url = format!("https://{bucket}.s3.amazonaws.com");
                        let head = reqwest::Client::new()
                            .head(&url)
                            .send()
                            .await
                            .context("Failed to HEAD bucket for region")?;
                        let region_str = head
                            .headers()
                            .get("x-amz-bucket-region")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("us-east-1")
                            .to_string();

                        // Retain the original credential provider, including assumed roles.
                        let conf =
                            client.config().to_builder().region(Region::new(region_str)).build();
                        client = Client::from_conf(conf);
                        // Retry the same scoped page in the correct region.
                        continue;
                    }

                    // Any other error is fatal
                    return Err(svc_err).context("Failed to list objects in bucket");
                }
            };

            // Process objects
            for obj in resp.contents.unwrap_or_default() {
                if let Some(key) = obj.key.as_ref() {
                    let listed_size = object_version(&obj).size;
                    if !filters.matches(key)
                        || (key.ends_with('/') && listed_size == Some(0))
                        || max_object_bytes
                            .is_some_and(|limit| listed_size.is_some_and(|size| size > limit))
                    {
                        continue;
                    }
                    let cached = state
                        .as_ref()
                        .map(|state| state.cached(key, &object_version(&obj)))
                        .transpose()?
                        .flatten();
                    let data = if let Some(data) = cached {
                        data
                    } else {
                        let response = match client
                            .get_object()
                            .bucket(bucket)
                            .key(key)
                            .send()
                            .await
                        {
                            Ok(response) => response,
                            Err(error)
                                if error
                                    .as_service_error()
                                    .is_some_and(|error| error.is_no_such_key())
                                    || error.raw_response().is_some_and(|response| {
                                        response.status().as_u16() == 404
                                    }) =>
                            {
                                warn!(object = %key, "S3 object disappeared after listing; skipping it until the next scan");
                                continue;
                            }
                            Err(error) => {
                                return Err(error)
                                    .with_context(|| format!("Failed to fetch object {key}"));
                            }
                        };
                        if max_object_bytes.is_some_and(|limit| {
                            response
                                .content_length
                                .and_then(|len| u64::try_from(len).ok())
                                .is_some_and(|len| len > limit)
                        }) {
                            continue;
                        }
                        let Some(data) = read_body(response.body, max_object_bytes).await? else {
                            continue;
                        };
                        data
                    };
                    if let Some(state) = &mut state {
                        state.store(key, object_version(&obj), &data)?;
                    }
                    visitor(key.clone(), data)?;
                }
            }

            // Continue or finish pagination
            if resp.is_truncated.unwrap_or(false) {
                let next = resp
                    .next_continuation_token
                    .context("Truncated S3 listing has no continuation token")?;
                anyhow::ensure!(
                    seen_tokens.insert(next.clone()),
                    "S3 listing repeated a continuation token"
                );
                continuation_token = Some(next);
            } else {
                if let Some(state) = &mut state {
                    state.finish_page(&prefix, None)?;
                }
                break;
            }
            if let Some(state) = &mut state {
                state.finish_page(&prefix, continuation_token.clone())?;
            }
        }
    }

    if let Some(state) = &mut state {
        state.finish()?;
    }

    Ok(())
}

async fn read_body(
    mut body: aws_sdk_s3::primitives::ByteStream,
    limit: Option<u64>,
) -> Result<Option<Vec<u8>>> {
    let mut data = Vec::new();
    while let Some(chunk) = body.try_next().await.context("Failed to read S3 object body")? {
        if limit.is_some_and(|limit| data.len() as u64 + chunk.len() as u64 > limit) {
            return Ok(None);
        }
        data.extend_from_slice(&chunk);
    }
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param, query_param_is_missing},
    };

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn client(server: &MockServer) -> Client {
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .endpoint_url(server.uri())
            .force_path_style(true)
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .build();
        Client::from_conf(config)
    }

    #[tokio::test]
    async fn checkpoint_resumes_scopes_and_incremental_downloads_preserve_complete_results() {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let filters = S3ObjectFilters {
            include_prefixes: strings(&["configs/", "deploy/"]),
            ..Default::default()
        };
        Mock::given(method("GET")).and(path("/bucket/")).and(query_param("prefix", "configs/"))
            .and(query_param_is_missing("continuation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>configs/first.env</Key><ETag>v1</ETag></Contents></ListBucketResult>"))
            .expect(1).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/bucket/configs/first.env"))
            .respond_with(ResponseTemplate::new(200).set_body_string("first secret"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("continuation-token", "next"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string("<Error><Code>AccessDenied</Code></Error>"),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            visit_with_client_cached(
                client(&server),
                "bucket",
                &filters,
                Some(directory.path()),
                None,
                Some(&server.uri()),
                |_, _| Ok(())
            )
            .await
            .is_err()
        );
        server.verify().await;
        server.reset().await;

        Mock::given(method("GET")).and(path("/bucket/")).and(query_param("prefix", "configs/"))
            .and(query_param("continuation-token", "next"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>configs/second.env</Key><ETag>v1</ETag></Contents></ListBucketResult>"))
            .expect(1).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/bucket/configs/second.env"))
            .respond_with(ResponseTemplate::new(200).set_body_string("second secret"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/bucket/"))
            .and(query_param("prefix", "deploy/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
            ))
            .expect(1)
            .mount(&server)
            .await;
        let mut replayed = Vec::new();
        visit_with_client_cached(
            client(&server),
            "bucket",
            &filters,
            Some(directory.path()),
            None,
            Some(&server.uri()),
            |key, bytes| {
                replayed.push((key, bytes));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(
            replayed,
            vec![
                ("configs/first.env".into(), b"first secret".to_vec()),
                ("configs/second.env".into(), b"second secret".to_vec())
            ]
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
        server.verify().await;
        server.reset().await;

        // A completed run lists afresh, downloads only a changed version, and
        // excludes deleted objects from the new report.
        Mock::given(method("GET")).and(path("/bucket/")).and(query_param("prefix", "configs/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>configs/first.env</Key><ETag>v1</ETag></Contents><Contents><Key>configs/second.env</Key><ETag>v2</ETag></Contents></ListBucketResult>"))
            .expect(1).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/bucket/configs/second.env"))
            .respond_with(ResponseTemplate::new(200).set_body_string("changed secret"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/bucket/"))
            .and(query_param("prefix", "deploy/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
            ))
            .expect(1)
            .mount(&server)
            .await;
        let mut current = Vec::new();
        visit_with_client_cached(
            client(&server),
            "bucket",
            &filters,
            Some(directory.path()),
            None,
            Some(&server.uri()),
            |key, bytes| {
                current.push((key, bytes));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(
            current,
            vec![
                ("configs/first.env".into(), b"first secret".to_vec()),
                ("configs/second.env".into(), b"changed secret".to_vec())
            ]
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn limits_listed_and_streamed_sizes_and_skips_only_empty_directory_markers() {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let filters = S3ObjectFilters::default();
        let policy = (&filters, Some(10u64));
        let old_version = ObjectVersion { identity: Some("old".into()), ..Default::default() };
        {
            let mut cache = ObjectCache::open(root.path(), "s3://bucket", &policy).unwrap();
            cache.store("deleted", old_version.clone(), b"old").unwrap();
            cache.finish_page("", None).unwrap();
            cache.finish().unwrap();
        }
        Mock::given(path("/bucket/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>listed-large</Key><Size>11</Size></Contents><Contents><Key>understated</Key><Size>1</Size></Contents><Contents><Key>payload/</Key><Size>3</Size></Contents><Contents><Key>marker/</Key><Size>0</Size></Contents><Contents><Key>deleted</Key><Size>3</Size></Contents><Contents><Key>raw-deleted</Key><Size>3</Size></Contents><Contents><Key>boundary</Key><Size>10</Size></Contents></ListBucketResult>"))
            .expect(1).mount(&server).await;
        for (key, data) in
            [("understated", "01234567890"), ("payload/", "key"), ("boundary", "0123456789")]
        {
            Mock::given(path(format!("/bucket/{key}")))
                .respond_with(ResponseTemplate::new(200).set_body_string(data))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(path("/bucket/deleted"))
            .respond_with(
                ResponseTemplate::new(404).set_body_string("<Error><Code>NoSuchKey</Code></Error>"),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/bucket/raw-deleted"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        let mut seen = Vec::new();
        visit_with_client_cached(
            client(&server),
            "bucket",
            &filters,
            Some(root.path()),
            Some(10),
            None,
            |key, data| {
                seen.push((key, data));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(
            seen,
            [("payload/".into(), b"key".to_vec()), ("boundary".into(), b"0123456789".to_vec())]
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 6);
        let cache = ObjectCache::open(root.path(), "s3://bucket", &policy).unwrap();
        assert!(cache.cached("deleted", &old_version).unwrap().is_none());
        // Exercise the streaming guard independently of HTTP Content-Length preflight.
        assert!(
            read_body(aws_sdk_s3::primitives::ByteStream::from_static(b"1234"), Some(3))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            read_body(aws_sdk_s3::primitives::ByteStream::from_static(b"123"), Some(3))
                .await
                .unwrap()
                .unwrap(),
            b"123"
        );
    }

    #[tokio::test]
    async fn matching_bucket_names_and_etags_on_different_endpoints_do_not_share_content() {
        let root = tempfile::tempdir().unwrap();
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        for (server, body) in [(&first, "first endpoint"), (&second, "second endpoint")] {
            Mock::given(path("/bucket/"))
                .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>key</Key><ETag>v1</ETag></Contents></ListBucketResult>"))
                .expect(1).mount(server).await;
            Mock::given(path("/bucket/key"))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(server)
                .await;
            let mut seen = Vec::new();
            visit_with_client_cached(
                client(server),
                "bucket",
                &S3ObjectFilters::default(),
                Some(root.path()),
                None,
                Some(&server.uri()),
                |_, bytes| {
                    seen.push(bytes);
                    Ok(())
                },
            )
            .await
            .unwrap();
            assert_eq!(seen, [body.as_bytes().to_vec()]);
            server.verify().await;
        }
    }

    #[test]
    fn endpoint_identity_respects_sdk_override_precedence_without_persisting_credentials() {
        #[derive(Debug)]
        struct ServiceEndpoint;
        impl aws_types::service_config::LoadServiceConfig for ServiceEndpoint {
            fn load_config(
                &self,
                key: aws_types::service_config::ServiceConfigKey<'_>,
            ) -> Option<String> {
                assert_eq!(key.service_id(), "S3");
                assert_eq!(key.env(), "AWS_ENDPOINT_URL");
                assert_eq!(key.profile(), "endpoint_url");
                Some("https://service.example".into())
            }
        }
        let config = aws_types::SdkConfig::builder()
            .endpoint_url("https://global.example")
            .service_config(ServiceEndpoint)
            .build();
        assert_eq!(configured_endpoint(&config).as_deref(), Some("https://service.example"));
        let mut builder = config.to_builder();
        builder.insert_origin("endpoint_url", aws_types::origin::Origin::shared_config());
        assert_eq!(
            configured_endpoint(&builder.build()).as_deref(),
            Some("https://global.example")
        );
        let source =
            cache_source("bucket", Some("https://user:secret@custom.example/path?token=hidden"));
        assert!(!source.contains("secret"));
        assert!(!source.contains("hidden"));
        assert_ne!(source, cache_source("bucket", Some("https://other.example")));
    }

    #[test]
    fn scopes_collapse_duplicates_and_nested_prefixes() {
        let filters = S3ObjectFilters {
            include_prefixes: strings(&[
                "deploy/",
                "configs/generated/",
                "configs/",
                "configs/",
                "skip/",
            ]),
            exclude_prefixes: strings(&["skip/"]),
            ..Default::default()
        };
        assert_eq!(filters.listing_prefixes(None), strings(&["configs/", "deploy/"]));
        assert_eq!(S3ObjectFilters::default().listing_prefixes(None), strings(&[""]));
    }

    #[test]
    fn filters_use_literal_prefixes_and_case_insensitive_final_extensions() {
        let filters = S3ObjectFilters {
            include_prefixes: strings(&["configs/"]),
            exclude_prefixes: strings(&["configs/generated/"]),
            include_extensions: strings(&[".json", "env", "YAML"]),
            exclude_extensions: strings(&["yaml"]),
        };
        for key in ["configs/settings.JSON", "configs/.env"] {
            assert!(filters.matches(key), "{key}");
        }
        for key in [
            "configs/generated/key.json",
            "configs/key.yaml",
            "Configs/key.json",
            "other/key.json",
            "configs/a.json.bak",
            "configs/",
            "configs/README",
        ] {
            assert!(!filters.matches(key), "{key}");
        }
    }

    #[tokio::test]
    async fn scoped_pagination_filters_before_get_and_does_not_duplicate_objects() {
        let server = MockServer::start().await;
        let filters = S3ObjectFilters {
            include_prefixes: strings(&["configs/", "configs/nested/", "deploy/"]),
            exclude_prefixes: strings(&["configs/generated/"]),
            include_extensions: strings(&["json", ".env"]),
            ..Default::default()
        };
        Mock::given(method("GET")).and(path("/bucket/")).and(query_param("prefix", "configs/"))
            .and(query_param_is_missing("continuation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>page2</NextContinuationToken><Contents><Key>configs/key.json</Key></Contents><Contents><Key>configs/generated/key.json</Key></Contents><Contents><Key>configs/image.png</Key></Contents></ListBucketResult>"))
            .expect(1).mount(&server).await;
        Mock::given(method("GET")).and(path("/bucket/")).and(query_param("prefix", "configs/"))
            .and(query_param("continuation-token", "page2"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>configs/nested/.env</Key></Contents></ListBucketResult>"))
            .expect(1).mount(&server).await;
        Mock::given(method("GET")).and(path("/bucket/")).and(query_param("prefix", "deploy/"))
            .and(query_param_is_missing("continuation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>deploy/key.json</Key></Contents></ListBucketResult>"))
            .expect(1).mount(&server).await;
        for key in ["configs/key.json", "configs/nested/.env", "deploy/key.json"] {
            Mock::given(method("GET"))
                .and(path(format!("/bucket/{key}")))
                .respond_with(ResponseTemplate::new(200).set_body_string("secret fixture"))
                .expect(1)
                .mount(&server)
                .await;
        }
        let mut keys = Vec::new();
        visit_with_client(client(&server), "bucket", &filters, |key, bytes| {
            assert_eq!(bytes, b"secret fixture");
            keys.push(key);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(keys, strings(&["configs/key.json", "configs/nested/.env", "deploy/key.json"]));
        assert_eq!(server.received_requests().await.unwrap().len(), 6);
    }

    #[tokio::test]
    async fn malformed_pagination_and_access_denial_fail_clearly() {
        for body in [
            "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
            "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken></ListBucketResult>",
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/bucket/"))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .mount(&server)
                .await;
            assert!(
                visit_with_client(
                    client(&server),
                    "bucket",
                    &S3ObjectFilters::default(),
                    |_, _| Ok(())
                )
                .await
                .is_err()
            );
            assert!(server.received_requests().await.unwrap().len() <= 2);
        }
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string("<Error><Code>AccessDenied</Code></Error>"),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            visit_with_client(
                client(&server),
                "bucket",
                &S3ObjectFilters::default(),
                |_, _| Ok(())
            )
            .await
            .is_err()
        );
    }
}
