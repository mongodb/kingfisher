use std::{collections::HashSet, path::Path};

use crate::{
    object_cache::{ObjectCache, ObjectVersion},
    path_selection::PathSelection,
};
use anyhow::{Context, Result};
use futures::TryStreamExt;
use gcloud_storage::{
    client::{Client, ClientConfig, google_cloud_auth::credentials::CredentialsFile},
    http::{
        Error as StorageError,
        objects::{
            Object,
            download::Range,
            get::GetObjectRequest,
            list::{ListObjectsRequest, ListObjectsResponse},
        },
    },
};
use tracing::{debug, warn};

fn object_version(object: &Object) -> ObjectVersion {
    ObjectVersion {
        identity: if object.generation > 0 {
            Some(object.generation.to_string())
        } else {
            (!object.etag.is_empty()).then(|| object.etag.clone())
        },
        modified: object.updated.map(|time| time.to_string()),
        size: u64::try_from(object.size).ok(),
    }
}

fn version_disappeared(error: &StorageError) -> bool {
    let code = match error {
        StorageError::Response(response) => Some(response.code),
        StorageError::HttpClient(error) | StorageError::RawResponse(error, _) => {
            error.status().map(|s| s.as_u16())
        }
        _ => None,
    };
    matches!(code, Some(404 | 412))
}

async fn download_current_object(
    client: &Client,
    bucket: &str,
    mut object: Object,
    max_object_bytes: Option<u64>,
) -> Result<Option<(ObjectVersion, Vec<u8>)>> {
    for attempt in 0..=1 {
        if max_object_bytes
            .is_some_and(|limit| object_version(&object).size.is_some_and(|size| size > limit))
        {
            return Ok(None);
        }
        let request = GetObjectRequest {
            bucket: bucket.to_owned(),
            object: object.name.clone(),
            generation: (object.generation > 0).then_some(object.generation),
            ..Default::default()
        };
        match client.download_streamed_object(&request, &Range::default()).await {
            Ok(stream) => {
                futures::pin_mut!(stream);
                let mut data = Vec::new();
                while let Some(chunk) =
                    stream.try_next().await.context("Failed to read GCS object body")?
                {
                    if max_object_bytes
                        .is_some_and(|limit| data.len() as u64 + chunk.len() as u64 > limit)
                    {
                        return Ok(None);
                    }
                    data.extend_from_slice(&chunk);
                }
                return Ok(Some((object_version(&object), data)));
            }
            Err(error) if version_disappeared(&error) => {
                if attempt == 1 {
                    warn!(object = %object.name, "GCS object changed again while downloading; skipping it until the next scan");
                    return Ok(None);
                }
                debug!(object = %object.name, "Listed GCS generation disappeared; refreshing object metadata");
                match client.get_object(&GetObjectRequest { generation: None, ..request }).await {
                    Ok(current) => object = current,
                    Err(error) if version_disappeared(&error) => {
                        warn!(object = %object.name, "GCS object disappeared after listing; skipping it until the next scan");
                        return Ok(None);
                    }
                    Err(error) => {
                        return Err(error).context("Cannot refresh changed GCS object metadata");
                    }
                }
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to fetch object {}", object.name));
            }
        }
    }
    unreachable!()
}

/// Visit every object in the given GCS bucket, optionally filtered by prefix.
///
/// Authentication is attempted via Application Default Credentials. When that
/// fails and no explicit service account path was provided, the client falls
/// back to anonymous access so public buckets can still be scanned.
pub async fn visit_bucket_objects<F>(
    bucket: &str,
    prefix: Option<&str>,
    service_account_path: Option<&Path>,
    visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    visit_bucket_objects_selected(
        bucket,
        prefix,
        service_account_path,
        &PathSelection::default(),
        None,
        None,
        visitor,
    )
    .await
}

pub async fn visit_bucket_objects_selected<F>(
    bucket: &str,
    prefix: Option<&str>,
    service_account_path: Option<&Path>,
    selection: &PathSelection,
    cache_dir: Option<&Path>,
    max_object_bytes: Option<u64>,
    visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    selection.check()?;
    let Some(selection) = selection.within_prefix(prefix) else { return Ok(()) };
    let config_result = if let Some(path) = service_account_path {
        let credentials = CredentialsFile::new_from_file(path.to_string_lossy().into_owned())
            .await
            .with_context(|| {
                format!("Failed to read GCS service account credentials from {}", path.display())
            })?;

        ClientConfig::default().with_credentials(credentials).await
    } else {
        ClientConfig::default().with_auth().await
    };

    let config = match config_result {
        Ok(config) => config,
        Err(err) => {
            if service_account_path.is_some()
                || std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok()
                || std::env::var("GOOGLE_APPLICATION_CREDENTIALS_JSON").is_ok()
            {
                return Err(err)
                    .context("Failed to authenticate with GCS using provided credentials");
            }
            debug!("Falling back to anonymous GCS access: {err}");
            ClientConfig::default().anonymous()
        }
    };

    visit_with_client(
        &Client::new(config),
        bucket,
        &selection,
        cache_dir,
        max_object_bytes,
        visitor,
    )
    .await
}

async fn visit_with_client<F>(
    client: &Client,
    bucket: &str,
    selection: &PathSelection,
    cache_dir: Option<&Path>,
    max_object_bytes: Option<u64>,
    mut visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    let mut cache = cache_dir
        .map(|dir| {
            ObjectCache::open(dir, &format!("gs://{bucket}"), &(selection, max_object_bytes))
        })
        .transpose()?;
    if let Some(cache) = &cache {
        for key in cache.completed_objects() {
            visitor(key.clone(), cache.read(&key)?)?;
        }
    }
    for prefix in selection.listing_prefixes(None) {
        if cache.as_ref().is_some_and(|cache| cache.scope_complete(&prefix)) {
            continue;
        }
        let mut page_token = cache.as_ref().and_then(|cache| cache.continuation_token(&prefix));
        let mut tokens = HashSet::new();
        if let Some(token) = &page_token {
            tokens.insert(token.clone());
        }

        loop {
            let request = ListObjectsRequest {
                bucket: bucket.to_string(),
                prefix: (!prefix.is_empty()).then(|| prefix.clone()),
                page_token: page_token.clone(),
                ..ListObjectsRequest::default()
            };

            let mut response: ListObjectsResponse = client
                .list_objects(&request)
                .await
                .with_context(|| format!("Failed to list objects in bucket {bucket}"))?;

            if let Some(items) = response.items.take() {
                for object in items.into_iter().filter(|o| !o.name.is_empty()) {
                    if !selection.matches(&object.name)
                        || (object.name.ends_with('/') && object.size == 0)
                        || max_object_bytes.is_some_and(|limit| {
                            object_version(&object).size.is_some_and(|size| size > limit)
                        })
                    {
                        continue;
                    }
                    let mut version = object_version(&object);
                    let cached = cache
                        .as_ref()
                        .map(|cache| cache.cached(&object.name, &version))
                        .transpose()?
                        .flatten();
                    let data = if let Some(data) = cached {
                        data
                    } else {
                        let Some((current_version, data)) = download_current_object(
                            client,
                            bucket,
                            object.clone(),
                            max_object_bytes,
                        )
                        .await?
                        else {
                            continue;
                        };
                        version = current_version;
                        data
                    };

                    if let Some(cache) = &mut cache {
                        cache.store(&object.name, version, &data)?;
                    }

                    visitor(object.name, data)?;
                }
            }

            match response.next_page_token {
                Some(token) if !token.is_empty() => {
                    anyhow::ensure!(
                        tokens.insert(token.clone()),
                        "GCS listing repeated a page token"
                    );
                    page_token = Some(token);
                    if let Some(cache) = &mut cache {
                        cache.finish_page(&prefix, page_token.clone())?;
                    }
                }
                _ => {
                    if let Some(cache) = &mut cache {
                        cache.finish_page(&prefix, None)?;
                    }
                    break;
                }
            }
        }
    }
    if let Some(cache) = &mut cache {
        cache.finish()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param, query_param_is_missing},
    };

    fn client(server: &MockServer) -> Client {
        Client::new(ClientConfig {
            storage_endpoint: server.uri(),
            ..ClientConfig::default().anonymous()
        })
    }

    fn object(key: &str, generation: i64) -> serde_json::Value {
        json!({"selfLink":"", "mediaLink":"", "name":key, "id":key, "bucket":"bucket", "metageneration":"1", "generation":generation.to_string(), "size":"6"})
    }

    #[tokio::test]
    async fn focused_listing_resumes_and_uses_generation_cache_without_losing_results() {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        let selection = PathSelection {
            include_prefixes: vec!["configs/".into(), "configs/nested/".into()],
            exclude_prefixes: vec!["configs/generated/".into()],
            include_extensions: vec!["env".into()],
            ..Default::default()
        };
        Mock::given(method("GET")).and(path("/storage/v1/b/bucket/o"))
            .and(query_param("prefix", "configs/")).and(query_param_is_missing("pageToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":[object("configs/first.env",1), object("configs/generated/key.env",1), object("configs/photo.png",1)], "nextPageToken":"next"})))
            .expect(1).mount(&server).await;
        Mock::given(query_param("alt", "media"))
            .and(query_param("generation", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(query_param("pageToken", "next"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            visit_with_client(
                &client(&server),
                "bucket",
                &selection,
                Some(root.path()),
                None,
                |_, _| Ok(())
            )
            .await
            .is_err()
        );
        server.verify().await;
        server.reset().await;
        Mock::given(path("/storage/v1/b/bucket/o"))
            .and(query_param("prefix", "configs/"))
            .and(query_param("pageToken", "next"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items":[object("configs/second.env",1)]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(query_param("alt", "media"))
            .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
            .expect(1)
            .mount(&server)
            .await;
        let mut keys = Vec::new();
        visit_with_client(
            &client(&server),
            "bucket",
            &selection,
            Some(root.path()),
            None,
            |key, _| {
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
        Mock::given(path("/storage/v1/b/bucket/o"))
            .and(query_param("prefix", "configs/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"items":[object("configs/first.env",1), object("configs/second.env",2)]}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(query_param("alt", "media"))
            .and(query_param("generation", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_string("new secret"))
            .expect(1)
            .mount(&server)
            .await;
        let mut bodies = Vec::new();
        visit_with_client(
            &client(&server),
            "bucket",
            &selection,
            Some(root.path()),
            None,
            |_, bytes| {
                bodies.push(bytes);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(bodies, [b"secret".to_vec(), b"new secret".to_vec()]);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn repeated_page_tokens_fail_instead_of_hanging() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items":[],"nextPageToken":"same"})),
            )
            .expect(2)
            .mount(&server)
            .await;
        let error = visit_with_client(
            &client(&server),
            "bucket",
            &PathSelection::default(),
            None,
            None,
            |_, _| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("repeated"));
    }

    #[tokio::test]
    async fn replaced_and_deleted_generations_do_not_abort_other_objects() {
        let server = MockServer::start().await;
        let root = tempfile::tempdir().unwrap();
        Mock::given(path("/storage/v1/b/bucket/o")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":[object("changing.env",1),object("deleted.env",1),object("stable.env",1)]}))).expect(1).mount(&server).await;
        Mock::given(path("/storage/v1/b/bucket/o/changing.env"))
            .and(query_param("alt", "media"))
            .and(query_param("generation", "1"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/storage/v1/b/bucket/o/changing.env"))
            .and(query_param_is_missing("alt"))
            .and(query_param_is_missing("generation"))
            .respond_with(ResponseTemplate::new(200).set_body_json(object("changing.env", 2)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/storage/v1/b/bucket/o/changing.env"))
            .and(query_param("alt", "media"))
            .and(query_param("generation", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_string("newest"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/storage/v1/b/bucket/o/deleted.env"))
            .respond_with(ResponseTemplate::new(404))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(path("/storage/v1/b/bucket/o/stable.env"))
            .and(query_param("generation", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("stable"))
            .expect(1)
            .mount(&server)
            .await;
        let mut seen = Vec::new();
        visit_with_client(
            &client(&server),
            "bucket",
            &PathSelection::default(),
            Some(root.path()),
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
            [
                ("changing.env".into(), b"newest".to_vec()),
                ("stable.env".into(), b"stable".to_vec())
            ]
        );
        server.verify().await;
        server.reset().await;
        Mock::given(path("/storage/v1/b/bucket/o"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"items":[object("changing.env",2),object("stable.env",1)]}),
                ),
            )
            .expect(1)
            .mount(&server)
            .await;
        visit_with_client(
            &client(&server),
            "bucket",
            &PathSelection::default(),
            Some(root.path()),
            None,
            |_, _| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn listed_and_streamed_caps_preserve_nonempty_slash_suffixed_objects() {
        let server = MockServer::start().await;
        let mut listed_large = object("listed-large", 1);
        listed_large["size"] = json!("11");
        let mut marker = object("marker/", 1);
        marker["size"] = json!("0");
        Mock::given(path("/storage/v1/b/bucket/o"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":[listed_large, object("understated",1), object("payload/",1), marker, object("boundary",1)]})))
            .expect(1).mount(&server).await;
        for (key, body) in
            [("understated", "01234567890"), ("payload/", "key"), ("boundary", "0123456789")]
        {
            Mock::given(path(format!("/storage/v1/b/bucket/o/{}", key.replace('/', "%2F"))))
                .and(query_param("alt", "media"))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let mut seen = Vec::new();
        visit_with_client(
            &client(&server),
            "bucket",
            &PathSelection::default(),
            None,
            Some(10),
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
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn replacement_metadata_is_size_checked_before_retrying_download() {
        let server = MockServer::start().await;
        Mock::given(path("/storage/v1/b/bucket/o"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"items":[object("changing",1)]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(query_param("alt", "media"))
            .and(query_param("generation", "1"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        let mut current = object("changing", 2);
        current["size"] = json!("11");
        Mock::given(path("/storage/v1/b/bucket/o/changing"))
            .and(query_param_is_missing("alt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(current))
            .expect(1)
            .mount(&server)
            .await;
        visit_with_client(
            &client(&server),
            "bucket",
            &PathSelection::default(),
            None,
            Some(10),
            |_, _| panic!("oversized replacement must not be visited"),
        )
        .await
        .unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn continuously_changing_generations_are_bounded_but_permission_errors_still_fail() {
        let server = MockServer::start().await;
        Mock::given(path("/storage/v1/b/bucket/o"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items":[object("changing.env",1)]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(query_param("alt", "media"))
            .respond_with(ResponseTemplate::new(412))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(path("/storage/v1/b/bucket/o/changing.env"))
            .and(query_param_is_missing("alt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(object("changing.env", 2)))
            .expect(1)
            .mount(&server)
            .await;
        visit_with_client(
            &client(&server),
            "bucket",
            &PathSelection::default(),
            None,
            None,
            |_, _| panic!("unstable object must not be visited"),
        )
        .await
        .unwrap();
        server.verify().await;
        server.reset().await;
        Mock::given(path("/storage/v1/b/bucket/o"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items":[object("private.env",1)]})),
            )
            .mount(&server)
            .await;
        Mock::given(query_param("alt", "media"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            visit_with_client(
                &client(&server),
                "bucket",
                &PathSelection::default(),
                None,
                None,
                |_, _| Ok(())
            )
            .await
            .is_err()
        );
    }
}
