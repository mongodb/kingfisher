//! Only the read-only Storage JSON API operations used by the scanner.
//!
//! Credential discovery, signing, token reuse and refresh remain entirely with
//! gcloud-auth; this module only adds authentication headers to storage requests.

use std::sync::Arc;

use futures::Stream;
use gcloud_auth::{
    credentials::CredentialsFile, project::Config, token::DefaultTokenSourceProvider,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{RequestBuilder, Response, StatusCode, header::AUTHORIZATION};
use serde::{Deserialize, Deserializer, Serialize};
use token_source::{TokenSource, TokenSourceProvider};

// Preserve the scopes used by the previous storage client, including ADC and
// service-account flows. Do not implement OAuth, JWT signing or refresh here.
const SCOPES: [&str; 2] = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/devstorage.full_control",
];
const PATH_ESCAPE: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'*').remove(b'-').remove(b'.').remove(b'_');

fn auth_config() -> Config<'static> {
    Config::default().with_scopes(&SCOPES)
}

pub(super) struct ClientConfig {
    pub(super) storage_endpoint: String,
    pub(super) token_source_provider: Option<Box<dyn TokenSourceProvider>>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            storage_endpoint: "https://storage.googleapis.com".into(),
            token_source_provider: None,
        }
    }
}

impl ClientConfig {
    pub(super) fn anonymous(mut self) -> Self {
        self.token_source_provider = None;
        self
    }

    pub(super) async fn with_auth(mut self) -> Result<Self, gcloud_auth::error::Error> {
        let provider = DefaultTokenSourceProvider::new(auth_config()).await?;
        self.token_source_provider = Some(Box::new(provider));
        Ok(self)
    }

    pub(super) async fn with_credentials(
        mut self,
        credentials: CredentialsFile,
    ) -> Result<Self, gcloud_auth::error::Error> {
        let provider =
            DefaultTokenSourceProvider::new_with_credentials(auth_config(), Box::new(credentials))
                .await?;
        self.token_source_provider = Some(Box::new(provider));
        Ok(self)
    }
}

pub(super) struct Client {
    http: reqwest::Client,
    endpoint: String,
    token_source: Option<Arc<dyn TokenSource>>,
}

impl Client {
    pub(super) fn new(config: ClientConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint: format!("{}/storage/v1", config.storage_endpoint.trim_end_matches('/')),
            token_source: config.token_source_provider.map(|provider| provider.token_source()),
        }
    }

    fn objects_url(&self, bucket: &str, object: Option<&str>) -> String {
        let mut url =
            format!("{}/b/{}/o", self.endpoint, utf8_percent_encode(bucket, PATH_ESCAPE),);
        if let Some(object) = object {
            url.push('/');
            url.push_str(&utf8_percent_encode(object, PATH_ESCAPE).to_string());
        }
        url
    }

    async fn send(&self, builder: RequestBuilder) -> Result<Response, Error> {
        let mut builder = builder
            .header("X-Goog-Api-Client", "rust")
            .header(reqwest::header::USER_AGENT, concat!("kingfisher/", env!("CARGO_PKG_VERSION")));
        if let Some(source) = &self.token_source {
            let token = source.token().await.map_err(Error::TokenSource)?;
            builder = builder.header(AUTHORIZATION, token);
        }
        let response = builder.send().await?;
        let error = match response.error_for_status_ref() {
            Ok(_) => return Ok(response),
            Err(error) => error,
        };
        let status = response.status();
        match response.json::<ErrorResponse>().await {
            Ok(body) => Err(Error::Response { status, message: body.error.message }),
            Err(_) => Err(Error::HttpClient(error)),
        }
    }

    pub(super) async fn list_objects(
        &self,
        request: &ListObjectsRequest,
    ) -> Result<ListObjectsResponse, Error> {
        let builder = self.http.get(self.objects_url(&request.bucket, None)).query(request);
        Ok(self.send(builder).await?.json().await?)
    }

    pub(super) async fn get_object(&self, request: &GetObjectRequest) -> Result<Object, Error> {
        let builder =
            self.http.get(self.objects_url(&request.bucket, Some(&request.object))).query(request);
        Ok(self.send(builder).await?.json().await?)
    }

    pub(super) async fn download_streamed_object(
        &self,
        request: &GetObjectRequest,
    ) -> Result<impl Stream<Item = Result<bytes::Bytes, reqwest::Error>> + use<>, Error> {
        let builder = self
            .http
            .get(self.objects_url(&request.bucket, Some(&request.object)))
            .query(&[("alt", "media")])
            .query(request);
        Ok(self.send(builder).await?.bytes_stream())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct Object {
    pub(super) name: String,
    #[serde(deserialize_with = "from_i64_string")]
    pub(super) generation: i64,
    #[serde(default, deserialize_with = "from_i64_string")]
    pub(super) size: i64,
    #[serde(default)]
    pub(super) etag: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub(super) updated: Option<time::OffsetDateTime>,
}

fn from_i64_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ListObjectsRequest {
    #[serde(skip_serializing)]
    pub(super) bucket: String,
    pub(super) prefix: Option<String>,
    pub(super) page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ListObjectsResponse {
    pub(super) items: Option<Vec<Object>>,
    pub(super) next_page_token: Option<String>,
}

#[derive(Default, Serialize)]
pub(super) struct GetObjectRequest {
    #[serde(skip_serializing)]
    pub(super) bucket: String,
    #[serde(skip_serializing)]
    pub(super) object: String,
    pub(super) generation: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error(transparent)]
    HttpClient(#[from] reqwest::Error),
    #[error("{message} (GCS HTTP {status})")]
    Response { status: StatusCode, message: String },
    #[error("GCS token source failed: {0}")]
    TokenSource(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    pub(super) fn status(&self) -> Option<StatusCode> {
        match self {
            Self::HttpClient(error) => error.status(),
            Self::Response { status, .. } => Some(*status),
            Self::TokenSource(_) => None,
        }
    }
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: ErrorMessage,
}

#[derive(Deserialize)]
struct ErrorMessage {
    message: String,
}
