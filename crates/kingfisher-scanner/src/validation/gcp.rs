use std::sync::{Arc, OnceLock};

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration as ChronoDuration, Utc};
use pem::parse;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, Proxy};
use ring::{rand, signature};
use serde_json::Value as JsonValue;
use tokio::sync::Semaphore;
use tracing::debug;

use super::GLOBAL_USER_AGENT;

static GLOBAL_VALIDATOR: OnceLock<GcpValidator> = OnceLock::new();

pub struct GcpValidator {
    semaphore: Arc<Semaphore>,
    client: Client,
}

/// Context returned after exchanging a service account key for an access token.
#[derive(Debug, Clone)]
pub struct GcpTokenContext {
    pub access_token: String,
    pub project_id: String,
    pub client_email: String,
}

/// Result of a GCP service account key revocation attempt.
#[derive(Debug, Clone)]
pub struct GcpRevocationOutcome {
    pub revoked: bool,
    pub status_code: Option<u16>,
    pub message: String,
}

impl GcpValidator {
    pub fn global() -> Result<&'static Self> {
        if let Some(v) = GLOBAL_VALIDATOR.get() {
            return Ok(v);
        }
        let v = Self::new()?;
        Ok(GLOBAL_VALIDATOR.get_or_init(|| v))
    }

    /// Retrieve a reference to the underlying HTTP client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Given a service account key JSON blob, mint an OAuth2 access token and return
    /// the token alongside basic identity details.
    pub async fn get_access_token_from_sa_json(&self, gcp_json: &str) -> Result<GcpTokenContext> {
        let _permit = self.semaphore.acquire().await?;
        let token_info: JsonValue = serde_json::from_str(gcp_json)?;

        let project_id = token_info["project_id"].as_str().unwrap_or("").to_string();
        let client_email = token_info["client_email"].as_str().unwrap_or("").to_string();
        let private_key = token_info["private_key"].as_str().unwrap_or("").to_string();
        let token_uri = token_info["token_uri"].as_str().unwrap_or("").to_string();

        if project_id.is_empty()
            || client_email.is_empty()
            || private_key.is_empty()
            || token_uri.is_empty()
        {
            return Err(anyhow!(
                "Missing required GCP fields: project_id/client_email/private_key/token_uri"
            ));
        }

        let jwt = self.create_jwt(&client_email, &private_key, &token_uri)?;
        let response = self
            .client
            .post(&token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await?
            .error_for_status()?;

        let json: JsonValue = response.json().await?;
        let access_token = json["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing access_token in GCP response"))?
            .to_string();

        Ok(GcpTokenContext { access_token, project_id, client_email })
    }
}

/// Revoke a GCP service account key using the IAM API.
pub async fn revoke_gcp_service_account_key(
    gcp_json: &str,
    key_id_override: Option<&str>,
) -> Result<GcpRevocationOutcome> {
    let validator = GcpValidator::global()?;
    let token_info: JsonValue = serde_json::from_str(gcp_json)?;

    let project_id = token_info["project_id"].as_str().unwrap_or("").to_string();
    let client_email = token_info["client_email"].as_str().unwrap_or("").to_string();
    let mut key_id = token_info["private_key_id"].as_str().unwrap_or("").to_string();
    if let Some(override_id) = key_id_override
        && !override_id.trim().is_empty()
    {
        key_id = override_id.trim().to_string();
    }

    if project_id.is_empty() || client_email.is_empty() || key_id.is_empty() {
        return Err(anyhow!("Missing required GCP fields: project_id/client_email/private_key_id"));
    }

    let ctx = validator.get_access_token_from_sa_json(gcp_json).await?;
    let encode = |value: &str| utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
    let url = format!(
        "https://iam.googleapis.com/v1/projects/{}/serviceAccounts/{}/keys/{}",
        encode(&project_id),
        encode(&client_email),
        encode(&key_id),
    );

    let response = validator.client().delete(url).bearer_auth(&ctx.access_token).send().await?;

    let status = response.status();
    let body =
        response.text().await.unwrap_or_else(|e| format!("Failed to read response body: {}", e));
    let message = if body.trim().is_empty() { status.to_string() } else { body };

    Ok(GcpRevocationOutcome {
        revoked: status.is_success(),
        status_code: Some(status.as_u16()),
        message,
    })
}

/// Generate a standardized cache key for GCP validation attempts.
pub fn generate_gcp_cache_key(gcp_json: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(gcp_json.as_bytes());
    format!("GCP:{}", hex::encode(hasher.finalize()))
}

impl GcpValidator {
    pub fn new() -> Result<Self> {
        const MAX_CONCURRENT_VALIDATIONS: usize = 500;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS));
        let mut builder = Client::builder();

        if let Ok(proxy) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) {
            builder = builder.proxy(Proxy::all(&proxy)?);
        }

        let client = builder.user_agent(GLOBAL_USER_AGENT.as_str()).build()?;
        Ok(Self { semaphore, client })
    }

    pub async fn validate_gcp_credentials(&self, gcp_json: &[u8]) -> Result<(bool, Vec<String>)> {
        let gcp_json_str = String::from_utf8_lossy(gcp_json);
        let ctx = match self.get_access_token_from_sa_json(&gcp_json_str).await {
            Ok(ctx) => ctx,
            Err(err) => {
                debug!("Missing required GCP fields: {err}");
                return Ok((false, vec![]));
            }
        };

        let metadata = vec![
            "GCP Credential Type == service_account".to_string(),
            format!("GCP Project ID == {}", ctx.project_id),
            format!("GCP Client Email == {}", ctx.client_email),
        ];

        Ok((true, metadata))
    }

    fn create_jwt(
        &self,
        client_email: &str,
        private_key_pem: &str,
        token_uri: &str,
    ) -> Result<String> {
        let now = Utc::now();
        let iat = now.timestamp();
        let exp = (now + ChronoDuration::hours(1)).timestamp();

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = format!(
            r#"{{
                "iss": "{}",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "aud": "{}",
                "exp": {},
                "iat": {}
            }}"#,
            client_email, token_uri, exp, iat
        );
        let claims_encoded = URL_SAFE_NO_PAD.encode(claims);
        let message = format!("{}.{}", header, claims_encoded);

        let pem = parse(private_key_pem).map_err(|e| anyhow!("Failed to parse PEM: {}", e))?;
        let key_pair = signature::RsaKeyPair::from_pkcs8(pem.contents())
            .map_err(|_| anyhow!("Invalid RSA private key"))?;

        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; key_pair.public().modulus_len()];
        key_pair
            .sign(&signature::RSA_PKCS1_SHA256, &rng, message.as_bytes(), &mut signature)
            .map_err(|_| anyhow!("Failed to sign JWT"))?;
        let signature_encoded = URL_SAFE_NO_PAD.encode(&signature);
        Ok(format!("{}.{}.{}", header, claims_encoded, signature_encoded))
    }
}
