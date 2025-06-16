use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration as ChronoDuration, Utc};
use pem::parse;
use reqwest::Client;
use ring::{rand, signature};
use serde_json::Value as JsonValue;
use tokio::sync::Semaphore;
use tracing::debug;

pub struct GcpValidator {
    semaphore: Arc<Semaphore>,
}

/// Generate a standardized cache key for GCP validation attempts.
pub fn generate_gcp_cache_key(gcp_json: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(gcp_json.as_bytes());
    format!("GCP:{:x}", hasher.finalize())
}

impl GcpValidator {
    pub fn new() -> Result<Self> {
        const MAX_CONCURRENT_VALIDATIONS: usize = 500;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS));
        Ok(Self { semaphore })
    }

    pub async fn validate_gcp_credentials(&self, gcp_json: &[u8]) -> Result<(bool, Vec<String>)> {
        let _permit = self.semaphore.acquire().await?;
        let gcp_json_str = String::from_utf8_lossy(gcp_json);
        let token_info: JsonValue = serde_json::from_str(&gcp_json_str)?;

        // Extract required fields.
        let project_id = token_info["project_id"].as_str().unwrap_or("");
        let client_email = token_info["client_email"].as_str().unwrap_or("");
        let private_key = token_info["private_key"].as_str().unwrap_or("");
        let token_uri = token_info["token_uri"].as_str().unwrap_or("");
        if project_id.is_empty()
            || client_email.is_empty()
            || private_key.is_empty()
            || token_uri.is_empty()
        {
            debug!(
                "Missing required GCP fields: project_id='{}', client_email='{}', private_key present={}, token_uri='{}'",
                project_id,
                client_email,
                !private_key.is_empty(),
                token_uri
            );
            return Ok((false, vec![]));
        }

        // Generate JWT
        let jwt = self.create_jwt(client_email, private_key, token_uri)?;

        // Request an access token
        let client = Client::new();
        let response = client
            .post(token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await?;
        if response.status().is_success() {
            let metadata = vec![
                "GCP Credential Type == service_account".to_string(),
                format!("GCP Project ID == {}", project_id),
                format!("GCP Client Email == {}", client_email),
            ];
            Ok((true, metadata))
        } else {
            Err(anyhow!("Failed to validate GCP credentials"))
        }
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

        // JWT Header and Claims.
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

        // Parse PEM and create RSA key pair.
        let pem = parse(private_key_pem).map_err(|e| anyhow!("Failed to parse PEM: {}", e))?;
        let key_pair = signature::RsaKeyPair::from_pkcs8(&pem.contents())
            .map_err(|_| anyhow!("Invalid RSA private key"))?;

        // Sign the message.
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; key_pair.public().modulus_len()];
        key_pair
            .sign(&signature::RSA_PKCS1_SHA256, &rng, message.as_bytes(), &mut signature)
            .map_err(|_| anyhow!("Failed to sign JWT"))?;
        let signature_encoded = URL_SAFE_NO_PAD.encode(&signature);
        Ok(format!("{}.{}.{}", header, claims_encoded, signature_encoded))
    }
}
