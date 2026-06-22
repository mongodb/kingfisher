use super::http_validation::{SsrfBlockedError, check_url_resolvable};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation as JwtValidation, decode, decode_header, jwk::JwkSet,
};
use reqwest::{Client, Url, redirect::Policy};
use serde::Deserialize;
use std::sync::{LazyLock, Once};

/// Global redirect-free client with strict TLS validation.
static STRICT_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .redirect(Policy::none())
        .danger_accept_invalid_certs(false)
        .build()
        .expect("failed to build strict Client")
});

/// Global redirect-free client with lax TLS validation (accepts any cert).
static LAX_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .redirect(Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .expect("failed to build lax Client")
});

fn get_client(lax_tls: bool) -> &'static Client {
    if lax_tls { &LAX_CLIENT } else { &STRICT_CLIENT }
}

static JWT_CRYPTO_PROVIDER: Once = Once::new();

pub fn ensure_crypto_provider() {
    JWT_CRYPTO_PROVIDER.call_once(|| {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    });
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Aud {
    Str(String),
    Arr(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct Claims {
    exp: Option<i64>,
    nbf: Option<i64>,
    iss: Option<String>,
    aud: Option<Aud>,
}

#[derive(Clone, Default)]
pub struct ValidateOptions {
    /// If true, accept unsigned tokens (`alg: "none"`) as long as temporal checks pass.
    pub allow_alg_none: bool,
    /// If provided and `iss` is absent, use this key to cryptographically verify the token.
    pub fallback_decoding_key: Option<DecodingKey>,
}

/// Backwards-compatible entry point with secure defaults.
pub async fn validate_jwt(
    token: &str,
    lax_tls: bool,
    allow_internal_ips: bool,
) -> Result<(bool, String)> {
    validate_jwt_with(
        token,
        &ValidateOptions { allow_alg_none: false, fallback_decoding_key: None },
        lax_tls,
        allow_internal_ips,
    )
    .await
}

/// Strict validator with policy control.
pub async fn validate_jwt_with(
    token: &str,
    opts: &ValidateOptions,
    lax_tls: bool,
    allow_internal_ips: bool,
) -> Result<(bool, String)> {
    ensure_crypto_provider();

    let client = get_client(lax_tls);
    let claims: Claims = {
        let payload_b64 = token.split('.').nth(1).ok_or_else(|| anyhow!("invalid JWT format"))?;
        let payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| anyhow!("invalid base64 in payload: {e}"))?;
        serde_json::from_slice(&payload_json).map_err(|e| anyhow!("invalid JSON claims: {e}"))?
    };

    let now = Utc::now().timestamp();
    if let Some(nbf) = claims.nbf
        && now < nbf
    {
        return Ok((false, format!("Token not valid before {nbf}")));
    }
    if let Some(exp) = claims.exp
        && now > exp
    {
        return Ok((false, format!("Token expired at {exp}")));
    }

    let header_b64 = token.split('.').next().ok_or_else(|| anyhow!("invalid JWT format"))?;
    let header_json =
        URL_SAFE_NO_PAD.decode(header_b64).map_err(|e| anyhow!("invalid base64 in header: {e}"))?;
    let header_val: serde_json::Value =
        serde_json::from_slice(&header_json).map_err(|e| anyhow!("invalid header json: {e}"))?;
    let alg_str = header_val.get("alg").and_then(|v| v.as_str()).unwrap_or("");

    if alg_str.eq_ignore_ascii_case("none") {
        if opts.allow_alg_none {
            return Ok((
                true,
                format!(
                    "JWT valid (alg: none, iss: {}, aud: {:?})",
                    claims.iss.clone().unwrap_or_default(),
                    extract_aud_strings(&claims),
                ),
            ));
        } else {
            return Ok((false, "unsigned JWT (alg: none) not allowed".into()));
        }
    }

    let header = decode_header(token).map_err(|e| anyhow!("decode header: {e}"))?;
    let alg = header.alg;

    if matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
        return Ok((false, format!("HMAC-signed JWTs are not validated ({alg:?})")));
    }

    let issuer = claims.iss.clone().unwrap_or_default();
    let aud_strings = extract_aud_strings(&claims);

    if issuer.trim().is_empty() {
        if let Some(decoding_key) = opts.fallback_decoding_key.as_ref() {
            let mut validation = JwtValidation::new(alg);
            if !aud_strings.is_empty() {
                validation.set_audience(&aud_strings);
            }
            validation.validate_exp = false;
            validation.validate_nbf = false;

            decode::<Claims>(token, decoding_key, &validation)
                .map_err(|e| anyhow!("signature verification (fallback key) failed: {e}"))?;

            return Ok((
                true,
                format!("JWT valid via fallback key (alg: {:?}, aud: {:?})", alg, aud_strings),
            ));
        } else {
            return Ok((
                false,
                "issuer (iss) required or a fallback verification key must be provided".into(),
            ));
        }
    }

    let Some(kid) = header.kid.clone() else {
        return Ok((false, "no kid in header".into()));
    };

    let issuer_url = normalize_issuer_url(&issuer)?;
    let config_url =
        format!("{}/.well-known/openid-configuration", issuer_url.as_str().trim_end_matches('/'));
    let cfg_resp = client
        .get(&config_url)
        .send()
        .await
        .map_err(|e| anyhow!("issuer discovery failed: {e}"))?;

    if !cfg_resp.status().is_success() {
        return Ok((false, format!("issuer discovery failed: {}", cfg_resp.status())));
    }

    let cfg_json: serde_json::Value =
        cfg_resp.json().await.map_err(|e| anyhow!("invalid discovery JSON: {e}"))?;

    let jwks_uri = cfg_json
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("jwks_uri missing"))?;

    let url = Url::parse(jwks_uri).map_err(|e| anyhow!("invalid jwks_uri: {e}"))?;
    if url.scheme() != "https" {
        return Ok((false, "jwks_uri must use https".to_string()));
    }

    let iss_host = issuer_url.host_str().unwrap_or_default().to_ascii_lowercase();
    let jwks_host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if jwks_host != iss_host {
        return Ok((
            false,
            format!("jwks_uri host ({jwks_host}) must match issuer host ({iss_host})"),
        ));
    }

    if let Err(e) = check_url_resolvable(&url, allow_internal_ips).await {
        if e.downcast_ref::<SsrfBlockedError>().is_some() {
            return Ok((false, "jwks_uri resolves to non-public or reserved IP".to_string()));
        }
        return Err(anyhow!("jwks uri unresolvable: {e}"));
    }

    let jwks_resp = client.get(url).send().await.map_err(|e| anyhow!("jwks fetch failed: {e}"))?;
    if !jwks_resp.status().is_success() {
        return Ok((false, format!("jwks fetch failed: {}", jwks_resp.status())));
    }

    let jwk_set: JwkSet = jwks_resp.json().await.map_err(|e| anyhow!("invalid jwks json: {e}"))?;

    let jwk = jwk_set
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&kid))
        .ok_or_else(|| anyhow!("kid not found in jwks"))?;

    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| anyhow!("invalid jwk: {e}"))?;
    let mut validation = JwtValidation::new(header.alg);
    if !aud_strings.is_empty() {
        validation.set_audience(&aud_strings);
    }
    validation.validate_exp = false;
    validation.validate_nbf = false;

    decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| anyhow!("signature verification failed: {e}"))?;

    Ok((true, format!("JWT valid (alg: {:?}, iss: {issuer}, aud: {:?})", alg, aud_strings)))
}

fn extract_aud_strings(claims: &Claims) -> Vec<String> {
    match &claims.aud {
        Some(Aud::Str(s)) => vec![s.clone()],
        Some(Aud::Arr(v)) => v.clone(),
        None => vec![],
    }
}

fn normalize_issuer_url(issuer: &str) -> Result<Url> {
    let trimmed = issuer.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("invalid iss: empty issuer"));
    }

    if let Ok(url) = Url::parse(trimmed)
        && url.host_str().is_some()
    {
        return Ok(url);
    }

    if !trimmed.contains("://") {
        let with_https = format!("https://{trimmed}");
        let url = Url::parse(&with_https).map_err(|e| anyhow!("invalid iss: {e}"))?;
        if url.host_str().is_some() {
            return Ok(url);
        }
    }

    Err(anyhow!("invalid iss: missing host"))
}
