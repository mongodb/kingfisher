use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use chrono::Utc;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use uuid::Uuid;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const STS_API: &str = "https://sts.aliyuncs.com/";
const ALIBABA_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'*')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Debug, Deserialize)]
struct CallerIdentity {
    #[serde(rename = "IdentityType", default)]
    identity_type: Option<String>,
    #[serde(rename = "AccountId", default)]
    account_id: Option<String>,
    #[serde(rename = "Arn", default)]
    arn: Option<String>,
    #[serde(rename = "UserId", default)]
    user_id: Option<String>,
    #[serde(rename = "PrincipalId", default)]
    principal_id: Option<String>,
    #[serde(rename = "RoleId", default)]
    role_id: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Alibaba access-map requires a credential file with an access key pair")
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read Alibaba credential file from {}", path.display())
    })?;
    let (access_key, secret_key, session_token) = parse_alibaba_credentials(&raw)?;
    map_access_with_credentials(&access_key, &secret_key, session_token.as_deref()).await
}

pub async fn map_access_with_credentials(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Alibaba HTTP client")?;

    let caller = fetch_caller_identity(&client, access_key, secret_key, session_token).await?;
    let identity_type = caller.identity_type.clone().unwrap_or_else(|| "Unknown".to_string());
    let severity = derive_severity(&identity_type, session_token);

    let identity_id = caller
        .arn
        .clone()
        .or_else(|| caller.principal_id.clone())
        .or_else(|| caller.user_id.clone())
        .unwrap_or_else(|| access_key.to_string());
    let account_id = caller.account_id.clone();

    let identity = AccessSummary {
        id: identity_id.clone(),
        access_type: normalize_identity_type(&identity_type),
        project: None,
        tenant: None,
        account_id: account_id.clone(),
    };

    let principal_name = caller
        .arn
        .as_deref()
        .and_then(extract_principal_name)
        .or_else(|| caller.user_id.clone())
        .or_else(|| caller.principal_id.clone());

    let roles = vec![RoleBinding {
        name: principal_name.clone().unwrap_or_else(|| identity_type.clone()),
        source: "sts".into(),
        permissions: Vec::new(),
    }];

    let permissions = PermissionSummary::default();
    let mut resources = Vec::new();
    if let Some(account_id) = account_id.clone() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: account_id,
            permissions: Vec::new(),
            risk: severity_to_str(severity).to_string(),
            reason: "Alibaba Cloud account resolved from STS GetCallerIdentity".into(),
        });
    }
    if let Some(arn) = caller.arn.clone() {
        let (resource_type, resource_name) = classify_principal_resource(&arn);
        resources.push(ResourceExposure {
            resource_type: resource_type.into(),
            name: resource_name,
            permissions: Vec::new(),
            risk: severity_to_str(severity).to_string(),
            reason: "Alibaba Cloud principal resolved from STS GetCallerIdentity".into(),
        });
    }
    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "principal".into(),
            name: identity_id.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(severity).to_string(),
            reason: "Alibaba Cloud identity resolved from STS GetCallerIdentity".into(),
        });
    }

    let mut risk_notes = vec![
        "Alibaba access-map currently resolves caller identity from STS; broad service-level resource enumeration is not yet available."
            .to_string(),
    ];
    if session_token.is_some() || identity_type.eq_ignore_ascii_case("AssumedRoleUser") {
        risk_notes.push(
            "Credential is an STS temporary session; review the assumed role policy and expiration."
                .into(),
        );
    } else {
        risk_notes.push(
            "Credential is a long-lived access key pair; rotate it promptly if exposure is confirmed."
                .into(),
        );
    }
    if identity_type.eq_ignore_ascii_case("Account") {
        risk_notes.push(
            "Credential belongs to the Alibaba Cloud account principal and may grant broad account-level access."
                .into(),
        );
    }
    if caller.role_id.is_some() {
        risk_notes.push("Caller identity includes a RAM role context.".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "alibaba".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: principal_name,
            username: caller.user_id.clone(),
            account_type: Some(identity_type.clone()),
            company: None,
            location: None,
            email: None,
            url: Some(STS_API.into()),
            token_type: Some(if session_token.is_some() {
                "sts_access_key".into()
            } else {
                "access_key".into()
            }),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: caller.principal_id.or(caller.user_id),
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_caller_identity(
    client: &Client,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> Result<CallerIdentity> {
    let url = signed_sts_url(access_key, secret_key, session_token)?;
    let resp = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Alibaba access-map: failed to call STS GetCallerIdentity")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Alibaba access-map: STS GetCallerIdentity failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Alibaba access-map: invalid STS GetCallerIdentity JSON")
}

fn signed_sts_url(access_key: &str, secret_key: &str, session_token: Option<&str>) -> Result<Url> {
    let mut params = BTreeMap::from([
        ("AccessKeyId".to_string(), access_key.to_string()),
        ("Action".to_string(), "GetCallerIdentity".to_string()),
        ("Format".to_string(), "JSON".to_string()),
        ("SignatureMethod".to_string(), "HMAC-SHA1".to_string()),
        ("SignatureNonce".to_string(), Uuid::new_v4().to_string().to_uppercase()),
        ("SignatureVersion".to_string(), "1.0".to_string()),
        ("Timestamp".to_string(), Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        ("Version".to_string(), "2015-04-01".to_string()),
    ]);
    if let Some(token) = session_token {
        params.insert("SecurityToken".to_string(), token.to_string());
    }

    let canonical_query = canonical_query_string(&params);
    let string_to_sign = format!("GET&%2F&{}", encode_openapi(&canonical_query));
    let signature =
        b64.encode(hmac_sha1(format!("{secret_key}&").as_bytes(), string_to_sign.as_bytes()));
    params.insert("Signature".to_string(), signature);

    let mut url = Url::parse(STS_API).expect("valid Alibaba STS URL");
    for (key, value) in params {
        url.query_pairs_mut().append_pair(&key, &value);
    }
    Ok(url)
}

fn canonical_query_string(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", encode_openapi(key), encode_openapi(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_openapi(value: &str) -> String {
    utf8_percent_encode(value, ALIBABA_ENCODE_SET).to_string()
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;

    let mut normalized_key =
        if key.len() > BLOCK_SIZE { Sha1::digest(key).to_vec() } else { key.to_vec() };
    normalized_key.resize(BLOCK_SIZE, 0);

    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    for (index, byte) in normalized_key.iter().enumerate() {
        inner_pad[index] ^= *byte;
        outer_pad[index] ^= *byte;
    }

    let mut inner = Sha1::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().to_vec()
}

fn parse_alibaba_credentials(raw: &str) -> Result<(String, String, Option<String>)> {
    if let Ok(json) = serde_json::from_str::<Value>(raw) {
        let access_key = value_as_string(
            &json,
            &[
                "access_key_id",
                "accessKeyId",
                "AccessKeyId",
                "alibaba_access_key_id",
                "alibabacloud_access_key_id",
                "aliyun_access_key_id",
            ],
        );
        let secret_key = value_as_string(
            &json,
            &[
                "access_key_secret",
                "accessKeySecret",
                "AccessKeySecret",
                "secret_access_key",
                "secretAccessKey",
                "SecretAccessKey",
                "alibaba_access_key_secret",
                "alibabacloud_access_key_secret",
                "aliyun_access_key_secret",
            ],
        );
        let session_token = value_as_string(
            &json,
            &[
                "security_token",
                "securityToken",
                "SecurityToken",
                "session_token",
                "sessionToken",
                "SessionToken",
            ],
        );

        if let (Some(access_key), Some(secret_key)) = (access_key, secret_key) {
            return Ok((access_key, secret_key, session_token));
        }
    }

    let mut kv = BTreeMap::new();
    for line in raw.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            kv.insert(key.trim().to_ascii_lowercase(), value.trim().trim_matches('"').to_string());
        } else if let Some((key, value)) = line.split_once(':') {
            kv.insert(key.trim().to_ascii_lowercase(), value.trim().trim_matches('"').to_string());
        }
    }

    let access_key = first_present(
        &kv,
        &[
            "accesskeyid",
            "access_key_id",
            "alibaba_access_key_id",
            "alibabacloud_access_key_id",
            "aliyun_access_key_id",
        ],
    );
    let secret_key = first_present(
        &kv,
        &[
            "accesskeysecret",
            "access_key_secret",
            "secret_access_key",
            "alibaba_access_key_secret",
            "alibabacloud_access_key_secret",
            "aliyun_access_key_secret",
        ],
    );
    let session_token =
        first_present(&kv, &["securitytoken", "security_token", "sessiontoken", "session_token"]);

    if let (Some(access_key), Some(secret_key)) = (access_key, secret_key) {
        return Ok((access_key, secret_key, session_token));
    }

    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    match lines.as_slice() {
        [access_key, secret_key] => {
            Ok(((*access_key).to_string(), (*secret_key).to_string(), None))
        }
        [access_key, secret_key, session_token, ..] => Ok((
            (*access_key).to_string(),
            (*secret_key).to_string(),
            Some((*session_token).to_string()),
        )),
        _ => Err(anyhow!(
            "Alibaba access-map credential file must contain an access key ID and access key secret"
        )),
    }
}

fn value_as_string(json: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        json.get(*key)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

fn first_present(map: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| map.get(*key).cloned()).filter(|value| !value.is_empty())
}

fn normalize_identity_type(identity_type: &str) -> String {
    match identity_type {
        value if value.eq_ignore_ascii_case("Account") => "account".into(),
        value if value.eq_ignore_ascii_case("RAMUser") => "ram_user".into(),
        value if value.eq_ignore_ascii_case("AssumedRoleUser") => "assumed_role_user".into(),
        value => value.to_ascii_lowercase(),
    }
}

fn derive_severity(identity_type: &str, session_token: Option<&str>) -> Severity {
    if identity_type.eq_ignore_ascii_case("Account") {
        Severity::Critical
    } else if session_token.is_some() || identity_type.eq_ignore_ascii_case("AssumedRoleUser") {
        Severity::Medium
    } else {
        Severity::High
    }
}

fn classify_principal_resource(arn: &str) -> (&'static str, String) {
    let resource = arn.splitn(5, ':').last().unwrap_or_default();
    let mut parts = resource.splitn(2, '/');
    let kind = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or(resource);
    let resource_type = match kind {
        "user" => "ram_user",
        "role" => "ram_role",
        "assumed-role" => "ram_assumed_role",
        "root" | "account" => "account",
        _ => "principal",
    };
    let name = if rest.is_empty() { arn.to_string() } else { rest.to_string() };
    (resource_type, name)
}

fn extract_principal_name(arn: &str) -> Option<String> {
    let (_, name) = classify_principal_resource(arn);
    (!name.is_empty()).then_some(name)
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_credentials_with_security_token() {
        let raw = r#"{
            "AccessKeyId": "STS.example",
            "AccessKeySecret": "secret-value",
            "SecurityToken": "token-value"
        }"#;

        let (access_key, secret_key, session_token) =
            parse_alibaba_credentials(raw).expect("credentials should parse");
        assert_eq!(access_key, "STS.example");
        assert_eq!(secret_key, "secret-value");
        assert_eq!(session_token.as_deref(), Some("token-value"));
    }

    #[test]
    fn parses_key_value_credentials() {
        let raw = r#"
            access_key_id=LTAIexample
            access_key_secret=secret-value
        "#;

        let (access_key, secret_key, session_token) =
            parse_alibaba_credentials(raw).expect("credentials should parse");
        assert_eq!(access_key, "LTAIexample");
        assert_eq!(secret_key, "secret-value");
        assert!(session_token.is_none());
    }

    #[test]
    fn classifies_principal_resource_from_arn() {
        let (resource_type, name) =
            classify_principal_resource("acs:ram::1234567890123456:user/admin");
        assert_eq!(resource_type, "ram_user");
        assert_eq!(name, "admin");
    }
}
