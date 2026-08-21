use anyhow::{Context, Result, anyhow};
use http::StatusCode;
use tracing::debug;
use url::Url;
use xxhash_rust::xxh3::xxh3_64;

use super::postgres;

/// Result of attempting to validate a JDBC connection string.
pub struct JdbcValidationOutcome {
    pub valid: bool,
    pub status: StatusCode,
    pub message: String,
}

/// Produce a short-lived cache key for JDBC validations.
pub fn generate_jdbc_cache_key(raw: &str) -> String {
    format!("Jdbc:{:016x}", xxh3_64(raw.as_bytes()))
}

/// Validate a JDBC connection string by dispatching to the supported backend validators.
pub async fn validate_jdbc(
    jdbc_conn: &str,
    lax_tls: bool,
    allow_internal_ips: bool,
) -> Result<JdbcValidationOutcome> {
    let trimmed = jdbc_conn.trim();
    if !trimmed.to_ascii_lowercase().starts_with("jdbc:") {
        return Err(anyhow!("JDBC connection string must start with `jdbc:`"));
    }

    let without_prefix = &trimmed[5..];
    let (raw_subprotocol, subname) = without_prefix
        .split_once(':')
        .ok_or_else(|| anyhow!("JDBC connection string is missing a subprotocol"))?;
    let subprotocol = raw_subprotocol.trim();
    let subprotocol_lower = subprotocol.to_ascii_lowercase();

    match subprotocol_lower.as_str() {
        "postgres" | "postgresql" | "postgis" => {
            validate_postgres_jdbc(subname, lax_tls, allow_internal_ips)
                .await
                .context("Postgres JDBC validation failed")
        }
        other => {
            debug!("Unsupported JDBC subprotocol encountered: {}", other);
            Ok(JdbcValidationOutcome {
                valid: false,
                status: StatusCode::NOT_IMPLEMENTED,
                message: format!(
                    "JDBC validation not implemented for subprotocol `{}`.",
                    subprotocol
                ),
            })
        }
    }
}

async fn validate_postgres_jdbc(
    subname: &str,
    lax_tls: bool,
    allow_internal_ips: bool,
) -> Result<JdbcValidationOutcome> {
    let normalized = normalize_postgres_url(subname)?;
    let (ok, meta) = postgres::validate_postgres(&normalized, lax_tls, allow_internal_ips).await?;

    let mut message = if ok {
        "JDBC Postgres connection is valid.".to_string()
    } else {
        "JDBC Postgres connection failed.".to_string()
    };

    if !meta.is_empty() {
        let joined = meta.join("; ");
        if ok {
            message.push_str(&format!(" Details: {}", joined));
        } else {
            message = format!("JDBC Postgres validation result: {}", joined);
        }
    }

    let status = if ok {
        StatusCode::OK
    } else if meta.iter().any(|m| {
        let lower = m.to_ascii_lowercase();
        lower.contains("skip") || lower.contains("ssrf")
    }) {
        StatusCode::CONTINUE
    } else {
        StatusCode::UNAUTHORIZED
    };

    Ok(JdbcValidationOutcome { valid: ok, status, message })
}

fn normalize_postgres_url(subname: &str) -> Result<String> {
    let trimmed = subname.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Postgres JDBC connection string is empty"));
    }

    let candidate = format!("postgresql:{}", trimmed);
    let mut url = Url::parse(&candidate).or_else(|_| {
        let fallback = format!("postgresql://{}", trimmed.trim_start_matches('/'));
        Url::parse(&fallback)
    })?;

    let mut user = None;
    let mut password = None;
    if url.query().is_some() {
        let mut preserved = Vec::new();
        for (key, value) in url.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "user" | "username" => user = Some(value.into_owned()),
                "password" | "pass" | "pwd" => password = Some(value.into_owned()),
                _ => preserved.push((key.into_owned(), value.into_owned())),
            }
        }

        {
            let mut pairs = url.query_pairs_mut();
            pairs.clear();
            for (key, value) in preserved {
                pairs.append_pair(&key, &value);
            }
        }
    }

    if let Some(user) = user {
        url.set_username(&user).map_err(|_| anyhow!("Failed to apply Postgres username"))?;
    }
    if let Some(password) = password {
        url.set_password(Some(&password))
            .map_err(|_| anyhow!("Failed to apply Postgres password"))?;
    }

    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_private_ipv4_host() {
        let outcome =
            validate_jdbc("jdbc:postgresql://10.0.0.1:5432/app?user=u&password=p", false, false)
                .await
                .unwrap();
        assert!(!outcome.valid);
        assert_eq!(outcome.status, StatusCode::CONTINUE);
        assert!(
            outcome.message.contains("SSRF protection"),
            "unexpected message: {}",
            outcome.message
        );
    }

    #[tokio::test]
    async fn rejects_link_local_metadata_host() {
        // 169.254.0.0/16 is additionally caught by the Postgres validator's own
        // legacy link-local check, so only assert that it is refused — not which
        // of the two gates refused it.
        let outcome = validate_jdbc(
            "jdbc:postgresql://169.254.169.254:5432/app?user=u&password=p",
            false,
            false,
        )
        .await
        .unwrap();
        assert!(!outcome.valid);
        assert_eq!(outcome.status, StatusCode::CONTINUE);
    }

    #[tokio::test]
    async fn rejects_rfc1918_host_that_the_legacy_check_missed() {
        // 192.168.0.0/16 is not loopback, not unspecified, and not link-local,
        // so before the SSRF gate this connection string was dialed for real.
        let outcome =
            validate_jdbc("jdbc:postgresql://192.168.1.5:5432/app?user=u&password=p", false, false)
                .await
                .unwrap();
        assert!(!outcome.valid);
        assert_eq!(outcome.status, StatusCode::CONTINUE);
        assert!(
            outcome.message.contains("SSRF protection"),
            "unexpected message: {}",
            outcome.message
        );
    }
}
