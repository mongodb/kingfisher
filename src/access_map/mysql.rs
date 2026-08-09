use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use mysql_async::prelude::*;
use mysql_async::{Opts, Pool};
use tokio::time::timeout;
use tracing::warn;

use crate::cli::commands::access_map::AccessMapArgs;

use super::{
    AccessMapResult, AccessSummary, PermissionSummary, ResourceExposure, RoleBinding, Severity,
    build_recommendations,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

// ─── Grant classification ───────────────────────────────────────────────────

const ADMIN_GRANTS: &[&str] = &["ALL PRIVILEGES", "SUPER", "GRANT OPTION", "CREATE USER"];
const RISKY_GRANTS: &[&str] = &["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE"];
const READ_GRANTS: &[&str] = &["SELECT", "SHOW DATABASES", "SHOW VIEW"];

// ─── Public entry points ────────────────────────────────────────────────────

/// Entry point when invoked via `kingfisher access-map mysql <CREDENTIAL>`.
pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("MySQL access-map requires a credential file containing the connection URI")
    })?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read MySQL URI from {}", path.display()))?;
    let uri = raw.trim().to_string();
    map_access_from_uri(&uri).await
}

/// Map access for a MySQL connection URI discovered during scanning.
pub async fn map_access_from_uri(uri: &str) -> Result<AccessMapResult> {
    let opts = Opts::from_url(uri).map_err(|e| anyhow!("Failed to parse MySQL URI: {e}"))?;

    let pool = Pool::new(opts.clone());
    let mut conn = timeout(CONNECT_TIMEOUT, pool.get_conn())
        .await
        .map_err(|_| anyhow!("MySQL connection timed out after {CONNECT_TIMEOUT:?}"))?
        .context("MySQL connection failed")?;

    let mut risk_notes: Vec<String> = Vec::new();

    // ── 1. Identity ─────────────────────────────────────────────────────────
    let current_user: String = conn
        .query_first("SELECT CURRENT_USER()")
        .await
        .context("Failed to query CURRENT_USER()")?
        .unwrap_or_else(|| "unknown".to_string());

    // ── 2. Server version ───────────────────────────────────────────────────
    let server_version: String = conn
        .query_first("SELECT VERSION()")
        .await
        .unwrap_or(Some("unknown".to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    // ── 3. Grants ───────────────────────────────────────────────────────────
    let grant_rows: Vec<String> =
        conn.query("SHOW GRANTS FOR CURRENT_USER()").await.unwrap_or_else(|e| {
            warn!("MySQL access-map: failed to query grants: {e}");
            risk_notes.push(format!("Grant enumeration failed: {e}"));
            Vec::new()
        });

    // ── 4. Databases (resources) ────────────────────────────────────────────
    let databases: Vec<String> = conn.query("SHOW DATABASES").await.unwrap_or_else(|e| {
        warn!("MySQL access-map: failed to list databases: {e}");
        risk_notes.push(format!("Database enumeration failed: {e}"));
        Vec::new()
    });

    // Done with the connection — disconnect cleanly.
    drop(conn);
    pool.disconnect().await.ok();

    // ── Parse grants ────────────────────────────────────────────────────────
    let parsed_grants = parse_grants(&grant_rows);

    // ── Build permissions ───────────────────────────────────────────────────
    let mut permissions = PermissionSummary::default();

    for grant in &parsed_grants {
        for priv_name in &grant.privileges {
            let upper = priv_name.to_uppercase();
            if ADMIN_GRANTS.contains(&upper.as_str()) {
                if !permissions.admin.contains(&upper) {
                    permissions.admin.push(upper);
                }
            } else if RISKY_GRANTS.contains(&upper.as_str()) {
                let label = format!("{} ON {}", upper, grant.scope);
                permissions.risky.push(label);
            } else if READ_GRANTS.contains(&upper.as_str()) {
                let label = format!("{} ON {}", upper, grant.scope);
                permissions.read_only.push(label);
            }
        }
    }

    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    // ── Build roles ─────────────────────────────────────────────────────────
    let mut roles = Vec::new();
    for grant in &parsed_grants {
        roles.push(RoleBinding {
            name: format!("grant:{}", grant.scope),
            source: "SHOW GRANTS".into(),
            permissions: grant.privileges.clone(),
        });
    }

    // ── Build resources ─────────────────────────────────────────────────────
    let has_global_write = parsed_grants.iter().any(|g| {
        g.scope == "*.*"
            && g.privileges.iter().any(|p| {
                let u = p.to_uppercase();
                ADMIN_GRANTS.contains(&u.as_str()) || RISKY_GRANTS.contains(&u.as_str())
            })
    });

    let mut resources: Vec<ResourceExposure> = Vec::new();
    for db in &databases {
        let db_specific_write = parsed_grants.iter().any(|g| {
            (g.scope == "*.*" || g.scope == format!("`{db}`.*"))
                && g.privileges.iter().any(|p| {
                    let u = p.to_uppercase();
                    ADMIN_GRANTS.contains(&u.as_str()) || RISKY_GRANTS.contains(&u.as_str())
                })
        });
        let risk = if db_specific_write { "medium" } else { "low" };
        resources.push(ResourceExposure {
            resource_type: "database".into(),
            name: db.clone(),
            permissions: parsed_grants
                .iter()
                .filter(|g| g.scope == "*.*" || g.scope == format!("`{db}`.*"))
                .flat_map(|g| g.privileges.clone())
                .collect(),
            risk: risk.into(),
            reason: format!("Database accessible by user '{current_user}'"),
        });
    }

    // ── Severity ────────────────────────────────────────────────────────────
    let has_all_on_global = parsed_grants.iter().any(|g| {
        g.scope == "*.*" && g.privileges.iter().any(|p| p.to_uppercase() == "ALL PRIVILEGES")
    });
    let has_write_on_global = has_global_write;
    let has_write_on_specific = parsed_grants.iter().any(|g| {
        g.scope != "*.*"
            && g.privileges.iter().any(|p| {
                let u = p.to_uppercase();
                RISKY_GRANTS.contains(&u.as_str())
            })
    });

    let severity = if has_all_on_global {
        Severity::Critical
    } else if has_write_on_global {
        Severity::High
    } else if has_write_on_specific {
        Severity::Medium
    } else {
        Severity::Low
    };

    // ── Risk notes ──────────────────────────────────────────────────────────
    if has_all_on_global {
        risk_notes.push(
            "User has ALL PRIVILEGES on *.* — full administrative access to all databases".into(),
        );
    }
    if !permissions.admin.is_empty() && !has_all_on_global {
        risk_notes.push(format!("User has admin-level grants: {}", permissions.admin.join(", ")));
    }

    let identity = AccessSummary {
        id: current_user.clone(),
        access_type: if has_all_on_global { "superuser" } else { "user" }.into(),
        project: None,
        tenant: None,
        account_id: None,
    };

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "mysql".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: None,
        provider_metadata: Some(super::ProviderMetadata {
            version: Some(server_version),
            enterprise: None,
        }),
        fingerprint: None,
    })
}

// ─── Grant parsing ──────────────────────────────────────────────────────────

#[derive(Debug)]
struct ParsedGrant {
    privileges: Vec<String>,
    scope: String,
}

/// Parse `SHOW GRANTS` output lines into structured grant entries.
///
/// Example line: `GRANT SELECT, INSERT ON `mydb`.* TO 'user'@'host'`
fn parse_grants(grant_rows: &[String]) -> Vec<ParsedGrant> {
    let mut results = Vec::new();

    for row in grant_rows {
        let upper = row.to_uppercase();
        // Skip proxy grants or other non-standard lines
        if !upper.starts_with("GRANT ") {
            continue;
        }

        // Split at " ON " to separate privileges from scope
        let on_idx = match upper.find(" ON ") {
            Some(idx) => idx,
            None => continue,
        };

        let priv_part = &row[6..on_idx]; // skip "GRANT "
        let after_on = &row[on_idx + 4..]; // skip " ON "

        // Scope is everything up to the next " TO "
        let to_upper = after_on.to_uppercase();
        let scope = match to_upper.find(" TO ") {
            Some(idx) => after_on[..idx].trim().to_string(),
            None => after_on.trim().to_string(),
        };

        let privileges: Vec<String> = priv_part
            .split(',')
            .map(|s| s.trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect();

        if !privileges.is_empty() {
            results.push(ParsedGrant { privileges, scope });
        }
    }

    results
}
