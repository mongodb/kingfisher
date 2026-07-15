use std::sync::Arc;
use std::time::Duration;

use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme, client::ClientConfig};
use tokio::time::timeout;
use tokio_postgres::config::SslMode;
use tokio_postgres::tls::NoTls;
use tokio_postgres::{Client, Config};
use tokio_postgres_rustls::MakeRustlsConnect;
use tracing::{debug, warn};

use crate::cli::commands::access_map::AccessMapArgs;

use super::{
    AccessMapResult, AccessSummary, PermissionSummary, ResourceExposure, RoleBinding, Severity,
    build_recommendations,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

static INIT_PROVIDER: OnceLock<()> = OnceLock::new();
fn ensure_crypto_provider() {
    INIT_PROVIDER.get_or_init(|| {
        let _ = CryptoProvider::install_default(aws_lc_rs::default_provider());
    });
}

#[derive(Debug)]
struct LaxCertVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for LaxCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Entry point when invoked via `kingfisher access-map postgres <CREDENTIAL>`.
pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Postgres access-map requires a credential file containing the connection URI")
    })?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Postgres URI from {}", path.display()))?;
    let uri = raw.trim().to_string();
    map_access_from_uri(&uri).await
}

/// Map access for a Postgres connection URI discovered during scanning.
pub async fn map_access_from_uri(pg_url: &str) -> Result<AccessMapResult> {
    let client = connect(pg_url).await?;

    let mut risk_notes: Vec<String> = Vec::new();

    // ── 1. Identity ──────────────────────────────────────────────────────────
    let current_user = query_scalar(&client, "SELECT current_user").await?;
    let server_version =
        query_scalar(&client, "SELECT version()").await.unwrap_or_else(|_| "unknown".into());

    // ── 2. Role attributes ───────────────────────────────────────────────────
    let role_attrs = query_role_attributes(&client, &current_user).await.unwrap_or_else(|e| {
        warn!("Postgres access-map: failed to query role attributes: {e}");
        risk_notes.push(format!("Role attribute enumeration failed: {e}"));
        RoleAttributes::default()
    });

    // ── 3. Role memberships ──────────────────────────────────────────────────
    let memberships = query_role_memberships(&client, &current_user).await.unwrap_or_else(|e| {
        warn!("Postgres access-map: failed to query role memberships: {e}");
        risk_notes.push(format!("Role membership enumeration failed: {e}"));
        Vec::new()
    });

    // ── 4. Database privileges ───────────────────────────────────────────────
    let db_privs = query_database_privileges(&client, &current_user).await.unwrap_or_else(|e| {
        warn!("Postgres access-map: failed to query database privileges: {e}");
        risk_notes.push(format!("Database privilege enumeration failed: {e}"));
        Vec::new()
    });

    // ── 5. Table privileges (in current database) ────────────────────────────
    let table_privs = query_table_privileges(&client, &current_user).await.unwrap_or_else(|e| {
        warn!("Postgres access-map: failed to query table privileges: {e}");
        risk_notes.push(format!("Table privilege enumeration failed: {e}"));
        Vec::new()
    });

    // ── Build roles ──────────────────────────────────────────────────────────
    let mut roles = Vec::new();
    let role_perms: Vec<String> = role_attrs.to_permission_list();

    roles.push(RoleBinding {
        name: current_user.clone(),
        source: "pg_roles".into(),
        permissions: role_perms.clone(),
    });

    for membership in &memberships {
        roles.push(RoleBinding {
            name: membership.clone(),
            source: "role_membership".into(),
            permissions: Vec::new(),
        });
    }

    // ── Build permissions ────────────────────────────────────────────────────
    let mut permissions = PermissionSummary::default();

    // Admin-level attributes
    if role_attrs.superuser {
        permissions.admin.push("SUPERUSER".into());
    }
    if role_attrs.bypass_rls {
        permissions.admin.push("BYPASSRLS".into());
    }

    // Privilege escalation
    if role_attrs.create_role {
        permissions.privilege_escalation.push("CREATEROLE".into());
    }
    if role_attrs.create_db {
        permissions.privilege_escalation.push("CREATEDB".into());
    }
    if role_attrs.replication {
        permissions.privilege_escalation.push("REPLICATION".into());
    }

    // Classify table privileges
    for tp in &table_privs {
        let label =
            format!("{}.{}.{}: {}", tp.database, tp.schema, tp.table, tp.privileges.join(", "));
        let has_write = tp.privileges.iter().any(|p| {
            matches!(
                p.to_uppercase().as_str(),
                "INSERT" | "UPDATE" | "DELETE" | "TRUNCATE" | "TRIGGER"
            )
        });
        if has_write {
            permissions.risky.push(label);
        } else {
            permissions.read_only.push(label);
        }
    }

    // ── Build resources ──────────────────────────────────────────────────────
    let mut resources: Vec<ResourceExposure> = Vec::new();

    for db in &db_privs {
        let priv_list: Vec<String> = db.privileges.clone();
        let has_create = priv_list.iter().any(|p| p.to_uppercase() == "CREATE");
        let risk = if has_create { "medium" } else { "low" };
        resources.push(ResourceExposure {
            resource_type: "database".into(),
            name: db.name.clone(),
            permissions: priv_list,
            risk: risk.into(),
            reason: format!("Database accessible by user '{}'", current_user),
        });
    }

    for tp in &table_privs {
        let has_write = tp.privileges.iter().any(|p| {
            matches!(
                p.to_uppercase().as_str(),
                "INSERT" | "UPDATE" | "DELETE" | "TRUNCATE" | "TRIGGER"
            )
        });
        let risk = if has_write { "medium" } else { "low" };
        resources.push(ResourceExposure {
            resource_type: "table".into(),
            name: format!("{}.{}.{}", tp.database, tp.schema, tp.table),
            permissions: tp.privileges.clone(),
            risk: risk.into(),
            reason: if let Some(ref size) = tp.estimated_size {
                format!("Table with estimated size {size}")
            } else {
                "Table accessible by user".into()
            },
        });
    }

    // ── Severity ─────────────────────────────────────────────────────────────
    let severity = derive_severity(&role_attrs, &permissions);

    // ── Risk notes ───────────────────────────────────────────────────────────
    if role_attrs.superuser {
        risk_notes.push("User has SUPERUSER privilege — full administrative access".into());
    }
    if role_attrs.bypass_rls {
        risk_notes.push("User can bypass Row-Level Security policies".into());
    }
    if role_attrs.create_role {
        risk_notes.push("User can create new roles — potential privilege escalation vector".into());
    }

    let identity = AccessSummary {
        id: current_user.clone(),
        access_type: if role_attrs.superuser { "superuser" } else { "user" }.into(),
        project: None,
        tenant: None,
        account_id: None,
    };

    Ok(AccessMapResult {
        cloud: "postgres".into(),
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct RoleAttributes {
    superuser: bool,
    create_role: bool,
    create_db: bool,
    login: bool,
    replication: bool,
    bypass_rls: bool,
    inherit: bool,
}

impl RoleAttributes {
    fn to_permission_list(&self) -> Vec<String> {
        let mut perms = Vec::new();
        if self.superuser {
            perms.push("SUPERUSER".into());
        }
        if self.create_role {
            perms.push("CREATEROLE".into());
        }
        if self.create_db {
            perms.push("CREATEDB".into());
        }
        if self.login {
            perms.push("LOGIN".into());
        }
        if self.replication {
            perms.push("REPLICATION".into());
        }
        if self.bypass_rls {
            perms.push("BYPASSRLS".into());
        }
        if self.inherit {
            perms.push("INHERIT".into());
        }
        perms
    }
}

#[derive(Debug)]
struct DatabasePrivilege {
    name: String,
    #[expect(dead_code)]
    owner: String,
    privileges: Vec<String>,
}

#[derive(Debug)]
struct TablePrivilege {
    database: String,
    schema: String,
    table: String,
    privileges: Vec<String>,
    estimated_size: Option<String>,
}

async fn connect(pg_url: &str) -> Result<Client> {
    let mut cfg = parse_postgres_url(pg_url)?;
    let original_mode = cfg.get_ssl_mode();
    if original_mode == SslMode::Prefer {
        cfg.ssl_mode(SslMode::Disable);
    }

    for attempt in 0..=1 {
        let cfg_try = cfg.clone();
        let result = if cfg_try.get_ssl_mode() == SslMode::Disable {
            timeout(CONNECT_TIMEOUT, async {
                let (client, connection) = cfg_try.connect(NoTls).await?;
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        debug!("Postgres access-map connection error: {e}");
                    }
                });
                Ok::<Client, tokio_postgres::Error>(client)
            })
            .await
        } else {
            timeout(CONNECT_TIMEOUT, async {
                ensure_crypto_provider();
                let tls_cfg = {
                    let provider = Arc::new(aws_lc_rs::default_provider());
                    ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(LaxCertVerifier(provider)))
                        .with_no_client_auth()
                };
                let tls = MakeRustlsConnect::new(tls_cfg);
                let (client, connection) = cfg_try.connect(tls).await?;
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        debug!("Postgres access-map connection error: {e}");
                    }
                });
                Ok::<Client, tokio_postgres::Error>(client)
            })
            .await
        };

        match result {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(e)) if attempt == 0 && e.to_string().contains("server requires encryption") => {
                debug!("Postgres access-map: server requires encryption, retrying with SSL");
                cfg.ssl_mode(SslMode::Require);
                continue;
            }
            Ok(Err(e)) if attempt == 0 && e.to_string().contains("sslmode") => {
                debug!("Postgres access-map: SSL error, retrying without SSL");
                cfg.ssl_mode(SslMode::Disable);
                continue;
            }
            Ok(Err(e)) => return Err(anyhow!("Postgres connection failed: {e}")),
            Err(_) => {
                return Err(anyhow!("Postgres connection timed out after {CONNECT_TIMEOUT:?}"));
            }
        }
    }

    Err(anyhow!("Postgres connection failed after retries"))
}

fn parse_postgres_url(pg_url: &str) -> Result<Config> {
    use std::str::FromStr;
    match Config::from_str(pg_url) {
        Ok(cfg) => Ok(cfg),
        Err(e) => {
            if let Some(rest) = pg_url.strip_prefix("postgis://") {
                let fallback = format!("postgres://{rest}");
                Config::from_str(&fallback)
                    .map_err(|_| anyhow!("Failed to parse Postgres URL: {e}"))
            } else {
                Err(anyhow!("Failed to parse Postgres URL: {e}"))
            }
        }
    }
}

async fn query_scalar(client: &Client, query: &str) -> Result<String> {
    let row = client.query_one(query, &[]).await.context("query_scalar failed")?;
    let val: String = row.get(0);
    Ok(val)
}

async fn query_role_attributes(client: &Client, username: &str) -> Result<RoleAttributes> {
    let row = client
        .query_one(
            "SELECT rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls, rolinherit \
             FROM pg_roles WHERE rolname = $1",
            &[&username],
        )
        .await
        .context("Failed to query pg_roles")?;

    Ok(RoleAttributes {
        superuser: row.get(0),
        create_role: row.get(1),
        create_db: row.get(2),
        login: row.get(3),
        replication: row.get(4),
        bypass_rls: row.get(5),
        inherit: row.get(6),
    })
}

async fn query_role_memberships(client: &Client, username: &str) -> Result<Vec<String>> {
    let rows = client
        .query(
            "SELECT r.rolname FROM pg_roles r \
             JOIN pg_auth_members m ON r.oid = m.roleid \
             JOIN pg_roles u ON u.oid = m.member \
             WHERE u.rolname = $1",
            &[&username],
        )
        .await
        .context("Failed to query role memberships")?;

    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

async fn query_database_privileges(
    client: &Client,
    username: &str,
) -> Result<Vec<DatabasePrivilege>> {
    let rows = client
        .query(
            "SELECT d.datname, pg_catalog.pg_get_userbyid(d.datdba) as owner \
             FROM pg_database d \
             WHERE d.datallowconn = true \
             ORDER BY d.datname",
            &[],
        )
        .await
        .context("Failed to query pg_database")?;

    let mut results = Vec::new();
    for row in &rows {
        let db_name: String = row.get(0);
        let owner: String = row.get(1);

        // Check individual privileges using has_database_privilege()
        let mut privs = Vec::new();
        for priv_name in &["CONNECT", "CREATE", "TEMP"] {
            let check_query =
                format!("SELECT has_database_privilege($1, '{}', '{}')", db_name, priv_name);
            match client.query_one(&check_query, &[&username]).await {
                Ok(r) => {
                    let has: bool = r.get(0);
                    if has {
                        privs.push(priv_name.to_string());
                    }
                }
                Err(e) => {
                    debug!(
                        "Postgres access-map: privilege check failed for {} on {}: {}",
                        priv_name, db_name, e
                    );
                }
            }
        }

        if !privs.is_empty() {
            results.push(DatabasePrivilege { name: db_name, owner, privileges: privs });
        }
    }

    Ok(results)
}

async fn query_table_privileges(client: &Client, username: &str) -> Result<Vec<TablePrivilege>> {
    let current_db = query_scalar(client, "SELECT current_database()").await?;

    // Use information_schema to find tables the user has any privilege on.
    let rows = client
        .query(
            "SELECT table_schema, table_name, \
                    array_agg(DISTINCT privilege_type ORDER BY privilege_type) as privileges \
             FROM information_schema.role_table_grants \
             WHERE grantee = $1 \
               AND table_schema NOT IN ('pg_catalog', 'information_schema') \
             GROUP BY table_schema, table_name \
             ORDER BY table_schema, table_name",
            &[&username],
        )
        .await
        .context("Failed to query role_table_grants")?;

    let mut results = Vec::new();
    for row in &rows {
        let schema: String = row.get(0);
        let table: String = row.get(1);
        let privileges: Vec<String> = row.get(2);

        // Estimate table size (best-effort, read-only)
        let size_query = format!(
            "SELECT pg_size_pretty(pg_total_relation_size('{}.{}'))",
            schema.replace('\'', "''"),
            table.replace('\'', "''")
        );
        let estimated_size = match client.query_one(&size_query, &[]).await {
            Ok(r) => Some(r.get::<_, String>(0)),
            Err(_) => None,
        };

        results.push(TablePrivilege {
            database: current_db.clone(),
            schema,
            table,
            privileges,
            estimated_size,
        });
    }

    Ok(results)
}

fn derive_severity(attrs: &RoleAttributes, permissions: &PermissionSummary) -> Severity {
    if attrs.superuser || !permissions.admin.is_empty() {
        Severity::Critical
    } else if attrs.create_role || attrs.replication || !permissions.privilege_escalation.is_empty()
    {
        Severity::High
    } else if !permissions.risky.is_empty() {
        Severity::Medium
    } else {
        Severity::Low
    }
}
