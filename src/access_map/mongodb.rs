use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use mongodb::{
    Client,
    bson::{Document, doc},
    options::{ClientOptions, Tls, TlsOptions},
};
use tracing::{debug, warn};

use crate::cli::commands::access_map::AccessMapArgs;

use super::{
    AccessMapResult, AccessSummary, PermissionSummary, ProviderMetadata, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const CONNECT_TIMEOUT_MS: u64 = 5_000;
const SELECT_TIMEOUT_MS: u64 = 5_000;

/// Entry point when invoked via `kingfisher access-map mongodb <CREDENTIAL>`.
pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("MongoDB access-map requires a credential file containing the connection URI")
    })?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read MongoDB URI from {}", path.display()))?;
    let uri = raw.trim().to_string();
    map_access_from_uri(&uri).await
}

/// Map access for a MongoDB connection URI discovered during scanning.
pub async fn map_access_from_uri(uri: &str) -> Result<AccessMapResult> {
    let client = connect(uri).await?;

    let mut risk_notes: Vec<String> = Vec::new();

    // ── 1. Connection status & identity ──────────────────────────────────────
    let conn_status =
        run_admin_command(&client, doc! { "connectionStatus": 1, "showPrivileges": true })
            .await
            .context("Failed to get connectionStatus")?;

    let (username, auth_db, auth_roles, auth_privileges) = parse_connection_status(&conn_status);

    // ── 2. Server info (read-only) ───────────────────────────────────────────
    let server_version = match run_admin_command(&client, doc! { "buildInfo": 1 }).await {
        Ok(doc) => doc.get_str("version").unwrap_or("unknown").to_string(),
        Err(e) => {
            debug!("MongoDB access-map: buildInfo failed: {e}");
            "unknown".into()
        }
    };

    // ── 3. List databases (read-only) ────────────────────────────────────────
    let databases =
        match run_admin_command(&client, doc! { "listDatabases": 1, "nameOnly": false }).await {
            Ok(doc) => parse_database_list(&doc),
            Err(e) => {
                warn!("MongoDB access-map: listDatabases failed: {e}");
                risk_notes.push(format!("Database enumeration failed: {e}"));
                Vec::new()
            }
        };

    // ── 4. For each database, list collections (read-only) ───────────────────
    let mut collection_resources = Vec::new();
    for db_info in &databases {
        match list_collections(&client, &db_info.name).await {
            Ok(colls) => {
                for coll in colls {
                    collection_resources.push(CollectionInfo {
                        database: db_info.name.clone(),
                        name: coll.name,
                        collection_type: coll.collection_type,
                        size_bytes: coll.size_bytes,
                    });
                }
            }
            Err(e) => {
                debug!("MongoDB access-map: listCollections on {} failed: {}", db_info.name, e);
            }
        }
    }

    // ── Build roles ──────────────────────────────────────────────────────────
    let mut roles: Vec<RoleBinding> = Vec::new();
    for role in &auth_roles {
        let role_permissions: Vec<String> = auth_privileges
            .iter()
            .filter(|p| {
                // Include privileges from this role's database or cluster-wide
                p.resource_db.as_deref() == Some(&role.db) || p.resource_db.as_deref() == Some("")
            })
            .flat_map(|p| p.actions.clone())
            .collect();

        roles.push(RoleBinding {
            name: format!("{}.{}", role.db, role.role),
            source: "connectionStatus".into(),
            permissions: role_permissions,
        });
    }

    if roles.is_empty() && !username.is_empty() {
        roles.push(RoleBinding {
            name: username.clone(),
            source: "connectionStatus".into(),
            permissions: Vec::new(),
        });
    }

    // ── Build permissions ────────────────────────────────────────────────────
    let mut permissions = PermissionSummary::default();
    let all_actions: Vec<String> = auth_privileges.iter().flat_map(|p| p.actions.clone()).collect();

    for action in &all_actions {
        let a = action.to_lowercase();
        if is_admin_action(&a) {
            permissions.admin.push(action.clone());
        } else if is_privilege_escalation_action(&a) {
            permissions.privilege_escalation.push(action.clone());
        } else if is_read_only_action(&a) {
            permissions.read_only.push(action.clone());
        } else if is_risky_action(&a) {
            permissions.risky.push(action.clone());
        } else {
            // Default: classify unknown as risky
            permissions.risky.push(action.clone());
        }
    }

    // Deduplicate
    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.privilege_escalation.sort();
    permissions.privilege_escalation.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    // ── Build resources ──────────────────────────────────────────────────────
    let mut resources: Vec<ResourceExposure> = Vec::new();

    for db_info in &databases {
        let db_actions: Vec<String> = auth_privileges
            .iter()
            .filter(|p| {
                p.resource_db.as_deref() == Some(&db_info.name)
                    || p.resource_db.as_deref() == Some("")
            })
            .flat_map(|p| p.actions.clone())
            .collect();

        let has_write = db_actions.iter().any(|a| is_write_action(a));
        let risk = if has_write { "medium" } else { "low" };

        resources.push(ResourceExposure {
            resource_type: "database".into(),
            name: db_info.name.clone(),
            permissions: db_actions,
            risk: risk.into(),
            reason: if let Some(size) = db_info.size_on_disk {
                format!("Database (size: {size} bytes)")
            } else {
                "Database accessible by user".into()
            },
        });
    }

    for coll in &collection_resources {
        let has_write = auth_privileges.iter().any(|p| {
            (p.resource_db.as_deref() == Some(&coll.database)
                || p.resource_db.as_deref() == Some(""))
                && (p.resource_collection.as_deref() == Some(&coll.name)
                    || p.resource_collection.as_deref() == Some(""))
                && p.actions.iter().any(|a| is_write_action(a))
        });
        let risk = if has_write { "medium" } else { "low" };

        resources.push(ResourceExposure {
            resource_type: "collection".into(),
            name: format!("{}.{}", coll.database, coll.name),
            permissions: Vec::new(),
            risk: risk.into(),
            reason: if let Some(size) = coll.size_bytes {
                format!("{} collection (size: {size} bytes)", coll.collection_type)
            } else {
                format!("{} collection", coll.collection_type)
            },
        });
    }

    // ── Severity ─────────────────────────────────────────────────────────────
    let severity = derive_severity(&permissions);

    // ── Risk notes ───────────────────────────────────────────────────────────
    if !permissions.admin.is_empty() {
        risk_notes.push("User has administrative privileges on this MongoDB deployment".into());
    }
    if auth_privileges.iter().any(|p| {
        p.resource_db.as_deref() == Some("") && p.resource_collection.as_deref() == Some("")
    }) {
        risk_notes.push("User has cluster-wide privileges".into());
    }

    let identity = AccessSummary {
        id: if username.is_empty() { "anonymous".into() } else { username.clone() },
        access_type: if !permissions.admin.is_empty() {
            "admin_user".into()
        } else {
            "user".into()
        },
        project: Some(auth_db.clone()).filter(|s| !s.is_empty()),
        tenant: None,
        account_id: None,
    };

    Ok(AccessMapResult {
        cloud: "mongodb".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: None,
        provider_metadata: Some(ProviderMetadata {
            version: Some(server_version),
            enterprise: None,
            authorization_evidence: None,
        }),
        fingerprint: None,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn connect(uri: &str) -> Result<Client> {
    let mut opts = ClientOptions::parse(uri).await.context("Failed to parse MongoDB URI")?;
    opts.connect_timeout = Some(Duration::from_millis(CONNECT_TIMEOUT_MS));
    opts.server_selection_timeout = Some(Duration::from_millis(SELECT_TIMEOUT_MS));
    opts.max_pool_size = Some(1);
    opts.min_pool_size = Some(0);

    // Always use lax TLS for access-map (we're probing, not running production)
    let tls_options = TlsOptions::builder().allow_invalid_certificates(true).build();
    opts.tls = Some(Tls::Enabled(tls_options));

    Client::with_options(opts).context("Failed to create MongoDB client")
}

async fn run_admin_command(client: &Client, command: Document) -> Result<Document> {
    client.database("admin").run_command(command).await.context("MongoDB admin command failed")
}

#[derive(Debug, Default)]
struct MongoRole {
    role: String,
    db: String,
}

#[derive(Debug, Default)]
struct MongoPrivilege {
    resource_db: Option<String>,
    resource_collection: Option<String>,
    actions: Vec<String>,
}

#[derive(Debug)]
struct DatabaseInfo {
    name: String,
    size_on_disk: Option<i64>,
}

#[derive(Debug)]
struct CollectionInfo {
    database: String,
    name: String,
    collection_type: String,
    size_bytes: Option<i64>,
}

struct RawCollectionInfo {
    name: String,
    collection_type: String,
    size_bytes: Option<i64>,
}

fn parse_connection_status(
    doc: &Document,
) -> (String, String, Vec<MongoRole>, Vec<MongoPrivilege>) {
    let auth_info = doc.get_document("authInfo").ok();

    let users = auth_info
        .and_then(|ai| ai.get_array("authenticatedUsers").ok())
        .cloned()
        .unwrap_or_default();

    let (username, auth_db) = users
        .first()
        .and_then(|u| {
            let doc = u.as_document()?;
            let user = doc.get_str("user").ok()?.to_string();
            let db = doc.get_str("db").ok()?.to_string();
            Some((user, db))
        })
        .unwrap_or_default();

    let roles_arr = auth_info
        .and_then(|ai| ai.get_array("authenticatedUserRoles").ok())
        .cloned()
        .unwrap_or_default();

    let roles: Vec<MongoRole> = roles_arr
        .iter()
        .filter_map(|r| {
            let doc = r.as_document()?;
            Some(MongoRole {
                role: doc.get_str("role").ok()?.to_string(),
                db: doc.get_str("db").ok()?.to_string(),
            })
        })
        .collect();

    let privs_arr = auth_info
        .and_then(|ai| ai.get_array("authenticatedUserPrivileges").ok())
        .cloned()
        .unwrap_or_default();

    let privileges: Vec<MongoPrivilege> = privs_arr
        .iter()
        .filter_map(|p| {
            let doc = p.as_document()?;
            let resource = doc.get_document("resource").ok()?;
            let actions = doc
                .get_array("actions")
                .ok()?
                .iter()
                .filter_map(|a| a.as_str().map(|s| s.to_string()))
                .collect();

            Some(MongoPrivilege {
                resource_db: resource.get_str("db").ok().map(|s| s.to_string()),
                resource_collection: resource.get_str("collection").ok().map(|s| s.to_string()),
                actions,
            })
        })
        .collect();

    (username, auth_db, roles, privileges)
}

fn parse_database_list(doc: &Document) -> Vec<DatabaseInfo> {
    let dbs = match doc.get_array("databases") {
        Ok(arr) => arr,
        Err(_) => return Vec::new(),
    };

    dbs.iter()
        .filter_map(|d| {
            let doc = d.as_document()?;
            let name = doc.get_str("name").ok()?.to_string();
            let size_on_disk = doc
                .get_i64("sizeOnDisk")
                .ok()
                .or_else(|| doc.get_f64("sizeOnDisk").ok().map(|f| f as i64));
            Some(DatabaseInfo { name, size_on_disk })
        })
        .collect()
}

async fn list_collections(client: &Client, db_name: &str) -> Result<Vec<RawCollectionInfo>> {
    let db = client.database(db_name);
    let result = db
        .run_command(doc! { "listCollections": 1, "nameOnly": false })
        .await
        .context("listCollections failed")?;

    let cursor = match result.get_document("cursor") {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let first_batch = match cursor.get_array("firstBatch") {
        Ok(arr) => arr,
        Err(_) => return Ok(Vec::new()),
    };

    let mut collections = Vec::new();
    for item in first_batch {
        if let Some(doc) = item.as_document() {
            let name = doc.get_str("name").unwrap_or("unknown").to_string();
            let coll_type = doc.get_str("type").unwrap_or("collection").to_string();

            // Try to get size from options or info subdocument
            let size_bytes =
                doc.get_document("info").ok().and_then(|info| info.get_i64("size").ok());

            collections.push(RawCollectionInfo { name, collection_type: coll_type, size_bytes });
        }
    }

    Ok(collections)
}

fn is_admin_action(action: &str) -> bool {
    matches!(
        action,
        "shutdown"
            | "replsetstatechange"
            | "resync"
            | "applicationmessage"
            | "closeallsessions"
            | "forceuniverserecovery"
            | "internal"
            | "hostinfo"
    ) || action.contains("adm")
        || action == "root"
}

fn is_privilege_escalation_action(action: &str) -> bool {
    matches!(
        action,
        "createrole"
            | "createuser"
            | "droprole"
            | "dropuser"
            | "grantrole"
            | "revokerole"
            | "grantrolestouser"
            | "revokerolesfrommuser"
            | "updateuser"
    )
}

fn is_read_only_action(action: &str) -> bool {
    matches!(
        action,
        "find"
            | "listdatabases"
            | "listcollections"
            | "listindexes"
            | "collstats"
            | "dbstats"
            | "connpoolstats"
            | "serverstatus"
            | "toploogy"
            | "getcmdlineopts"
            | "getlog"
            | "getparameter"
            | "indexstats"
            | "top"
            | "validate"
            | "dbhash"
    )
}

fn is_risky_action(action: &str) -> bool {
    is_write_action(action)
        || matches!(
            action,
            "bypassdocumentvalidation" | "enablesharding" | "movechunk" | "splitchunk"
        )
}

fn is_write_action(action: &str) -> bool {
    matches!(
        action,
        "insert"
            | "update"
            | "remove"
            | "createcollection"
            | "dropcollection"
            | "dropdatabase"
            | "createindex"
            | "dropindex"
            | "converttorecapped"
            | "renamecollectionsamedatabase"
    )
}

fn derive_severity(permissions: &PermissionSummary) -> Severity {
    if !permissions.admin.is_empty() {
        Severity::Critical
    } else if !permissions.privilege_escalation.is_empty() {
        Severity::High
    } else if !permissions.risky.is_empty() {
        Severity::Medium
    } else {
        Severity::Low
    }
}
