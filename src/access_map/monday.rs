use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const MONDAY_API: &str = "https://api.monday.com/v2";

#[derive(Deserialize)]
struct MondayGraphResponse<T> {
    #[serde(default = "Option::default")]
    data: Option<T>,
    #[serde(default)]
    errors: Option<Vec<MondayGraphError>>,
}

#[derive(Deserialize)]
struct MondayGraphError {
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize, Default)]
struct MeEnvelope {
    #[serde(default)]
    me: Option<MondayUser>,
}

#[derive(Deserialize, Default)]
struct MondayUser {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    is_admin: Option<bool>,
    #[serde(default)]
    is_guest: Option<bool>,
    #[serde(default)]
    is_view_only: Option<bool>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    last_activity: Option<String>,
    #[serde(default)]
    account: Option<MondayAccount>,
    #[serde(default)]
    teams: Vec<MondayTeam>,
}

#[derive(Deserialize, Default)]
struct MondayAccount {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    plan: Option<MondayPlan>,
}

#[derive(Deserialize, Default)]
struct MondayPlan {
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Deserialize, Default)]
struct MondayTeam {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize, Default)]
struct WorkspacesEnvelope {
    #[serde(default)]
    workspaces: Vec<MondayWorkspace>,
}

#[derive(Deserialize, Default)]
struct MondayWorkspace {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Deserialize, Default)]
struct BoardsEnvelope {
    #[serde(default)]
    boards: Vec<MondayBoard>,
}

#[derive(Deserialize, Default)]
struct MondayBoard {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    board_kind: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read monday.com token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("monday.com access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build monday.com HTTP client")?;

    let me = fetch_me(&client, token).await?;

    let username =
        me.name.clone().or_else(|| me.email.clone()).unwrap_or_else(|| "monday_user".to_string());

    let user_id = me.id.as_ref().map(value_to_string);
    let account_slug = me.account.as_ref().and_then(|a| a.slug.clone());
    let account_id = me.account.as_ref().and_then(|a| a.id.as_ref().map(value_to_string));
    let account_name = me.account.as_ref().and_then(|a| a.name.clone());
    let plan_tier = me.account.as_ref().and_then(|a| a.plan.as_ref().and_then(|p| p.tier.clone()));

    let access_type = if me.is_guest.unwrap_or(false) {
        "guest"
    } else if me.is_view_only.unwrap_or(false) {
        "viewer"
    } else if me.is_admin.unwrap_or(false) {
        "admin"
    } else {
        "user"
    };

    let identity = AccessSummary {
        id: username.clone(),
        access_type: access_type.to_string(),
        project: account_name.clone().or_else(|| account_slug.clone()),
        tenant: account_slug.clone(),
        account_id: account_id.clone(),
    };

    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();
    let mut risk_notes = Vec::new();

    if me.is_admin.unwrap_or(false) {
        let role = RoleBinding {
            name: "account_admin".into(),
            source: "monday".into(),
            permissions: vec!["account:admin".into()],
        };
        roles.push(role);
        permissions.admin.push("account:admin".into());
        risk_notes.push("Token is attached to a monday.com account administrator".into());
    } else if me.is_guest.unwrap_or(false) {
        roles.push(RoleBinding {
            name: "guest".into(),
            source: "monday".into(),
            permissions: vec!["account:guest".into()],
        });
        permissions.read_only.push("account:guest".into());
    } else if me.is_view_only.unwrap_or(false) {
        roles.push(RoleBinding {
            name: "viewer".into(),
            source: "monday".into(),
            permissions: vec!["account:viewer".into()],
        });
        permissions.read_only.push("account:viewer".into());
    } else {
        roles.push(RoleBinding {
            name: "member".into(),
            source: "monday".into(),
            permissions: vec!["account:member".into()],
        });
        permissions.risky.push("account:member".into());
    }

    for team in &me.teams {
        let team_name = team.name.clone().unwrap_or_else(|| "unknown_team".into());
        roles.push(RoleBinding {
            name: format!("team:{team_name}"),
            source: "monday".into(),
            permissions: Vec::new(),
        });
    }

    let workspaces = list_workspaces(&client, token).await.unwrap_or_else(|err| {
        warn!("monday.com access-map: workspace enumeration failed: {err}");
        Vec::new()
    });

    for workspace in &workspaces {
        let ws_name = workspace
            .name
            .clone()
            .or_else(|| workspace.id.as_ref().map(value_to_string))
            .unwrap_or_else(|| "unknown_workspace".to_string());
        let kind = workspace.kind.as_deref().unwrap_or("unknown");
        let state = workspace.state.as_deref().unwrap_or("active");

        let risk = match kind {
            "open" => Severity::Medium,
            "closed" => Severity::Low,
            _ => Severity::Low,
        };

        resources.push(ResourceExposure {
            resource_type: "workspace".into(),
            name: ws_name,
            permissions: vec![format!("workspace:{kind}"), format!("state:{state}")],
            risk: severity_to_str(risk).to_string(),
            reason: format!("monday.com {kind} workspace accessible with this token"),
        });
    }

    let boards = list_boards(&client, token).await.unwrap_or_else(|err| {
        warn!("monday.com access-map: board enumeration failed: {err}");
        Vec::new()
    });

    for board in &boards {
        let board_name = board
            .name
            .clone()
            .or_else(|| board.id.as_ref().map(value_to_string))
            .unwrap_or_else(|| "unknown_board".to_string());
        let kind = board.board_kind.as_deref().unwrap_or("unknown");
        let state = board.state.as_deref().unwrap_or("active");

        let risk = match kind {
            "private" | "share" => Severity::Medium,
            _ => Severity::Low,
        };

        resources.push(ResourceExposure {
            resource_type: "board".into(),
            name: board_name,
            permissions: vec![format!("board:{kind}"), format!("state:{state}")],
            risk: severity_to_str(risk).to_string(),
            reason: format!("monday.com {kind} board accessible with this token"),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&me, &workspaces, &boards);

    if workspaces.is_empty() && boards.is_empty() {
        if !me.is_admin.unwrap_or(false) {
            resources.push(ResourceExposure {
                resource_type: "account".into(),
                name: account_name.clone().unwrap_or_else(|| username.clone()),
                permissions: Vec::new(),
                risk: severity_to_str(Severity::Low).to_string(),
                reason: "monday.com account associated with the token".into(),
            });
        }
        risk_notes.push(
            "Token did not enumerate any workspaces or boards (limited scope or empty account)"
                .into(),
        );
    }

    let token_type = if me.is_admin.unwrap_or(false) {
        Some("admin_api_token".into())
    } else if me.is_guest.unwrap_or(false) {
        Some("guest_api_token".into())
    } else {
        Some("api_token".into())
    };

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "monday".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: me.name.clone(),
            username: me.email.clone(),
            account_type: Some(access_type.to_string()),
            company: account_name,
            location: None,
            email: me.email.clone(),
            url: account_slug.map(|slug| format!("https://{slug}.monday.com")),
            token_type,
            created_at: me.created_at.clone(),
            last_used_at: me.last_activity.clone(),
            expires_at: None,
            user_id,
            scopes: Vec::new(),
        }),
        provider_metadata: Some(ProviderMetadata { version: plan_tier, enterprise: None }),
        fingerprint: None,
    })
}

async fn fetch_me(client: &Client, token: &str) -> Result<MondayUser> {
    let query = r#"
        query {
            me {
                id
                name
                email
                is_admin
                is_guest
                is_view_only
                enabled
                created_at
                last_activity
                account { id name slug plan { tier } }
                teams { id name }
            }
        }
    "#;

    let body: MondayGraphResponse<MeEnvelope> = send_query(client, token, query).await?;
    if let Some(errors) = body.errors.as_ref().filter(|e| !e.is_empty()) {
        let message =
            errors.iter().filter_map(|e| e.message.clone()).collect::<Vec<_>>().join("; ");
        return Err(anyhow!("monday.com access-map: me query failed: {message}"));
    }

    body.data
        .and_then(|d| d.me)
        .ok_or_else(|| anyhow!("monday.com access-map: me query returned no data"))
}

async fn list_workspaces(client: &Client, token: &str) -> Result<Vec<MondayWorkspace>> {
    let query = r#"
        query {
            workspaces(limit: 100) {
                id
                name
                kind
                state
            }
        }
    "#;

    let body: MondayGraphResponse<WorkspacesEnvelope> = send_query(client, token, query).await?;
    if let Some(errors) = body.errors.as_ref().filter(|e| !e.is_empty()) {
        let message =
            errors.iter().filter_map(|e| e.message.clone()).collect::<Vec<_>>().join("; ");
        warn!("monday.com access-map: workspaces query reported errors: {message}");
        return Ok(Vec::new());
    }

    Ok(body.data.map(|d| d.workspaces).unwrap_or_default())
}

async fn list_boards(client: &Client, token: &str) -> Result<Vec<MondayBoard>> {
    let query = r#"
        query {
            boards(limit: 50) {
                id
                name
                board_kind
                state
            }
        }
    "#;

    let body: MondayGraphResponse<BoardsEnvelope> = send_query(client, token, query).await?;
    if let Some(errors) = body.errors.as_ref().filter(|e| !e.is_empty()) {
        let message =
            errors.iter().filter_map(|e| e.message.clone()).collect::<Vec<_>>().join("; ");
        warn!("monday.com access-map: boards query reported errors: {message}");
        return Ok(Vec::new());
    }

    Ok(body.data.map(|d| d.boards).unwrap_or_default())
}

async fn send_query<T: for<'de> Deserialize<'de>>(
    client: &Client,
    token: &str,
    query: &str,
) -> Result<MondayGraphResponse<T>> {
    let resp = client
        .post(MONDAY_API)
        .header(header::AUTHORIZATION, token)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&json!({ "query": query }))
        .send()
        .await
        .context("monday.com access-map: request failed")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "monday.com access-map: GraphQL request failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("monday.com access-map: invalid GraphQL response JSON")
}

fn derive_severity(
    user: &MondayUser,
    workspaces: &[MondayWorkspace],
    boards: &[MondayBoard],
) -> Severity {
    if user.is_admin.unwrap_or(false) {
        return Severity::Critical;
    }

    let workspace_count = workspaces.len();
    let board_count = boards.len();

    if user.is_guest.unwrap_or(false) || user.is_view_only.unwrap_or(false) {
        return Severity::Low;
    }

    if workspace_count > 5 || board_count > 20 {
        return Severity::High;
    }

    if workspace_count > 0 || board_count > 0 {
        return Severity::Medium;
    }

    Severity::Low
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}
