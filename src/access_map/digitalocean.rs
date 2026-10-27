use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, AuthorizationEvidence, PermissionSummary,
    ProviderMetadata, ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const DIGITALOCEAN_API: &str = "https://api.digitalocean.com";

#[derive(Deserialize)]
struct AccountResponse {
    #[serde(default)]
    account: Option<DigitalOceanAccount>,
}

#[derive(Deserialize)]
struct DigitalOceanAccount {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    status: Option<String>,
    #[serde(default)]
    team: Option<DigitalOceanTeam>,
}

#[derive(Deserialize)]
struct DigitalOceanTeam {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    uuid: Option<String>,
}

#[derive(Deserialize)]
struct ProjectsResponse {
    projects: Vec<DigitalOceanProject>,
}

#[derive(Deserialize)]
struct DigitalOceanProject {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    is_default: Option<bool>,
}

#[derive(Deserialize)]
struct DropletsResponse {
    droplets: Vec<DigitalOceanDroplet>,
}

#[derive(Deserialize)]
struct DigitalOceanDroplet {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct DatabasesResponse {
    databases: Vec<DigitalOceanDatabase>,
}

#[derive(Deserialize)]
struct DigitalOceanDatabase {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    engine: Option<String>,
}

#[derive(Deserialize)]
struct KubernetesClustersResponse {
    kubernetes_clusters: Vec<DigitalOceanKubernetesCluster>,
}

#[derive(Deserialize)]
struct DigitalOceanKubernetesCluster {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    region: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path).with_context(|| {
            format!("Failed to read DigitalOcean token from {}", path.display())
        })?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!(
            "DigitalOcean access-map requires a validated token from scan results"
        ));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    map_access_from_token_at(token, DIGITALOCEAN_API).await
}

async fn map_access_from_token_at(token: &str, api_base: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build DigitalOcean HTTP client")?;

    map_access_with_client(&client, token, api_base).await
}

async fn map_access_with_client(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<AccessMapResult> {
    let account = fetch_account(client, token, api_base).await?;

    let username = account
        .email
        .clone()
        .unwrap_or_else(|| account.uuid.clone().unwrap_or_else(|| "do_user".to_string()));

    let team_name = account.team.as_ref().and_then(|t| t.name.clone());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: "user".into(),
        project: None,
        tenant: team_name.clone(),
        account_id: account.uuid.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();
    let mut has_droplets = false;
    let mut has_databases = false;
    let mut has_kubernetes = false;

    // Enumerate projects
    let projects = inventory_result(
        list_projects(client, token, api_base).await,
        "project:list",
        &mut permissions,
        &mut risk_notes,
    );

    for project in &projects {
        let project_name = project
            .name
            .clone()
            .or_else(|| project.id.clone())
            .unwrap_or_else(|| "unknown_project".to_string());

        let is_default = project.is_default.unwrap_or(false);

        resources.push(ResourceExposure {
            resource_type: "project".into(),
            name: project_name.clone(),
            permissions: vec!["project:read".to_string()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: if is_default {
                "Default DigitalOcean project".to_string()
            } else {
                "DigitalOcean project accessible with this token".to_string()
            },
        });
    }

    // Enumerate droplets
    let droplets = inventory_result(
        list_droplets(client, token, api_base).await,
        "droplet:list",
        &mut permissions,
        &mut risk_notes,
    );

    if !droplets.is_empty() {
        has_droplets = true;

        let role = RoleBinding {
            name: "droplet:access".into(),
            source: "digitalocean".into(),
            permissions: vec!["droplet:read".to_string()],
        };
        roles.push(role);
    }

    for droplet in &droplets {
        let droplet_name = droplet.name.clone().unwrap_or_else(|| {
            droplet.id.map(|id| id.to_string()).unwrap_or_else(|| "unknown_droplet".to_string())
        });

        let status = droplet.status.as_deref().unwrap_or("unknown");

        resources.push(ResourceExposure {
            resource_type: "droplet".into(),
            name: droplet_name.clone(),
            permissions: vec!["droplet:read".to_string()],
            risk: severity_to_str(Severity::High).to_string(),
            reason: format!("Compute droplet (status: {status}) accessible with this token"),
        });
    }

    // Enumerate databases
    let databases = inventory_result(
        list_databases(client, token, api_base).await,
        "database:list",
        &mut permissions,
        &mut risk_notes,
    );

    if !databases.is_empty() {
        has_databases = true;

        let role = RoleBinding {
            name: "database:access".into(),
            source: "digitalocean".into(),
            permissions: vec!["database:read".to_string()],
        };
        roles.push(role);
    }

    for db in &databases {
        let db_name = db
            .name
            .clone()
            .or_else(|| db.id.clone())
            .unwrap_or_else(|| "unknown_database".to_string());

        let engine = db.engine.as_deref().unwrap_or("unknown");

        resources.push(ResourceExposure {
            resource_type: "database".into(),
            name: db_name.clone(),
            permissions: vec!["database:read".to_string()],
            risk: severity_to_str(Severity::Critical).to_string(),
            reason: format!("Managed database ({engine}) accessible with this token"),
        });
    }

    // Enumerate Kubernetes clusters
    let clusters = inventory_result(
        list_kubernetes_clusters(client, token, api_base).await,
        "kubernetes:list",
        &mut permissions,
        &mut risk_notes,
    );

    if !clusters.is_empty() {
        has_kubernetes = true;

        let role = RoleBinding {
            name: "kubernetes:access".into(),
            source: "digitalocean".into(),
            permissions: vec!["kubernetes:read".to_string()],
        };
        roles.push(role);
    }

    for cluster in &clusters {
        let cluster_name = cluster
            .name
            .clone()
            .or_else(|| cluster.id.clone())
            .unwrap_or_else(|| "unknown_cluster".to_string());

        let region = cluster.region.as_deref().unwrap_or("unknown");

        resources.push(ResourceExposure {
            resource_type: "kubernetes_cluster".into(),
            name: cluster_name.clone(),
            permissions: vec!["kubernetes:read".to_string()],
            risk: severity_to_str(Severity::High).to_string(),
            reason: format!("Kubernetes cluster in {region} accessible with this token"),
        });
    }

    if team_name.is_some() {
        permissions.risky.push("team:member".to_string());
        risk_notes.push("Token has team-level access".into());
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(has_droplets, has_databases, has_kubernetes, &projects);

    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "DigitalOcean account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any resources".into());
    }

    Ok(AccessMapResult {
        cloud: "digitalocean".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: None,
            username: account.email.clone(),
            account_type: None,
            company: team_name,
            location: None,
            email: account.email.clone(),
            url: None,
            token_type: None,
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: account.uuid,
            scopes: Vec::new(),
        }),
        provider_metadata: Some(ProviderMetadata {
            authorization_evidence: Some(AuthorizationEvidence {
                limitations: vec![
                    "Resource listing proves metadata visibility, not write access or access to stored data".into(),
                    "Resource inventories are limited to their first API response; inaccessible services may be omitted".into(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        }),
        fingerprint: None,
    })
}

// A successful empty inventory still proves list access. Denials and malformed
// responses must remain distinguishable from empty successful inventories.
fn inventory_result<T>(
    result: Result<Vec<T>>,
    permission: &str,
    permissions: &mut PermissionSummary,
    risk_notes: &mut Vec<String>,
) -> Vec<T> {
    match result {
        Ok(items) => {
            permissions.read_only.push(permission.to_owned());
            items
        }
        Err(error) => {
            warn!("DigitalOcean access-map: {permission} failed: {error}");
            risk_notes.push(format!("{permission} inventory could not be read"));
            Vec::new()
        }
    }
}

async fn fetch_account(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<DigitalOceanAccount> {
    let resp = client
        .get(format!("{api_base}/v2/account"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("DigitalOcean access-map: failed to fetch account info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "DigitalOcean access-map: account lookup failed with HTTP {}",
            resp.status()
        ));
    }

    let body: AccountResponse =
        resp.json().await.context("DigitalOcean access-map: invalid account JSON")?;

    body.account
        .ok_or_else(|| anyhow!("DigitalOcean access-map: account field missing from response"))
}

async fn list_projects(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<Vec<DigitalOceanProject>> {
    let resp = client
        .get(format!("{api_base}/v2/projects"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("DigitalOcean access-map: failed to list projects")?;

    if !resp.status().is_success() {
        return Err(anyhow!("project enumeration failed with HTTP {}", resp.status()));
    }

    let body: ProjectsResponse =
        resp.json().await.context("DigitalOcean access-map: invalid projects JSON")?;
    Ok(body.projects)
}

async fn list_droplets(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<Vec<DigitalOceanDroplet>> {
    let resp = client
        .get(format!("{api_base}/v2/droplets"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("DigitalOcean access-map: failed to list droplets")?;

    if !resp.status().is_success() {
        return Err(anyhow!("droplet enumeration failed with HTTP {}", resp.status()));
    }

    let body: DropletsResponse =
        resp.json().await.context("DigitalOcean access-map: invalid droplets JSON")?;
    Ok(body.droplets)
}

async fn list_databases(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<Vec<DigitalOceanDatabase>> {
    let resp = client
        .get(format!("{api_base}/v2/databases"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("DigitalOcean access-map: failed to list databases")?;

    if !resp.status().is_success() {
        return Err(anyhow!("database enumeration failed with HTTP {}", resp.status()));
    }

    let body: DatabasesResponse =
        resp.json().await.context("DigitalOcean access-map: invalid databases JSON")?;
    Ok(body.databases)
}

async fn list_kubernetes_clusters(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<Vec<DigitalOceanKubernetesCluster>> {
    let resp = client
        .get(format!("{api_base}/v2/kubernetes/clusters"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("DigitalOcean access-map: failed to list kubernetes clusters")?;

    if !resp.status().is_success() {
        return Err(anyhow!("kubernetes enumeration failed with HTTP {}", resp.status()));
    }

    let body: KubernetesClustersResponse =
        resp.json().await.context("DigitalOcean access-map: invalid kubernetes JSON")?;
    Ok(body.kubernetes_clusters)
}

fn derive_severity(
    has_droplets: bool,
    has_databases: bool,
    _has_kubernetes: bool,
    projects: &[DigitalOceanProject],
) -> Severity {
    if has_databases {
        return Severity::Critical;
    }

    if has_droplets {
        return Severity::High;
    }

    if !projects.is_empty() {
        return Severity::Medium;
    }

    Severity::Low
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Unknown => "unknown",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn token_header_is_never_forwarded_to_a_redirect() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method},
        };
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", destination.uri().replace("127.0.0.1", "localhost")),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(super::map_access_from_token_at("test-token", &server.uri()).await.is_err());
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[tokio::test]
    async fn empty_successful_inventories_prove_list_access_but_denials_do_not() {
        for (status, valid_body) in [(200, true), (403, true), (500, true), (200, false)] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v2/account"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "account": { "email": "member@example.test" }
                })))
                .mount(&server)
                .await;
            for (endpoint, field) in [
                ("projects", "projects"),
                ("droplets", "droplets"),
                ("databases", "databases"),
                ("kubernetes/clusters", "kubernetes_clusters"),
            ] {
                Mock::given(method("GET"))
                    .and(path(format!("/v2/{endpoint}")))
                    .respond_with(ResponseTemplate::new(status).set_body_json(if valid_body {
                        json!({field: []})
                    } else {
                        json!({"unexpected": []})
                    }))
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            let result =
                map_access_with_client(&Client::new(), "token", &server.uri()).await.unwrap();
            if status == 200 && valid_body {
                assert_eq!(
                    result.permissions.read_only,
                    ["database:list", "droplet:list", "kubernetes:list", "project:list"]
                );
            } else {
                assert!(result.permissions.read_only.is_empty());
                assert!(result.risk_notes.iter().any(|note| note.contains("could not be read")));
            }
            assert!(result.roles.is_empty());
            assert!(matches!(result.severity, Severity::Low));
        }
    }

    #[tokio::test]
    async fn list_responses_do_not_establish_write_permissions() {
        let server = MockServer::start().await;
        for (endpoint, body) in [
            ("account", json!({ "account": { "email": "member@example.test" } })),
            ("projects", json!({ "projects": [] })),
            ("droplets", json!({ "droplets": [{ "id": 1, "name": "compute" }] })),
            ("databases", json!({ "databases": [{ "id": "database", "name": "data" }] })),
            (
                "kubernetes/clusters",
                json!({ "kubernetes_clusters": [{ "id": "cluster", "name": "cluster" }] }),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/v2/{endpoint}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let result = map_access_with_client(&Client::new(), "token", &server.uri()).await.unwrap();
        assert!(
            result
                .roles
                .iter()
                .flat_map(|role| &role.permissions)
                .all(|permission| !permission.ends_with(":write"))
        );
        assert!(result.permissions.admin.is_empty());
        assert!(result.permissions.read_only.contains(&"database:list".into()));
        assert!(matches!(result.severity, Severity::Critical));
    }
}
