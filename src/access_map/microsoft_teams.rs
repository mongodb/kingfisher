use anyhow::{Result, anyhow};
use reqwest::Url;

use crate::cli::commands::access_map::AccessMapArgs;

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, AuthorizationEvidence, PermissionSummary,
    ProviderMetadata, ResourceExposure, RoleBinding, Severity, build_recommendations,
};

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Microsoft Teams access-map requires a file containing the webhook URL")
    })?;
    let webhook_url = std::fs::read_to_string(path)?.trim().to_string();
    map_access_from_webhook_url(&webhook_url).await
}

pub async fn map_access_from_webhook_url(webhook_url: &str) -> Result<AccessMapResult> {
    let parsed = parse_webhook_url(webhook_url)?;

    let mut risk_notes = Vec::new();
    let mut permissions = PermissionSummary::default();

    let permission_label = "channel:post_messages".to_string();
    permissions.risky.push(permission_label.clone());

    risk_notes
        .push("Posting capability is inferred from the webhook format; no request was sent".into());

    risk_notes.push(format!("Tenant ID: {}", parsed.tenant_id));

    if parsed.is_workflow_webhook {
        risk_notes.push("Workflow webhook (webhookb2) — may support Adaptive Cards".into());
    } else {
        risk_notes
            .push("Legacy Incoming Webhook — connector-based, posts to a single channel".into());
    }

    let severity = Severity::Medium;

    let roles = vec![RoleBinding {
        name: "Incoming Webhook".into(),
        source: "microsoft_teams".into(),
        permissions: vec![permission_label],
    }];

    let resource_name = if let Some(ref subdomain) = parsed.subdomain {
        format!("{subdomain}.webhook.office.com")
    } else {
        "outlook.office.com".into()
    };

    let resources = vec![ResourceExposure {
        resource_type: "channel".into(),
        name: resource_name,
        permissions: vec!["post_messages".into()],
        risk: "medium".into(),
        reason: "Webhook format indicates potential message posting to this Teams channel".into(),
    }];

    let token_details = AccessTokenDetails {
        token_type: Some(if parsed.is_workflow_webhook {
            "workflow_webhook".into()
        } else {
            "incoming_webhook".into()
        }),
        url: Some(Url::parse(webhook_url)?.origin().ascii_serialization()),
        ..Default::default()
    };

    Ok(AccessMapResult {
        cloud: "microsoft_teams".into(),
        identity: AccessSummary {
            id: format!("webhook:{}", parsed.webhook_id),
            access_type: "webhook".into(),
            project: None,
            tenant: Some(parsed.tenant_id),
            account_id: None,
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(token_details),
        provider_metadata: Some(ProviderMetadata {
            authorization_evidence: Some(AuthorizationEvidence {
                limitations: vec!["Webhook liveness and posting rights were not probed because a request can trigger a configured workflow".into()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        fingerprint: None,
    })
}

struct ParsedWebhookUrl {
    tenant_id: String,
    webhook_id: String,
    subdomain: Option<String>,
    is_workflow_webhook: bool,
}

fn parse_webhook_url(url: &str) -> Result<ParsedWebhookUrl> {
    let parsed_url =
        Url::parse(url).map_err(|_| anyhow!("Malformed Microsoft Teams webhook URL"))?;
    let host = parsed_url.host_str().unwrap_or_default();
    if parsed_url.scheme() != "https"
        || !parsed_url.username().is_empty()
        || parsed_url.password().is_some()
        || !(host == "outlook.office.com" || host.ends_with(".webhook.office.com"))
    {
        return Err(anyhow!("URL does not have a supported Microsoft Teams webhook origin"));
    }
    let is_workflow = url.contains(".webhook.office.com/webhookb2/");
    let is_legacy = url.contains(".office.com/webhook/");

    if !is_workflow && !is_legacy {
        return Err(anyhow!("URL does not appear to be a Microsoft Teams webhook"));
    }

    let parts: Vec<&str> = url.splitn(2, "://").collect();
    let host_and_path = parts.get(1).unwrap_or(&"");

    let slash_pos = host_and_path.find('/').ok_or_else(|| anyhow!("Malformed webhook URL"))?;
    let host = &host_and_path[..slash_pos];
    let path = &host_and_path[slash_pos..];

    let subdomain = if is_workflow {
        host.strip_suffix(".webhook.office.com").map(|s| s.to_string())
    } else {
        None
    };

    let path_prefix = if is_workflow { "/webhookb2/" } else { "/webhook/" };
    let after_prefix =
        path.strip_prefix(path_prefix).ok_or_else(|| anyhow!("Cannot parse webhook path"))?;

    let segments: Vec<&str> = after_prefix.split('/').collect();

    let (webhook_id, tenant_id) = if let Some(at_pos) = segments.first().and_then(|s| s.find('@')) {
        let first = segments[0];
        let wid = &first[..at_pos];
        let tid = &first[at_pos + 1..];
        (wid.to_string(), tid.to_string())
    } else {
        let wid = segments.first().unwrap_or(&"unknown").to_string();
        let tid = segments.get(1).unwrap_or(&"unknown").to_string();
        (wid, tid)
    };

    Ok(ParsedWebhookUrl { tenant_id, webhook_id, subdomain, is_workflow_webhook: is_workflow })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mapping_is_passive_and_does_not_export_the_secret_url() {
        let url = "https://example.webhook.office.com/webhookb2/webhook-id@tenant-id/IncomingWebhook/secret-token/channel-id";
        let result = map_access_from_webhook_url(url).await.unwrap();
        let exported = serde_json::to_string(&result).unwrap();
        assert!(!exported.contains("secret-token"));
        assert_eq!(
            result.token_details.unwrap().url.as_deref(),
            Some("https://example.webhook.office.com")
        );
        assert!(result.risk_notes.iter().any(|note| note.contains("no request was sent")));
    }

    #[test]
    fn rejects_lookalike_webhook_origins() {
        assert!(
            parse_webhook_url(
                "https://example.invalid/x/.webhook.office.com/webhookb2/id@tenant/secret"
            )
            .is_err()
        );
    }
}
