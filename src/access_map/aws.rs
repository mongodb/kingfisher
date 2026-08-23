use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use aws_config::{BehaviorVersion, SdkConfig};
use aws_credential_types::Credentials;
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ecr::Client as EcrClient;
use aws_sdk_iam::{
    Client as IamClient,
    error::{ProvideErrorMetadata, SdkError},
    types::Role as IamRole,
};
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_lambda::Client as LambdaClient;
use aws_sdk_rds::Client as RdsClient;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_sns::Client as SnsClient;
use aws_sdk_sqs::Client as SqsClient;
use aws_sdk_ssm::Client as SsmClient;
use aws_sdk_sts::Client as StsClient;
use percent_encoding::percent_decode_str;
use serde_json::Value;
use tracing::warn;

use crate::cli::commands::access_map::AccessMapArgs;

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, AuthorizationEvidence, AuthorizationHop,
    AuthorizationPath, AuthorizationStatement, HierarchyScope, PermissionSummary, PolicyEvidence,
    PrincipalEvidence, ProviderMetadata, ResourceExposure, RoleBinding, Severity,
    build_default_account_resource, build_recommendations,
};

const MAX_DISCOVERED_ROLES: usize = 2_000;
const MAX_AUTHORIZATION_PATHS: usize = 256;
const MAX_EXPANDED_PATH_ROLES: usize = 32;
const MAX_PATH_ROLE_POLICY_EXPANSIONS: usize = 64;
const MAX_POLICY_EVIDENCE: usize = 512;
const MAX_POLICY_STATEMENTS: usize = 2_000;

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let config = load_config_from_path(args.credential_path.as_deref()).await?;
    map_access_with_config(config).await
}

fn permissions_for_prefix(summary: &PermissionSummary, prefix: &str) -> Vec<String> {
    let mut matches = BTreeSet::new();
    for perm in summary
        .admin
        .iter()
        .chain(&summary.privilege_escalation)
        .chain(&summary.risky)
        .chain(&summary.read_only)
    {
        if perm == "*" || perm.starts_with(prefix) {
            matches.insert(perm.clone());
        }
    }

    matches.into_iter().collect()
}

pub async fn map_access_with_credentials(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> Result<AccessMapResult> {
    let credentials = match session_token {
        Some(token) => {
            Credentials::new(access_key, secret_key, Some(token.to_string()), None, "access_map")
        }
        None => Credentials::new(access_key, secret_key, None, None, "access_map"),
    };

    let config = load_config(Some(credentials)).await?;
    map_access_with_config(config).await
}

async fn map_access_with_config(config: SdkConfig) -> Result<AccessMapResult> {
    let sts = StsClient::new(&config);
    let iam = IamClient::new(&config);

    let caller =
        sts.get_caller_identity().send().await.context("Failed to call sts:GetCallerIdentity")?;

    let arn = caller
        .arn()
        .ok_or_else(|| anyhow!("AWS GetCallerIdentity response missing ARN"))?
        .to_string();
    let account_id = caller.account().map(|s| s.to_string());
    let caller_user_id = caller.user_id().map(str::to_string);

    let identity = AccessSummary {
        id: arn.clone(),
        access_type: classify_identity(&arn).into(),
        project: None,
        tenant: None,
        account_id: account_id.clone(),
    };

    let mut roles = derive_roles_from_arn(&arn);
    let mut risk_notes = Vec::new();
    let mut authorization_evidence = AuthorizationEvidence {
        hierarchy: account_id
            .iter()
            .map(|account| HierarchyScope { kind: "account".into(), id: account.clone() })
            .collect(),
        ..AuthorizationEvidence::default()
    };
    let mut principal = PrincipalContext::new(
        arn.clone(),
        account_id.clone(),
        caller_user_id,
        classify_identity(&arn),
    );
    let groups =
        inspect_principal(&iam, &mut principal, &mut authorization_evidence, &mut risk_notes).await;

    let permissions = expand_permissions(
        &iam,
        &principal,
        &groups,
        &mut roles,
        &mut authorization_evidence,
        &mut risk_notes,
    )
    .await
    .unwrap_or_else(|err| {
        warn!("AWS access-map: failed to enumerate IAM permissions: {err}");
        risk_notes.push(format!("IAM enumeration failed: {err}"));
        PermissionSummary::default()
    });

    let role_discovery =
        discover_role_paths(&iam, &principal, &mut authorization_evidence, &mut risk_notes).await;
    let mut resources = enumerate_resources(
        &config,
        &permissions,
        account_id.as_deref(),
        &role_discovery.inventory,
        &mut risk_notes,
    )
    .await
    .unwrap_or_else(|err| {
        warn!("AWS access-map: resource enumeration failed: {err}");
        risk_notes.push(format!("AWS enumeration failed: {err}"));
        Vec::new()
    });

    let severity = max_severity(
        derive_severity(&identity.access_type, &permissions, !resources.is_empty()),
        severity_for_reachable_permissions(&role_discovery.reachable_permissions),
    );
    if !role_discovery.reachable_permissions.is_empty() {
        risk_notes.push(format!(
            "Potential role paths reach {} additional permission entries.",
            role_discovery.reachable_permissions.total()
        ));
    }

    if roles.is_empty() {
        roles.push(RoleBinding {
            name: identity.access_type.clone(),
            source: "sts".into(),
            permissions: Vec::new(),
        });
    }

    if resources.is_empty() {
        resources.push(build_default_account_resource(account_id.as_deref(), severity));
    }

    if arn.contains(":assumed-role/") {
        risk_notes.push(
            "Credential represents an assumed role session; review the role trust policy and session duration".into(),
        );
    }
    if identity.access_type == "root" {
        risk_notes.push(
            "Credential authenticates as the AWS account root user; root access keys have unrestricted account-level impact.".into(),
        );
    }
    if identity.access_type != "root"
        && permissions.admin.is_empty()
        && permissions.privilege_escalation.is_empty()
        && permissions.risky.is_empty()
        && permissions.read_only.is_empty()
    {
        risk_notes.push("IAM permissions could not be enumerated for this identity.".into());
    }

    let recommendations = build_recommendations(severity);
    truncate_authorization_evidence(&mut authorization_evidence);

    Ok(AccessMapResult {
        cloud: "aws".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations,
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: principal.name.clone().or_else(|| account_id.clone()),
            username: (principal.kind == "user").then(|| principal.name.clone()).flatten(),
            account_type: Some(principal.kind.clone()),
            company: None,
            location: None,
            email: None,
            url: None,
            token_type: Some("access_key".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: Some(principal.authorization_arn().to_string()),
            scopes: Vec::new(),
        }),
        provider_metadata: Some(ProviderMetadata {
            version: None,
            enterprise: None,
            authorization_evidence: Some(authorization_evidence),
        }),
        fingerprint: None,
    })
}

#[derive(Clone, Debug)]
struct PrincipalContext {
    raw_arn: String,
    canonical_arn: Option<String>,
    account_id: Option<String>,
    user_id: Option<String>,
    kind: String,
    name: Option<String>,
    tags: BTreeMap<String, String>,
    tags_complete: bool,
}

impl PrincipalContext {
    fn new(
        raw_arn: String,
        account_id: Option<String>,
        user_id: Option<String>,
        kind: &str,
    ) -> Self {
        let resource = raw_arn.split(':').nth(5).unwrap_or_default();
        let name = principal_name_from_resource(resource, &["assumed-role", "role", "user"]);
        Self {
            raw_arn,
            canonical_arn: None,
            account_id,
            user_id,
            kind: kind.to_string(),
            name,
            tags: BTreeMap::new(),
            tags_complete: false,
        }
    }

    fn authorization_arn(&self) -> &str {
        self.canonical_arn.as_deref().unwrap_or(&self.raw_arn)
    }
}

#[derive(Clone, Debug)]
struct AwsGroup {
    name: String,
    arn: String,
}

async fn inspect_principal(
    iam: &IamClient,
    principal: &mut PrincipalContext,
    evidence: &mut AuthorizationEvidence,
    risk_notes: &mut Vec<String>,
) -> Vec<AwsGroup> {
    let mut groups = Vec::new();
    let mut attributes = BTreeMap::new();
    if let Some(user_id) = principal.user_id.as_ref() {
        attributes.insert("sts_user_id".into(), user_id.clone());
    }

    match principal.kind.as_str() {
        "user" => {
            if let Some(user_name) = principal.name.as_deref() {
                match iam.get_user().user_name(user_name).send().await {
                    Ok(output) => {
                        if let Some(user) = output.user() {
                            principal.canonical_arn = Some(user.arn().to_string());
                            principal.tags = tags_to_map(user.tags());
                            principal.tags_complete = true;
                            attributes.insert("iam_id".into(), user.user_id().to_string());
                            attributes.insert("path".into(), user.path().to_string());
                            if user.permissions_boundary().is_some() {
                                attributes.insert("permissions_boundary".into(), "present".into());
                                push_unique_note(
                                    &mut evidence.limitations,
                                    "An IAM permissions boundary applies to the principal and may reduce the listed permissions.".into(),
                                );
                            }
                        }
                    }
                    Err(err) => record_iam_error(
                        err,
                        risk_notes,
                        &format!("get_user failed for user {user_name}"),
                    ),
                }

                let mut pages =
                    iam.list_groups_for_user().user_name(user_name).into_paginator().items().send();
                loop {
                    match pages.try_next().await {
                        Ok(Some(group)) => groups.push(AwsGroup {
                            name: group.group_name().to_string(),
                            arn: group.arn().to_string(),
                        }),
                        Ok(None) => break,
                        Err(err) => {
                            record_iam_error(
                                err,
                                risk_notes,
                                &format!("list_groups_for_user failed for user {user_name}"),
                            );
                            push_unique_note(
                                &mut evidence.limitations,
                                "IAM group membership could not be completely enumerated.".into(),
                            );
                            break;
                        }
                    }
                }
            }
        }
        "role" | "assumed_role" => {
            if let Some(role_name) = principal.name.as_deref() {
                match iam.get_role().role_name(role_name).send().await {
                    Ok(output) => {
                        if let Some(role) = output.role() {
                            principal.canonical_arn = Some(role.arn().to_string());
                            principal.tags = tags_to_map(role.tags());
                            principal.tags_complete = true;
                            attributes.insert("iam_id".into(), role.role_id().to_string());
                            attributes.insert("path".into(), role.path().to_string());
                            if let Some(duration) = role.max_session_duration() {
                                attributes.insert(
                                    "max_session_duration_seconds".into(),
                                    duration.to_string(),
                                );
                            }
                            if role.permissions_boundary().is_some() {
                                attributes.insert("permissions_boundary".into(), "present".into());
                                push_unique_note(
                                    &mut evidence.limitations,
                                    "An IAM permissions boundary applies to the principal and may reduce the listed permissions.".into(),
                                );
                            }
                            if let Some(document) = role.assume_role_policy_document()
                                && let Err(err) = add_policy_evidence(
                                    document,
                                    PolicySource::trust(role.arn()),
                                    evidence,
                                )
                            {
                                push_unique_note(
                                    risk_notes,
                                    format!(
                                        "Failed to parse trust policy for role {role_name}: {err}"
                                    ),
                                );
                            }
                        }
                    }
                    Err(err) => {
                        record_iam_error(
                            err,
                            risk_notes,
                            &format!("get_role failed for role {role_name}"),
                        );
                        push_unique_note(
                            &mut evidence.limitations,
                            "The backing IAM role could not be resolved from the session ARN."
                                .into(),
                        );
                    }
                }
            }
        }
        _ => {}
    }

    groups.sort_by(|left, right| left.name.cmp(&right.name));
    evidence.principal = Some(PrincipalEvidence {
        id: principal.raw_arn.clone(),
        kind: principal.kind.clone(),
        canonical_id: principal.canonical_arn.clone(),
        name: principal.name.clone(),
        groups: groups.iter().map(|group| group.name.clone()).collect(),
        tags: redacted_tag_presence(&principal.tags),
        attributes,
    });

    groups
}

fn tags_to_map(tags: &[aws_sdk_iam::types::Tag]) -> BTreeMap<String, String> {
    tags.iter().map(|tag| (tag.key().to_string(), tag.value().to_string())).collect()
}

fn redacted_tag_presence(tags: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    tags.keys().map(|key| (key.clone(), "present".into())).collect()
}

fn classify_identity(arn: &str) -> &'static str {
    if arn.contains(":assumed-role/") {
        "assumed_role"
    } else if arn.contains(":role/") {
        "role"
    } else if arn.contains(":user/") {
        "user"
    } else if arn.contains(":root") {
        "root"
    } else {
        "unknown"
    }
}

fn derive_roles_from_arn(arn: &str) -> Vec<RoleBinding> {
    let resource = arn.split(':').nth(5).unwrap_or_default();
    let role_name = principal_name_from_resource(resource, &["assumed-role", "role"]);

    if let Some(name) = role_name {
        vec![RoleBinding { name, source: "iam".into(), permissions: Vec::new() }]
    } else {
        Vec::new()
    }
}

async fn expand_permissions(
    iam: &IamClient,
    principal: &PrincipalContext,
    groups: &[AwsGroup],
    roles: &mut Vec<RoleBinding>,
    evidence: &mut AuthorizationEvidence,
    risk_notes: &mut Vec<String>,
) -> Result<PermissionSummary> {
    let access_type = principal.kind.as_str();
    let name = principal.name.clone().unwrap_or_default();

    if principal.raw_arn.contains(":assumed-role/AWSReservedSSO_") {
        risk_notes.push(
            "This is an AWS IAM Identity Center session; Kingfisher will inspect the backing AWSReservedSSO role when IAM read access is available.".into(),
        );
    }

    let mut policy_flags = PolicyDocumentFlags::default();
    let mut actions = match access_type {
        "role" | "assumed_role" => {
            collect_role_actions(
                iam,
                &name,
                principal.authorization_arn(),
                &mut policy_flags,
                evidence,
                risk_notes,
            )
            .await
        }
        "user" => {
            collect_user_actions(
                iam,
                &name,
                principal.authorization_arn(),
                groups,
                &mut policy_flags,
                evidence,
                risk_notes,
            )
            .await
        }
        _ => Vec::new(),
    };

    finalize_policy_actions(&mut actions, &policy_flags, risk_notes);

    if roles.is_empty() && access_type == "user" {
        roles.push(RoleBinding {
            name,
            source: "iam_user_and_groups".into(),
            permissions: actions.clone(),
        });
    }

    for role in roles.iter_mut() {
        if role.permissions.is_empty() {
            role.permissions = actions.clone();
        }
    }

    Ok(classify_permissions(&actions))
}

fn principal_name_from_resource(resource: &str, kinds: &[&str]) -> Option<String> {
    let (kind, name_and_path) = resource.split_once('/')?;
    if !kinds.contains(&kind) {
        return None;
    }

    let name = if kind == "assumed-role" {
        name_and_path.split('/').next()
    } else {
        name_and_path.rsplit('/').next()
    }?;

    (!name.is_empty()).then(|| name.to_string())
}

#[derive(Default)]
struct PolicyDocumentFlags {
    denied_actions: Vec<String>,
    saw_deny: bool,
    saw_allow_not_action: bool,
    saw_condition: bool,
    saw_scoped_resource: bool,
}

async fn collect_role_actions(
    iam: &IamClient,
    role_name: &str,
    role_arn: &str,
    policy_flags: &mut PolicyDocumentFlags,
    evidence: &mut AuthorizationEvidence,
    risk_notes: &mut Vec<String>,
) -> Vec<String> {
    let mut actions = Vec::new();

    let mut attached =
        iam.list_attached_role_policies().role_name(role_name).into_paginator().items().send();
    loop {
        match attached.try_next().await {
            Ok(Some(policy)) => {
                if let Some(arn) = policy.policy_arn()
                    && let Err(err) = collect_managed_policy_actions(
                        iam,
                        arn,
                        ManagedPolicyAttachment::new(policy.policy_name(), role_arn, None),
                        &mut actions,
                        policy_flags,
                        evidence,
                        risk_notes,
                    )
                    .await
                {
                    push_unique_note(risk_notes, format!("IAM enumeration incomplete: {err}"));
                }
            }
            Ok(None) => break,
            Err(err) => {
                record_iam_error(
                    err,
                    risk_notes,
                    &format!("list_attached_role_policies failed for role {role_name}"),
                );
                break;
            }
        }
    }

    let mut inline = iam.list_role_policies().role_name(role_name).into_paginator().items().send();
    loop {
        match inline.try_next().await {
            Ok(Some(name)) => {
                match iam.get_role_policy().role_name(role_name).policy_name(&name).send().await {
                    Ok(policy) => {
                        if let Err(err) = extract_actions_from_document(
                            policy.policy_document(),
                            &mut actions,
                            policy_flags,
                        ) {
                            push_unique_note(
                                risk_notes,
                                format!(
                                    "Failed to parse inline policy {name} for role {role_name}: {err}"
                                ),
                            );
                        } else if let Err(err) = add_policy_evidence(
                            policy.policy_document(),
                            PolicySource::inline(&name, role_arn, None),
                            evidence,
                        ) {
                            push_unique_note(
                                risk_notes,
                                format!(
                                    "Failed to retain inline policy {name} for role {role_name}: {err}"
                                ),
                            );
                        }
                    }
                    Err(err) => record_iam_error(
                        err,
                        risk_notes,
                        &format!("get_role_policy failed for role {role_name} policy {name}"),
                    ),
                }
            }
            Ok(None) => break,
            Err(err) => {
                record_iam_error(
                    err,
                    risk_notes,
                    &format!("list_role_policies failed for role {role_name}"),
                );
                break;
            }
        }
    }

    actions
}

async fn collect_user_actions(
    iam: &IamClient,
    user_name: &str,
    user_arn: &str,
    groups: &[AwsGroup],
    policy_flags: &mut PolicyDocumentFlags,
    evidence: &mut AuthorizationEvidence,
    risk_notes: &mut Vec<String>,
) -> Vec<String> {
    let mut actions = Vec::new();

    let mut attached =
        iam.list_attached_user_policies().user_name(user_name).into_paginator().items().send();
    loop {
        match attached.try_next().await {
            Ok(Some(policy)) => {
                if let Some(arn) = policy.policy_arn()
                    && let Err(err) = collect_managed_policy_actions(
                        iam,
                        arn,
                        ManagedPolicyAttachment::new(policy.policy_name(), user_arn, None),
                        &mut actions,
                        policy_flags,
                        evidence,
                        risk_notes,
                    )
                    .await
                {
                    push_unique_note(risk_notes, format!("IAM enumeration incomplete: {err}"));
                }
            }
            Ok(None) => break,
            Err(err) => {
                record_iam_error(
                    err,
                    risk_notes,
                    &format!("list_attached_user_policies failed for user {user_name}"),
                );
                break;
            }
        }
    }

    let mut inline = iam.list_user_policies().user_name(user_name).into_paginator().items().send();
    loop {
        match inline.try_next().await {
            Ok(Some(name)) => {
                match iam.get_user_policy().user_name(user_name).policy_name(&name).send().await {
                    Ok(policy) => {
                        if let Err(err) = extract_actions_from_document(
                            policy.policy_document(),
                            &mut actions,
                            policy_flags,
                        ) {
                            push_unique_note(
                                risk_notes,
                                format!(
                                    "Failed to parse inline policy {name} for user {user_name}: {err}"
                                ),
                            );
                        } else if let Err(err) = add_policy_evidence(
                            policy.policy_document(),
                            PolicySource::inline(&name, user_arn, None),
                            evidence,
                        ) {
                            push_unique_note(
                                risk_notes,
                                format!(
                                    "Failed to retain inline policy {name} for user {user_name}: {err}"
                                ),
                            );
                        }
                    }
                    Err(err) => record_iam_error(
                        err,
                        risk_notes,
                        &format!("get_user_policy failed for user {user_name} policy {name}"),
                    ),
                }
            }
            Ok(None) => break,
            Err(err) => {
                record_iam_error(
                    err,
                    risk_notes,
                    &format!("list_user_policies failed for user {user_name}"),
                );
                break;
            }
        }
    }

    collect_user_group_actions(
        iam,
        user_arn,
        groups,
        &mut actions,
        policy_flags,
        evidence,
        risk_notes,
    )
    .await;

    actions
}

async fn collect_user_group_actions(
    iam: &IamClient,
    user_arn: &str,
    groups: &[AwsGroup],
    actions: &mut Vec<String>,
    policy_flags: &mut PolicyDocumentFlags,
    evidence: &mut AuthorizationEvidence,
    risk_notes: &mut Vec<String>,
) {
    for group in groups {
        let group_name = group.name.as_str();

        let mut attached = iam
            .list_attached_group_policies()
            .group_name(group_name)
            .into_paginator()
            .items()
            .send();
        loop {
            match attached.try_next().await {
                Ok(Some(policy)) => {
                    if let Some(arn) = policy.policy_arn()
                        && let Err(err) = collect_managed_policy_actions(
                            iam,
                            arn,
                            ManagedPolicyAttachment::new(
                                policy.policy_name(),
                                &group.arn,
                                Some(user_arn),
                            ),
                            actions,
                            policy_flags,
                            evidence,
                            risk_notes,
                        )
                        .await
                    {
                        push_unique_note(risk_notes, format!("IAM enumeration incomplete: {err}"));
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_iam_error(
                        err,
                        risk_notes,
                        &format!("list_attached_group_policies failed for group {group_name}"),
                    );
                    break;
                }
            }
        }

        let mut inline =
            iam.list_group_policies().group_name(group_name).into_paginator().items().send();
        loop {
            match inline.try_next().await {
                Ok(Some(name)) => {
                    match iam
                        .get_group_policy()
                        .group_name(group_name)
                        .policy_name(&name)
                        .send()
                        .await
                    {
                        Ok(policy) => {
                            if let Err(err) = extract_actions_from_document(
                                policy.policy_document(),
                                actions,
                                policy_flags,
                            ) {
                                push_unique_note(
                                    risk_notes,
                                    format!(
                                        "Failed to parse inline policy {name} for group {group_name}: {err}"
                                    ),
                                );
                            } else if let Err(err) = add_policy_evidence(
                                policy.policy_document(),
                                PolicySource::inline(&name, &group.arn, Some(user_arn)),
                                evidence,
                            ) {
                                push_unique_note(
                                    risk_notes,
                                    format!(
                                        "Failed to retain inline policy {name} for group {group_name}: {err}"
                                    ),
                                );
                            }
                        }
                        Err(err) => record_iam_error(
                            err,
                            risk_notes,
                            &format!(
                                "get_group_policy failed for group {group_name} policy {name}"
                            ),
                        ),
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_iam_error(
                        err,
                        risk_notes,
                        &format!("list_group_policies failed for group {group_name}"),
                    );
                    break;
                }
            }
        }
    }
}

async fn collect_managed_policy_actions(
    iam: &IamClient,
    policy_arn: &str,
    attachment: ManagedPolicyAttachment<'_>,
    actions: &mut Vec<String>,
    policy_flags: &mut PolicyDocumentFlags,
    evidence: &mut AuthorizationEvidence,
    risk_notes: &mut Vec<String>,
) -> Result<()> {
    let policy = iam.get_policy().policy_arn(policy_arn).send().await.map_err(|err| {
        map_iam_error(err, risk_notes, &format!("get_policy failed for {policy_arn}"))
    })?;
    let version = policy
        .policy()
        .and_then(|p| p.default_version_id())
        .ok_or_else(|| anyhow!("Managed policy {policy_arn} missing default version"))?;

    let document =
        iam.get_policy_version().policy_arn(policy_arn).version_id(version).send().await.map_err(
            |err| {
                map_iam_error(
                    err,
                    risk_notes,
                    &format!("get_policy_version failed for {policy_arn} version {version}"),
                )
            },
        )?;

    if let Some(doc) = document.policy_version().and_then(|v| v.document()) {
        extract_actions_from_document(doc, actions, policy_flags)?;
        add_policy_evidence(
            doc,
            PolicySource::managed(
                policy_arn,
                attachment.name,
                version,
                attachment.attached_to,
                attachment.attached_via,
            ),
            evidence,
        )?;
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ManagedPolicyAttachment<'a> {
    name: Option<&'a str>,
    attached_to: &'a str,
    attached_via: Option<&'a str>,
}

impl<'a> ManagedPolicyAttachment<'a> {
    fn new(name: Option<&'a str>, attached_to: &'a str, attached_via: Option<&'a str>) -> Self {
        Self { name, attached_to, attached_via }
    }
}

#[derive(Clone, Debug)]
struct PolicySource {
    id: String,
    name: Option<String>,
    kind: String,
    attached_to: String,
    attached_via: Option<String>,
    version: Option<String>,
}

impl PolicySource {
    fn managed(
        arn: &str,
        name: Option<&str>,
        version: &str,
        attached_to: &str,
        attached_via: Option<&str>,
    ) -> Self {
        Self {
            id: format!("{arn}:{version}:{attached_to}"),
            name: name.map(str::to_string),
            kind: "managed".into(),
            attached_to: attached_to.into(),
            attached_via: attached_via.map(str::to_string),
            version: Some(version.into()),
        }
    }

    fn inline(name: &str, attached_to: &str, attached_via: Option<&str>) -> Self {
        Self {
            id: format!("inline:{attached_to}:{name}"),
            name: Some(name.into()),
            kind: "inline".into(),
            attached_to: attached_to.into(),
            attached_via: attached_via.map(str::to_string),
            version: None,
        }
    }

    fn trust(role_arn: &str) -> Self {
        Self {
            id: format!("trust:{role_arn}"),
            name: Some("AssumeRolePolicyDocument".into()),
            kind: "trust".into(),
            attached_to: role_arn.into(),
            attached_via: None,
            version: None,
        }
    }
}

fn add_policy_evidence(
    document: &str,
    source: PolicySource,
    evidence: &mut AuthorizationEvidence,
) -> Result<()> {
    if evidence.policies.iter().any(|policy| policy.id == source.id) {
        return Ok(());
    }
    let statements = parse_policy_statements(document, &source.id)?;
    if statements.is_empty() {
        return Ok(());
    }
    evidence.policies.push(PolicyEvidence {
        id: source.id,
        name: source.name,
        kind: source.kind,
        attached_to: source.attached_to,
        attached_via: source.attached_via,
        scope: None,
        version: source.version,
        statements,
    });
    Ok(())
}

fn truncate_authorization_evidence(evidence: &mut AuthorizationEvidence) {
    let referenced: HashSet<String> =
        evidence.paths.iter().flat_map(|path| path.evidence.iter().cloned()).collect();
    evidence.policies.sort_by_key(|policy| {
        let referenced_policy = referenced.contains(&policy.id)
            || policy.statements.iter().any(|statement| referenced.contains(&statement.id));
        !referenced_policy
    });
    for policy in &mut evidence.policies {
        policy.statements.sort_by_key(|statement| !referenced.contains(&statement.id));
    }

    if evidence.policies.len() > MAX_POLICY_EVIDENCE {
        evidence.policies.truncate(MAX_POLICY_EVIDENCE);
        push_unique_note(
            &mut evidence.limitations,
            format!("Policy evidence was limited to {MAX_POLICY_EVIDENCE} documents."),
        );
    }

    let mut remaining = MAX_POLICY_STATEMENTS;
    let mut statements_truncated = false;
    for policy in &mut evidence.policies {
        if policy.statements.len() > remaining {
            policy.statements.truncate(remaining);
            statements_truncated = true;
        }
        remaining = remaining.saturating_sub(policy.statements.len());
    }
    if statements_truncated {
        push_unique_note(
            &mut evidence.limitations,
            format!("Policy evidence was limited to {MAX_POLICY_STATEMENTS} statements."),
        );
    }
    evidence.policies.retain(|policy| !policy.statements.is_empty());

    let retained_statements: HashSet<&str> = evidence
        .policies
        .iter()
        .flat_map(|policy| policy.statements.iter().map(|statement| statement.id.as_str()))
        .collect();
    let mut references_truncated = false;
    for path in &mut evidence.paths {
        let previous = path.evidence.len();
        path.evidence
            .retain(|item| retained_statements.contains(item.as_str()) || !item.contains('#'));
        references_truncated |= path.evidence.len() != previous;
    }
    if references_truncated {
        push_unique_note(
            &mut evidence.limitations,
            "Some path evidence references were omitted by report-size limits.".into(),
        );
    }
}

fn decode_policy_document(document: &str) -> Result<Value> {
    let trimmed = document.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return match value {
            Value::String(inner) => serde_json::from_str(&inner)
                .map_err(|err| anyhow!("Failed to parse wrapped IAM policy document: {err}")),
            other => Ok(other),
        };
    }

    let decoded = percent_decode_str(trimmed).decode_utf8()?.into_owned();
    let value: Value = serde_json::from_str(&decoded)
        .map_err(|err| anyhow!("Failed to parse IAM policy document: {err}"))?;
    match value {
        Value::String(inner) => serde_json::from_str(&inner)
            .map_err(|err| anyhow!("Failed to parse wrapped IAM policy document: {err}")),
        other => Ok(other),
    }
}

fn parse_policy_statements(document: &str, policy_id: &str) -> Result<Vec<AuthorizationStatement>> {
    let json = decode_policy_document(document)?;
    let statements = match json.get("Statement") {
        Some(Value::Array(statements)) => statements.clone(),
        Some(statement) => vec![statement.clone()],
        None => Vec::new(),
    };

    Ok(statements
        .iter()
        .enumerate()
        .map(|(index, statement)| authorization_statement(statement, policy_id, index))
        .collect())
}

fn authorization_statement(
    statement: &Value,
    policy_id: &str,
    index: usize,
) -> AuthorizationStatement {
    let sid = statement.get("Sid").and_then(Value::as_str).map(str::to_string);
    let statement_id = sid.clone().unwrap_or_else(|| index.to_string());
    AuthorizationStatement {
        id: format!("{policy_id}#{statement_id}"),
        sid,
        effect: statement.get("Effect").and_then(Value::as_str).unwrap_or("Unknown").to_string(),
        actions: string_values(statement.get("Action")),
        not_actions: string_values(statement.get("NotAction")),
        resources: string_values(statement.get("Resource")),
        not_resources: string_values(statement.get("NotResource")),
        principals: principal_values(statement.get("Principal")),
        not_principals: principal_values(statement.get("NotPrincipal")),
        condition_keys: condition_keys(statement.get("Condition")),
    }
}

fn string_values(value: Option<&Value>) -> Vec<String> {
    let mut values = match value {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => {
            values.iter().filter_map(Value::as_str).map(str::to_string).collect()
        }
        _ => Vec::new(),
    };
    values.sort();
    values.dedup();
    values
}

fn principal_values(value: Option<&Value>) -> Vec<String> {
    let mut values = Vec::new();
    match value {
        Some(Value::String(value)) => values.push(value.clone()),
        Some(Value::Array(items)) => {
            values.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
        }
        Some(Value::Object(principals)) => {
            for (kind, principal) in principals {
                for value in string_values(Some(principal)) {
                    values.push(format!("{kind}:{value}"));
                }
            }
        }
        _ => {}
    }
    values.sort();
    values.dedup();
    values
}

fn condition_keys(value: Option<&Value>) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(Value::Object(operators)) = value {
        for (operator, entries) in operators {
            if let Value::Object(entries) = entries {
                keys.extend(entries.keys().map(|key| format!("{operator}:{key}")));
            } else {
                keys.push(operator.clone());
            }
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

fn extract_actions_from_document(
    doc: &str,
    actions: &mut Vec<String>,
    policy_flags: &mut PolicyDocumentFlags,
) -> Result<()> {
    let json = decode_policy_document(doc)?;

    if let Some(statements) = json.get("Statement") {
        if let Some(array) = statements.as_array() {
            for stmt in array {
                collect_actions_from_statement(stmt, actions, policy_flags);
            }
        } else {
            collect_actions_from_statement(statements, actions, policy_flags);
        }
    }

    Ok(())
}

fn collect_actions_from_statement(
    statement: &Value,
    actions: &mut Vec<String>,
    policy_flags: &mut PolicyDocumentFlags,
) {
    let effect = statement.get("Effect").and_then(Value::as_str).unwrap_or_default();
    if effect.eq_ignore_ascii_case("Deny") {
        let has_condition = statement.get("Condition").is_some();
        let has_scoped_resource = statement_has_scoped_resource(statement);
        policy_flags.saw_deny = true;
        policy_flags.saw_condition |= has_condition;
        policy_flags.saw_scoped_resource |= has_scoped_resource;

        // Only subtract unconditional, account-wide denies from concrete actions. Conditional
        // and resource-scoped denies cannot be flattened safely without evaluating request
        // context, resource policies, boundaries, and organization policies.
        if !has_condition
            && !has_scoped_resource
            && let Some(action) = statement.get("Action")
        {
            collect_action_values(action, &mut policy_flags.denied_actions);
        }
        return;
    }
    if !effect.eq_ignore_ascii_case("Allow") {
        return;
    }

    policy_flags.saw_condition |= statement.get("Condition").is_some();
    policy_flags.saw_scoped_resource |= statement_has_scoped_resource(statement);

    if let Some(action) = statement.get("Action") {
        collect_action_values(action, actions);
    }

    if let Some(not_action) = statement.get("NotAction") {
        policy_flags.saw_allow_not_action = true;
        collect_action_values(not_action, &mut policy_flags.denied_actions);
        actions.push("*".into());
    }
}

fn statement_has_scoped_resource(statement: &Value) -> bool {
    if statement.get("NotResource").is_some() {
        return true;
    }

    match statement.get("Resource") {
        None => false,
        Some(Value::String(resource)) => resource != "*",
        Some(Value::Array(resources)) => {
            resources.iter().any(|resource| resource.as_str() != Some("*"))
        }
        Some(_) => true,
    }
}

fn collect_action_values(value: &Value, actions: &mut Vec<String>) {
    match value {
        Value::String(s) => actions.push(s.to_lowercase().replace(':', ".")),
        Value::Array(arr) => {
            for v in arr {
                if let Some(s) = v.as_str() {
                    actions.push(s.to_lowercase().replace(':', "."));
                }
            }
        }
        _ => {}
    }
}

fn finalize_policy_actions(
    actions: &mut Vec<String>,
    policy_flags: &PolicyDocumentFlags,
    risk_notes: &mut Vec<String>,
) {
    actions.sort();
    actions.dedup();

    if policy_flags.denied_actions.iter().any(|action| action == "*") {
        actions.clear();
    } else {
        actions.retain(|action| {
            action.contains('*')
                || !policy_flags
                    .denied_actions
                    .iter()
                    .any(|denied| wildcard_matches(denied, action))
        });
    }

    if policy_flags.saw_deny || !policy_flags.denied_actions.is_empty() {
        push_unique_note(
            risk_notes,
            "IAM policies include explicit exclusions or Deny statements; wildcard permissions may be narrower than the summary can represent.".into(),
        );
    }
    if policy_flags.saw_allow_not_action {
        push_unique_note(
            risk_notes,
            "An IAM Allow statement uses NotAction; Kingfisher conservatively summarizes it as wildcard access with exclusions.".into(),
        );
    }
    if policy_flags.saw_condition {
        push_unique_note(
            risk_notes,
            "Some IAM permissions are conditional; actual access depends on request and session context.".into(),
        );
    }
    if policy_flags.saw_scoped_resource {
        push_unique_note(
            risk_notes,
            "Some IAM permissions are resource-scoped; action summaries do not imply access to every resource in the service.".into(),
        );
    }
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star_index, mut star_value_index) = (None, 0);

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

#[derive(Clone, Debug)]
struct TrustMatch {
    statement_id: String,
    related_statement_ids: Vec<String>,
    conditional: bool,
    condition_keys: Vec<String>,
    identity_policy_required: bool,
}

#[derive(Clone, Debug)]
struct DirectRolePath {
    role: IamRole,
    path: AuthorizationPath,
}

struct RolePathDiscovery {
    inventory: Vec<IamRole>,
    reachable_permissions: PermissionSummary,
}

async fn discover_role_paths(
    iam: &IamClient,
    principal: &PrincipalContext,
    evidence: &mut AuthorizationEvidence,
    risk_notes: &mut Vec<String>,
) -> RolePathDiscovery {
    push_unique_note(
        &mut evidence.limitations,
        "Role paths are inferred from visible IAM policies; Kingfisher does not assume discovered roles.".into(),
    );
    push_unique_note(
        &mut evidence.limitations,
        "Organization policies, resource control policies, permissions boundaries, session policies, and request context can reduce effective access.".into(),
    );
    push_unique_note(
        &mut evidence.limitations,
        "Role trust discovery is limited to roles visible in the caller's current account; cross-account target roles cannot be confirmed from this inventory.".into(),
    );

    let mut inventory = Vec::new();
    let mut pages = iam.list_roles().into_paginator().items().send();
    loop {
        match pages.try_next().await {
            Ok(Some(role)) => {
                inventory.push(role);
                if inventory.len() >= MAX_DISCOVERED_ROLES {
                    push_unique_note(
                        &mut evidence.limitations,
                        format!("IAM role discovery stopped after {MAX_DISCOVERED_ROLES} roles."),
                    );
                    break;
                }
            }
            Ok(None) => break,
            Err(err) => {
                record_iam_error(err, risk_notes, "list_roles failed during role-path discovery");
                push_unique_note(
                    &mut evidence.limitations,
                    "IAM role inventory could not be completely enumerated.".into(),
                );
                break;
            }
        }
    }

    let mut emitted_edges = HashSet::new();
    let mut inspected_role_policies = HashSet::new();
    let mut reachable_actions = Vec::new();
    let mut direct_paths = Vec::new();
    for role in &inventory {
        if evidence.paths.len() >= MAX_AUTHORIZATION_PATHS {
            record_path_cap(evidence);
            break;
        }
        if role.arn() == principal.authorization_arn() {
            continue;
        }
        let Some(document) = role.assume_role_policy_document() else {
            continue;
        };
        let matches = trust_matches(document, role.arn(), principal);
        if matches.is_empty() {
            continue;
        }

        if let Err(err) = add_policy_evidence(document, PolicySource::trust(role.arn()), evidence) {
            push_unique_note(
                risk_notes,
                format!("Failed to retain trust policy for role {}: {err}", role.role_name()),
            );
        }
        let Some(path) =
            build_role_path(principal.authorization_arn(), role.arn(), &matches, evidence)
        else {
            continue;
        };
        emitted_edges.insert((principal.authorization_arn().to_string(), role.arn().to_string()));
        if !push_authorization_path(evidence, path.clone()) {
            break;
        }
        direct_paths.push(DirectRolePath { role: role.clone(), path });
    }

    for direct in direct_paths.iter().take(MAX_EXPANDED_PATH_ROLES) {
        if direct.path.status == "trust_only" {
            continue;
        }
        inspected_role_policies.insert(direct.role.arn().to_string());
        let mut flags = PolicyDocumentFlags::default();
        let mut actions = collect_role_actions(
            iam,
            direct.role.role_name(),
            direct.role.arn(),
            &mut flags,
            evidence,
            risk_notes,
        )
        .await;
        finalize_policy_actions(&mut actions, &flags, risk_notes);
        reachable_actions.extend(actions);

        let source = PrincipalContext {
            raw_arn: direct.role.arn().to_string(),
            canonical_arn: Some(direct.role.arn().to_string()),
            account_id: arn_account(direct.role.arn()).map(str::to_string),
            // The next hop would originate from a new role session. Its session name, user ID,
            // source identity, and session tags are not known until AssumeRole executes.
            user_id: None,
            kind: "assumed_role".into(),
            name: None,
            tags: tags_to_map(direct.role.tags()),
            tags_complete: false,
        };

        for target in &inventory {
            if evidence.paths.len() >= MAX_AUTHORIZATION_PATHS {
                record_path_cap(evidence);
                break;
            }
            if target.arn() == direct.role.arn()
                || target.arn() == principal.authorization_arn()
                || !emitted_edges.insert((direct.role.arn().into(), target.arn().into()))
            {
                continue;
            }
            let Some(document) = target.assume_role_policy_document() else {
                continue;
            };
            let matches = trust_matches(document, target.arn(), &source);
            if matches.is_empty() {
                continue;
            }
            if let Err(err) =
                add_policy_evidence(document, PolicySource::trust(target.arn()), evidence)
            {
                push_unique_note(
                    risk_notes,
                    format!("Failed to retain trust policy for role {}: {err}", target.role_name()),
                );
            }

            let Some(mut path) =
                build_role_path(direct.role.arn(), target.arn(), &matches, evidence)
            else {
                continue;
            };
            path.hops.insert(
                0,
                AuthorizationHop {
                    from: principal.authorization_arn().into(),
                    to: direct.role.arn().into(),
                    relationship: "can_assume_role".into(),
                },
            );
            path.evidence.extend(direct.path.evidence.iter().cloned());
            path.conditions.extend(direct.path.conditions.iter().cloned());
            path.evidence.sort();
            path.evidence.dedup();
            path.conditions.sort();
            path.conditions.dedup();
            path.status = combine_path_status(&direct.path.status, &path.status).into();
            if !push_authorization_path(evidence, path) {
                break;
            }

            if inspected_role_policies.len() < MAX_PATH_ROLE_POLICY_EXPANSIONS
                && inspected_role_policies.insert(target.arn().to_string())
            {
                let mut flags = PolicyDocumentFlags::default();
                let mut actions = collect_role_actions(
                    iam,
                    target.role_name(),
                    target.arn(),
                    &mut flags,
                    evidence,
                    risk_notes,
                )
                .await;
                finalize_policy_actions(&mut actions, &flags, risk_notes);
                reachable_actions.extend(actions);
            }
        }
    }

    if direct_paths.len() > MAX_EXPANDED_PATH_ROLES {
        push_unique_note(
            &mut evidence.limitations,
            format!(
                "Second-hop policy expansion was limited to {MAX_EXPANDED_PATH_ROLES} directly reachable roles."
            ),
        );
    }
    if inspected_role_policies.len() >= MAX_PATH_ROLE_POLICY_EXPANSIONS {
        push_unique_note(
            &mut evidence.limitations,
            format!(
                "Attached-policy collection was limited to {MAX_PATH_ROLE_POLICY_EXPANSIONS} reachable roles."
            ),
        );
    }

    reachable_actions.sort();
    reachable_actions.dedup();
    RolePathDiscovery { inventory, reachable_permissions: classify_permissions(&reachable_actions) }
}

fn record_path_cap(evidence: &mut AuthorizationEvidence) {
    push_unique_note(
        &mut evidence.limitations,
        format!("Role-path discovery stopped after {MAX_AUTHORIZATION_PATHS} paths."),
    );
}

fn push_authorization_path(evidence: &mut AuthorizationEvidence, path: AuthorizationPath) -> bool {
    if evidence.paths.len() >= MAX_AUTHORIZATION_PATHS {
        record_path_cap(evidence);
        return false;
    }
    evidence.paths.push(path);
    true
}

fn build_role_path(
    source_arn: &str,
    target_arn: &str,
    trust_matches: &[TrustMatch],
    evidence: &AuthorizationEvidence,
) -> Option<AuthorizationPath> {
    let identity_support = identity_policy_support(evidence, source_arn, target_arn);
    if identity_support.denied {
        return None;
    }
    let trust_conditional = trust_matches.iter().all(|matched| matched.conditional);
    let identity_policy_required =
        trust_matches.iter().all(|matched| matched.identity_policy_required);
    let identity_conditional = identity_support.conditional_deny
        || (!identity_support.unconditional_allow && identity_support.conditional_allow);
    let status = if trust_conditional || (identity_policy_required && identity_conditional) {
        "conditional"
    } else if identity_policy_required && identity_support.allow_evidence.is_empty() {
        "trust_only"
    } else {
        "potential"
    };
    let mut statement_evidence: Vec<String> =
        trust_matches.iter().map(|matched| matched.statement_id.clone()).collect();
    statement_evidence.extend(
        trust_matches.iter().flat_map(|matched| matched.related_statement_ids.iter().cloned()),
    );
    statement_evidence.extend(identity_support.allow_evidence);
    statement_evidence.extend(identity_support.deny_evidence);
    statement_evidence.sort();
    statement_evidence.dedup();
    let mut conditions: Vec<String> =
        trust_matches.iter().flat_map(|matched| matched.condition_keys.iter().cloned()).collect();
    conditions.extend(identity_support.condition_keys);
    conditions.sort();
    conditions.dedup();

    Some(AuthorizationPath {
        direction: Some("outbound".into()),
        status: status.into(),
        hops: vec![AuthorizationHop {
            from: source_arn.into(),
            to: target_arn.into(),
            relationship: "can_assume_role".into(),
        }],
        evidence: statement_evidence,
        conditions,
    })
}

fn combine_path_status(first: &str, second: &str) -> &'static str {
    if first == "conditional" || second == "conditional" {
        "conditional"
    } else if first == "trust_only" || second == "trust_only" {
        "trust_only"
    } else {
        "potential"
    }
}

fn trust_matches(document: &str, role_arn: &str, principal: &PrincipalContext) -> Vec<TrustMatch> {
    let Ok(json) = decode_policy_document(document) else {
        return Vec::new();
    };
    let statements: Vec<&Value> = match json.get("Statement") {
        Some(Value::Array(statements)) => statements.iter().collect(),
        Some(statement) => vec![statement],
        None => Vec::new(),
    };
    let policy_id = format!("trust:{role_arn}");
    let mut allows = Vec::new();
    let mut conditional_denies = Vec::new();

    for (index, statement) in statements.iter().enumerate() {
        if !statement_allows_action(statement, "sts:AssumeRole") {
            continue;
        }
        let Some(identity_policy_required) =
            principal_clause_requirement(statement, principal, role_arn)
        else {
            continue;
        };
        let (condition_matches, conditional, keys) =
            evaluate_principal_conditions(statement.get("Condition"), principal);
        if !condition_matches {
            continue;
        }
        let statement_id = statement
            .get("Sid")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| index.to_string());
        let statement_id = format!("{policy_id}#{statement_id}");
        match statement.get("Effect").and_then(Value::as_str).unwrap_or_default() {
            effect if effect.eq_ignore_ascii_case("Allow") => allows.push(TrustMatch {
                statement_id,
                related_statement_ids: Vec::new(),
                conditional,
                condition_keys: keys,
                identity_policy_required,
            }),
            effect if effect.eq_ignore_ascii_case("Deny") => {
                if conditional {
                    conditional_denies.push((statement_id, keys));
                } else {
                    return Vec::new();
                }
            }
            _ => {}
        }
    }
    if !conditional_denies.is_empty() {
        for matched in &mut allows {
            matched.conditional = true;
            matched
                .related_statement_ids
                .extend(conditional_denies.iter().map(|(id, _)| id.clone()));
            matched
                .condition_keys
                .extend(conditional_denies.iter().flat_map(|(_, keys)| keys.iter().cloned()));
            matched.related_statement_ids.sort();
            matched.related_statement_ids.dedup();
            matched.condition_keys.sort();
            matched.condition_keys.dedup();
        }
    }
    allows
}

fn statement_allows_action(statement: &Value, requested: &str) -> bool {
    let requested = requested.to_ascii_lowercase();
    let actions = string_values(statement.get("Action"));
    if !actions.is_empty() {
        return actions
            .iter()
            .any(|action| wildcard_matches(&action.to_ascii_lowercase(), requested.as_str()));
    }
    let not_actions = string_values(statement.get("NotAction"));
    !not_actions.is_empty()
        && !not_actions
            .iter()
            .any(|action| wildcard_matches(&action.to_ascii_lowercase(), requested.as_str()))
}

fn principal_clause_requirement(
    statement: &Value,
    principal: &PrincipalContext,
    target_role_arn: &str,
) -> Option<bool> {
    if let Some(not_principal) = statement.get("NotPrincipal")
        && principal_value_matches(not_principal, principal)
    {
        return None;
    }
    if statement.get("NotPrincipal").is_some() {
        return Some(true);
    }
    let principal_value = statement.get("Principal")?;
    principal_value_matches(principal_value, principal).then(|| {
        let same_account = arn_account(target_role_arn) == principal.account_id.as_deref();
        !(same_account && principal_value_directly_names(principal_value, principal))
    })
}

fn principal_value_directly_names(value: &Value, principal: &PrincipalContext) -> bool {
    match value {
        Value::String(value) => principal_string_directly_names(value, principal),
        Value::Array(values) => {
            values.iter().any(|value| principal_value_directly_names(value, principal))
        }
        Value::Object(principals) => principals
            .get("AWS")
            .is_some_and(|value| principal_value_directly_names(value, principal)),
        _ => false,
    }
}

fn principal_string_directly_names(value: &str, principal: &PrincipalContext) -> bool {
    value == principal.raw_arn
        || value == principal.authorization_arn()
        || principal.user_id.as_deref() == Some(value)
        || principal.user_id.as_deref().and_then(|id| id.split(':').next()) == Some(value)
}

fn principal_value_matches(value: &Value, principal: &PrincipalContext) -> bool {
    match value {
        Value::String(value) => principal_string_matches(value, principal),
        Value::Array(values) => {
            values.iter().any(|value| principal_value_matches(value, principal))
        }
        Value::Object(principals) => {
            principals.get("AWS").is_some_and(|value| principal_value_matches(value, principal))
        }
        _ => false,
    }
}

fn principal_string_matches(value: &str, principal: &PrincipalContext) -> bool {
    if value == "*"
        || value == principal.raw_arn
        || value == principal.authorization_arn()
        || principal.user_id.as_deref() == Some(value)
        || principal.user_id.as_deref().and_then(|id| id.split(':').next()) == Some(value)
    {
        return true;
    }
    let Some(account) = principal.account_id.as_deref() else {
        return false;
    };
    value == account || (is_account_root_arn(value) && arn_account(value) == Some(account))
}

fn arn_account(arn: &str) -> Option<&str> {
    let mut fields = arn.splitn(6, ':');
    (fields.next()? == "arn").then_some(())?;
    fields.next()?;
    fields.next()?;
    fields.next()?;
    let account = fields.next()?;
    (!account.is_empty()).then_some(account)
}

fn is_account_root_arn(arn: &str) -> bool {
    let mut fields = arn.splitn(6, ':');
    fields.next() == Some("arn")
        && fields.next().is_some()
        && fields.next() == Some("iam")
        && fields.next() == Some("")
        && fields.next().is_some_and(|account| !account.is_empty())
        && fields.next() == Some("root")
}

fn evaluate_principal_conditions(
    condition: Option<&Value>,
    principal: &PrincipalContext,
) -> (bool, bool, Vec<String>) {
    let Some(Value::Object(operators)) = condition else {
        return (true, false, Vec::new());
    };
    let mut conditional = false;
    let keys = condition_keys(condition);

    for (operator, entries) in operators {
        let Value::Object(entries) = entries else {
            conditional = true;
            continue;
        };
        for (key, expected) in entries {
            let expected = string_values(Some(expected));
            let key_lower = key.to_ascii_lowercase();
            if expected.iter().any(|value| value.contains("${")) {
                conditional = true;
                continue;
            }
            if key_lower.starts_with("aws:principaltag/") && principal.kind == "assumed_role" {
                // Session tags can override role tags and are not visible through IAM GetRole.
                conditional = true;
                continue;
            }
            let actual = if key_lower == "aws:principalarn" {
                Some(principal.authorization_arn())
            } else if key_lower == "aws:principalaccount" {
                principal.account_id.as_deref()
            } else if key_lower == "aws:userid" {
                principal.user_id.as_deref()
            } else if key_lower == "aws:username" {
                principal.name.as_deref()
            } else if let Some(tag) = key_lower.strip_prefix("aws:principaltag/") {
                principal
                    .tags
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case(tag))
                    .map(|(_, value)| value.as_str())
            } else {
                conditional = true;
                continue;
            };

            let Some(actual) = actual else {
                if key_lower == "aws:userid"
                    && principal.kind == "assumed_role"
                    && principal.user_id.is_none()
                {
                    conditional = true;
                    continue;
                }
                if key_lower.starts_with("aws:principaltag/")
                    && (principal.kind == "assumed_role" || !principal.tags_complete)
                {
                    conditional = true;
                    continue;
                }
                if key_lower == "aws:username" && principal.kind == "assumed_role" {
                    if operator.contains("Not") {
                        continue;
                    }
                    return (false, conditional, keys);
                }
                if operator.ends_with("IfExists") || operator.contains("Not") {
                    continue;
                }
                return (false, conditional, keys);
            };
            let operator = operator.strip_suffix("IfExists").unwrap_or(operator);
            let known = match operator {
                "ArnEquals" | "StringEquals" => expected.iter().any(|value| value == actual),
                "ArnLike" | "StringLike" => {
                    expected.iter().any(|value| wildcard_matches(value, actual))
                }
                "ArnNotEquals" | "StringNotEquals" => expected.iter().all(|value| value != actual),
                "ArnNotLike" | "StringNotLike" => {
                    expected.iter().all(|value| !wildcard_matches(value, actual))
                }
                _ => {
                    conditional = true;
                    continue;
                }
            };
            if !known {
                return (false, conditional, keys);
            }
        }
    }
    (true, conditional, keys)
}

#[derive(Default)]
struct IdentityPolicySupport {
    allow_evidence: Vec<String>,
    deny_evidence: Vec<String>,
    condition_keys: Vec<String>,
    conditional_allow: bool,
    unconditional_allow: bool,
    conditional_deny: bool,
    denied: bool,
}

fn identity_policy_support(
    evidence: &AuthorizationEvidence,
    source_arn: &str,
    target_arn: &str,
) -> IdentityPolicySupport {
    let mut support = IdentityPolicySupport::default();
    for policy in &evidence.policies {
        if policy.kind == "trust"
            || (policy.attached_to != source_arn
                && policy.attached_via.as_deref() != Some(source_arn))
        {
            continue;
        }
        for statement in &policy.statements {
            if !normalized_statement_allows_action(statement, "sts:AssumeRole")
                || !statement_matches_resource(statement, target_arn)
            {
                continue;
            }
            if statement.effect.eq_ignore_ascii_case("Deny") {
                support.deny_evidence.push(statement.id.clone());
                if statement.condition_keys.is_empty() {
                    support.denied = true;
                } else {
                    support.conditional_deny = true;
                }
            } else if statement.effect.eq_ignore_ascii_case("Allow") {
                support.allow_evidence.push(statement.id.clone());
                if statement.condition_keys.is_empty() {
                    support.unconditional_allow = true;
                } else {
                    support.conditional_allow = true;
                }
            }
            support.condition_keys.extend(statement.condition_keys.iter().cloned());
        }
    }
    support.allow_evidence.sort();
    support.allow_evidence.dedup();
    support.deny_evidence.sort();
    support.deny_evidence.dedup();
    support.condition_keys.sort();
    support.condition_keys.dedup();
    support
}

fn normalized_statement_allows_action(statement: &AuthorizationStatement, requested: &str) -> bool {
    let requested = requested.to_ascii_lowercase();
    if !statement.actions.is_empty() {
        return statement
            .actions
            .iter()
            .any(|action| wildcard_matches(&action.to_ascii_lowercase(), requested.as_str()));
    }
    !statement.not_actions.is_empty()
        && !statement
            .not_actions
            .iter()
            .any(|action| wildcard_matches(&action.to_ascii_lowercase(), requested.as_str()))
}

fn statement_matches_resource(statement: &AuthorizationStatement, target: &str) -> bool {
    if !statement.not_resources.is_empty() {
        return !statement.not_resources.iter().any(|resource| wildcard_matches(resource, target));
    }
    statement.resources.iter().any(|resource| wildcard_matches(resource, target))
}

fn classify_permissions(actions: &[String]) -> PermissionSummary {
    let mut admin = Vec::new();
    let mut privilege_escalation = Vec::new();
    let mut risky = Vec::new();
    let mut read_only = Vec::new();

    for action in actions {
        let a = action.to_lowercase();
        if a == "*" || a.ends_with(".*") {
            admin.push(action.clone());
            continue;
        }

        if a.contains("iam.passrole")
            || a.contains("iam.create")
            || a.contains("iam.putrolepolicy")
            || a.contains("iam.updaterolepolicy")
            || a.contains("iam.updaterole")
            || a.contains("sts.assumerole")
            || a.contains("organizations.attachpolicy")
        {
            privilege_escalation.push(action.clone());
            continue;
        }

        if a.contains(".get") || a.contains(".list") || a.contains(".describe") {
            read_only.push(action.clone());
            continue;
        }

        risky.push(action.clone());
    }

    PermissionSummary { admin, privilege_escalation, risky, read_only }
}

fn derive_severity(
    access_type: &str,
    permissions: &PermissionSummary,
    has_resources: bool,
) -> Severity {
    if access_type == "root"
        || !permissions.admin.is_empty()
        || !permissions.privilege_escalation.is_empty()
    {
        Severity::Critical
    } else if !permissions.risky.is_empty() {
        Severity::High
    } else if !permissions.read_only.is_empty() || has_resources {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn severity_for_reachable_permissions(permissions: &PermissionSummary) -> Severity {
    if !permissions.admin.is_empty() || !permissions.privilege_escalation.is_empty() {
        Severity::Critical
    } else if !permissions.risky.is_empty() {
        Severity::High
    } else if !permissions.read_only.is_empty() {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn max_severity(left: Severity, right: Severity) -> Severity {
    use Severity::{Critical, High, Low, Medium};
    match (left, right) {
        (Critical, _) | (_, Critical) => Critical,
        (High, _) | (_, High) => High,
        (Medium, _) | (_, Medium) => Medium,
        (Low, Low) => Low,
    }
}

fn can_read(permissions: &PermissionSummary, service_prefix: &str) -> bool {
    let prefix = service_prefix.to_lowercase();

    permissions
        .admin
        .iter()
        .chain(&permissions.privilege_escalation)
        .chain(&permissions.risky)
        .chain(&permissions.read_only)
        .any(|action| action == "*" || action.starts_with(&prefix))
}

async fn enumerate_resources(
    config: &SdkConfig,
    permissions: &PermissionSummary,
    account_id: Option<&str>,
    role_inventory: &[IamRole],
    risk_notes: &mut Vec<String>,
) -> Result<Vec<ResourceExposure>> {
    let mut resources = Vec::new();
    let no_permissions = permissions.admin.is_empty()
        && permissions.privilege_escalation.is_empty()
        && permissions.risky.is_empty()
        && permissions.read_only.is_empty();

    if no_permissions {
        risk_notes.push(
            "IAM permissions unavailable; attempting best-effort resource discovery without permission gating.".into(),
        );
    }

    if no_permissions || can_read(permissions, "s3.") {
        let client = S3Client::new(config);
        let mut pages = client.list_buckets().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for bucket in resp.buckets() {
                        if let Some(name) = bucket.name() {
                            resources.push(ResourceExposure {
                                resource_type: "s3_bucket".into(),
                                name: format!("arn:aws:s3:::{name}"),
                                permissions: permissions_for_prefix(permissions, "s3."),
                                risk: "medium".into(),
                                reason: "S3 bucket visible to the identity".into(),
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("s3", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "ec2.") {
        let ec2 = Ec2Client::new(config);
        let mut pages = ec2.describe_instances().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    let region = config
                        .region()
                        .map(|r| r.as_ref().to_string())
                        .unwrap_or_else(|| "unknown-region".into());
                    let account = account_id.unwrap_or("unknown-account");

                    for reservation in resp.reservations() {
                        for instance in reservation.instances() {
                            if let Some(id) = instance.instance_id() {
                                resources.push(ResourceExposure {
                                    resource_type: "ec2_instance".into(),
                                    name: format!(
                                        "arn:aws:ec2:{}:{}:instance/{}",
                                        region, account, id
                                    ),
                                    permissions: permissions_for_prefix(permissions, "ec2."),
                                    risk: "medium".into(),
                                    reason: "EC2 instance readable by the identity".into(),
                                });
                            }
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("ec2", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "iam.") {
        for role in role_inventory {
            resources.push(ResourceExposure {
                resource_type: "iam_role".into(),
                name: role.arn().to_string(),
                permissions: permissions_for_prefix(permissions, "iam."),
                risk: "high".into(),
                reason: "Identity can view IAM roles; may indicate privilege escalation potential"
                    .into(),
            });
        }
    }

    if no_permissions || can_read(permissions, "lambda.") {
        let lambda = LambdaClient::new(config);
        let mut pages = lambda.list_functions().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for function in resp.functions() {
                        if let Some(arn) = function.function_arn() {
                            resources.push(ResourceExposure {
                                resource_type: "lambda_function".into(),
                                name: arn.to_string(),
                                permissions: permissions_for_prefix(permissions, "lambda."),
                                risk: "medium".into(),
                                reason: "Lambda visible; may imply code execution pathways".into(),
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("lambda", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "dynamodb.") {
        let dynamo = DynamoClient::new(config);
        let mut pages = dynamo.list_tables().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for table in resp.table_names() {
                        resources.push(ResourceExposure {
                            resource_type: "dynamodb_table".into(),
                            name: aws_resource_arn(
                                config,
                                account_id,
                                "dynamodb",
                                &format!("table/{table}"),
                            )
                            .unwrap_or_else(|| table.to_string()),
                            permissions: permissions_for_prefix(permissions, "dynamodb."),
                            risk: "medium".into(),
                            reason: "DynamoDB table visible to the identity".into(),
                        });
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("dynamodb", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "kms.") {
        let kms = KmsClient::new(config);
        let mut pages = kms.list_keys().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for key in resp.keys() {
                        if let Some(id) = key.key_id() {
                            let arn = key
                                .key_arn()
                                .map(ToString::to_string)
                                .or_else(|| {
                                    aws_resource_arn(
                                        config,
                                        account_id,
                                        "kms",
                                        &format!("key/{id}"),
                                    )
                                })
                                .unwrap_or_else(|| id.to_string());

                            resources.push(ResourceExposure {
                                resource_type: "kms_key".into(),
                                name: arn,
                                permissions: permissions_for_prefix(permissions, "kms."),
                                risk: "high".into(),
                                reason:
                                    "Identity can view KMS keys; possible cryptographic privilege paths"
                                        .into(),
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("kms", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "secretsmanager.") {
        let sm = SecretsManagerClient::new(config);
        let mut pages = sm.list_secrets().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for secret in resp.secret_list() {
                        if let Some(arn) = secret.arn() {
                            resources.push(ResourceExposure {
                                resource_type: "secret".into(),
                                name: arn.to_string(),
                                permissions: permissions_for_prefix(permissions, "secretsmanager."),
                                risk: "high".into(),
                                reason: "Secret visible to the identity".into(),
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("secretsmanager", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "sqs.") {
        let sqs = SqsClient::new(config);
        let can_send = permissions
            .admin
            .iter()
            .chain(&permissions.privilege_escalation)
            .chain(&permissions.risky)
            .any(|perm| {
                perm == "*"
                    || perm.starts_with("sqs.sendmessage")
                    || perm.starts_with("sqs.purgequeue")
                    || perm.starts_with("sqs.deletequeue")
                    || perm.starts_with("sqs.createqueue")
            });
        let mut pages = sqs.list_queues().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for queue_url in resp.queue_urls() {
                        resources.push(ResourceExposure {
                            resource_type: "sqs_queue".into(),
                            name: queue_url.to_string(),
                            permissions: permissions_for_prefix(permissions, "sqs."),
                            risk: if can_send { "high".into() } else { "medium".into() },
                            reason: if can_send {
                                "SQS queue visible and queue messages may be writable or destructive"
                                    .into()
                            } else {
                                "SQS queue visible to the identity".into()
                            },
                        });
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("sqs", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "sns.") {
        let sns = SnsClient::new(config);
        let can_publish = permissions
            .admin
            .iter()
            .chain(&permissions.privilege_escalation)
            .chain(&permissions.risky)
            .any(|perm| {
                perm == "*"
                    || perm.starts_with("sns.publish")
                    || perm.starts_with("sns.createtopic")
                    || perm.starts_with("sns.deletetopic")
                    || perm.starts_with("sns.settopicattributes")
            });
        let mut pages = sns.list_topics().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for topic in resp.topics() {
                        if let Some(arn) = topic.topic_arn() {
                            resources.push(ResourceExposure {
                                resource_type: "sns_topic".into(),
                                name: arn.to_string(),
                                permissions: permissions_for_prefix(permissions, "sns."),
                                risk: if can_publish { "high".into() } else { "medium".into() },
                                reason: if can_publish {
                                    "SNS topic visible and publish or topic-management actions appear available"
                                        .into()
                                } else {
                                    "SNS topic visible to the identity".into()
                                },
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("sns", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "rds.") {
        let rds = RdsClient::new(config);
        let can_modify = permissions
            .admin
            .iter()
            .chain(&permissions.privilege_escalation)
            .chain(&permissions.risky)
            .any(|perm| {
                perm == "*"
                    || perm.starts_with("rds.modifydbinstance")
                    || perm.starts_with("rds.createdbinstance")
                    || perm.starts_with("rds.deletedbinstance")
                    || perm.starts_with("rds.restoredbinstance")
            });
        let mut pages = rds.describe_db_instances().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for db in resp.db_instances() {
                        let name = db
                            .db_instance_arn()
                            .map(ToString::to_string)
                            .or_else(|| db.db_instance_identifier().map(ToString::to_string));

                        if let Some(name) = name {
                            resources.push(ResourceExposure {
                                resource_type: "rds_instance".into(),
                                name,
                                permissions: permissions_for_prefix(permissions, "rds."),
                                risk: if can_modify { "high".into() } else { "medium".into() },
                                reason: if can_modify {
                                    "RDS instance visible and instance lifecycle changes appear possible"
                                        .into()
                                } else {
                                    "RDS instance visible to the identity".into()
                                },
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("rds", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "ecr.") {
        let ecr = EcrClient::new(config);
        let can_push = permissions
            .admin
            .iter()
            .chain(&permissions.privilege_escalation)
            .chain(&permissions.risky)
            .any(|perm| {
                perm == "*"
                    || perm.starts_with("ecr.putimage")
                    || perm.starts_with("ecr.batchdeleteimage")
                    || perm.starts_with("ecr.setrepositorypolicy")
                    || perm.starts_with("ecr.deleterepository")
                    || perm.starts_with("ecr.createrepository")
            });
        let mut pages = ecr.describe_repositories().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for repo in resp.repositories() {
                        let name = repo
                            .repository_arn()
                            .map(ToString::to_string)
                            .or_else(|| repo.repository_name().map(ToString::to_string));

                        if let Some(name) = name {
                            resources.push(ResourceExposure {
                                resource_type: "ecr_repository".into(),
                                name,
                                permissions: permissions_for_prefix(permissions, "ecr."),
                                risk: if can_push { "high".into() } else { "medium".into() },
                                reason: if can_push {
                                    "ECR repository visible and image push or policy changes appear possible"
                                        .into()
                                } else {
                                    "ECR repository visible to the identity".into()
                                },
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("ecr", &err, risk_notes);
                    break;
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "ssm.") {
        let ssm = SsmClient::new(config);
        let can_read_values = permissions
            .admin
            .iter()
            .chain(&permissions.privilege_escalation)
            .chain(&permissions.risky)
            .chain(&permissions.read_only)
            .any(|perm| {
                perm == "*"
                    || perm.starts_with("ssm.getparameter")
                    || perm.starts_with("ssm.getparameters")
                    || perm.starts_with("ssm.getparametersbypath")
            });
        let can_modify = permissions
            .admin
            .iter()
            .chain(&permissions.privilege_escalation)
            .chain(&permissions.risky)
            .any(|perm| {
                perm == "*"
                    || perm.starts_with("ssm.putparameter")
                    || perm.starts_with("ssm.deleteparameter")
                    || perm.starts_with("ssm.labelparameterversion")
            });
        let mut pages = ssm.describe_parameters().into_paginator().send();
        loop {
            match pages.try_next().await {
                Ok(Some(resp)) => {
                    for parameter in resp.parameters() {
                        if let Some(name) = parameter.name() {
                            let reason = if can_modify && can_read_values {
                                "SSM parameter visible and parameter values may be readable and writable"
                            } else if can_modify {
                                "SSM parameter visible and parameter metadata suggests write access"
                            } else if can_read_values {
                                "SSM parameter visible and parameter values may be readable"
                            } else {
                                "SSM parameter visible to the identity"
                            };

                            resources.push(ResourceExposure {
                                resource_type: "ssm_parameter".into(),
                                name: aws_resource_arn(
                                    config,
                                    account_id,
                                    "ssm",
                                    &format!("parameter/{}", name.trim_start_matches('/')),
                                )
                                .unwrap_or_else(|| name.to_string()),
                                permissions: permissions_for_prefix(permissions, "ssm."),
                                risk: if can_modify || can_read_values {
                                    "high".into()
                                } else {
                                    "medium".into()
                                },
                                reason: reason.into(),
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    record_enumeration_error("ssm", &err, risk_notes);
                    break;
                }
            }
        }
    }

    Ok(resources)
}

fn aws_resource_arn(
    config: &SdkConfig,
    account_id: Option<&str>,
    service: &str,
    resource: &str,
) -> Option<String> {
    let region = config.region()?.as_ref();
    let account = account_id?;
    Some(format!("arn:aws:{service}:{region}:{account}:{resource}"))
}

async fn load_config_from_path(path: Option<&Path>) -> Result<SdkConfig> {
    if let Some(path) = path {
        let creds = load_credentials_from_file(path)?;
        load_config(Some(creds)).await
    } else {
        load_config(None).await
    }
}

async fn load_config(credentials: Option<Credentials>) -> Result<SdkConfig> {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());

    if let Some(creds) = credentials {
        loader = loader.credentials_provider(creds);
    }

    Ok(loader.load().await)
}

fn load_credentials_from_file(path: &Path) -> Result<Credentials> {
    let raw = std::fs::read_to_string(path).context("Failed to read AWS credential file")?;

    if let Ok(value) = serde_json::from_str::<Value>(&raw) {
        return credentials_from_json(&value);
    }

    credentials_from_kv(&raw)
}

fn credentials_from_json(value: &Value) -> Result<Credentials> {
    let map = value.as_object().ok_or_else(|| anyhow!("Credential JSON must be an object"))?;
    let access_key = get_case_insensitive(
        map,
        &["access_key_id", "accessKeyId", "aws_access_key_id", "AccessKeyId"],
    )
    .ok_or_else(|| anyhow!("Missing access_key_id in credential JSON"))?;
    let secret_key = get_case_insensitive(
        map,
        &["secret_access_key", "secretAccessKey", "aws_secret_access_key", "SecretAccessKey"],
    )
    .ok_or_else(|| anyhow!("Missing secret_access_key in credential JSON"))?;
    let session_token = get_case_insensitive(
        map,
        &["session_token", "sessionToken", "aws_session_token", "SessionToken"],
    );

    Ok(match session_token {
        Some(token) => Credentials::new(&access_key, &secret_key, Some(token), None, "access_map"),
        None => Credentials::new(&access_key, &secret_key, None, None, "access_map"),
    })
}

fn get_case_insensitive(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        map.iter()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(key))
            .and_then(|(_, v)| v.as_str().map(|s| s.to_string()))
    })
}

fn credentials_from_kv(raw: &str) -> Result<Credentials> {
    let mut access_key = None;
    let mut secret_key = None;
    let mut session_token = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim().strip_prefix("export ").unwrap_or(key.trim());
            let key_lower = key.to_ascii_lowercase();
            let value = value.trim();
            let val = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|value| value.strip_suffix('\'')))
                .unwrap_or(value)
                .to_string();
            match key_lower.as_str() {
                "aws_access_key_id" | "access_key_id" => access_key = Some(val),
                "aws_secret_access_key" | "secret_access_key" => secret_key = Some(val),
                "aws_session_token" | "session_token" => session_token = Some(val),
                _ => {}
            }
        }
    }

    let access_key =
        access_key.ok_or_else(|| anyhow!("Missing aws_access_key_id in credential file"))?;
    let secret_key =
        secret_key.ok_or_else(|| anyhow!("Missing aws_secret_access_key in credential file"))?;

    Ok(match session_token {
        Some(token) => Credentials::new(&access_key, &secret_key, Some(token), None, "access_map"),
        None => Credentials::new(&access_key, &secret_key, None, None, "access_map"),
    })
}

fn handle_access_denied<
    E: std::error::Error + Send + Sync + 'static + std::fmt::Display + ProvideErrorMetadata,
>(
    service: &str,
    err: &SdkError<E>,
    risk_notes: &mut Vec<String>,
) -> bool {
    let message = iam_error_message(err);
    if iam_error_is_access_denied(err) {
        warn!("AWS access-map: access denied while enumerating {service}: {message}");
        risk_notes.push(format!("AWS enumeration incomplete: AccessDenied for {service}"));
        return true;
    }

    false
}

fn record_enumeration_error<
    E: std::error::Error + Send + Sync + 'static + std::fmt::Display + ProvideErrorMetadata,
>(
    service: &str,
    err: &SdkError<E>,
    risk_notes: &mut Vec<String>,
) {
    if !handle_access_denied(service, err, risk_notes) {
        warn!("AWS access-map: failed to enumerate {service}: {err}");
        push_unique_note(risk_notes, format!("AWS enumeration failed for {service}: {err}"));
    }
}

fn is_access_denied(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("accessdenied")
        || message.contains("unauthorizedoperation")
        || message.contains("notauthorized")
}

fn iam_error_is_access_denied<
    E: std::error::Error + Send + Sync + 'static + std::fmt::Display + ProvideErrorMetadata,
>(
    err: &SdkError<E>,
) -> bool {
    err.code().is_some_and(|code| {
        matches!(
            code.to_ascii_lowercase().as_str(),
            "accessdenied"
                | "accessdeniedexception"
                | "notauthorized"
                | "notauthorizedexception"
                | "unauthorizedoperation"
        )
    }) || is_access_denied(&iam_error_message(err))
}

fn iam_error_message<
    E: std::error::Error + Send + Sync + 'static + std::fmt::Display + ProvideErrorMetadata,
>(
    err: &SdkError<E>,
) -> String {
    match (err.code(), err.message()) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code.to_string(),
        _ => err.to_string(),
    }
}

fn record_iam_error<
    E: std::error::Error + Send + Sync + 'static + std::fmt::Display + ProvideErrorMetadata,
>(
    err: SdkError<E>,
    risk_notes: &mut Vec<String>,
    context: &str,
) {
    let _ = map_iam_error(err, risk_notes, context);
}

fn map_iam_error<
    E: std::error::Error + Send + Sync + 'static + std::fmt::Display + ProvideErrorMetadata,
>(
    err: SdkError<E>,
    risk_notes: &mut Vec<String>,
    context: &str,
) -> anyhow::Error {
    let message = iam_error_message(&err);
    if iam_error_is_access_denied(&err) {
        push_unique_note(
            risk_notes,
            "IAM policy enumeration blocked: the caller does not have iam:Get* or iam:List* permissions. Permissions incomplete.".into(),
        );
    }
    warn!("AWS access-map IAM error: {context}: {message}");
    anyhow!("{context}: {message}")
}

fn push_unique_note(risk_notes: &mut Vec<String>, note: String) {
    if !risk_notes.contains(&note) {
        risk_notes.push(note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_principal_names_from_iam_and_sts_arns() {
        assert_eq!(
            principal_name_from_resource("role/service-role/DeployRole", &["role"]),
            Some("DeployRole".into())
        );
        assert_eq!(
            principal_name_from_resource(
                "assumed-role/AWSReservedSSO_Admin/session@example.com",
                &["assumed-role"]
            ),
            Some("AWSReservedSSO_Admin".into())
        );
        assert_eq!(
            principal_name_from_resource("user/engineering/alice", &["user"]),
            Some("alice".into())
        );
    }

    #[test]
    fn policy_parser_applies_concrete_denies_and_records_scope_limits() {
        let document = r#"{
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:DeleteObject"],
                    "Resource": "arn:aws:s3:::example/*",
                    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-west-2"}}
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:Delete*",
                    "Resource": "*"
                },
                {
                    "Action": "iam:CreateUser",
                    "Resource": "*"
                }
            ]
        }"#;
        let mut actions = Vec::new();
        let mut flags = PolicyDocumentFlags::default();
        extract_actions_from_document(document, &mut actions, &mut flags).unwrap();

        let mut notes = Vec::new();
        finalize_policy_actions(&mut actions, &flags, &mut notes);

        assert_eq!(actions, vec!["s3.getobject"]);
        assert!(notes.iter().any(|note| note.contains("Deny statements")));
        assert!(notes.iter().any(|note| note.contains("conditional")));
        assert!(notes.iter().any(|note| note.contains("resource-scoped")));
    }

    #[test]
    fn allow_not_action_is_summarized_as_constrained_wildcard() {
        let document = r#"{
            "Statement": {
                "Effect": "Allow",
                "NotAction": ["iam:DeleteUser", "organizations:*"],
                "Resource": "*"
            }
        }"#;
        let mut actions = Vec::new();
        let mut flags = PolicyDocumentFlags::default();
        extract_actions_from_document(document, &mut actions, &mut flags).unwrap();

        let mut notes = Vec::new();
        finalize_policy_actions(&mut actions, &flags, &mut notes);

        assert_eq!(actions, vec!["*"]);
        assert!(notes.iter().any(|note| note.contains("NotAction")));
    }

    #[test]
    fn conditional_deny_is_reported_without_erasing_possible_access() {
        let document = r#"{
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-west-2"}}
                }
            ]
        }"#;
        let mut actions = Vec::new();
        let mut flags = PolicyDocumentFlags::default();
        extract_actions_from_document(document, &mut actions, &mut flags).unwrap();

        let mut notes = Vec::new();
        finalize_policy_actions(&mut actions, &flags, &mut notes);

        assert_eq!(actions, vec!["s3.getobject"]);
        assert!(notes.iter().any(|note| note.contains("Deny statements")));
        assert!(notes.iter().any(|note| note.contains("conditional")));
    }

    #[test]
    fn wildcard_matching_handles_iam_action_patterns() {
        assert!(wildcard_matches("s3.get*", "s3.getobject"));
        assert!(wildcard_matches("iam.?reateuser", "iam.createuser"));
        assert!(!wildcard_matches("s3.get*", "s3.putobject"));
    }

    #[test]
    fn policy_evidence_preserves_provenance_and_redacts_condition_values() {
        let document = r#"{
            "Statement": {
                "Sid": "AllowDeploy",
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "iam:PassRole"],
                "Resource": "arn:aws:iam::123456789012:role/Deploy",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "sensitive-value"
                    }
                }
            }
        }"#;
        let mut evidence = AuthorizationEvidence::default();
        add_policy_evidence(
            document,
            PolicySource::inline("deployment", "arn:aws:iam::123456789012:user/alice", None),
            &mut evidence,
        )
        .unwrap();

        assert_eq!(evidence.policies.len(), 1);
        let policy = &evidence.policies[0];
        assert_eq!(policy.name.as_deref(), Some("deployment"));
        assert_eq!(policy.attached_to, "arn:aws:iam::123456789012:user/alice");
        assert_eq!(policy.statements[0].sid.as_deref(), Some("AllowDeploy"));
        assert_eq!(policy.statements[0].actions, ["iam:PassRole", "sts:AssumeRole"]);
        assert_eq!(policy.statements[0].condition_keys, ["StringEquals:sts:ExternalId"]);
        assert!(!serde_json::to_string(&evidence).unwrap().contains("sensitive-value"));
    }

    #[test]
    fn policy_sources_preserve_managed_inline_and_trust_provenance() {
        let managed = PolicySource::managed(
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
            Some("ReadOnlyAccess"),
            "v4",
            "arn:aws:iam::123456789012:group/developers",
            Some("arn:aws:iam::123456789012:user/alice"),
        );
        assert_eq!(managed.kind, "managed");
        assert_eq!(managed.name.as_deref(), Some("ReadOnlyAccess"));
        assert_eq!(managed.version.as_deref(), Some("v4"));
        assert_eq!(managed.attached_via.as_deref(), Some("arn:aws:iam::123456789012:user/alice"));

        let inline =
            PolicySource::inline("deploy", "arn:aws:iam::123456789012:role/application", None);
        assert_eq!(inline.id, "inline:arn:aws:iam::123456789012:role/application:deploy");
        assert_eq!(inline.kind, "inline");

        let trust = PolicySource::trust("arn:aws:iam::123456789012:role/application");
        assert_eq!(trust.id, "trust:arn:aws:iam::123456789012:role/application");
        assert_eq!(trust.kind, "trust");
        assert_eq!(trust.name.as_deref(), Some("AssumeRolePolicyDocument"));
    }

    #[test]
    fn principal_tag_values_are_not_retained() {
        let tags = BTreeMap::from([
            ("environment".into(), "production".into()),
            ("external-id".into(), "sensitive-value".into()),
        ]);

        let retained = redacted_tag_presence(&tags);
        assert_eq!(retained["environment"], "present");
        assert_eq!(retained["external-id"], "present");
        assert!(!serde_json::to_string(&retained).unwrap().contains("sensitive-value"));
    }

    #[test]
    fn authorization_evidence_enforces_document_statement_and_path_caps() {
        let statement_document = r#"{
            "Statement": {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}
        }"#;

        let mut document_capped = AuthorizationEvidence {
            policies: (0..MAX_POLICY_EVIDENCE)
                .map(|index| PolicyEvidence {
                    id: format!("policy-{index}"),
                    statements: vec![AuthorizationStatement {
                        id: format!("policy-{index}#0"),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        add_policy_evidence(
            statement_document,
            PolicySource::inline("overflow", "principal", None),
            &mut document_capped,
        )
        .unwrap();
        truncate_authorization_evidence(&mut document_capped);
        assert_eq!(document_capped.policies.len(), MAX_POLICY_EVIDENCE);
        assert!(document_capped.limitations.iter().any(|note| note.contains("documents")));

        let mut statement_capped = AuthorizationEvidence {
            policies: vec![PolicyEvidence {
                id: "full".into(),
                statements: vec![AuthorizationStatement::default(); MAX_POLICY_STATEMENTS],
                ..Default::default()
            }],
            ..Default::default()
        };
        add_policy_evidence(
            statement_document,
            PolicySource::inline("overflow", "principal", None),
            &mut statement_capped,
        )
        .unwrap();
        truncate_authorization_evidence(&mut statement_capped);
        assert_eq!(statement_capped.policies.len(), 1);
        assert!(statement_capped.limitations.iter().any(|note| note.contains("statements")));

        let mut path_capped = AuthorizationEvidence {
            paths: vec![AuthorizationPath::default(); MAX_AUTHORIZATION_PATHS],
            ..Default::default()
        };
        assert!(!push_authorization_path(&mut path_capped, AuthorizationPath::default()));
        assert_eq!(path_capped.paths.len(), MAX_AUTHORIZATION_PATHS);
        assert!(path_capped.limitations.iter().any(|note| note.contains("paths")));
    }

    #[test]
    fn plain_policy_json_does_not_decode_literal_percent_sequences() {
        let document = r#"{
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example/%2Fobject"
            }
        }"#;

        let statements = parse_policy_statements(document, "example").unwrap();
        assert_eq!(statements[0].resources, ["arn:aws:s3:::example/%2Fobject"]);
    }

    #[test]
    fn trust_policy_matches_account_delegation_and_marks_unknown_conditions() {
        let principal = PrincipalContext {
            raw_arn: "arn:aws:iam::123456789012:user/alice".into(),
            canonical_arn: None,
            account_id: Some("123456789012".into()),
            user_id: Some("AIDAEXAMPLE".into()),
            kind: "user".into(),
            name: Some("alice".into()),
            tags: BTreeMap::new(),
            tags_complete: true,
        };
        let document = r#"{
            "Statement": {
                "Sid": "AccountWithExternalId",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "required"}}
            }
        }"#;

        let matches = trust_matches(document, "arn:aws:iam::123456789012:role/Target", &principal);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].conditional);
        assert_eq!(matches[0].condition_keys, ["StringEquals:sts:ExternalId"]);
        assert!(matches[0].identity_policy_required);
    }

    #[test]
    fn direct_same_account_principal_grant_does_not_require_identity_allow() {
        let principal = PrincipalContext {
            raw_arn: "arn:aws:iam::123456789012:user/alice".into(),
            canonical_arn: None,
            account_id: Some("123456789012".into()),
            user_id: Some("AIDAEXAMPLE".into()),
            kind: "user".into(),
            name: Some("alice".into()),
            tags: BTreeMap::new(),
            tags_complete: true,
        };
        let document = r#"{
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                "Action": "sts:AssumeRole"
            }
        }"#;
        let target = "arn:aws:iam::123456789012:role/Target";
        let matches = trust_matches(document, target, &principal);

        assert_eq!(matches.len(), 1);
        assert!(!matches[0].identity_policy_required);
        let path = build_role_path(
            principal.authorization_arn(),
            target,
            &matches,
            &AuthorizationEvidence::default(),
        )
        .unwrap();
        assert_eq!(path.status, "potential");
    }

    #[test]
    fn future_role_session_user_id_condition_is_unknown() {
        let principal = PrincipalContext {
            raw_arn: "arn:aws:iam::123456789012:role/Source".into(),
            canonical_arn: Some("arn:aws:iam::123456789012:role/Source".into()),
            account_id: Some("123456789012".into()),
            user_id: None,
            kind: "assumed_role".into(),
            name: None,
            tags: BTreeMap::new(),
            tags_complete: false,
        };
        let document = r#"{
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/Source"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringLike": {"aws:userid": "AROAEXAMPLE:*"}}
            }
        }"#;

        let matches = trust_matches(document, "arn:aws:iam::123456789012:role/Target", &principal);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].conditional);
        assert_eq!(matches[0].condition_keys, ["StringLike:aws:userid"]);
    }

    #[test]
    fn unconditional_identity_deny_suppresses_role_path() {
        let source = "arn:aws:iam::123456789012:user/alice";
        let target = "arn:aws:iam::123456789012:role/Target";
        let evidence = AuthorizationEvidence {
            policies: vec![PolicyEvidence {
                id: "identity-policy".into(),
                name: Some("identity-policy".into()),
                kind: "inline".into(),
                attached_to: source.into(),
                statements: vec![
                    AuthorizationStatement {
                        id: "identity-policy#allow".into(),
                        effect: "Allow".into(),
                        actions: vec!["sts:AssumeRole".into()],
                        resources: vec![target.into()],
                        ..AuthorizationStatement::default()
                    },
                    AuthorizationStatement {
                        id: "identity-policy#deny".into(),
                        effect: "Deny".into(),
                        actions: vec!["sts:AssumeRole".into()],
                        resources: vec![target.into()],
                        ..AuthorizationStatement::default()
                    },
                ],
                ..PolicyEvidence::default()
            }],
            ..AuthorizationEvidence::default()
        };
        let trust = [TrustMatch {
            statement_id: "trust#allow".into(),
            related_statement_ids: Vec::new(),
            conditional: false,
            condition_keys: Vec::new(),
            identity_policy_required: true,
        }];

        assert!(build_role_path(source, target, &trust, &evidence).is_none());
    }

    #[test]
    fn role_path_links_trust_and_identity_policy_evidence() {
        let source = "arn:aws:iam::123456789012:user/alice";
        let target = "arn:aws:iam::123456789012:role/Target";
        let evidence = AuthorizationEvidence {
            policies: vec![PolicyEvidence {
                id: "identity-policy".into(),
                name: None,
                kind: "managed".into(),
                attached_to: source.into(),
                statements: vec![AuthorizationStatement {
                    id: "identity-policy#allow".into(),
                    effect: "Allow".into(),
                    actions: vec!["sts:*".into()],
                    resources: vec!["arn:aws:iam::123456789012:role/*".into()],
                    ..AuthorizationStatement::default()
                }],
                ..PolicyEvidence::default()
            }],
            ..AuthorizationEvidence::default()
        };
        let trust = [TrustMatch {
            statement_id: "trust#allow".into(),
            related_statement_ids: Vec::new(),
            conditional: false,
            condition_keys: Vec::new(),
            identity_policy_required: true,
        }];

        let path = build_role_path(source, target, &trust, &evidence).unwrap();
        assert_eq!(path.status, "potential");
        assert_eq!(path.evidence, ["identity-policy#allow", "trust#allow"]);
        assert_eq!(path.hops[0].relationship, "can_assume_role");
    }

    #[test]
    fn role_path_distinguishes_trust_only_and_conditional_evidence() {
        let source = "arn:aws:iam::123456789012:user/alice";
        let target = "arn:aws:iam::123456789012:role/Target";
        let evidence = AuthorizationEvidence::default();

        let trust_only = [TrustMatch {
            statement_id: "trust#allow".into(),
            related_statement_ids: Vec::new(),
            conditional: false,
            condition_keys: Vec::new(),
            identity_policy_required: true,
        }];
        assert_eq!(
            build_role_path(source, target, &trust_only, &evidence).unwrap().status,
            "trust_only"
        );

        let conditional = [TrustMatch {
            statement_id: "trust#conditional".into(),
            related_statement_ids: Vec::new(),
            conditional: true,
            condition_keys: vec!["StringEquals:sts:ExternalId".into()],
            identity_policy_required: true,
        }];
        let path = build_role_path(source, target, &conditional, &evidence).unwrap();
        assert_eq!(path.status, "conditional");
        assert_eq!(path.conditions, ["StringEquals:sts:ExternalId"]);
    }

    #[test]
    fn not_resource_allows_targets_outside_the_exclusion() {
        let statement = AuthorizationStatement {
            effect: "Allow".into(),
            actions: vec!["sts:AssumeRole".into()],
            not_resources: vec!["arn:aws:iam::123456789012:role/Blocked".into()],
            ..AuthorizationStatement::default()
        };

        assert!(statement_matches_resource(&statement, "arn:aws:iam::123456789012:role/Allowed"));
        assert!(!statement_matches_resource(&statement, "arn:aws:iam::123456789012:role/Blocked"));
    }

    #[test]
    fn account_root_match_requires_the_iam_root_resource() {
        let principal = PrincipalContext {
            raw_arn: "arn:aws:iam::123456789012:user/alice".into(),
            canonical_arn: None,
            account_id: Some("123456789012".into()),
            user_id: Some("AIDAEXAMPLE".into()),
            kind: "user".into(),
            name: Some("alice".into()),
            tags: BTreeMap::new(),
            tags_complete: true,
        };

        assert!(principal_string_matches("arn:aws:iam::123456789012:root", &principal));
        assert!(!principal_string_matches(
            "arn:aws:sts::123456789012:assumed-role/root",
            &principal
        ));
    }

    #[test]
    fn root_identity_is_always_critical() {
        assert!(matches!(
            derive_severity("root", &PermissionSummary::default(), false),
            Severity::Critical
        ));
    }

    #[test]
    fn reachable_admin_permissions_raise_severity() {
        let direct = Severity::Low;
        let reachable = PermissionSummary { admin: vec!["*".into()], ..Default::default() };

        assert!(matches!(
            max_severity(direct, severity_for_reachable_permissions(&reachable)),
            Severity::Critical
        ));
    }

    #[test]
    fn kv_credentials_accept_exported_and_quoted_values() {
        let credentials = credentials_from_kv(
            "export AWS_ACCESS_KEY_ID='AKIAEXAMPLE'\n\
             export AWS_SECRET_ACCESS_KEY=\"secret\"\n\
             export AWS_SESSION_TOKEN='session'\n",
        )
        .unwrap();

        assert_eq!(credentials.access_key_id(), "AKIAEXAMPLE");
        assert_eq!(credentials.secret_access_key(), "secret");
        assert_eq!(credentials.session_token(), Some("session"));
    }
}
