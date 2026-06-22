use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use aws_config::{BehaviorVersion, SdkConfig};
use aws_credential_types::Credentials;
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_ecr::Client as EcrClient;
use aws_sdk_iam::{Client as IamClient, error::SdkError};
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
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_default_account_resource, build_recommendations,
};

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

    let identity = AccessSummary {
        id: arn.clone(),
        access_type: classify_identity(&arn).into(),
        project: None,
        tenant: None,
        account_id: account_id.clone(),
    };

    let mut roles = derive_roles_from_arn(&arn);
    let mut risk_notes = Vec::new();

    let permissions =
        expand_permissions(&iam, &arn, &mut roles, &mut risk_notes).await.unwrap_or_else(|err| {
            warn!("AWS access-map: failed to enumerate IAM permissions: {err}");
            risk_notes.push(format!("IAM enumeration failed: {err}"));
            PermissionSummary::default()
        });
    let mut resources =
        enumerate_resources(&config, &permissions, account_id.as_deref(), &mut risk_notes)
            .await
            .unwrap_or_else(|err| {
                warn!("AWS access-map: resource enumeration failed: {err}");
                risk_notes.push(format!("AWS enumeration failed: {err}"));
                Vec::new()
            });

    let severity = derive_severity(&permissions, !resources.is_empty());

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
    if permissions.admin.is_empty()
        && permissions.privilege_escalation.is_empty()
        && permissions.risky.is_empty()
        && permissions.read_only.is_empty()
    {
        risk_notes.push("IAM permissions could not be enumerated for this identity.".into());
    }

    let recommendations = build_recommendations(severity);

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
            name: account_id.clone(),
            username: None,
            account_type: None,
            company: None,
            location: None,
            email: None,
            url: None,
            token_type: Some("access_key".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: Some(arn.clone()),
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
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
    let mut parts = resource.split('/');
    let kind = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();

    let role_name = match kind {
        "assumed-role" | "role" => Some(name.to_string()),
        _ => None,
    };

    if let Some(name) = role_name {
        vec![RoleBinding { name, source: "iam".into(), permissions: Vec::new() }]
    } else {
        Vec::new()
    }
}

async fn expand_permissions(
    iam: &IamClient,
    arn: &str,
    roles: &mut [RoleBinding],
    risk_notes: &mut Vec<String>,
) -> Result<PermissionSummary> {
    let access_type = classify_identity(arn);
    let resource = arn.split(':').nth(5).unwrap_or_default();
    let mut parts = resource.split('/');
    let _kind = parts.next();
    let name = parts.next().unwrap_or_default();

    if arn.contains(":assumed-role/AWSReservedSSO_") {
        risk_notes.push(
            "This is an AWS IAM Identity Center session. These sessions cannot enumerate role policies. IAM permission mapping skipped.".into(),
        );
        return Ok(PermissionSummary::default());
    }

    let mut actions = match access_type {
        "role" | "assumed_role" => collect_role_actions(iam, name, risk_notes).await,
        "user" => collect_user_actions(iam, name, risk_notes).await,
        _ => Ok(Vec::new()),
    }
    .unwrap_or_else(|err| {
        if err.to_string().contains("AccessDenied") {
            risk_notes.push(
                "IAM policy enumeration blocked: the caller does not have iam:Get* or iam:List* permissions. Permissions incomplete.".into(),
            );
        }
        risk_notes.push(format!("IAM enumeration failed: {err}"));
        warn!("AWS access-map: IAM enumeration failed: {err}");
        Vec::new()
    });

    actions.sort();
    actions.dedup();

    for role in roles.iter_mut() {
        if role.permissions.is_empty() {
            role.permissions = actions.clone();
        }
    }

    Ok(classify_permissions(&actions))
}

async fn collect_role_actions(
    iam: &IamClient,
    role_name: &str,
    risk_notes: &mut Vec<String>,
) -> Result<Vec<String>> {
    let mut actions = Vec::new();

    let attached =
        iam.list_attached_role_policies().role_name(role_name).send().await.map_err(|err| {
            map_iam_error(
                err,
                risk_notes,
                &format!("list_attached_role_policies failed for role {role_name}"),
            )
        })?;

    for policy in attached.attached_policies() {
        if let Some(arn) = policy.policy_arn() {
            collect_managed_policy_actions(iam, arn, &mut actions, risk_notes).await?;
        }
    }

    let inline = iam.list_role_policies().role_name(role_name).send().await.map_err(|err| {
        map_iam_error(err, risk_notes, &format!("list_role_policies failed for role {role_name}"))
    })?;

    for name in inline.policy_names() {
        let policy =
            iam.get_role_policy().role_name(role_name).policy_name(name).send().await.map_err(
                |err| {
                    map_iam_error(
                        err,
                        risk_notes,
                        &format!("get_role_policy failed for role {role_name} policy {name}"),
                    )
                },
            )?;

        extract_actions_from_document(policy.policy_document(), &mut actions)?;
    }

    Ok(actions)
}

async fn collect_user_actions(
    iam: &IamClient,
    user_name: &str,
    risk_notes: &mut Vec<String>,
) -> Result<Vec<String>> {
    let mut actions = Vec::new();

    let attached =
        iam.list_attached_user_policies().user_name(user_name).send().await.map_err(|err| {
            map_iam_error(
                err,
                risk_notes,
                &format!("list_attached_user_policies failed for user {user_name}"),
            )
        })?;

    for policy in attached.attached_policies() {
        if let Some(arn) = policy.policy_arn() {
            collect_managed_policy_actions(iam, arn, &mut actions, risk_notes).await?;
        }
    }

    let inline = iam.list_user_policies().user_name(user_name).send().await.map_err(|err| {
        map_iam_error(err, risk_notes, &format!("list_user_policies failed for user {user_name}"))
    })?;

    for name in inline.policy_names() {
        let policy =
            iam.get_user_policy().user_name(user_name).policy_name(name).send().await.map_err(
                |err| {
                    map_iam_error(
                        err,
                        risk_notes,
                        &format!("get_user_policy failed for user {user_name} policy {name}"),
                    )
                },
            )?;

        extract_actions_from_document(policy.policy_document(), &mut actions)?;
    }

    Ok(actions)
}

async fn collect_managed_policy_actions(
    iam: &IamClient,
    policy_arn: &str,
    actions: &mut Vec<String>,
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
        extract_actions_from_document(doc, actions)?;
    }

    Ok(())
}

fn extract_actions_from_document(doc: &str, actions: &mut Vec<String>) -> Result<()> {
    let decoded = percent_decode_str(doc).decode_utf8()?.into_owned();
    let decoded = if decoded.starts_with('"') {
        serde_json::from_str::<String>(&decoded).unwrap_or(decoded)
    } else {
        decoded
    };

    let json: Value = serde_json::from_str(&decoded)
        .map_err(|err| anyhow!("Failed to parse IAM policy document: {err}"))?;

    if let Some(statements) = json.get("Statement") {
        if let Some(array) = statements.as_array() {
            for stmt in array {
                collect_actions_from_statement(stmt, actions);
            }
        } else {
            collect_actions_from_statement(statements, actions);
        }
    }

    Ok(())
}

fn collect_actions_from_statement(statement: &Value, actions: &mut Vec<String>) {
    if statement.get("Effect").and_then(|e| e.as_str()) == Some("Deny") {
        return;
    }

    if let Some(action) = statement.get("Action") {
        collect_action_values(action, actions);
    }

    if let Some(not_action) = statement.get("NotAction") {
        collect_action_values(not_action, actions);
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

fn derive_severity(permissions: &PermissionSummary, has_resources: bool) -> Severity {
    if !permissions.admin.is_empty() || !permissions.privilege_escalation.is_empty() {
        Severity::Critical
    } else if !permissions.risky.is_empty() {
        Severity::High
    } else if !permissions.read_only.is_empty() || has_resources {
        Severity::Medium
    } else {
        Severity::Low
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
        match client.list_buckets().send().await {
            Ok(resp) => {
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
            Err(err) => {
                if !handle_access_denied("s3", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate s3 buckets: {err}");
                    risk_notes.push(format!("AWS enumeration failed for s3: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "ec2.") {
        let ec2 = Ec2Client::new(config);
        match ec2.describe_instances().send().await {
            Ok(resp) => {
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
                                name: format!("arn:aws:ec2:{}:{}:instance/{}", region, account, id),
                                permissions: permissions_for_prefix(permissions, "ec2."),
                                risk: "medium".into(),
                                reason: "EC2 instance readable by the identity".into(),
                            });
                        }
                    }
                }
            }
            Err(err) => {
                if !handle_access_denied("ec2", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate ec2 instances: {err}");
                    risk_notes.push(format!("AWS enumeration failed for ec2: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "iam.") {
        let iam = IamClient::new(config);
        match iam.list_roles().send().await {
            Ok(resp) => {
                for role in resp.roles() {
                    let arn = role.arn();
                    resources.push(ResourceExposure {
                        resource_type: "iam_role".into(),
                        name: arn.to_string(),
                        permissions: permissions_for_prefix(permissions, "iam."),
                        risk: "high".into(),
                        reason: "Identity can view IAM roles; may indicate privilege escalation potential".into(),
                    });
                }
            }
            Err(err) => {
                if !handle_access_denied("iam", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate iam roles: {err}");
                    risk_notes.push(format!("AWS enumeration failed for iam: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "lambda.") {
        let lambda = LambdaClient::new(config);
        match lambda.list_functions().send().await {
            Ok(resp) => {
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
            Err(err) => {
                if !handle_access_denied("lambda", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate lambda functions: {err}");
                    risk_notes.push(format!("AWS enumeration failed for lambda: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "dynamodb.") {
        let dynamo = DynamoClient::new(config);
        match dynamo.list_tables().send().await {
            Ok(resp) => {
                for table in resp.table_names() {
                    resources.push(ResourceExposure {
                        resource_type: "dynamodb_table".into(),
                        name: table.to_string(),
                        permissions: permissions_for_prefix(permissions, "dynamodb."),
                        risk: "medium".into(),
                        reason: "DynamoDB table visible to the identity".into(),
                    });
                }
            }
            Err(err) => {
                if !handle_access_denied("dynamodb", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate dynamodb tables: {err}");
                    risk_notes.push(format!("AWS enumeration failed for dynamodb: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "kms.") {
        let kms = KmsClient::new(config);
        match kms.list_keys().send().await {
            Ok(resp) => {
                let region = config.region().map(|r| r.as_ref().to_string());
                let account = account_id.unwrap_or("");

                for key in resp.keys() {
                    if let Some(id) = key.key_id() {
                        let arn = region
                            .as_ref()
                            .filter(|r| !r.is_empty())
                            .and_then(|r| {
                                if account.is_empty() {
                                    None
                                } else {
                                    Some(format!("arn:aws:kms:{r}:{account}:key/{id}"))
                                }
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
            Err(err) => {
                if !handle_access_denied("kms", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate kms keys: {err}");
                    risk_notes.push(format!("AWS enumeration failed for kms: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "secretsmanager.") {
        let sm = SecretsManagerClient::new(config);
        match sm.list_secrets().send().await {
            Ok(resp) => {
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
            Err(err) => {
                if !handle_access_denied("secretsmanager", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate secretsmanager secrets: {err}");
                    risk_notes.push(format!("AWS enumeration failed for secretsmanager: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "sqs.") {
        let sqs = SqsClient::new(config);
        match sqs.list_queues().send().await {
            Ok(resp) => {
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
            Err(err) => {
                if !handle_access_denied("sqs", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate sqs queues: {err}");
                    risk_notes.push(format!("AWS enumeration failed for sqs: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "sns.") {
        let sns = SnsClient::new(config);
        match sns.list_topics().send().await {
            Ok(resp) => {
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
            Err(err) => {
                if !handle_access_denied("sns", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate sns topics: {err}");
                    risk_notes.push(format!("AWS enumeration failed for sns: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "rds.") {
        let rds = RdsClient::new(config);
        match rds.describe_db_instances().send().await {
            Ok(resp) => {
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
            Err(err) => {
                if !handle_access_denied("rds", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate rds instances: {err}");
                    risk_notes.push(format!("AWS enumeration failed for rds: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "ecr.") {
        let ecr = EcrClient::new(config);
        match ecr.describe_repositories().send().await {
            Ok(resp) => {
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
            Err(err) => {
                if !handle_access_denied("ecr", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate ecr repositories: {err}");
                    risk_notes.push(format!("AWS enumeration failed for ecr: {err}"));
                }
            }
        }
    }

    if no_permissions || can_read(permissions, "ssm.") {
        let ssm = SsmClient::new(config);
        match ssm.describe_parameters().send().await {
            Ok(resp) => {
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
                            name: name.to_string(),
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
            Err(err) => {
                if !handle_access_denied("ssm", &err, risk_notes) {
                    warn!("AWS access-map: failed to enumerate ssm parameters: {err}");
                    risk_notes.push(format!("AWS enumeration failed for ssm: {err}"));
                }
            }
        }
    }

    Ok(resources)
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
            let key_lower = key.trim().to_ascii_lowercase();
            let val = value.trim().to_string();
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

fn handle_access_denied<E: std::error::Error + Send + Sync + 'static + std::fmt::Display>(
    service: &str,
    err: &SdkError<E>,
    risk_notes: &mut Vec<String>,
) -> bool {
    let message = err.to_string();
    if is_access_denied(&message) {
        warn!("AWS access-map: access denied while enumerating {service}: {message}");
        risk_notes.push(format!("AWS enumeration incomplete: AccessDenied for {service}"));
        return true;
    }

    false
}

fn is_access_denied(message: &str) -> bool {
    message.contains("AccessDenied") || message.contains("AccessDeniedException")
}

fn map_iam_error<E: std::error::Error + Send + Sync + 'static + std::fmt::Display>(
    err: SdkError<E>,
    risk_notes: &mut Vec<String>,
    context: &str,
) -> anyhow::Error {
    let message = err.to_string();
    if err.as_service_error().is_some() && is_access_denied(&message) {
        risk_notes.push(
            "IAM policy enumeration blocked: the caller does not have iam:Get* or iam:List* permissions. Permissions incomplete.".into(),
        );
    }
    warn!("AWS access-map IAM error: {context}: {message}");
    anyhow!("{context}: {message}")
}
