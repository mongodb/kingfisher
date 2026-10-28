//! Versioned investigation assessments. Legacy severities and report fields are untouched.
use std::collections::BTreeSet;

use globset::Glob;
use schemars::JsonSchema;
use serde::Serialize;

use super::{
    AccessMapResult, AuthorizationEvidence, AuthorizationStatement, PolicyEvidence,
    ProviderMetadata, severity_to_str,
};

const MAX_CAPABILITIES: usize = 4096;
const MAX_RESOURCES: usize = 1000;
const MAX_RESOURCE_PERMISSIONS: usize = 256;

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct AccessAssessment {
    pub schema_version: u8,
    pub observed_at: String,
    pub legacy_severity: String,
    pub capability_risk: String,
    pub coverage: String,
    pub capabilities: Vec<CapabilityEvidence>,
    pub resources: Vec<ResourceEvidence>,
    pub recommendations: Vec<String>,
    pub risk_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CapabilityEvidence {
    pub permission: String,
    pub category: String,
    /// `direct`, `reachable`, or `unspecified`; reachable grants are never merged into direct access.
    pub reach: String,
    /// `observed`, `policy_grant`, `conditional`, `reported`, or `unspecified`.
    /// An observed permission check proves only the checked operation at that scope.
    pub evidence: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ResourceEvidence {
    pub resource_type: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub risk: String,
    pub reason: String,
}

/// Add risk and coverage explanations without rewriting existing report fields.
pub(super) fn attach(result: &mut AccessMapResult) {
    let assessment = assess(result);
    let evidence = result
        .provider_metadata
        .get_or_insert_with(ProviderMetadata::default)
        .authorization_evidence
        .get_or_insert_with(AuthorizationEvidence::default);
    evidence.assessment = Some(assessment);
}

fn assess(result: &AccessMapResult) -> AccessAssessment {
    assess_at(result, chrono::Utc::now().to_rfc3339())
}

fn assess_at(result: &AccessMapResult, observed_at: String) -> AccessAssessment {
    let evidence =
        result.provider_metadata.as_ref().and_then(|m| m.authorization_evidence.as_ref());
    let mut builder =
        CapabilityBuilder { cloud: &result.cloud, capabilities: Vec::new(), seen: BTreeSet::new() };
    let mut assessment_notes = Vec::new();
    if let Some(evidence) = evidence {
        // Preserve exact observed operations before less certain grants can fill the cap.
        for probe in &evidence.probes {
            if probe.status != "accepted" || probe.method.is_empty() {
                continue;
            }
            let scope = match (probe.resource.as_deref(), probe.region.as_deref()) {
                (Some(resource), Some(region)) => format!("{resource} (region: {region})"),
                (Some(resource), None) => resource.to_owned(),
                (None, Some(region)) => format!("Region: {region}; target scope not recorded"),
                (None, None) => "Target scope not recorded".into(),
            };
            let permission = if result.cloud == "aws"
                && !probe.service.is_empty()
                && !probe.method.contains(['.', ':'])
            {
                format!("{}.{}", probe.service, probe.method)
            } else {
                probe.method.clone()
            };
            builder.add(&permission, "direct", "observed", &scope);
        }
        let reachable_roles: BTreeSet<_> =
            evidence.role_impacts.iter().map(|i| i.role.as_str()).collect();
        for policy in &evidence.policies {
            if builder.capabilities.len() > MAX_CAPABILITIES {
                break;
            }
            // Trust policies describe a relationship, not the caller's action permissions.
            if policy.kind.contains("trust") {
                continue;
            }
            for statement in &policy.statements {
                if builder.capabilities.len() > MAX_CAPABILITIES {
                    break;
                }
                let observed = statement.effect.eq_ignore_ascii_case("observed");
                if !statement.effect.eq_ignore_ascii_case("allow") && !observed {
                    continue;
                }
                let caller_member = format!("serviceAccount:{}", result.identity.id);
                let trust_only = role_is_trust_only(evidence, &policy.attached_to);
                let reach = if trust_only {
                    "unspecified"
                } else if reachable_roles.contains(policy.attached_to.as_str()) {
                    "reachable"
                } else if result.cloud == "gcp" && !statement.principals.is_empty() {
                    if statement
                        .principals
                        .iter()
                        .any(|p| p == &caller_member || p == &result.identity.id)
                    {
                        "direct"
                    } else if evidence.role_impacts.iter().filter_map(|i| i.target.as_ref()).any(
                        |target| {
                            statement
                                .principals
                                .iter()
                                .any(|p| p == target || p == &format!("serviceAccount:{target}"))
                        },
                    ) {
                        "reachable"
                    } else {
                        // Policies visible to the collector may describe other principals.
                        continue;
                    }
                } else {
                    "direct"
                };
                let constrained =
                    !observed && has_constraint_context(result, evidence, policy, statement, reach);
                let conditional = trust_only
                    || constrained
                    || !statement.condition_keys.is_empty()
                    || !statement.not_actions.is_empty()
                    || !statement.not_resources.is_empty()
                    || !statement.not_principals.is_empty();
                if constrained {
                    assessment_notes.push("Visible deny or permissions-boundary context may restrict policy grants; the detailed assessment does not resolve effective authorization".to_owned());
                }
                // Resource scope belongs to each statement, not the identity the policy attaches to.
                for action in &statement.actions {
                    if builder.capabilities.len() > MAX_CAPABILITIES {
                        break;
                    }
                    for scope in statement.resources.iter().map(String::as_str).chain(
                        statement
                            .resources
                            .is_empty()
                            .then_some(policy.scope.as_deref().unwrap_or(&policy.attached_to)),
                    ) {
                        if builder.capabilities.len() > MAX_CAPABILITIES {
                            break;
                        }
                        builder.add(
                            action,
                            reach,
                            if conditional {
                                "conditional"
                            } else if observed {
                                "observed"
                            } else {
                                "policy_grant"
                            },
                            scope,
                        );
                    }
                }
            }
        }
        for impact in &evidence.role_impacts {
            let trust_only = impact.status == "trust_only";
            if trust_only {
                assessment_notes.push(format!("Trust for {} is visible, but caller authorization to assume it was not established; its grants remain conditional potential impact", impact.role));
            }
            for grant in &impact.grants {
                for permission in &grant.permissions {
                    if builder.capabilities.len() > MAX_CAPABILITIES {
                        break;
                    }
                    for resource in grant
                        .resources
                        .iter()
                        .map(String::as_str)
                        .chain(grant.resources.is_empty().then_some("Scope not established"))
                    {
                        if builder.capabilities.len() > MAX_CAPABILITIES {
                            break;
                        }
                        builder.add(
                            permission,
                            if trust_only { "unspecified" } else { "reachable" },
                            if trust_only
                                || impact.status == "conditional"
                                || !grant.condition_keys.is_empty()
                                || !grant.excluded_resources.is_empty()
                                || !grant.excluded_permissions.is_empty()
                            {
                                "conditional"
                            } else {
                                "policy_grant"
                            },
                            resource,
                        );
                    }
                }
            }
        }
    }
    for role in &result.roles {
        let source = role.source.to_ascii_lowercase();
        let trust_only = evidence.is_some_and(|e| role_is_trust_only(e, &role.name));
        let reach = if trust_only {
            "unspecified"
        } else if source.contains("assumable") || source.contains("impersonat") {
            "reachable"
        } else {
            "direct"
        };
        if role.permissions.is_empty() {
            // Entra directory-role membership has a defined authorization
            // meaning. Other providers also put arbitrary identity/role names
            // here when expansion is denied: those names are not operations.
            if result.cloud == "azure" && source == "entra_directory_role" {
                builder.add(
                    &role.name,
                    reach,
                    if trust_only { "conditional" } else { "reported" },
                    &role.source,
                );
                assessment_notes.push(format!("The permission list for directory role {} was not expanded; its reported role name is retained", role.name));
            } else {
                assessment_notes.push(format!("The permission list for role {} was not expanded; its name alone does not establish capabilities", role.name));
            }
        }
        for permission in &role.permissions {
            if builder.capabilities.len() > MAX_CAPABILITIES {
                break;
            }
            // Policy evidence is more precise than a flattened role summary.
            if !builder.seen.iter().any(|(p, r, _, _)| p == permission && r == reach) {
                let conditional = trust_only
                    || evidence.is_some_and(|e| {
                        e.policies.iter().any(|p| {
                            p.name.as_deref() == Some(role.name.as_str())
                                && p.statements.iter().any(|s| !s.condition_keys.is_empty())
                        })
                    });
                builder.add(
                    permission,
                    reach,
                    if conditional { "conditional" } else { "reported" },
                    &role.source,
                );
            }
        }
    }
    // Providers without role expansion can still carry declared scopes/permissions. Their
    // flattened summaries do not establish a direct or a resource-specific grant.
    if builder.capabilities.is_empty() {
        for permission in result
            .permissions
            .admin
            .iter()
            .chain(&result.permissions.privilege_escalation)
            .chain(&result.permissions.risky)
            .chain(&result.permissions.read_only)
        {
            builder.add(permission, "unspecified", "unspecified", "Scope not established");
        }
    }
    let mut notes = result.risk_notes.clone();
    if let Some(evidence) = evidence {
        notes.extend(evidence.limitations.iter().cloned());
    }
    assessment_notes.sort();
    assessment_notes.dedup();
    notes.extend(assessment_notes);
    let mut capabilities = builder.capabilities;
    // Include the overflow record: it can be the only high-risk observation.
    let mut risk = capabilities.iter().map(|c| category_rank(&c.category)).max().unwrap_or(0);
    if risk < 4
        && (!result.permissions.admin.is_empty()
            || !result.permissions.privilege_escalation.is_empty())
    {
        risk = 4;
        notes.push("The provider reports administrative or privilege-escalation access not fully represented by expanded capability evidence".into());
    }
    // Keep one overflow record while building so an exactly full assessment is
    // not reported as truncated. Empty-permission resources are never emitted.
    let capped = capabilities.len() > MAX_CAPABILITIES
        || result.resources.iter().filter(|r| !r.permissions.is_empty()).count() > MAX_RESOURCES
        || result
            .resources
            .iter()
            .any(|resource| resource.permissions.len() > MAX_RESOURCE_PERMISSIONS);
    capabilities.truncate(MAX_CAPABILITIES);
    if capped {
        notes.push(format!("Detailed assessment is limited to {MAX_CAPABILITIES} capabilities, {MAX_RESOURCES} resources, and {MAX_RESOURCE_PERMISSIONS} permissions per resource; legacy data is retained."));
    }
    let failed = result.identity.access_type == "unknown";
    let mut seen_notes = BTreeSet::new();
    notes.retain(|note| seen_notes.insert(note.clone()));
    let coverage = if failed {
        "unknown"
    } else if capped || !notes.is_empty() {
        "partial"
    } else {
        "recorded"
    };
    AccessAssessment {
        schema_version: 1,
        observed_at,
        legacy_severity: severity_to_str(result.severity).into(),
        capability_risk: match risk {
            4 => "critical",
            3 => "high",
            1 => "low",
            _ => "unknown",
        }
        .into(),
        coverage: coverage.into(),
        capabilities,
        resources: result
            .resources
            .iter()
            .filter(|r| !r.permissions.is_empty())
            .take(MAX_RESOURCES)
            .map(|r| ResourceEvidence {
                resource_type: r.resource_type.clone(),
                name: r.name.clone(),
                permissions: r.permissions.iter().take(MAX_RESOURCE_PERMISSIONS).cloned().collect(),
                risk: r.risk.clone(),
                reason: r.reason.clone(),
            })
            .collect(),
        recommendations: result.recommendations.clone(),
        risk_notes: notes,
    }
}

fn role_is_trust_only(evidence: &AuthorizationEvidence, role: &str) -> bool {
    let mut impacts = evidence
        .role_impacts
        .iter()
        .filter(|impact| impact.role == role || impact.name.as_deref() == Some(role));
    impacts.next().is_some_and(|impact| impact.status == "trust_only")
        && impacts.all(|impact| impact.status == "trust_only")
}

fn has_constraint_context(
    result: &AccessMapResult,
    evidence: &AuthorizationEvidence,
    policy: &PolicyEvidence,
    statement: &AuthorizationStatement,
    reach: &str,
) -> bool {
    if reach == "direct"
        && evidence.principal.as_ref().is_some_and(|principal| {
            principal.attributes.get("permissions_boundary").is_some_and(|value| value == "present")
        })
    {
        return true;
    }
    let subject = policy.attached_via.as_deref().unwrap_or(&policy.attached_to);
    evidence.policies.iter().any(|candidate| {
        if candidate.kind.contains("trust") {
            return false;
        }
        let same_subject =
            candidate.attached_via.as_deref().unwrap_or(&candidate.attached_to) == subject;
        if candidate.kind.contains("boundary") && same_subject {
            return true;
        }
        candidate.statements.iter().any(|restriction| {
            if !restriction.effect.eq_ignore_ascii_case("deny") {
                return false;
            }
            if result.cloud == "gcp" && !restriction.principals.is_empty() {
                let caller = format!("serviceAccount:{}", result.identity.id);
                let applicable_subject =
                    if reach == "direct" { Some(caller.as_str()) } else { None };
                restriction.principals.iter().any(|principal| {
                    if let Some(caller) = applicable_subject {
                        principal == caller || principal == &result.identity.id
                    } else {
                        statement.principals.contains(principal)
                    }
                })
            } else {
                same_subject
            }
        })
    })
}

struct CapabilityBuilder<'a> {
    cloud: &'a str,
    capabilities: Vec<CapabilityEvidence>,
    seen: BTreeSet<(String, String, String, String)>,
}

impl CapabilityBuilder<'_> {
    fn add(&mut self, permission: &str, reach: &str, basis: &str, scope: &str) {
        if self.capabilities.len() > MAX_CAPABILITIES
            || !self.seen.insert((
                permission.to_owned(),
                reach.to_owned(),
                basis.to_owned(),
                scope.to_owned(),
            ))
        {
            return;
        }
        self.capabilities.push(CapabilityEvidence {
            permission: permission.to_owned(),
            category: category(self.cloud, permission).into(),
            reach: reach.into(),
            evidence: basis.into(),
            scope: scope.into(),
        });
    }
}

/// Capability classification is provider-aware; a verb alone is never enough to imply low risk.
fn category(provider: &str, permission: &str) -> &'static str {
    let p = permission.to_ascii_lowercase().replace(':', ".");
    if matches!(
        p.as_str(),
        "*" | "owner" | "roles/owner" | "administrator" | "admin" | "key.full_access"
    ) || provider == "aws" && p == "*.*"
    {
        return "administration";
    }
    if provider == "azure" {
        if matches!(p.as_str(), "global administrator" | "privileged authentication administrator")
        {
            return "administration";
        }
        if matches!(p.as_str(), "user.read.all" | "directory.read.all" | "group.read.all") {
            return "sensitive_read";
        }
        if p.contains("microsoft.authorization/roleassignments/write")
            || p.contains("microsoft.authorization/roledefinitions/write")
            || matches!(
                p.as_str(),
                "privileged role administrator"
                    | "user access administrator"
                    | "role based access control administrator"
                    | "application administrator"
                    | "cloud application administrator"
            )
            || wildcard_grants(
                &p,
                &[
                    "microsoft.authorization/roleassignments/write",
                    "microsoft.authorization/roledefinitions/write",
                ],
            )
        {
            return "iam_change";
        }
        // ARM Actions and DataActions are separate permission domains. The
        // provider marks DataActions as `data:` (normalized above to `data.`).
        // In particular, Reader's management-plane `*/read` grants no values.
        // Key Vault value access is getSecret/action, not secrets/read or
        // readMetadata/action; its data-plane Reader must not be over-flagged either.
        if let Some(action) = p.strip_prefix("data.")
            && (action.contains("/blobs/read")
                || action.contains("/secrets/getsecret/")
                || wildcard_grants(
                    action,
                    &[
                        "microsoft.storage/storageaccounts/blobservices/containers/blobs/read",
                        "microsoft.keyvault/vaults/secrets/getsecret/action",
                    ],
                ))
        {
            return "sensitive_read";
        }
        if p == "data.microsoft.keyvault/vaults/secrets/readmetadata/action" {
            return "metadata_read";
        }
        if p.contains("/runcommand/") || p.contains("/virtualmachines/extensions/write") {
            return "workload_execution";
        }
        if !p.starts_with("data.") && !p.contains(['*', '?']) && p.ends_with("/read") {
            return "metadata_read";
        }
    }
    if provider == "aws"
        && wildcard_grants(
            &p,
            &[
                "iam.createaccesskey",
                "iam.attachuserpolicy",
                "iam.attachrolepolicy",
                "iam.putuserpolicy",
                "iam.putrolepolicy",
                "iam.passrole",
            ],
        )
    {
        return "iam_change";
    }
    if p.contains("getaccesstoken")
        || p.contains("getopenidtoken")
        || p.contains("signjwt")
        || p.contains("signblob")
        || p.contains("createaccesskey")
        || p.contains("serviceaccountkeys.create")
        || p == "create_credentials"
    {
        return "credential_minting";
    }
    if p.contains("assumerole") || p.contains("passrole") || p.contains("serviceaccounts.actas") {
        return "identity_delegation";
    }
    if provider == "aws"
        && wildcard_grants(
            &p,
            &["sts.assumerole", "sts.assumerolewithsaml", "sts.assumerolewithwebidentity"],
        )
    {
        return "identity_delegation";
    }
    if p.contains("setiampolicy")
        || p.contains("putrolepolicy")
        || p.contains("attachrolepolicy")
        || p.contains("attachuserpolicy")
        || p.contains("updateassumerolepolicy")
        || p.contains("roles.create")
        || p.contains("roles.update")
        || p == "manage_users"
    {
        return "iam_change";
    }
    if p.contains("getsecretvalue")
        || p.contains("getparameter")
        || p.contains("secretmanager.versions.access")
        || p.contains("decrypt")
        || p.contains("storage.objects.get")
        || p.contains("s3.getobject")
        || p.contains("bigquery.tables.getdata")
        || p.contains("download")
        || matches!(
            p.as_str(),
            "read_secrets"
                | "database.read"
                | "dynamodb.getitem"
                | "dynamodb.batchgetitem"
                | "dynamodb.query"
                | "dynamodb.scan"
                | "sqs.receivemessage"
                | "ec2.getpassworddata"
                | "kinesis.getrecords"
        )
    {
        return "sensitive_read";
    }
    if p == "ecr.getauthorizationtoken" {
        return "credential_minting";
    }
    if p.contains("invokefunction")
        || p.contains("runinstances")
        || p.contains("runjob")
        || p.contains("sendcommand")
        || p.contains("exec")
        || p.contains("registertaskdefinition")
    {
        return "workload_execution";
    }
    if provider == "aws" && p.ends_with(".*") {
        return "service_control";
    }
    if p.contains('*') {
        return "unclassified";
    }
    // Known metadata getters only: an arbitrary Get operation may return data
    // or credentials, not just metadata. Unknown getters remain unclassified.
    if matches!(p.as_str(), "bedrock.getfoundationmodelavailability")
        || p.contains(".list")
        || p.contains(".describe")
        || p.ends_with(".aggregatedlist")
        || p.ends_with(".read")
        || p.ends_with(":read")
        || p == "read"
    {
        return "metadata_read";
    }
    if p.rsplit('.').next().is_some_and(|operation| operation.starts_with("get")) {
        return "unclassified";
    }
    if [
        "create",
        "write",
        "delete",
        "update",
        "put",
        "manage",
        "admin",
        "push",
        "post_messages",
        "destroy",
    ]
    .iter()
    .any(|v| p.contains(v))
    {
        return "mutation";
    }
    "unclassified"
}

fn wildcard_grants(pattern: &str, actions: &[&str]) -> bool {
    pattern.contains(['*', '?'])
        && Glob::new(pattern).is_ok_and(|glob| {
            let matcher = glob.compile_matcher();
            actions.iter().any(|action| matcher.is_match(action))
        })
}

fn category_rank(category: &str) -> u8 {
    match category {
        "administration" | "credential_minting" | "iam_change" | "identity_delegation" => 4,
        "sensitive_read" | "workload_execution" | "service_control" | "mutation" => 3,
        "metadata_read" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(cloud: &str, evidence: AuthorizationEvidence) -> AccessMapResult {
        let mut result =
            super::super::build_failed_result(cloud, "caller@example", anyhow::anyhow!("fixture"));
        result.identity.access_type = "service_account".into();
        result.risk_notes.clear();
        result.provider_metadata =
            Some(ProviderMetadata { authorization_evidence: Some(evidence), ..Default::default() });
        result
    }

    #[test]
    fn aws_statement_resources_keep_each_action_scope_pair() {
        let result = fixture(
            "aws",
            AuthorizationEvidence {
                policies: vec![PolicyEvidence {
                    attached_to: "arn:aws:iam::123456789012:user/caller".into(),
                    statements: vec![
                        AuthorizationStatement {
                            effect: "Allow".into(),
                            actions: vec!["s3.GetObject".into()],
                            resources: vec!["arn:aws:s3:::one/*".into()],
                            ..Default::default()
                        },
                        AuthorizationStatement {
                            effect: "Allow".into(),
                            actions: vec!["lambda.InvokeFunction".into()],
                            resources: vec![
                                "arn:aws:lambda:us-east-1:123456789012:function:worker".into(),
                            ],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), 2);
        assert!(
            assessment
                .capabilities
                .iter()
                .any(|capability| capability.permission == "s3.GetObject"
                    && capability.scope == "arn:aws:s3:::one/*")
        );
        assert!(
            assessment
                .capabilities
                .iter()
                .any(|capability| capability.permission == "lambda.InvokeFunction"
                    && capability.scope.ends_with("function:worker"))
        );
        assert!(
            !assessment.capabilities.iter().any(|capability| capability.scope.contains(":user/"))
        );
    }

    #[test]
    fn deny_and_boundary_context_prevent_unqualified_policy_claims() {
        use super::super::PrincipalEvidence;
        let mut result = fixture(
            "aws",
            AuthorizationEvidence {
                policies: vec![PolicyEvidence {
                    attached_to: "caller".into(),
                    statements: vec![
                        AuthorizationStatement {
                            effect: "Allow".into(),
                            actions: vec!["s3.GetObject".into()],
                            resources: vec!["*".into()],
                            ..Default::default()
                        },
                        AuthorizationStatement {
                            effect: "Deny".into(),
                            actions: vec!["s3.GetObject".into()],
                            resources: vec!["*".into()],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), 1);
        assert_eq!(assessment.capabilities[0].evidence, "conditional");
        let evidence =
            result.provider_metadata.as_mut().unwrap().authorization_evidence.as_mut().unwrap();
        evidence.policies[0].statements.pop();
        evidence.principal = Some(PrincipalEvidence {
            attributes: [("permissions_boundary".into(), "present".into())].into(),
            ..Default::default()
        });
        assert_eq!(assess(&result).capabilities[0].evidence, "conditional");
    }

    #[test]
    fn unrelated_subject_policies_neither_grant_nor_constrain_caller_capabilities() {
        let result = fixture(
            "gcp",
            AuthorizationEvidence {
                policies: vec![PolicyEvidence {
                    attached_to: "projects/example".into(),
                    statements: vec![
                        AuthorizationStatement {
                            effect: "Allow".into(),
                            actions: vec!["storage.buckets.list".into()],
                            principals: vec!["serviceAccount:caller@example".into()],
                            resources: vec!["projects/example".into()],
                            ..Default::default()
                        },
                        AuthorizationStatement {
                            effect: "Allow".into(),
                            actions: vec!["iam.serviceAccountKeys.create".into()],
                            principals: vec!["serviceAccount:unrelated@example".into()],
                            ..Default::default()
                        },
                        AuthorizationStatement {
                            effect: "Deny".into(),
                            actions: vec!["storage.buckets.list".into()],
                            principals: vec!["serviceAccount:unrelated@example".into()],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), 1);
        assert_eq!(assessment.capabilities[0].permission, "storage.buckets.list");
        assert_eq!(assessment.capabilities[0].evidence, "policy_grant");
    }

    #[test]
    fn trust_only_role_grants_remain_conditional_potential_impact() {
        use super::super::{AuthorizationGrant, RoleBinding, RoleImpact};
        let mut result = fixture(
            "aws",
            AuthorizationEvidence {
                policies: vec![PolicyEvidence {
                    attached_to: "role".into(),
                    statements: vec![AuthorizationStatement {
                        effect: "Allow".into(),
                        actions: vec!["secretsmanager.GetSecretValue".into()],
                        resources: vec!["secret".into()],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                role_impacts: vec![RoleImpact {
                    role: "role".into(),
                    status: "trust_only".into(),
                    grants: vec![AuthorizationGrant {
                        permissions: vec!["secretsmanager.GetSecretValue".into()],
                        resources: vec!["secret".into()],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        result.roles.push(RoleBinding {
            name: "role".into(),
            source: "assumable role".into(),
            permissions: vec!["secretsmanager.GetSecretValue".into()],
        });
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), 1);
        assert_eq!(assessment.capabilities[0].reach, "unspecified");
        assert_eq!(assessment.capabilities[0].evidence, "conditional");
        assert!(assessment.risk_notes.iter().any(|note| note.contains("caller authorization")));
    }

    #[test]
    fn accepted_probes_only_establish_the_exact_method_and_scope() {
        use super::super::AccessProbeEvidence;
        let result = fixture(
            "aws",
            AuthorizationEvidence {
                probes: vec![
                    AccessProbeEvidence {
                        service: "bedrock".into(),
                        method: "ListFoundationModels".into(),
                        status: "accepted".into(),
                        region: Some("us-east-1".into()),
                        resource: Some("catalog".into()),
                        ..Default::default()
                    },
                    AccessProbeEvidence {
                        service: "bedrock".into(),
                        method: "InvokeModel".into(),
                        status: "restricted".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), 1);
        assert_eq!(assessment.capabilities[0].permission, "bedrock.ListFoundationModels");
        assert_eq!(assessment.capabilities[0].category, "metadata_read");
        assert_eq!(assessment.capabilities[0].scope, "catalog (region: us-east-1)");
        assert_eq!(assessment.capabilities[0].evidence, "observed");
        assert!(
            !assessment
                .capabilities
                .iter()
                .any(|capability| capability.permission.contains("Invoke"))
        );
    }

    #[test]
    fn sensitive_reads_and_credentials_are_not_metadata_reads() {
        for (provider, permission, expected) in [
            ("aws", "secretsmanager.GetSecretValue", "sensitive_read"),
            ("aws", "ssm:GetParameters", "sensitive_read"),
            ("gcp", "iam.serviceAccounts.getAccessToken", "credential_minting"),
            ("gcp", "secretmanager.versions.access", "sensitive_read"),
            ("aws", "s3.ListBuckets", "metadata_read"),
            ("aws", "s3.*", "service_control"),
            ("aws", "iam.PassRole", "identity_delegation"),
            ("gcp", "example.get*", "unclassified"),
            ("custom.betterleaks", "read_secrets", "sensitive_read"),
            ("custom.betterleaks", "create_credentials", "credential_minting"),
            ("custom.betterleaks", "manage_users", "iam_change"),
            ("anthropic", "key:full_access", "administration"),
            ("microsoft_teams", "channel:post_messages", "mutation"),
            ("terraform", "can-destroy", "mutation"),
            ("azure", "User.Read.All", "sensitive_read"),
            ("digitalocean", "database:read", "sensitive_read"),
            ("aws", "dynamodb.GetItem", "sensitive_read"),
            ("aws", "dynamodb.Query", "sensitive_read"),
            ("aws", "sqs.ReceiveMessage", "sensitive_read"),
            ("aws", "ec2.GetPasswordData", "sensitive_read"),
            ("aws", "kinesis.GetRecords", "sensitive_read"),
            ("aws", "ecr.GetAuthorizationToken", "credential_minting"),
            ("aws", "example.GetData", "unclassified"),
            ("aws", "example.GetAdminCredential", "unclassified"),
            ("gcp", "compute.instances.get", "unclassified"),
            ("aws", "bedrock.ListInferenceProfiles", "metadata_read"),
            ("aws", "bedrock.GetFoundationModelAvailability", "metadata_read"),
            ("gcp", "compute.instances.aggregatedList", "metadata_read"),
            (
                "azure",
                "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                "sensitive_read",
            ),
            ("azure", "data:Microsoft.KeyVault/vaults/secrets/getSecret/action", "sensitive_read"),
            ("azure", "data:Microsoft.KeyVault/vaults/secrets/*", "sensitive_read"),
            ("azure", "data:Microsoft.KeyVault/vaults/*", "sensitive_read"),
            ("azure", "data:Microsoft.KeyVault/vaults/*/read", "unclassified"),
            (
                "azure",
                "data:Microsoft.KeyVault/vaults/secrets/readMetadata/action",
                "metadata_read",
            ),
            (
                "azure",
                "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*",
                "sensitive_read",
            ),
            ("azure", "Microsoft.KeyVault/vaults/secrets/*", "unclassified"),
            ("azure", "Microsoft.KeyVault/vaults/secrets/read", "metadata_read"),
            ("azure", "data:example/resources/read", "unclassified"),
            ("azure", "data:*", "sensitive_read"),
            ("azure", "*", "administration"),
            ("azure", "Microsoft.Authorization/roleAssignments/write", "iam_change"),
            ("azure", "Microsoft.Authorization/*", "iam_change"),
            ("azure", "Microsoft.Authorization/roleAssignments/*", "iam_change"),
            ("azure", "Microsoft.Authorization/roleAssignments/read*", "unclassified"),
            ("aws", "iam:*", "iam_change"),
            ("aws", "iam:Put*Policy", "iam_change"),
            ("aws", "*:*", "administration"),
            ("aws", "s3:*", "service_control"),
            ("aws", "sts:*", "identity_delegation"),
            ("aws", "sts:Assume*", "identity_delegation"),
            ("aws", "sts:GetCaller*", "unclassified"),
            ("azure", "Application Administrator", "iam_change"),
            ("azure", "Cloud Application Administrator", "iam_change"),
            ("azure", "Microsoft.Compute/virtualMachines/read", "metadata_read"),
            ("azure", "*/read", "unclassified"),
        ] {
            assert_eq!(category(provider, permission), expected, "{permission}");
        }
    }

    #[test]
    fn accepted_gcp_aggregated_inventory_probe_is_metadata_read() {
        let result = fixture(
            "gcp",
            AuthorizationEvidence {
                probes: vec![super::super::AccessProbeEvidence {
                    service: "compute".into(),
                    method: "compute.instances.aggregatedList".into(),
                    status: "accepted".into(),
                    resource: Some("projects/example".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities[0].permission, "compute.instances.aggregatedList");
        assert_eq!(assessment.capabilities[0].category, "metadata_read");
        assert_eq!(assessment.capabilities[0].scope, "projects/example");
        assert_eq!(assessment.capability_risk, "low");
    }

    #[test]
    fn provider_permission_vocabularies_reach_the_reported_risk() {
        for (provider, permission, risk) in [
            ("betterleaks.example", "read_secrets", "high"),
            ("anthropic", "key:full_access", "critical"),
            ("microsoft_teams", "channel:post_messages", "high"),
            ("terraform", "can-destroy", "high"),
            ("azure", "User.Read.All", "high"),
            ("digitalocean", "database:read", "high"),
        ] {
            let mut result = fixture(provider, AuthorizationEvidence::default());
            result.permissions.risky.push(permission.into());
            assert_eq!(assess(&result).capability_risk, risk, "{provider}: {permission}");
        }
    }

    #[test]
    fn identity_delegation_has_critical_capability_impact() {
        let mut result = fixture("aws", AuthorizationEvidence::default());
        for permission in ["iam:PassRole", "sts:AssumeRole"] {
            result.permissions.privilege_escalation = vec![permission.into()];
            assert_eq!(assess(&result).capability_risk, "critical", "{permission}");
        }
    }

    #[test]
    fn unexpanded_admin_roles_are_not_hidden_by_unrelated_read_scopes() {
        let mut result = fixture("azure", AuthorizationEvidence::default());
        result.roles = vec![
            super::super::RoleBinding {
                name: "Graph scopes".into(),
                source: "access_token_claims".into(),
                permissions: vec!["User.Read".into()],
            },
            super::super::RoleBinding {
                name: "Global Administrator".into(),
                source: "entra_directory_role".into(),
                permissions: vec![],
            },
        ];
        let assessment = assess(&result);
        assert_eq!(assessment.capability_risk, "critical");
        assert!(
            assessment
                .capabilities
                .iter()
                .any(|capability| capability.permission == "Global Administrator"
                    && capability.category == "administration"
                    && capability.evidence == "reported")
        );
        result.roles.pop();
        result.permissions.admin.push("unexpanded provider admin role".into());
        assert_eq!(assess(&result).capability_risk, "critical");
    }

    #[test]
    fn unexpanded_identity_names_do_not_establish_capabilities_or_hide_permissions() {
        for cloud in ["aws", "alibaba", "mongodb"] {
            for name in ["admin", "LambdaExecutionRole", "Owner"] {
                let mut result = fixture(cloud, AuthorizationEvidence::default());
                result.roles.push(super::super::RoleBinding {
                    name: name.into(),
                    source: "identity".into(),
                    permissions: vec![],
                });
                let assessment = assess(&result);
                assert!(assessment.capabilities.is_empty(), "{cloud}: {name}");
                assert_eq!(assessment.capability_risk, "unknown", "{cloud}: {name}");

                result.permissions.read_only.push("service.ListResources".into());
                let assessment = assess(&result);
                assert_eq!(assessment.capabilities.len(), 1, "{cloud}: {name}");
                assert_eq!(assessment.capabilities[0].permission, "service.ListResources");
                assert_eq!(assessment.capabilities[0].reach, "unspecified");
                assert_eq!(assessment.capability_risk, "low", "{cloud}: {name}");
            }
        }
    }

    #[test]
    fn collection_and_risk_notes_are_not_duplicated() {
        let mut result = fixture(
            "azure",
            AuthorizationEvidence {
                limitations: vec!["Partial enumeration".into()],
                ..Default::default()
            },
        );
        result.risk_notes.push("Partial enumeration".into());
        assert_eq!(assess(&result).risk_notes, ["Partial enumeration"]);
    }

    #[test]
    fn overflow_capability_contributes_to_risk_before_output_truncation() {
        let mut result = fixture("aws", AuthorizationEvidence::default());
        result.permissions.read_only = (0..MAX_CAPABILITIES)
            .map(|index| format!("service.List{index}"))
            .chain(std::iter::once("iam.PassRole".into()))
            .collect();
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), MAX_CAPABILITIES);
        assert!(!assessment.capabilities.iter().any(|c| c.permission == "iam.PassRole"));
        assert_eq!(assessment.capability_risk, "critical");
        assert_eq!(assessment.coverage, "partial");
    }

    #[test]
    fn assessment_caps_report_only_actual_truncation() {
        let mut result = fixture("aws", AuthorizationEvidence::default());
        result.permissions.read_only =
            (0..MAX_CAPABILITIES).map(|index| format!("service.List{index}")).collect();
        // Duplicates at the cap do not establish truncation either.
        result.permissions.read_only.push("service.List0".into());
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), MAX_CAPABILITIES);
        assert_eq!(assessment.coverage, "recorded");
        result.permissions.read_only.push("service.ListOverflow".into());
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), MAX_CAPABILITIES);
        assert_eq!(assessment.coverage, "partial");
        assert!(assessment.risk_notes.iter().any(|note| note.contains("limited to")));

        result.permissions.read_only.clear();
        let resource = super::super::ResourceExposure {
            resource_type: "project".into(),
            name: "example".into(),
            permissions: vec!["read".into()],
            risk: "low".into(),
            reason: "fixture".into(),
        };
        result.resources = vec![resource.clone(); MAX_RESOURCES];
        let mut empty = resource.clone();
        empty.permissions.clear();
        result.resources.push(empty);
        assert_eq!(assess(&result).coverage, "recorded");
        result.resources.push(resource);
        assert_eq!(assess(&result).coverage, "partial");
        result.resources.truncate(1);
        result.resources[0].permissions = vec!["read".into(); MAX_RESOURCE_PERMISSIONS];
        assert_eq!(assess(&result).coverage, "recorded");
        result.resources[0].permissions.push("write".into());
        assert_eq!(assess(&result).coverage, "partial");
    }

    #[test]
    fn assessment_clock_can_be_fixed_for_reproducible_tests() {
        let result = fixture("aws", AuthorizationEvidence::default());
        let timestamp = "2026-10-26T00:00:00Z";
        let first = serde_json::to_value(assess_at(&result, timestamp.into())).unwrap();
        let second = serde_json::to_value(assess_at(&result, timestamp.into())).unwrap();
        assert_eq!(first, second);
        assert_eq!(first["observed_at"], timestamp);
    }

    #[test]
    fn assessment_preserves_existing_fields_and_survives_report_conversion() {
        let mut result =
            super::super::build_failed_result("aws", "identity", anyhow::anyhow!("denied"));
        let legacy = serde_json::to_value(&result).unwrap();
        assert!(legacy.get("provider_metadata").is_none());
        attach(&mut result);
        let detailed = serde_json::to_value(&result).unwrap();
        assert_eq!(legacy["severity"], detailed["severity"]);
        assert_eq!(legacy["resources"], detailed["resources"]);
        let assessment = &detailed["provider_metadata"]["authorization_evidence"]["assessment"];
        assert_eq!(assessment["schema_version"], 1);
        assert_eq!(assessment["coverage"], "unknown");
        assert_eq!(assessment["capability_risk"], "unknown");
        assert_eq!(assessment["resources"], serde_json::json!([]));
        let entry = crate::reporter::access_map_entry_from_result(&result);
        let entry = serde_json::to_value(entry).unwrap();
        assert_eq!(entry["provider_metadata"]["authorization_evidence"]["assessment"], *assessment);
    }

    #[test]
    fn policy_scope_and_identity_transitions_remain_distinct() {
        use super::super::{
            AuthorizationGrant, AuthorizationStatement, PolicyEvidence, RoleImpact,
        };
        let mut result =
            super::super::build_failed_result("gcp", "caller@example", anyhow::anyhow!("unused"));
        result.identity.access_type = "service_account".into();
        result.risk_notes.clear();
        result.provider_metadata = Some(ProviderMetadata {
            authorization_evidence: Some(AuthorizationEvidence {
                policies: vec![
                    PolicyEvidence {
                        attached_to: "projects/example".into(),
                        statements: vec![AuthorizationStatement {
                            effect: "Allow".into(),
                            actions: vec!["iam.serviceAccounts.getAccessToken".into()],
                            principals: vec!["serviceAccount:unrelated@example".into()],
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    PolicyEvidence {
                        attached_to: "projects/example".into(),
                        scope: Some("projects/example".into()),
                        statements: vec![AuthorizationStatement {
                            effect: "Allow".into(),
                            actions: vec!["storage.buckets.list".into()],
                            principals: vec!["serviceAccount:caller@example".into()],
                            condition_keys: vec!["request.time".into()],
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
                role_impacts: vec![RoleImpact {
                    role: "roles/secretmanager.secretAccessor".into(),
                    target: Some("target@example".into()),
                    status: "conditional".into(),
                    grants: vec![AuthorizationGrant {
                        permissions: vec!["secretmanager.versions.access".into()],
                        resources: vec!["projects/production".into()],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        });
        let assessment = assess(&result);
        assert_eq!(assessment.capabilities.len(), 2);
        assert!(!assessment.capabilities.iter().any(|c| c.permission.contains("getAccessToken")));
        assert!(assessment.capabilities.iter().any(|c| c.reach == "direct"
            && c.evidence == "conditional"
            && c.scope == "projects/example"));
        assert!(assessment.capabilities.iter().any(|c| c.reach == "reachable"
            && c.evidence == "conditional"
            && c.category == "sensitive_read"));
    }
}
