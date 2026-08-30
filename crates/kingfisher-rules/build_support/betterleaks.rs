use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

const OMITTED_BUILTIN_RULE_IDS: &[&str] =
    &["generic-api-key", "generic-password", "generic-username"];

#[derive(Deserialize)]
struct BetterleaksConfig {
    prefilter: Option<String>,
    filter: Option<String>,
    rules: Vec<BetterleaksRule>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BetterleaksRule {
    id: String,
    description: String,
    regex: Option<String>,
    path: Option<String>,
    #[serde(default)]
    secret_group: usize,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    skip_report: bool,
    validate: Option<String>,
    filter: Option<String>,
    components: Option<Vec<BetterleaksComponent>>,
}

#[derive(Deserialize)]
struct BetterleaksComponent {
    id: String,
    #[serde(default)]
    optional: bool,
    within: Option<String>,
}

#[derive(Serialize)]
struct Snapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    betterleaks_prefilter: Option<BetterleaksExpr>,
    rules: Vec<ImportedRule>,
}

#[derive(Deserialize)]
struct CapabilityOverlay {
    version: u32,
    #[serde(default)]
    rules: BTreeMap<String, RuleCapabilities>,
}

#[derive(Clone, Default, Deserialize)]
struct RuleCapabilities {
    access_map: Option<BetterleaksAccessMap>,
    revocation: Option<serde_yaml::Value>,
    revocation_bindings: Option<BetterleaksRevocationBindings>,
    validation: Option<TypedValidation>,
    validation_override: Option<String>,
    filter_override: Option<String>,
    authoritative: Option<bool>,
    confidence: Option<String>,
    tls_mode: Option<String>,
}

/// Kingfisher validators that can be bound directly to a Betterleaks detector.
#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum TypedValidation {
    Named(NamedTypedValidation),
    Configured(ConfiguredTypedValidation),
}

#[derive(Clone, Deserialize)]
enum NamedTypedValidation {
    #[serde(rename = "Assumed")]
    Assumed,
    #[serde(rename = "JWT")]
    Jwt,
    #[serde(rename = "MongoDB")]
    MongoDb,
    #[serde(rename = "CredentialUri")]
    CredentialUri,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", content = "content")]
enum ConfiguredTypedValidation {
    Ethereum(EthereumValidation),
}

#[derive(Serialize)]
struct ImportedRule {
    name: String,
    id: String,
    pattern: String,
    #[serde(skip_serializing_if = "is_medium")]
    confidence: String,
    #[serde(skip_serializing_if = "is_true")]
    authoritative: bool,
    #[serde(skip_serializing_if = "is_true")]
    visible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation: Option<Validation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    depends_on_rule: Vec<DependsOnRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    betterleaks_filter: Option<BetterleaksExpr>,
    betterleaks_secret_group: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_mode: Option<String>,
}

#[derive(Serialize)]
struct DependsOnRule {
    rule_id: String,
    variable: String,
    #[serde(skip_serializing_if = "is_false")]
    optional: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    within: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "type", content = "content")]
enum Validation {
    Betterleaks(BetterleaksValidation),
    Assumed,
    #[serde(rename = "AWS")]
    Aws,
    #[serde(rename = "JWT")]
    Jwt,
    MongoDB,
    CredentialUri,
    Ethereum(EthereumValidation),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum EthereumValidation {
    PrivateKey,
    PublicKey,
    Mnemonic,
}

#[derive(Serialize)]
struct BetterleaksValidation {
    source: String,
    expression: BetterleaksExpr,
    #[serde(default)]
    components: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BetterleaksCapabilities::is_empty")]
    capabilities: BetterleaksCapabilities,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct BetterleaksCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_map: Option<BetterleaksAccessMap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revocation_bindings: Option<BetterleaksRevocationBindings>,
}

impl BetterleaksCapabilities {
    fn is_empty(&self) -> bool {
        self.access_map.is_none() && self.revocation_bindings.is_none()
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct BetterleaksAccessMap {
    handler: BetterleaksAccessMapHandler,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "is_false")]
    reachable_2xx: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum BetterleaksAccessMapHandler {
    Aws,
    Gcp,
    AzureClientSecret,
    AzureStorage,
    Algolia,
    Alibaba,
    Artifactory,
    Salesforce,
    Airtable,
    Anthropic,
    Auth0,
    Buildkite,
    Circleci,
    Fastly,
    Github,
    Gitlab,
    Harness,
    Huggingface,
    IbmCloud,
    Monday,
    Openai,
    Paypal,
    Pinecone,
    Sendinblue,
    Stripe,
    WeightsAndBiases,
}

#[derive(Clone, Deserialize, Serialize)]
struct BetterleaksRevocationBindings {
    #[serde(default = "default_finding_secret_source")]
    secret: String,
    #[serde(default)]
    variables: BTreeMap<String, String>,
}

fn default_finding_secret_source() -> String {
    "finding.secret".to_string()
}

#[derive(Debug, Serialize, PartialEq, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BetterleaksExpr {
    Nil,
    Identifier {
        value: String,
    },
    Integer {
        value: i64,
    },
    Float {
        value: String,
    },
    Bool {
        value: bool,
    },
    String {
        value: String,
    },
    Unary {
        operator: String,
        node: Box<BetterleaksExpr>,
    },
    Binary {
        operator: String,
        left: Box<BetterleaksExpr>,
        right: Box<BetterleaksExpr>,
    },
    Member {
        node: Box<BetterleaksExpr>,
        property: Box<BetterleaksExpr>,
        #[serde(default)]
        optional: bool,
        #[serde(default)]
        method: bool,
    },
    Slice {
        node: Box<BetterleaksExpr>,
        from: Box<BetterleaksExpr>,
        to: Box<BetterleaksExpr>,
    },
    Call {
        callee: Box<BetterleaksExpr>,
        #[serde(default)]
        arguments: Vec<BetterleaksExpr>,
    },
    Builtin {
        name: String,
        #[serde(default)]
        arguments: Vec<BetterleaksExpr>,
    },
    Conditional {
        cond: Box<BetterleaksExpr>,
        exp1: Box<BetterleaksExpr>,
        exp2: Box<BetterleaksExpr>,
    },
    VariableDeclarator {
        name: String,
        value: Box<BetterleaksExpr>,
        expr: Box<BetterleaksExpr>,
    },
    Array {
        #[serde(default)]
        nodes: Vec<BetterleaksExpr>,
    },
    Map {
        #[serde(default)]
        pairs: Vec<BetterleaksExpr>,
    },
    Pair {
        key: Box<BetterleaksExpr>,
        value: Box<BetterleaksExpr>,
    },
    Predicate {
        node: Box<BetterleaksExpr>,
    },
    Pointer {
        name: String,
    },
}

#[allow(dead_code)]
pub fn import_config(contents: &str, source: &str, capabilities: &str) -> Result<String> {
    import_config_with_namespace(contents, source, capabilities, "betterleaks.", true)
}

/// Import a Betterleaks TOML config supplied as a Kingfisher custom rule file.
///
/// Custom rules use the `custom.` namespace so they cannot accidentally replace a bundled
/// Betterleaks detector with the same upstream ID.
#[allow(dead_code)]
pub(crate) fn import_custom_config(contents: &str, source: &str) -> Result<String> {
    import_config_with_namespace(contents, source, "version: 1\nrules: {}\n", "custom.", false)
}

fn import_config_with_namespace(
    contents: &str,
    source: &str,
    capabilities: &str,
    namespace: &str,
    omit_low_value_builtins: bool,
) -> Result<String> {
    let source_config: BetterleaksConfig =
        toml::from_str(contents).context("invalid Betterleaks TOML")?;
    let mut capability_overlay: CapabilityOverlay =
        serde_yaml::from_str(capabilities).context("invalid Betterleaks capability overlay")?;
    if capability_overlay.version != 1 {
        bail!("unsupported Betterleaks capability overlay version {}", capability_overlay.version);
    }
    let source_count = source_config.rules.len();
    let prefilter = source_config
        .prefilter
        .as_deref()
        .map(parse_expression)
        .transpose()
        .context("failed to parse the Betterleaks global prefilter")?;
    if let Some(expression) = prefilter.as_ref() {
        validate_filter_expression(expression)
            .context("unsupported operation in the Betterleaks global prefilter")?;
    }
    let global_filter = source_config
        .filter
        .as_deref()
        .map(parse_expression)
        .transpose()
        .context("failed to parse the Betterleaks global filter")?;
    if let Some(expression) = global_filter.as_ref() {
        validate_filter_expression(expression)
            .context("unsupported operation in the Betterleaks global filter")?;
    }
    let mut imported = Vec::with_capacity(source_count);
    let mut skipped_path_only = Vec::new();
    let mut omitted_low_value = Vec::new();

    for source_rule in source_config.rules {
        if omit_low_value_builtins && OMITTED_BUILTIN_RULE_IDS.contains(&source_rule.id.as_str()) {
            omitted_low_value.push(source_rule.id);
            continue;
        }
        let rule_capabilities =
            capability_overlay.rules.remove(&source_rule.id).unwrap_or_default();
        let Some(source_pattern) = source_rule.regex else {
            if rule_capabilities.access_map.is_some()
                || rule_capabilities.revocation.is_some()
                || rule_capabilities.validation.is_some()
            {
                bail!("capabilities target path-only Betterleaks rule {}", source_rule.id);
            }
            skipped_path_only.push(source_rule.id);
            continue;
        };
        let compiled_pattern = regex::bytes::RegexBuilder::new(&source_pattern)
            .unicode(false)
            .size_limit(16 * 1024 * 1024)
            .build()
            .with_context(|| {
                format!("Betterleaks rule {} is not Rust-regex compatible", source_rule.id)
            })?;
        if source_rule.secret_group > 0
            && source_rule.secret_group >= compiled_pattern.captures_len()
        {
            bail!(
                "configured secret group {} does not exist on {} ({} capture groups)",
                source_rule.secret_group,
                source_rule.id,
                compiled_pattern.captures_len().saturating_sub(1)
            );
        }
        if let Some(path) = source_rule.path.as_deref() {
            Regex::new(path)
                .with_context(|| format!("invalid path regex on {}", source_rule.id))?;
        }

        let source_components = source_rule.components.as_deref().unwrap_or_default();
        let components: BTreeMap<String, String> = source_components
            .iter()
            .map(|component| (component.id.clone(), component_variable(&component.id)))
            .collect();
        validate_capability_sources(&source_rule.id, &components, &rule_capabilities)?;
        let depends_on_rule = source_components
            .iter()
            .map(|component| DependsOnRule {
                rule_id: qualify_id(&component.id, namespace),
                variable: component_variable(&component.id),
                optional: component.optional,
                // Preserve an explicit unconstrained marker so runtime association can distinguish
                // Betterleaks components from legacy Kingfisher dependencies with `within: None`.
                within: Some(component.within.clone().unwrap_or_else(|| "0".to_string())),
            })
            .collect();
        if rule_capabilities.validation.is_some()
            && (rule_capabilities.validation_override.is_some() || source_rule.validate.is_some())
        {
            bail!(
                "typed validation cannot be combined with a Betterleaks validation on {}",
                source_rule.id
            );
        }
        let validation_source =
            rule_capabilities.validation_override.as_deref().or(source_rule.validate.as_deref());
        let validation_expression = if rule_capabilities.validation.is_some() {
            None
        } else {
            validation_source
                .map(parse_expression)
                .transpose()
                .with_context(|| format!("failed to parse validation for {}", source_rule.id))?
        };
        if let Some(expression) = validation_expression.as_ref() {
            validate_validation_expression(expression).with_context(|| {
                format!("unsupported validation operation in {}", source_rule.id)
            })?;
        }
        if validation_expression.is_none()
            && (rule_capabilities.access_map.is_some()
                || rule_capabilities.revocation_bindings.is_some())
        {
            bail!(
                "access-map/revocation bindings on {} require Betterleaks validation",
                source_rule.id
            );
        }
        if rule_capabilities.revocation_bindings.is_some() && rule_capabilities.revocation.is_none()
        {
            bail!("revocation bindings on {} have no revocation action", source_rule.id);
        }
        let validation = if let Some(typed_validation) = rule_capabilities.validation {
            Some(match typed_validation {
                TypedValidation::Named(NamedTypedValidation::Assumed) => Validation::Assumed,
                TypedValidation::Named(NamedTypedValidation::Jwt) => Validation::Jwt,
                TypedValidation::Named(NamedTypedValidation::MongoDb) => Validation::MongoDB,
                TypedValidation::Named(NamedTypedValidation::CredentialUri) => {
                    Validation::CredentialUri
                }
                TypedValidation::Configured(ConfiguredTypedValidation::Ethereum(kind)) => {
                    Validation::Ethereum(kind)
                }
            })
        } else {
            validation_expression.map(|expression| {
                Validation::Betterleaks(BetterleaksValidation {
                    source: validation_source.expect("parsed validation has source").to_string(),
                    expression,
                    components,
                    capabilities: BetterleaksCapabilities {
                        access_map: rule_capabilities.access_map.clone(),
                        revocation_bindings: rule_capabilities.revocation_bindings.clone(),
                    },
                })
            })
        };
        let confidence = match rule_capabilities
            .confidence
            .as_deref()
            .unwrap_or(&source_rule.confidence)
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "medium" => "medium",
            "low" => "low",
            "high" => "high",
            other => bail!("unsupported confidence {other:?} on {}", source_rule.id),
        };
        // Betterleaks has no notion of TLS strictness, so `tls_mode` is a
        // Kingfisher operational capability supplied by the overlay. It only
        // relaxes anything when the operator also passes `--tls-mode lax`, and
        // it is meaningless without a validator, so reject it on rules that
        // never make a connection.
        let tls_mode = match rule_capabilities.tls_mode.as_deref() {
            None => None,
            Some(raw) => {
                let normalized = raw.to_ascii_lowercase();
                match normalized.as_str() {
                    "strict" | "lax" | "off" => {}
                    other => bail!("unsupported tls_mode {other:?} on {}", source_rule.id),
                }
                if validation.is_none() {
                    bail!("tls_mode on {} requires a validator", source_rule.id);
                }
                Some(normalized)
            }
        };
        let rule_filter = source_rule
            .filter
            .as_deref()
            .map(parse_expression)
            .transpose()
            .with_context(|| format!("failed to parse filter for {}", source_rule.id))?;
        if let Some(expression) = rule_filter.as_ref() {
            validate_filter_expression(expression)
                .with_context(|| format!("unsupported filter operation in {}", source_rule.id))?;
        }
        let capability_filter = rule_capabilities
            .filter_override
            .as_deref()
            .map(parse_expression)
            .transpose()
            .with_context(|| format!("failed to parse filter override for {}", source_rule.id))?;
        if let Some(expression) = capability_filter.as_ref() {
            validate_filter_expression(expression).with_context(|| {
                format!("unsupported filter override operation in {}", source_rule.id)
            })?;
        }
        let betterleaks_filter =
            combine_filters([global_filter.clone(), rule_filter, capability_filter]);

        imported.push(ImportedRule {
            name: if source_rule.description.trim().is_empty() {
                source_rule.id.clone()
            } else {
                source_rule.description
            },
            id: qualify_id(&source_rule.id, namespace),
            pattern: source_pattern,
            confidence: confidence.to_string(),
            authoritative: rule_capabilities.authoritative.unwrap_or(true),
            visible: !source_rule.skip_report,
            validation,
            revocation: rule_capabilities.revocation,
            depends_on_rule,
            path: source_rule.path,
            betterleaks_filter,
            betterleaks_secret_group: source_rule.secret_group,
            tls_mode,
        });
    }
    if !capability_overlay.rules.is_empty() {
        bail!(
            "capability overlay references missing Betterleaks rules: {}",
            capability_overlay.rules.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    if namespace == "betterleaks."
        && imported.iter().any(|rule| rule.id == "betterleaks.aws-access-token")
        && imported.iter().any(|rule| rule.id == "betterleaks.aws-secret-access-key")
    {
        imported.push(aws_session_token_rule(namespace));
    }
    imported.sort_by(|left, right| left.id.cmp(&right.id));

    let yaml =
        serde_yaml::to_string(&Snapshot { betterleaks_prefilter: prefilter, rules: imported })?;
    Ok(format!(
        "# Generated from source {source}; do not edit.\n\
         # Imported {} of {source_count} Betterleaks rules. Omitted low-value generic rules: {}.\n\
         # Path-only rules not representable as content detectors were skipped: {}.\n{yaml}",
        source_count - skipped_path_only.len() - omitted_low_value.len(),
        omitted_low_value.join(", "),
        skipped_path_only.join(", "),
    ))
}

/// Preserve AWS STS validation when the upstream AWS access-key rule is used with temporary
/// credentials. The session token is detected as a separate finding so the existing typed AWS
/// validator can receive all three credential values.
fn aws_session_token_rule(namespace: &str) -> ImportedRule {
    ImportedRule {
        name: "AWS Session Token".to_string(),
        id: qualify_id("aws-session-token", namespace),
        pattern: r#"(?x)\b(?i:AWS[_-]?(?:SESSION|SECURITY)[_-]?TOKEN)\b["']?\s*(?:=|:)\s*["']?([A-Za-z0-9/+=._-]{16,2048})(?:["'\s,;}]|$)"#.to_string(),
        confidence: "medium".to_string(),
        authoritative: true,
        visible: true,
        validation: Some(Validation::Aws),
        revocation: None,
        depends_on_rule: vec![
            DependsOnRule {
                rule_id: qualify_id("aws-access-token", namespace),
                variable: "AKID".to_string(),
                optional: false,
                within: Some("5L".to_string()),
            },
            DependsOnRule {
                rule_id: qualify_id("aws-secret-access-key", namespace),
                variable: "AWS_SECRET_ACCESS_KEY".to_string(),
                optional: false,
                within: Some("5L".to_string()),
            },
        ],
        path: None,
        betterleaks_filter: None,
        betterleaks_secret_group: 0,
        tls_mode: None,
    }
}

fn qualify_id(id: &str, namespace: &str) -> String {
    if namespace.is_empty() || id.starts_with(namespace) {
        id.to_string()
    } else {
        format!("{namespace}{id}")
    }
}

fn validate_capability_sources(
    rule_id: &str,
    components: &BTreeMap<String, String>,
    capabilities: &RuleCapabilities,
) -> Result<()> {
    let sources = capabilities
        .access_map
        .iter()
        .flat_map(|mapping| mapping.inputs.values())
        .chain(capabilities.revocation_bindings.iter().map(|bindings| &bindings.secret))
        .chain(
            capabilities
                .revocation_bindings
                .iter()
                .flat_map(|bindings| bindings.variables.values()),
        );
    for source in sources {
        if source == "finding.secret" {
            continue;
        }
        let Some(component_id) = source.strip_prefix("components.") else {
            bail!("invalid capability source {source:?} on {rule_id}");
        };
        if !components.contains_key(component_id) {
            bail!("capability source {source:?} on {rule_id} references a missing component");
        }
    }
    Ok(())
}

fn combine_filters<const N: usize>(
    filters: [Option<BetterleaksExpr>; N],
) -> Option<BetterleaksExpr> {
    filters.into_iter().flatten().reduce(|left, right| BetterleaksExpr::Binary {
        operator: "||".to_string(),
        left: Box::new(left),
        right: Box::new(right),
    })
}

fn validate_filter_expression(expression: &BetterleaksExpr) -> Result<()> {
    match expression {
        BetterleaksExpr::Call { callee, arguments } => {
            let name = expression_name(callee)
                .ok_or_else(|| anyhow!("dynamic function calls are not supported"))?;
            let supported = if let BetterleaksExpr::Member { method: true, .. } = callee.as_ref() {
                if name.starts_with("filter.") {
                    matches!(
                        name.as_str(),
                        "filter.matchesAny"
                            | "filter.findMatch"
                            | "filter.containsAny"
                            | "filter.entropy"
                            | "filter.tokenRatio"
                            | "filter.failsTokenEfficiency"
                            | "filter.setConfidence"
                    )
                } else {
                    matches!(
                        name.rsplit('.').next(),
                        Some(
                            "contains"
                                | "startsWith"
                                | "endsWith"
                                | "substring"
                                | "lastIndexOf"
                                | "replace"
                        )
                    )
                }
            } else {
                matches!(
                    name.as_str(),
                    "matchesAny"
                        | "findMatch"
                        | "containsAny"
                        | "entropy"
                        | "tokenRatio"
                        | "failsTokenEfficiency"
                        | "setConfidence"
                        | "len"
                        | "size"
                        | "max"
                        | "min"
                        | "split"
                        | "join"
                )
            };
            if !supported {
                bail!("unsupported Betterleaks filter call {name:?}");
            }
            validate_filter_expression(callee)?;
            for argument in arguments {
                validate_filter_expression(argument)?;
            }
        }
        BetterleaksExpr::Builtin { name, arguments } => {
            if !matches!(name.as_str(), "any" | "lastIndexOf" | "replace") {
                bail!("unsupported Betterleaks filter builtin {name:?}");
            }
            for argument in arguments {
                validate_filter_expression(argument)?;
            }
        }
        BetterleaksExpr::Unary { operator, node } => {
            if !matches!(operator.as_str(), "!" | "not" | "-") {
                bail!("unsupported Betterleaks filter unary operator {operator:?}");
            }
            validate_filter_expression(node)?
        }
        BetterleaksExpr::Predicate { node } => validate_filter_expression(node)?,
        BetterleaksExpr::Binary { operator, left, right } => {
            if !matches!(
                operator.as_str(),
                "||" | "or"
                    | "&&"
                    | "and"
                    | "??"
                    | "=="
                    | "!="
                    | "<"
                    | "<="
                    | ">"
                    | ">="
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "contains"
                    | "in"
            ) {
                bail!("unsupported Betterleaks filter binary operator {operator:?}");
            }
            validate_filter_expression(left)?;
            validate_filter_expression(right)?;
        }
        BetterleaksExpr::Member { node, property, .. } => {
            validate_filter_expression(node)?;
            validate_filter_expression(property)?;
        }
        BetterleaksExpr::Slice { node, from, to } => {
            validate_filter_expression(node)?;
            validate_filter_expression(from)?;
            validate_filter_expression(to)?;
        }
        BetterleaksExpr::Conditional { cond, exp1, exp2 } => {
            validate_filter_expression(cond)?;
            validate_filter_expression(exp1)?;
            validate_filter_expression(exp2)?;
        }
        BetterleaksExpr::VariableDeclarator { value, expr, .. } => {
            validate_filter_expression(value)?;
            validate_filter_expression(expr)?;
        }
        BetterleaksExpr::Array { nodes } | BetterleaksExpr::Map { pairs: nodes } => {
            for node in nodes {
                validate_filter_expression(node)?;
            }
        }
        BetterleaksExpr::Pair { key, value } => {
            validate_filter_expression(key)?;
            validate_filter_expression(value)?;
        }
        BetterleaksExpr::Nil
        | BetterleaksExpr::Identifier { .. }
        | BetterleaksExpr::Integer { .. }
        | BetterleaksExpr::Float { .. }
        | BetterleaksExpr::Bool { .. }
        | BetterleaksExpr::String { .. }
        | BetterleaksExpr::Pointer { .. } => {}
    }
    Ok(())
}

fn validate_validation_expression(expression: &BetterleaksExpr) -> Result<()> {
    match expression {
        BetterleaksExpr::Call { callee, arguments } => {
            let name = expression_name(callee)
                .ok_or_else(|| anyhow!("dynamic function calls are not supported"))?;
            let supported = if let BetterleaksExpr::Member { method: true, .. } = callee.as_ref() {
                matches!(name.rsplit('.').next(), Some("contains" | "split"))
                    || matches!(
                        name.as_str(),
                        "http.get"
                            | "http.post"
                            | "validate.unknown"
                            | "bytes"
                            | "size"
                            | "substring"
                            | "base64.encode"
                            | "base64.decode"
                            | "hex.encode"
                            | "crypto.sha1"
                            | "crypto.hmacSha1"
                            | "crypto.hmacSha256"
                            | "strings.urlQueryEscape"
                            | "json.string"
                            | "time.nowUnix"
                            | "time.nowRFC3339"
                            | "env.getOrDefault"
                            | "filter.matchesAny"
                            | "aws.validate"
                            | "gcp.validate"
                            | "azure.validateStorage"
                            | "azure.validateServicePrincipal"
                            | "azure.validateAppConfig"
                            | "azure.validateServiceBusSAS"
                    )
            } else {
                matches!(name.as_str(), "bytes" | "size" | "substring")
            };
            if !supported {
                bail!("unsupported Betterleaks validation call {name:?}");
            }
            validate_validation_expression(callee)?;
            for argument in arguments {
                validate_validation_expression(argument)?;
            }
        }
        BetterleaksExpr::Builtin { name, arguments } => {
            if !matches!(name.as_str(), "any" | "lastIndexOf" | "replace") {
                bail!("unsupported Betterleaks validation builtin {name:?}");
            }
            for argument in arguments {
                validate_validation_expression(argument)?;
            }
        }
        BetterleaksExpr::Unary { operator, node } => {
            if !matches!(operator.as_str(), "!" | "not" | "-") {
                bail!("unsupported Betterleaks validation unary operator {operator:?}");
            }
            validate_validation_expression(node)?;
        }
        BetterleaksExpr::Binary { operator, left, right } => {
            if !matches!(
                operator.as_str(),
                "&&" | "||" | "??" | "+" | "==" | "!=" | ">" | "in" | "contains"
            ) {
                bail!("unsupported Betterleaks validation binary operator {operator:?}");
            }
            validate_validation_expression(left)?;
            validate_validation_expression(right)?;
        }
        BetterleaksExpr::Predicate { node } => validate_validation_expression(node)?,
        BetterleaksExpr::Member { node, property, .. } => {
            validate_validation_expression(node)?;
            validate_validation_expression(property)?;
        }
        BetterleaksExpr::Slice { node, from, to } => {
            validate_validation_expression(node)?;
            validate_validation_expression(from)?;
            validate_validation_expression(to)?;
        }
        BetterleaksExpr::Conditional { cond, exp1, exp2 } => {
            validate_validation_expression(cond)?;
            validate_validation_expression(exp1)?;
            validate_validation_expression(exp2)?;
        }
        BetterleaksExpr::VariableDeclarator { value, expr, .. } => {
            validate_validation_expression(value)?;
            validate_validation_expression(expr)?;
        }
        BetterleaksExpr::Array { nodes } | BetterleaksExpr::Map { pairs: nodes } => {
            for node in nodes {
                validate_validation_expression(node)?;
            }
        }
        BetterleaksExpr::Pair { key, value } => {
            validate_validation_expression(key)?;
            validate_validation_expression(value)?;
        }
        BetterleaksExpr::Nil
        | BetterleaksExpr::Identifier { .. }
        | BetterleaksExpr::Integer { .. }
        | BetterleaksExpr::Float { .. }
        | BetterleaksExpr::Bool { .. }
        | BetterleaksExpr::String { .. }
        | BetterleaksExpr::Pointer { .. } => {}
    }
    Ok(())
}

fn expression_name(expression: &BetterleaksExpr) -> Option<String> {
    match expression {
        BetterleaksExpr::Identifier { value } => Some(value.clone()),
        BetterleaksExpr::Member { node, property, .. } => {
            let parent = expression_name(node)?;
            let BetterleaksExpr::String { value } = property.as_ref() else {
                return None;
            };
            Some(format!("{parent}.{value}"))
        }
        _ => None,
    }
}

fn component_variable(id: &str) -> String {
    let mut variable = String::new();
    for ch in id.chars() {
        if ch.is_ascii_alphanumeric() {
            variable.push(ch.to_ascii_uppercase());
        } else {
            variable.push('_');
        }
    }
    variable
}

fn is_medium(value: &String) -> bool {
    value == "medium"
}

fn is_true(value: &bool) -> bool {
    *value
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Identifier(String),
    Integer(i64),
    Float(String),
    String(String),
    Bool(bool),
    Nil,
    Let,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Semicolon,
    Dot,
    OptionalDot,
    Question,
    Operator(String),
    Eof,
}

fn parse_expression(source: &str) -> Result<BetterleaksExpr> {
    Parser::new(source)?.parse_program(Token::Eof)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn new(source: &str) -> Result<Self> {
        Ok(Self { tokens: lex(source)?, position: 0 })
    }

    fn parse_program(&mut self, terminator: Token) -> Result<BetterleaksExpr> {
        let mut declarations = Vec::new();
        while self.peek() == &Token::Let {
            self.advance();
            let name = self.take_identifier("variable name after `let`")?;
            self.expect_operator("=")?;
            let value = self.parse_expr(0)?;
            self.expect(Token::Semicolon)?;
            declarations.push((name, value));
        }
        let mut expression = self.parse_expr(0)?;
        if terminator != Token::Eof {
            self.expect(terminator)?;
        } else {
            self.expect(Token::Eof)?;
        }
        for (name, value) in declarations.into_iter().rev() {
            expression = BetterleaksExpr::VariableDeclarator {
                name,
                value: Box::new(value),
                expr: Box::new(expression),
            };
        }
        Ok(expression)
    }

    fn parse_expr(&mut self, min_precedence: u8) -> Result<BetterleaksExpr> {
        let mut left = self.parse_prefix()?;
        loop {
            if self.peek() == &Token::Question && min_precedence == 0 {
                self.advance();
                let exp1 = self.parse_expr(0)?;
                self.expect(Token::Colon)?;
                let exp2 = self.parse_expr(0)?;
                left = BetterleaksExpr::Conditional {
                    cond: Box::new(left),
                    exp1: Box::new(exp1),
                    exp2: Box::new(exp2),
                };
                continue;
            }

            let Token::Operator(operator) = self.peek() else {
                break;
            };
            if operator == "=" {
                break;
            }
            let Some((precedence, right_associative)) = binary_precedence(operator) else {
                break;
            };
            if precedence < min_precedence {
                break;
            }
            let operator = operator.clone();
            self.advance();
            let right =
                self.parse_expr(if right_associative { precedence } else { precedence + 1 })?;
            let binary = BetterleaksExpr::Binary {
                operator: if operator == "not in" { "in".to_string() } else { operator.clone() },
                left: Box::new(left),
                right: Box::new(right),
            };
            left = if operator == "not in" {
                BetterleaksExpr::Unary { operator: "not".to_string(), node: Box::new(binary) }
            } else {
                binary
            };
        }
        Ok(left)
    }

    fn parse_prefix(&mut self) -> Result<BetterleaksExpr> {
        if let Token::Operator(operator) = self.peek()
            && matches!(operator.as_str(), "!" | "not" | "-")
        {
            let operator = operator.clone();
            self.advance();
            return Ok(BetterleaksExpr::Unary { operator, node: Box::new(self.parse_prefix()?) });
        }
        let primary = self.parse_primary()?;
        self.parse_postfix(primary)
    }

    fn parse_primary(&mut self) -> Result<BetterleaksExpr> {
        match self.advance().clone() {
            Token::Identifier(value) if value == "#" => {
                Ok(BetterleaksExpr::Pointer { name: value })
            }
            Token::Identifier(value) => Ok(BetterleaksExpr::Identifier { value }),
            Token::Integer(value) => Ok(BetterleaksExpr::Integer { value }),
            Token::Float(value) => Ok(BetterleaksExpr::Float { value }),
            Token::String(value) => Ok(BetterleaksExpr::String { value }),
            Token::Bool(value) => Ok(BetterleaksExpr::Bool { value }),
            Token::Nil => Ok(BetterleaksExpr::Nil),
            Token::LParen => self.parse_program(Token::RParen),
            Token::LBracket => self.parse_array(),
            Token::LBrace => self.parse_braced(),
            token => bail!("unexpected token {token:?} in expression"),
        }
    }

    fn parse_postfix(&mut self, mut node: BetterleaksExpr) -> Result<BetterleaksExpr> {
        loop {
            match self.peek() {
                Token::Dot | Token::OptionalDot => {
                    let optional = self.advance() == &Token::OptionalDot;
                    if optional && self.peek() == &Token::LBracket {
                        self.advance();
                        let property = self.parse_expr(0)?;
                        self.expect(Token::RBracket)?;
                        node = BetterleaksExpr::Member {
                            node: Box::new(node),
                            property: Box::new(property),
                            optional: true,
                            method: false,
                        };
                        continue;
                    }
                    let property = self.take_member_name()?;
                    node = BetterleaksExpr::Member {
                        node: Box::new(node),
                        property: Box::new(BetterleaksExpr::String { value: property }),
                        optional,
                        method: false,
                    };
                }
                Token::LBracket => {
                    self.advance();
                    if self.peek() == &Token::Colon {
                        self.advance();
                        let to = if self.peek() == &Token::RBracket {
                            BetterleaksExpr::Integer { value: i64::MAX }
                        } else {
                            self.parse_expr(0)?
                        };
                        self.expect(Token::RBracket)?;
                        node = BetterleaksExpr::Slice {
                            node: Box::new(node),
                            from: Box::new(BetterleaksExpr::Integer { value: 0 }),
                            to: Box::new(to),
                        };
                    } else {
                        let from = self.parse_expr(0)?;
                        if self.peek() == &Token::Colon {
                            self.advance();
                            let to = if self.peek() == &Token::RBracket {
                                BetterleaksExpr::Integer { value: i64::MAX }
                            } else {
                                self.parse_expr(0)?
                            };
                            self.expect(Token::RBracket)?;
                            node = BetterleaksExpr::Slice {
                                node: Box::new(node),
                                from: Box::new(from),
                                to: Box::new(to),
                            };
                        } else {
                            self.expect(Token::RBracket)?;
                            node = BetterleaksExpr::Member {
                                node: Box::new(node),
                                property: Box::new(from),
                                optional: false,
                                method: false,
                            };
                        }
                    }
                }
                Token::LParen => {
                    let arguments = self.parse_arguments()?;
                    if let BetterleaksExpr::Member { method, .. } = &mut node {
                        *method = true;
                    }
                    let builtin_name = match &node {
                        BetterleaksExpr::Identifier { value }
                            if matches!(value.as_str(), "any" | "lastIndexOf" | "replace") =>
                        {
                            Some(value.clone())
                        }
                        _ => None,
                    };
                    node = if let Some(name) = builtin_name {
                        BetterleaksExpr::Builtin { name, arguments }
                    } else {
                        BetterleaksExpr::Call { callee: Box::new(node), arguments }
                    };
                }
                _ => break,
            }
        }
        Ok(node)
    }

    fn parse_arguments(&mut self) -> Result<Vec<BetterleaksExpr>> {
        self.expect(Token::LParen)?;
        let mut arguments = Vec::new();
        while self.peek() != &Token::RParen {
            arguments.push(self.parse_expr(0)?);
            if self.peek() != &Token::Comma {
                break;
            }
            self.advance();
        }
        self.expect(Token::RParen)?;
        Ok(arguments)
    }

    fn parse_array(&mut self) -> Result<BetterleaksExpr> {
        let mut nodes = Vec::new();
        while self.peek() != &Token::RBracket {
            nodes.push(self.parse_expr(0)?);
            if self.peek() != &Token::Comma {
                break;
            }
            self.advance();
        }
        self.expect(Token::RBracket)?;
        Ok(BetterleaksExpr::Array { nodes })
    }

    fn parse_braced(&mut self) -> Result<BetterleaksExpr> {
        if self.peek() == &Token::RBrace {
            self.advance();
            return Ok(BetterleaksExpr::Map { pairs: Vec::new() });
        }
        let is_map = matches!(self.peek(), Token::String(_) | Token::Identifier(_))
            && self.tokens.get(self.position + 1) == Some(&Token::Colon);
        if !is_map {
            let node = self.parse_expr(0)?;
            self.expect(Token::RBrace)?;
            return Ok(BetterleaksExpr::Predicate { node: Box::new(node) });
        }

        let mut pairs = Vec::new();
        while self.peek() != &Token::RBrace {
            let key = match self.advance().clone() {
                Token::String(value) | Token::Identifier(value) => value,
                token => bail!("unexpected map key {token:?}"),
            };
            self.expect(Token::Colon)?;
            pairs.push(BetterleaksExpr::Pair {
                key: Box::new(BetterleaksExpr::String { value: key }),
                value: Box::new(self.parse_expr(0)?),
            });
            if self.peek() != &Token::Comma {
                break;
            }
            self.advance();
        }
        self.expect(Token::RBrace)?;
        Ok(BetterleaksExpr::Map { pairs })
    }

    fn take_identifier(&mut self, description: &str) -> Result<String> {
        match self.advance().clone() {
            Token::Identifier(value) => Ok(value),
            token => bail!("expected {description}, found {token:?}"),
        }
    }

    fn take_member_name(&mut self) -> Result<String> {
        match self.advance().clone() {
            Token::Identifier(value) | Token::Operator(value)
                if value.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') =>
            {
                Ok(value)
            }
            token => bail!("expected member name, found {token:?}"),
        }
    }

    fn expect_operator(&mut self, expected: &str) -> Result<()> {
        match self.advance() {
            Token::Operator(actual) if actual == expected => Ok(()),
            actual => bail!("expected operator {expected:?}, found {actual:?}"),
        }
    }

    fn expect(&mut self, expected: Token) -> Result<()> {
        let actual = self.advance();
        if actual == &expected { Ok(()) } else { bail!("expected {expected:?}, found {actual:?}") }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.position).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> &Token {
        let position = self.position;
        self.position = self.position.saturating_add(1);
        self.tokens.get(position).unwrap_or(&Token::Eof)
    }
}

fn binary_precedence(operator: &str) -> Option<(u8, bool)> {
    Some(match operator {
        "||" | "or" => (1, false),
        "??" => (2, true),
        "&&" | "and" => (3, false),
        "==" | "!=" => (4, false),
        "in" | "not in" | "contains" | "<" | "<=" | ">" | ">=" => (5, false),
        "+" | "-" => (6, false),
        "*" | "/" | "%" => (7, false),
        _ => return None,
    })
}

fn lex(source: &str) -> Result<Vec<Token>> {
    let mut chars = source.char_indices().peekable();
    let mut tokens = Vec::new();
    while let Some((offset, ch)) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }
        let token = match ch {
            '(' => Token::LParen,
            ')' => Token::RParen,
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            ',' => Token::Comma,
            ':' => Token::Colon,
            ';' => Token::Semicolon,
            '.' => Token::Dot,
            '?' if chars.peek().is_some_and(|(_, next)| *next == '.') => {
                chars.next();
                Token::OptionalDot
            }
            '?' if chars.peek().is_some_and(|(_, next)| *next == '?') => {
                chars.next();
                Token::Operator("??".to_string())
            }
            '?' => Token::Question,
            '"' | '\'' | '`' => Token::String(read_string(source, &mut chars, ch)?),
            '/' if chars.peek().is_some_and(|(_, next)| *next == '/') => {
                chars.next();
                while chars.next().is_some_and(|(_, value)| value != '\n') {}
                continue;
            }
            '0'..='9' => {
                let end =
                    take_while_end(&mut chars, |value| value.is_ascii_digit() || value == '.');
                let raw = &source[offset..end];
                if raw.contains('.') {
                    Token::Float(raw.to_string())
                } else {
                    Token::Integer(raw.parse().with_context(|| format!("invalid integer {raw}"))?)
                }
            }
            'A'..='Z' | 'a'..='z' | '_' | '#' | '$' => {
                let end = take_while_end(&mut chars, |value| {
                    value.is_ascii_alphanumeric() || matches!(value, '_' | '#' | '$')
                });
                let word = &source[offset..end];
                match word {
                    "let" => Token::Let,
                    "true" => Token::Bool(true),
                    "false" => Token::Bool(false),
                    "nil" => Token::Nil,
                    "and" | "or" | "in" | "contains" | "not" => {
                        if word == "not" {
                            let saved = chars.clone();
                            while chars.peek().is_some_and(|(_, value)| value.is_whitespace()) {
                                chars.next();
                            }
                            let in_start = chars.peek().map(|(position, _)| *position);
                            if let Some(in_start) = in_start {
                                let mut lookahead = chars.clone();
                                let in_end = take_while_end(&mut lookahead, |value| {
                                    value.is_ascii_alphanumeric() || value == '_'
                                });
                                if &source[in_start..in_end] == "in" {
                                    chars = lookahead;
                                    Token::Operator("not in".to_string())
                                } else {
                                    chars = saved;
                                    Token::Operator(word.to_string())
                                }
                            } else {
                                chars = saved;
                                Token::Operator(word.to_string())
                            }
                        } else {
                            Token::Operator(word.to_string())
                        }
                    }
                    _ => Token::Identifier(word.to_string()),
                }
            }
            '+' | '-' | '*' | '%' | '^' => Token::Operator(ch.to_string()),
            '/' => Token::Operator("/".to_string()),
            '=' | '!' | '<' | '>' | '&' | '|' => {
                let mut operator = ch.to_string();
                if chars.peek().is_some_and(|(_, next)| {
                    matches!(
                        (ch, *next),
                        ('=', '=') | ('!', '=') | ('<', '=') | ('>', '=') | ('&', '&') | ('|', '|')
                    )
                }) {
                    operator.push(chars.next().expect("peeked character exists").1);
                }
                Token::Operator(operator)
            }
            other => bail!("unexpected character {other:?} at byte {offset}"),
        };
        tokens.push(token);
    }
    tokens.push(Token::Eof);
    Ok(tokens)
}

fn take_while_end<I, F>(chars: &mut std::iter::Peekable<I>, predicate: F) -> usize
where
    I: Iterator<Item = (usize, char)> + Clone,
    F: Fn(char) -> bool,
{
    let mut end = chars.peek().map_or(0, |(offset, _)| *offset);
    while let Some((offset, value)) = chars.peek().copied() {
        if !predicate(value) {
            return offset;
        }
        chars.next();
        end = offset + value.len_utf8();
    }
    end
}

fn read_string<I>(
    source: &str,
    chars: &mut std::iter::Peekable<I>,
    delimiter: char,
) -> Result<String>
where
    I: Iterator<Item = (usize, char)> + Clone,
{
    let mut result = String::new();
    while let Some((offset, value)) = chars.next() {
        if value == delimiter {
            return Ok(result);
        }
        if value != '\\' || delimiter == '`' {
            result.push(value);
            continue;
        }
        let (_, escaped) = chars.next().ok_or_else(|| anyhow!("unterminated escape"))?;
        result.push(match escaped {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'b' => '\u{0008}',
            'f' => '\u{000c}',
            '\\' => '\\',
            '/' => '/',
            '\'' => '\'',
            '"' => '"',
            'u' => {
                let start = chars.peek().map(|(position, _)| *position).unwrap_or(source.len());
                let end = take_while_end(chars, |ch| ch.is_ascii_hexdigit());
                if end.saturating_sub(start) != 4 {
                    bail!("invalid unicode escape at byte {offset}");
                }
                char::from_u32(u32::from_str_radix(&source[start..end], 16)?)
                    .ok_or_else(|| anyhow!("invalid unicode escape at byte {offset}"))?
            }
            other => bail!("unsupported escape \\{other} at byte {offset}"),
        });
    }
    bail!("unterminated string")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_CAPABILITIES: &str = "version: 1\nrules: {}\n";

    #[test]
    fn parses_validation_language_features() {
        let expression = parse_expression(
            r#"let r = http.get("https://example.test", {"Authorization": "Bearer " + finding["secret"]}); r.status == 200 ? {"result": "valid"} : validate.unknown(r)"#,
        )
        .unwrap();
        assert!(matches!(expression, BetterleaksExpr::VariableDeclarator { .. }));
    }

    #[test]
    fn component_variables_are_provider_neutral() {
        assert_eq!(component_variable("aws-secret-access-key"), "AWS_SECRET_ACCESS_KEY");
        assert!(!component_variable("aws-secret-access-key").contains("BETTERLEAKS"));
    }

    #[test]
    fn components_retain_constrained_and_unconstrained_association_markers() {
        let yaml = import_config(
            r#"
[[rules]]
id = "primary"
description = "Primary"
regex = '''(primary)'''
components = [
  { id = "near", within = "5L" },
  { id = "anywhere", optional = true },
]

[[rules]]
id = "near"
description = "Near"
regex = '''(near)'''
skipReport = true

[[rules]]
id = "anywhere"
description = "Anywhere"
regex = '''(anywhere)'''
skipReport = true
"#,
            "test",
            EMPTY_CAPABILITIES,
        )
        .unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rules = snapshot["rules"].as_sequence().unwrap();
        let primary = rules.iter().find(|rule| rule["id"] == "betterleaks.primary").unwrap();
        let dependencies = primary["depends_on_rule"].as_sequence().unwrap();

        assert_eq!(dependencies[0]["within"], "5L");
        assert_eq!(dependencies[1]["within"], "0");
    }

    #[test]
    fn preserves_capture_names_and_records_secret_group() {
        let yaml = import_config(
            r#"
[[rules]]
id = "capture-selection"
description = "Capture selection"
regex = '''(kind)-(?P<secret>[a-z]+)-([0-9]+)'''
secretGroup = 3
"#,
            "test",
            EMPTY_CAPABILITIES,
        )
        .unwrap();

        assert!(yaml.contains("pattern: (kind)-(?P<secret>[a-z]+)-([0-9]+)"));
        assert!(yaml.contains("betterleaks_secret_group: 3"));
    }

    #[test]
    fn rejects_a_missing_explicit_secret_group() {
        let error = import_config(
            r#"
[[rules]]
id = "bad-capture-selection"
description = "Bad capture selection"
regex = '''(only-one)'''
secretGroup = 2
"#,
            "test",
            EMPTY_CAPABILITIES,
        )
        .unwrap_err();

        assert!(error.to_string().contains("configured secret group 2 does not exist"));
    }

    #[test]
    fn does_not_emit_matching_engine_bypass_metadata() {
        let yaml = import_config(
            r#"
[[rules]]
id = "broad-password-test"
description = "Broad password test"
regex = '''password=(?P<secret>.{5,250})'''
confidence = "low"

[[rules]]
id = "ordinary-token"
description = "Ordinary token"
regex = '''token_(?P<secret>[a-z]+)'''
"#,
            "test",
            EMPTY_CAPABILITIES,
        )
        .unwrap();

        assert!(yaml.contains("id: betterleaks.broad-password-test"));
        assert!(!yaml.contains("vectorscan_compatible:"));
    }

    #[test]
    fn omits_low_value_generic_rules_only_from_builtins() {
        let source = r#"
[[rules]]
id = "generic-api-key"
description = "Generic API key"
regex = '''key=(?P<secret>[a-z]+)'''

[[rules]]
id = "generic-password"
description = "Generic password"
regex = '''password=(?P<secret>[a-z]+)'''

[[rules]]
id = "generic-username"
description = "Generic username"
regex = '''username=(?P<secret>[a-z]+)'''

[[rules]]
id = "specific-token"
description = "Specific token"
regex = '''specific_(?P<secret>[a-z]+)'''
"#;

        let builtins = import_config(source, "test", EMPTY_CAPABILITIES).unwrap();
        assert!(!builtins.contains("betterleaks.generic-api-key"));
        assert!(!builtins.contains("betterleaks.generic-password"));
        assert!(!builtins.contains("betterleaks.generic-username"));
        assert!(builtins.contains("betterleaks.specific-token"));

        let custom = import_custom_config(source, "test").unwrap();
        assert!(custom.contains("custom.generic-api-key"));
        assert!(custom.contains("custom.generic-password"));
        assert!(custom.contains("custom.generic-username"));
    }

    #[test]
    fn applies_capability_confidence_and_authority_overrides() {
        let yaml = import_config(
            r#"
[[rules]]
id = "broad-api-key-test"
description = "Broad API key test"
regex = '''key=(?P<secret>[a-z]+)'''
confidence = "high"
"#,
            "test",
            r#"
version: 1
rules:
  broad-api-key-test:
    confidence: low
    authoritative: false
"#,
        )
        .unwrap();

        assert!(yaml.contains("confidence: low"));
        assert!(yaml.contains("authoritative: false"));
    }

    #[test]
    fn applies_capability_tls_mode_override() {
        let yaml = import_config(
            r#"
[[rules]]
id = "mongodb-connection-string-test"
description = "MongoDB connection string test"
regex = '''(?P<secret>mongodb://[^\s]+)'''
"#,
            "test",
            r#"
version: 1
rules:
  mongodb-connection-string-test:
    validation: MongoDB
    tls_mode: lax
"#,
        )
        .unwrap();

        assert!(yaml.contains("tls_mode: lax"), "expected tls_mode in:\n{yaml}");
    }

    #[test]
    fn rejects_unsupported_tls_mode() {
        let error = import_config(
            r#"
[[rules]]
id = "tls-mode-typo-test"
description = "TLS mode typo test"
regex = '''(?P<secret>mongodb://[^\s]+)'''
"#,
            "test",
            r#"
version: 1
rules:
  tls-mode-typo-test:
    validation: MongoDB
    tls_mode: relaxed
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unsupported tls_mode"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_tls_mode_without_a_validator() {
        // `tls_mode` only affects how a validator dials an endpoint, so setting
        // it on a detect-only rule is a mistake worth failing the build over.
        let error = import_config(
            r#"
[[rules]]
id = "tls-mode-no-validator-test"
description = "TLS mode without validator test"
regex = '''key=(?P<secret>[a-z]+)'''
"#,
            "test",
            r#"
version: 1
rules:
  tls-mode-no-validator-test:
    tls_mode: lax
"#,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("tls_mode on tls-mode-no-validator-test requires a validator"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn keeps_source_prefilter_separate_and_ignores_keywords() {
        let yaml = import_config(
            r#"
prefilter = '''matchesAny(attributes["path"], ["vendor/"])'''
filter = '''containsAny(finding["secret"], ["global-filter"])'''

[[rules]]
id = "filter-separation"
description = "Filter separation"
regex = '''token_(?P<secret>[a-z]+)'''
keywords = ["token_"]
filter = '''containsAny(finding["secret"], ["rule-filter"])'''
"#,
            "test",
            EMPTY_CAPABILITIES,
        )
        .unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let prefilter = serde_yaml::to_string(&snapshot["betterleaks_prefilter"]).unwrap();
        let finding_filter =
            serde_yaml::to_string(&snapshot["rules"][0]["betterleaks_filter"]).unwrap();

        assert!(prefilter.contains("vendor/"));
        assert!(!prefilter.contains("global-filter"));
        assert!(finding_filter.contains("global-filter"));
        assert!(finding_filter.contains("rule-filter"));
        assert!(!finding_filter.contains("vendor/"));
        assert!(!yaml.contains("keywords"));
    }

    #[test]
    fn rejects_capability_component_drift() {
        let error = import_config(
            r#"
[[rules]]
id = "composite"
description = "Composite"
regex = '''token_(?P<secret>[a-z]+)'''
validate = '''true'''
"#,
            "test",
            r#"
version: 1
rules:
  composite:
    access_map:
      handler: aws
      inputs:
        secret: components.missing-secret
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("references a missing component"));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn validation_override_replaces_unsafe_upstream_expression_and_preserves_source() {
        let yaml = import_config(
            r#"
[[rules]]
id = "provider-token"
description = "Provider token"
regex = '''token_[a-z]+'''
validate = '''http.get("https://unsafe.example")'''
"#,
            "test",
            r#"
version: 1
rules:
  provider-token:
    validation_override: 'http.get("https://safe.example")'
"#,
        )
        .unwrap();

        assert!(yaml.contains("safe.example"));
        assert!(yaml.contains("value: https://safe.example"));
        assert!(!yaml.contains("unsafe.example"));
    }

    #[test]
    fn filter_override_is_combined_with_upstream_filter() {
        let yaml = import_config(
            r#"
[[rules]]
id = "stripe-access-token"
description = "Stripe access token"
regex = '''\b(sk_(?:test|live)_[A-Za-z0-9]{16})\b'''
filter = '''filter.entropy(finding["secret"]) < 3.5'''
"#,
            "test",
            r#"
version: 1
rules:
  stripe-access-token:
    filter_override: 'finding["secret"].startsWith("sk_test_")'
"#,
        )
        .unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let filter = serde_yaml::to_string(&snapshot["rules"][0]["betterleaks_filter"]).unwrap();

        assert!(filter.contains("sk_test_"));
        assert!(filter.contains("3.5"));
    }

    #[test]
    fn imports_typed_validation_overrides() {
        let yaml = import_config(
            r#"
[[rules]]
id = "private-key"
description = "Private key"
regex = '''(-----BEGIN PRIVATE KEY-----)'''

[[rules]]
id = "mongodb-connection-string"
description = "MongoDB URI"
regex = '''(mongodb://[^[:space:]]+)'''

[[rules]]
id = "jwt"
description = "JWT"
regex = '''(ey[a-z]+)'''

[[rules]]
id = "generic-credential-uri"
description = "Credential URI"
regex = '''(?P<uri>(?P<scheme>postgresql)://user:(?P<password>[^@]+)@host)'''
secretGroup = 3

[[rules]]
id = "polymarket-private-key"
description = "Polymarket private key"
regex = '''(0x[a-fA-F0-9]{64})'''
"#,
            "test",
            r#"
version: 1
rules:
  private-key:
    validation: Assumed
  mongodb-connection-string:
    validation: MongoDB
  jwt:
    validation: JWT
  generic-credential-uri:
    validation: CredentialUri
  polymarket-private-key:
    validation:
      type: Ethereum
      content: private_key
"#,
        )
        .unwrap();

        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let validations: BTreeMap<_, _> = snapshot["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| {
                (rule["id"].as_str().unwrap(), serde_yaml::to_string(&rule["validation"]).unwrap())
            })
            .collect();

        assert!(validations["betterleaks.private-key"].contains("type: Assumed"));
        assert!(validations["betterleaks.mongodb-connection-string"].contains("type: MongoDB"));
        assert!(validations["betterleaks.jwt"].contains("type: JWT"));
        assert!(validations["betterleaks.generic-credential-uri"].contains("type: CredentialUri"));
        assert!(validations["betterleaks.polymarket-private-key"].contains("type: Ethereum"));
        assert!(validations["betterleaks.polymarket-private-key"].contains("private_key"));
    }
}
