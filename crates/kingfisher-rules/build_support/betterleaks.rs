use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Relax assignment context without copying provider token formats into the overlay.
/// Only a single mandatory, top-level capture is supported: retaining its index/name
/// keeps the reported secret and capture-based expressions stable. Parsing the whole
/// pattern before extracting nodes preserves scoped flags (notably Voyage's prefix).
fn bare_pattern(pattern: &str, secret_group: usize) -> Result<String> {
    use regex_syntax::hir::{Hir, HirKind};

    let compiled = regex::bytes::RegexBuilder::new(pattern).unicode(false).build()?;
    if compiled.captures_len() != 2 || secret_group > 1 {
        bail!("bare requires exactly one secret capture (group 1)");
    }
    let hir =
        regex_syntax::ParserBuilder::new().unicode(false).utf8(false).build().parse(pattern)?;
    let nodes = match hir.kind() {
        HirKind::Concat(nodes) => nodes.as_slice(),
        HirKind::Capture(_) => std::slice::from_ref(&hir),
        _ => bail!("bare requires a mandatory top-level secret capture"),
    };
    let index = nodes
        .iter()
        .position(|node| matches!(node.kind(), HirKind::Capture(_)))
        .ok_or_else(|| anyhow!("bare requires a mandatory top-level secret capture"))?;
    if nodes[index].properties().minimum_len().is_none_or(|len| len == 0) {
        bail!("bare requires a nonempty secret capture");
    }

    // Preserve assertion-only prefixes on already-bare rules. Otherwise replace
    // assignment context with an ASCII token boundary. Consume the delimiter since
    // Vectorscan does not support lookbehind; the secret remains capture group 1.
    let prefix = &nodes[..index];
    let mut bare = if !prefix.is_empty()
        && prefix.iter().all(|node| matches!(node.kind(), HirKind::Look(_)))
    {
        prefix.to_vec()
    } else {
        vec![
            regex_syntax::ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(r"(?:\A|[^A-Za-z0-9_-])")?,
        ]
    };
    bare.extend_from_slice(&nodes[index..]);
    let bare = Hir::concat(bare);
    // HIR's printer emits (?-u:...) around byte classes/assertions. Both Kingfisher
    // engines already run in byte mode, and Vectorscan rejects Rust's `u` flag.
    // This replacement only touches printer-generated syntax (literal metacharacters
    // are escaped). Reparse and compare trees to enforce semantic equivalence.
    let result = bare.to_string().replace("(?-u:", "(?:");
    let reparsed =
        regex_syntax::ParserBuilder::new().unicode(false).utf8(false).build().parse(&result)?;
    if reparsed != bare {
        bail!("bare serialization changed regex semantics");
    }
    regex::bytes::RegexBuilder::new(&result)
        .unicode(false)
        .build()
        .context("bare generated an invalid byte regex")?;
    Ok(result)
}

const OMITTED_BUILTIN_RULE_IDS: &[&str] =
    &["generic-api-key", "generic-password", "generic-username"];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BetterleaksConfig {
    #[serde(default, rename = "title")]
    _title: String,
    #[serde(default, rename = "description")]
    _description: String,
    min_version: Option<String>,
    extend: Option<BetterleaksExtend>,
    prefilter: Option<String>,
    filter: Option<String>,
    #[serde(default)]
    rules: Vec<BetterleaksRule>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BetterleaksExtend {
    path: Option<String>,
    #[serde(default)]
    use_default: bool,
    #[serde(default)]
    disabled_rules: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BetterleaksRule {
    id: String,
    #[serde(default)]
    description: String,
    regex: Option<String>,
    path: Option<String>,
    #[serde(default, alias = "valueGroup")]
    secret_group: usize,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    specificity: i64,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    skip_report: bool,
    validate: Option<String>,
    analyze: Option<String>,
    revoke: Option<String>,
    filter: Option<String>,
    components: Option<Vec<BetterleaksComponent>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    verify_candidates: Vec<String>,
    access_map: Option<BetterleaksAccessMap>,
    revocation: Option<serde_yaml::Value>,
    revocation_bindings: Option<BetterleaksRevocationBindings>,
    validation: Option<TypedValidation>,
    validation_override: Option<String>,
    filter_override: Option<String>,
    authoritative: Option<bool>,
    confidence: Option<String>,
    tls_mode: Option<String>,
    #[serde(default)]
    bare: bool,
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
    #[serde(skip_serializing_if = "is_zero")]
    specificity: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    keywords: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    betterleaks_path_only: bool,
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
    #[serde(skip_serializing_if = "is_false")]
    verify_candidates: bool,
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
    Betterleaks(Box<BetterleaksValidation>),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    analyze: Option<BetterleaksExpr>,
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
    GcpApiKey,
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
    Chain {
        node: Box<BetterleaksExpr>,
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
    Sequence {
        #[serde(default)]
        nodes: Vec<BetterleaksExpr>,
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

/// Parse custom YAML Expr source into the same portable representation as imported TOML.
#[allow(dead_code)]
pub(crate) fn parse_custom_expression(source: &str) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(parse_expression(source)?)?)
}

fn resolve_config(
    contents: &str,
    ancestry: &mut Vec<std::path::PathBuf>,
    depth: usize,
) -> Result<BetterleaksConfig> {
    let mut config: BetterleaksConfig =
        toml::from_str(contents).context("invalid Betterleaks TOML")?;
    config.min_version = config.min_version.filter(|value| !value.trim().is_empty());
    config.prefilter = config.prefilter.filter(|value| !value.trim().is_empty());
    config.filter = config.filter.filter(|value| !value.trim().is_empty());
    for rule in &mut config.rules {
        rule.validate = rule.validate.take().filter(|value| !value.trim().is_empty());
        rule.analyze = rule.analyze.take().filter(|value| !value.trim().is_empty());
        rule.revoke = rule.revoke.take().filter(|value| !value.trim().is_empty());
        rule.filter = rule.filter.take().filter(|value| !value.trim().is_empty());
    }
    if let Some(version) = config.min_version.as_deref() {
        // This declares the Betterleaks configuration dialect, not Kingfisher's binary version.
        // Accept v1/v2 constraints while refusing a future incompatible dialect explicitly.
        let pattern =
            Regex::new(r"^v?([0-9]+)\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")?;
        let captures = pattern
            .captures(version)
            .ok_or_else(|| anyhow!("invalid Betterleaks minVersion {version:?}"))?;
        let major: u64 = captures[1].parse()?;
        if major > 2 {
            bail!(
                "unsupported Betterleaks minVersion {version:?}: supported configuration major version is 2"
            );
        }
    }
    let mut ids = BTreeSet::new();
    for rule in &config.rules {
        if !ids.insert(rule.id.clone()) {
            bail!("duplicate Betterleaks rule ID {:?}", rule.id);
        }
    }
    let Some(extend) = config.extend.take() else { return Ok(config) };
    if extend.path.as_deref().is_some_and(|path| !path.is_empty()) && extend.use_default {
        bail!("Betterleaks extend.path and extend.useDefault are mutually exclusive");
    }
    let path = extend.path.filter(|path| !path.is_empty());
    if path.is_none() && !extend.use_default {
        return Ok(config);
    }
    if depth >= 2 {
        bail!("Betterleaks config extension exceeds maximum depth of 2");
    }
    let base_contents = if let Some(path) = path.as_deref() {
        let canonical = std::fs::canonicalize(path)
            .with_context(|| format!("failed to load extended Betterleaks config {path:?}"))?;
        if ancestry.contains(&canonical) {
            bail!("Betterleaks config extension cycle at {path:?}");
        }
        ancestry.push(canonical);
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to load extended Betterleaks config {path:?}"))?
    } else {
        use std::io::Read;
        let mut decoded = String::new();
        flate2::read::GzDecoder::new(
            include_bytes!("../generated/upstream-sources.json.gz").as_slice(),
        )
        .read_to_string(&mut decoded)
        .context("failed to read archived Betterleaks defaults")?;
        let sources: BTreeMap<String, Option<String>> = serde_json::from_str(&decoded)?;
        sources
            .into_iter()
            .find_map(|(url, contents)| {
                url.ends_with("/config/betterleaks.toml").then_some(contents).flatten()
            })
            .ok_or_else(|| anyhow!("archived Betterleaks defaults are missing"))?
    };
    let base = resolve_config(&base_contents, ancestry, depth + 1)?;
    if path.is_some() {
        ancestry.pop();
    }
    let disabled: BTreeSet<_> = extend.disabled_rules.into_iter().collect();
    config.rules.extend(
        base.rules
            .into_iter()
            .filter(|rule| !ids.contains(&rule.id) && !disabled.contains(&rule.id)),
    );
    config.prefilter = extend_expression(base.prefilter, config.prefilter);
    config.filter = extend_expression(base.filter, config.filter);
    Ok(config)
}

fn extend_expression(base: Option<String>, child: Option<String>) -> Option<String> {
    match (
        base.filter(|source| !source.trim().is_empty()),
        child.filter(|source| !source.trim().is_empty()),
    ) {
        (Some(base), Some(child)) => Some(format!("({base}) || ({child})")),
        (base, child) => base.or(child),
    }
}

fn validate_source_config(config: &BetterleaksConfig) -> Result<()> {
    let rules: BTreeMap<_, _> = config.rules.iter().map(|rule| (rule.id.as_str(), rule)).collect();
    let window_pattern = Regex::new(r"(?i)^[+-]?[0-9]+[CL]?$")?;
    for rule in &config.rules {
        if rule.id.trim().is_empty() {
            bail!("Betterleaks rule id is missing or empty");
        }
        let path_only = rule.regex.as_deref().is_none_or(str::is_empty);
        if path_only && rule.path.as_deref().is_none_or(str::is_empty) {
            bail!("Betterleaks rule {} has neither regex nor path", rule.id);
        }
        if path_only
            && (rule.secret_group != 0
                || rule.components.as_ref().is_some_and(|components| !components.is_empty())
                || rule.validate.is_some()
                || rule.analyze.is_some()
                || rule.revoke.is_some())
        {
            bail!(
                "path-only Betterleaks rule {} cannot declare captures, components, validation, analysis, or revocation",
                rule.id
            );
        }
        if rule.analyze.is_some() && rule.validate.is_none() {
            bail!("analysis on {} requires a validation expression", rule.id);
        }
        let mut components = BTreeSet::new();
        for component in rule.components.as_deref().unwrap_or_default() {
            if component.id == rule.id {
                bail!("Betterleaks rule {} cannot reference itself as a component", rule.id);
            }
            if !components.insert(&component.id) {
                bail!("duplicate component {} on {}", component.id, rule.id);
            }
            let Some(target) = rules.get(component.id.as_str()) else {
                bail!("component {} on {} does not exist", component.id, rule.id)
            };
            if target.regex.as_deref().is_none_or(str::is_empty)
                || target.components.as_ref().is_some_and(|components| !components.is_empty())
            {
                bail!(
                    "component {} on {} must be a content rule without components",
                    component.id,
                    rule.id
                );
            }
            if let Some(window) =
                component.within.as_deref().map(str::trim).filter(|window| !window.is_empty())
            {
                for token in window.split(',').map(str::trim) {
                    if !window_pattern.is_match(token)
                        || token
                            .trim_start_matches(['+', '-'])
                            .trim_end_matches(['C', 'c', 'L', 'l'])
                            .parse::<usize>()
                            .is_err()
                    {
                        bail!("invalid component within {window:?} on {}", rule.id);
                    }
                }
            }
        }
    }
    Ok(())
}

fn import_config_with_namespace(
    contents: &str,
    source: &str,
    capabilities: &str,
    namespace: &str,
    filter_builtins: bool,
) -> Result<String> {
    let source_config = resolve_config(contents, &mut Vec::new(), 0)?;
    validate_source_config(&source_config)?;
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
    let mut omitted_low_value = Vec::new();
    let mut omitted_path_only = Vec::new();

    for source_rule in source_config.rules {
        if filter_builtins && OMITTED_BUILTIN_RULE_IDS.contains(&source_rule.id.as_str()) {
            omitted_low_value.push(source_rule.id);
            continue;
        }
        let path_only = source_rule.regex.as_deref().is_none_or(str::is_empty);
        // A filename alone is not evidence of exposed secret material. Keep these
        // rules available to explicit custom configs, but never bundle them.
        if filter_builtins && path_only {
            omitted_path_only.push(source_rule.id);
            continue;
        }
        let rule_capabilities =
            capability_overlay.rules.remove(&source_rule.id).unwrap_or_default();
        let source_pattern = if path_only {
            if rule_capabilities.bare {
                bail!("bare on {} requires a regex", source_rule.id);
            }
            if !rule_capabilities.verify_candidates.is_empty()
                || rule_capabilities.access_map.is_some()
                || rule_capabilities.revocation.is_some()
                || rule_capabilities.validation.is_some()
            {
                bail!("capabilities target path-only Betterleaks rule {}", source_rule.id);
            }
            "(?:)".to_string()
        } else {
            source_rule.regex.clone().expect("checked regex")
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
        let source_pattern = if rule_capabilities.bare {
            bare_pattern(&source_pattern, source_rule.secret_group)
                .with_context(|| format!("cannot apply bare to {}", source_rule.id))?
        } else {
            source_pattern
        };
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
        for variable in &rule_capabilities.verify_candidates {
            if !components.values().any(|name| name == variable) {
                bail!(
                    "candidate verification on {} references missing component variable {variable}",
                    source_rule.id
                );
            }
        }
        let depends_on_rule = source_components
            .iter()
            .map(|component| DependsOnRule {
                rule_id: qualify_id(&component.id, namespace),
                verify_candidates: rule_capabilities
                    .verify_candidates
                    .contains(&component_variable(&component.id)),
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
        let analysis_expression = source_rule
            .analyze
            .as_deref()
            .map(parse_expression)
            .transpose()
            .with_context(|| format!("failed to parse analysis for {}", source_rule.id))?;
        if let Some(expression) = analysis_expression.as_ref() {
            validate_analysis_expression(expression)
                .with_context(|| format!("unsupported analysis operation in {}", source_rule.id))?;
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
                Validation::Betterleaks(Box::new(BetterleaksValidation {
                    source: validation_source.expect("parsed validation has source").to_string(),
                    expression,
                    analyze: analysis_expression,
                    components: components.clone(),
                    capabilities: BetterleaksCapabilities {
                        access_map: rule_capabilities.access_map.clone(),
                        revocation_bindings: rule_capabilities.revocation_bindings.clone(),
                    },
                }))
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
            specificity: source_rule.specificity,
            tags: source_rule.tags,
            keywords: if rule_capabilities.bare { Vec::new() } else { source_rule.keywords },
            betterleaks_path_only: path_only,
            confidence: confidence.to_string(),
            authoritative: rule_capabilities.authoritative.unwrap_or(true),
            visible: !source_rule.skip_report,
            validation,
            revocation: match (rule_capabilities.revocation, source_rule.revoke.as_deref()) {
                (Some(revocation), _) => Some(revocation),
                (None, Some(source)) => {
                    let expression = parse_expression(source).with_context(|| {
                        format!("failed to parse revocation for {}", source_rule.id)
                    })?;
                    validate_revocation_expression(&expression).with_context(|| {
                        format!("unsupported revocation operation in {}", source_rule.id)
                    })?;
                    Some(serde_yaml::to_value(Validation::Betterleaks(Box::new(
                        BetterleaksValidation {
                            source: source.to_string(),
                            expression,
                            analyze: None,
                            components,
                            capabilities: BetterleaksCapabilities::default(),
                        },
                    )))?)
                }
                (None, None) => None,
            },
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
         # Omitted filename-only built-in rules: {}.\n\
         # Custom path-only rules retain path matching semantics.\n{yaml}",
        source_count - omitted_low_value.len() - omitted_path_only.len(),
        omitted_low_value.join(", "),
        omitted_path_only.join(", "),
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
        specificity: 0,
        tags: Vec::new(),
        keywords: Vec::new(),
        betterleaks_path_only: false,
        confidence: "medium".to_string(),
        authoritative: true,
        visible: true,
        validation: Some(Validation::Aws),
        revocation: None,
        depends_on_rule: vec![
            DependsOnRule {
                rule_id: qualify_id("aws-access-token", namespace),
                verify_candidates: true,
                variable: "AKID".to_string(),
                optional: false,
                within: Some("5L".to_string()),
            },
            DependsOnRule {
                rule_id: qualify_id("aws-secret-access-key", namespace),
                verify_candidates: true,
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
                    matches!(name.as_str(), "crypto.sha256")
                        || matches!(
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
                        | "malformedPrivateKey"
                        | "findMatch"
                        | "containsAny"
                        | "startsWithAny"
                        | "intersects"
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
                        | "lower"
                        | "upper"
                        | "trim"
                        | "trimPrefix"
                        | "trimSuffix"
                        | "repeat"
                        | "indexOf"
                        | "lastIndexOf"
                        | "hasPrefix"
                        | "hasSuffix"
                        | "keys"
                        | "values"
                        | "reverse"
                        | "sort"
                        | "uniq"
                        | "flatten"
                        | "concat"
                        | "first"
                        | "last"
                        | "get"
                        | "sum"
                        | "mean"
                        | "abs"
                        | "ceil"
                        | "floor"
                        | "round"
                        | "type"
                        | "string"
                        | "int"
                        | "float"
                        | "toJSON"
                        | "fromJSON"
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
            if !matches!(
                name.as_str(),
                "any"
                    | "all"
                    | "none"
                    | "one"
                    | "map"
                    | "filter"
                    | "find"
                    | "findLast"
                    | "findIndex"
                    | "findLastIndex"
                    | "count"
                    | "lastIndexOf"
                    | "replace"
            ) {
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
        BetterleaksExpr::Predicate { node } | BetterleaksExpr::Chain { node } => {
            validate_filter_expression(node)?
        }
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
                    | "startsWith"
                    | "endsWith"
                    | "matches"
                    | ".."
                    | "**"
                    | "^"
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
        BetterleaksExpr::Array { nodes }
        | BetterleaksExpr::Map { pairs: nodes }
        | BetterleaksExpr::Sequence { nodes } => {
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
    validate_provider_expression(expression, false, false)
}

fn validate_revocation_expression(expression: &BetterleaksExpr) -> Result<()> {
    validate_provider_expression(expression, true, false)
}

fn validate_analysis_expression(expression: &BetterleaksExpr) -> Result<()> {
    validate_provider_expression(expression, false, true)
}

fn validate_provider_expression(
    expression: &BetterleaksExpr,
    revoke: bool,
    analyze: bool,
) -> Result<()> {
    match expression {
        BetterleaksExpr::Call { callee, arguments } => {
            let name = expression_name(callee)
                .ok_or_else(|| anyhow!("dynamic function calls are not supported"))?;
            let supported = (revoke && matches!(name.as_str(), "http.delete" | "revoke.unknown"))
                || (analyze && name == "analysis.capabilities")
                || if let BetterleaksExpr::Member { method: true, .. } = callee.as_ref() {
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
                                | "crypto.sha256"
                                | "crypto.md5"
                                | "crypto.hmacSha1"
                                | "crypto.hmacSha256"
                                | "strings.urlQueryEscape"
                                | "strings.splitTrim"
                                | "strings.obfuscate"
                                | "json.string"
                                | "time.nowUnix"
                                | "time.nowRFC3339"
                                | "env.getOrDefault"
                                | "env.get"
                                | "filter.matchesAny"
                                | "aws.validate"
                                | "gcp.validate"
                                | "azure.validateStorage"
                                | "azure.validateServicePrincipal"
                                | "azure.validateAppConfig"
                                | "azure.validateServiceBusSAS"
                        )
                } else {
                    matches!(
                        name.as_str(),
                        "bytes"
                            | "size"
                            | "substring"
                            | "toJSON"
                            | "type"
                            | "string"
                            | "int"
                            | "len"
                            | "trim"
                            | "split"
                            | "matchesAny"
                            | "containsAny"
                            | "startsWithAny"
                            | "entropy"
                            | "tokenRatio"
                            | "failsTokenEfficiency"
                            | "findMatch"
                            | "intersects"
                            | "flatten"
                            | "sort"
                            | "uniq"
                            | "concat"
                            | "last"
                            | "lower"
                            | "upper"
                            | "join"
                            | "keys"
                            | "values"
                            | "get"
                            | "fromJSON"
                            | "trimPrefix"
                            | "trimSuffix"
                            | "repeat"
                            | "indexOf"
                            | "hasPrefix"
                            | "hasSuffix"
                            | "reverse"
                            | "first"
                            | "sum"
                            | "min"
                            | "max"
                            | "mean"
                            | "abs"
                            | "ceil"
                            | "floor"
                            | "round"
                    )
                };
            if !supported {
                bail!("unsupported Betterleaks validation call {name:?}");
            }
            validate_provider_expression(callee, revoke, analyze)?;
            for argument in arguments {
                validate_provider_expression(argument, revoke, analyze)?;
            }
        }
        BetterleaksExpr::Builtin { name, arguments } => {
            if !matches!(
                name.as_str(),
                "any"
                    | "all"
                    | "none"
                    | "one"
                    | "filter"
                    | "map"
                    | "find"
                    | "findLast"
                    | "findIndex"
                    | "findLastIndex"
                    | "count"
                    | "lastIndexOf"
                    | "replace"
            ) {
                bail!("unsupported Betterleaks validation builtin {name:?}");
            }
            for argument in arguments {
                validate_provider_expression(argument, revoke, analyze)?;
            }
        }
        BetterleaksExpr::Unary { operator, node } => {
            if !matches!(operator.as_str(), "!" | "not" | "-") {
                bail!("unsupported Betterleaks validation unary operator {operator:?}");
            }
            validate_provider_expression(node, revoke, analyze)?;
        }
        BetterleaksExpr::Binary { operator, left, right } => {
            if !matches!(
                operator.as_str(),
                "&&" | "and"
                    | "||"
                    | "or"
                    | "??"
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "**"
                    | "^"
                    | ".."
                    | "=="
                    | "!="
                    | ">"
                    | ">="
                    | "<"
                    | "<="
                    | "in"
                    | "contains"
                    | "startsWith"
                    | "endsWith"
                    | "matches"
            ) {
                bail!("unsupported Betterleaks validation binary operator {operator:?}");
            }
            validate_provider_expression(left, revoke, analyze)?;
            validate_provider_expression(right, revoke, analyze)?;
        }
        BetterleaksExpr::Predicate { node } | BetterleaksExpr::Chain { node } => {
            validate_provider_expression(node, revoke, analyze)?
        }
        BetterleaksExpr::Member { node, property, .. } => {
            validate_provider_expression(node, revoke, analyze)?;
            validate_provider_expression(property, revoke, analyze)?;
        }
        BetterleaksExpr::Slice { node, from, to } => {
            validate_provider_expression(node, revoke, analyze)?;
            validate_provider_expression(from, revoke, analyze)?;
            validate_provider_expression(to, revoke, analyze)?;
        }
        BetterleaksExpr::Conditional { cond, exp1, exp2 } => {
            validate_provider_expression(cond, revoke, analyze)?;
            validate_provider_expression(exp1, revoke, analyze)?;
            validate_provider_expression(exp2, revoke, analyze)?;
        }
        BetterleaksExpr::VariableDeclarator { value, expr, .. } => {
            validate_provider_expression(value, revoke, analyze)?;
            validate_provider_expression(expr, revoke, analyze)?;
        }
        BetterleaksExpr::Array { nodes }
        | BetterleaksExpr::Map { pairs: nodes }
        | BetterleaksExpr::Sequence { nodes } => {
            for node in nodes {
                validate_provider_expression(node, revoke, analyze)?;
            }
        }
        BetterleaksExpr::Pair { key, value } => {
            validate_provider_expression(key, revoke, analyze)?;
            validate_provider_expression(value, revoke, analyze)?;
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

fn is_zero(value: &i64) -> bool {
    *value == 0
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
        if self.peek() == &Token::Semicolon {
            self.advance();
            let rest = self.parse_program(terminator)?;
            expression = BetterleaksExpr::Sequence { nodes: vec![expression, rest] };
        } else {
            if terminator != Token::Eof {
                self.expect(terminator)?;
            } else {
                self.expect(Token::Eof)?;
            }
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
        let mut optional_chain = false;
        loop {
            match self.peek() {
                Token::Dot | Token::OptionalDot => {
                    let optional = self.advance() == &Token::OptionalDot;
                    optional_chain |= optional;
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
                            if matches!(
                                value.as_str(),
                                "any"
                                    | "all"
                                    | "none"
                                    | "one"
                                    | "filter"
                                    | "map"
                                    | "find"
                                    | "findLast"
                                    | "findIndex"
                                    | "findLastIndex"
                                    | "count"
                                    | "lastIndexOf"
                                    | "replace"
                            ) =>
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
        Ok(if optional_chain { BetterleaksExpr::Chain { node: Box::new(node) } } else { node })
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
        "in" | "not in" | "contains" | "startsWith" | "endsWith" | "matches" | "<" | "<=" | ">"
        | ">=" => (5, false),
        "+" | "-" => (6, false),
        "*" | "/" | "%" => (7, false),
        ".." => (8, false),
        "**" | "^" => (9, true),
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
            '.' if chars.peek().is_some_and(|(_, next)| *next == '.') => {
                chars.next();
                Token::Operator("..".to_string())
            }
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
            '"' | '\'' | '`' => Token::String(read_string(&mut chars, ch)?),
            '/' if chars.peek().is_some_and(|(_, next)| *next == '/') => {
                chars.next();
                while chars.next().is_some_and(|(_, value)| value != '\n') {}
                continue;
            }
            '0'..='9' => {
                let mut end = offset + ch.len_utf8();
                while let Some((position, value)) = chars.peek().copied() {
                    if value.is_ascii_digit() {
                        chars.next();
                        end = position + value.len_utf8();
                    } else if value == '.'
                        && !source[position..].starts_with("..")
                        && !source[offset..end].contains('.')
                    {
                        chars.next();
                        end = position + 1;
                    } else {
                        break;
                    }
                }
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
                })
                .max(offset + ch.len_utf8());
                let word = &source[offset..end];
                match word {
                    "let" => Token::Let,
                    "true" => Token::Bool(true),
                    "false" => Token::Bool(false),
                    "nil" => Token::Nil,
                    "and" | "or" | "in" | "contains" | "startsWith" | "endsWith" | "matches"
                    | "not" => {
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
            '*' if chars.peek().is_some_and(|(_, next)| *next == '*') => {
                chars.next();
                Token::Operator("**".to_string())
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

fn read_string<I>(chars: &mut std::iter::Peekable<I>, delimiter: char) -> Result<String>
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
                let mut codepoint = String::new();
                for _ in 0..4 {
                    let (_, digit) = chars
                        .next()
                        .ok_or_else(|| anyhow!("invalid unicode escape at byte {offset}"))?;
                    if !digit.is_ascii_hexdigit() {
                        bail!("invalid unicode escape at byte {offset}");
                    }
                    codepoint.push(digit);
                }
                char::from_u32(u32::from_str_radix(&codepoint, 16)?)
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

    #[test]
    fn v2_validation_analysis_and_revocation_import_as_separate_programs() {
        let source = r#"
[[rules]]
id = "v2-token"
description = "Synthetic v2 token"
regex = '(cf[ua]t_[A-Za-z0-9]{48})'
filter = 'lower(finding["match"]) contains "client"'
validate = '''
let account_token = finding["secret"] startsWith "cfat_";
let scopes = filter(["read", 42], {type(#) == "string"});
let valid = all(scopes, {type(#) == "string"}) && len(scopes) > 0;
valid ? {"result": "valid", "analysis": {"account_token": account_token}} : {"result": "unknown"}
'''
analyze = 'analysis.capabilities({"read": len(validation.analysis?.scopes ?? []) > 0})'
revoke = 'http.delete("https://example.invalid/revoke")'
"#;
        let yaml = import_config(source, "synthetic-v2", "version: 1\nrules: {}\n").unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rule = &snapshot["rules"][0];
        assert_eq!(rule["validation"]["type"].as_str(), Some("Betterleaks"));
        assert!(rule["validation"]["content"]["source"].as_str().unwrap().contains("startsWith"));
        assert!(yaml.contains("name: filter"));
        assert!(yaml.contains("name: all"));
        assert_eq!(rule["revocation"]["type"].as_str(), Some("Betterleaks"));
        assert!(!rule["validation"]["content"]["analyze"].is_null());
        assert!(rule["revocation"]["content"]["source"].as_str().unwrap().contains("http.delete"));
        assert!(!rule["validation"]["content"]["source"].as_str().unwrap().contains("http.delete"));
    }

    #[test]
    fn imports_immutable_v2_provider_program_fixture_without_losing_stages() {
        let source = include_str!("fixtures/betterleaks-v2.toml");
        let yaml =
            import_custom_config(source, "Betterleaks 22ae2f41a70d759e83e832a6a1b205fac729223b")
                .unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rule = &snapshot["rules"][0];
        assert_eq!(rule["id"], "custom.buildkite-user-access-token");
        assert_eq!(rule["validation"]["type"], "Betterleaks");
        assert!(!rule["validation"]["content"]["analyze"].is_null());
        assert_eq!(rule["revocation"]["type"], "Betterleaks");
        assert!(yaml.contains("value: analysis") && yaml.contains("value: capabilities"));
        assert!(yaml.contains("value: revoke") && yaml.contains("value: delete"));
        assert!(!rule["betterleaks_filter"].is_null());
    }

    #[test]
    fn dangerous_revocation_helpers_are_rejected_outside_revocation() {
        for field in ["validate", "analyze"] {
            let validation = if field == "analyze" { "validate='true'\n" } else { "" };
            let source = format!(
                "[[rules]]\nid='scope-test'\nregex='token'\n{validation}{field}='http.delete(\"https://example.invalid\")'"
            );
            assert!(import_custom_config(&source, "test").is_err());
        }
    }

    #[test]
    fn retains_v2_metadata_and_path_only_rules() {
        let yaml = import_custom_config(
            r#"
minVersion = "v2.0.0-rc.1"
[[rules]]
id = "private-key-file"
path = '\.key$'
specificity = -17
tags = ["private", "key"]
"#,
            "test",
        )
        .unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rule = &snapshot["rules"][0];
        assert_eq!(rule["id"], "custom.private-key-file");
        assert_eq!(rule["specificity"].as_i64(), Some(-17));
        assert_eq!(rule["tags"][0], "private");
        assert_eq!(rule["betterleaks_path_only"].as_bool(), Some(true));
        assert_eq!(rule["pattern"], "(?:)");
    }

    #[test]
    fn excludes_filename_only_rules_from_builtins_but_preserves_custom_rules() {
        let source = r#"
[[rules]]
id = "filename-without-regex"
path = '\.key$'

[[rules]]
id = "filename-with-empty-regex"
regex = ''
path = '\.p12$'

[[rules]]
id = "content-with-path"
regex = '(specific_[a-z0-9]{16})'
path = '\.env$'

[[rules]]
id = "content-only"
regex = '(other_[a-z0-9]{16})'
"#;
        let builtins = import_config(source, "test", EMPTY_CAPABILITIES).unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&builtins).unwrap();
        let rules = snapshot["rules"].as_sequence().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "betterleaks.content-only");
        assert_eq!(rules[1]["id"], "betterleaks.content-with-path");
        assert_eq!(rules[1]["path"], r"\.env$");
        assert!(rules.iter().all(|rule| rule["betterleaks_path_only"].as_bool() != Some(true)));
        assert!(builtins.contains("Imported 2 of 4 Betterleaks rules"));

        let custom = import_custom_config(source, "test").unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&custom).unwrap();
        let rules = snapshot["rules"].as_sequence().unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(
            rules
                .iter()
                .filter(|rule| rule["betterleaks_path_only"].as_bool() == Some(true))
                .count(),
            2
        );
        assert!(rules.iter().all(|rule| rule["id"].as_str().unwrap().starts_with("custom.")));
    }

    #[test]
    fn rejects_invalid_v2_configuration_instead_of_dropping_fields() {
        for source in [
            "unknown = true\n[[rules]]\nid='x'\nregex='token'",
            "[[rules]]\nid='x'\nregex='token'\nvalidte='true'",
            "[[rules]]\nid='x'\nregex='token'\n[[rules]]\nid='x'\nregex='other'",
            "[[rules]]\nid=''\nregex='token'",
            "[[rules]]\nid='x'",
            "[[rules]]\nid='x'\npath='secret'\nvalidate='true'",
            "[[rules]]\nid='x'\nregex='token'\nanalyze='true'",
            "[[rules]]\nid='x'\nregex='token'\ncomponents=[{id='missing'}]",
            "[[rules]]\nid='x'\nregex='token'\ncomponents=[{id='x'}]",
            "minVersion='broken'\n[[rules]]\nid='x'\nregex='token'",
            "minVersion='v3.0.0'\n[[rules]]\nid='x'\nregex='token'",
            "[extend]\nurl='https://example.invalid/config.toml'",
            "[extend]\npath='base.toml'\nuseDefault=true",
        ] {
            assert!(import_custom_config(source, "invalid-test").is_err(), "{source}");
        }
    }

    #[test]
    fn extends_local_configs_with_complete_rule_replacement_and_additive_filters() {
        let unique =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir()
            .join(format!("kingfisher-betterleaks-extend-{}-{unique}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let base_path = directory.join("base.toml");
        std::fs::write(
            &base_path,
            r#"
prefilter = 'containsAny(attributes.path, ["base/"])'
filter = 'finding.secret == "base-secret"'
[[rules]]
id = "keep"
regex = 'base-token'
[[rules]]
id = "replace"
regex = 'old-token'
tags = ["old"]
[[rules]]
id = "disabled"
regex = 'disabled-token'
"#,
        )
        .unwrap();
        let path_literal = serde_json::to_string(&base_path.to_string_lossy()).unwrap();
        let child = format!(
            r#"
prefilter = 'containsAny(attributes.path, ["child/"])'
filter = 'finding.secret == "child-secret"'
[extend]
path = {path_literal}
disabledRules = ["disabled"]
[[rules]]
id = "replace"
regex = 'new-token'
"#
        );
        let yaml = import_custom_config(&child, "child").unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rules = snapshot["rules"].as_sequence().unwrap();
        assert_eq!(rules.len(), 2);
        let replacement = rules.iter().find(|rule| rule["id"] == "custom.replace").unwrap();
        assert_eq!(replacement["pattern"], "new-token");
        assert!(replacement["tags"].is_null());
        assert!(yaml.contains("base-secret") && yaml.contains("child-secret"));
        assert!(yaml.contains("base/") && yaml.contains("child/"));
        // A cycle and an overdeep inheritance chain must both fail deterministically.
        std::fs::write(&base_path, format!("[extend]\npath={path_literal}\n")).unwrap();
        assert!(
            format!("{:#}", import_custom_config(&child, "cycle").unwrap_err()).contains("cycle")
        );
        let middle_path = directory.join("middle.toml");
        let last_path = directory.join("last.toml");
        std::fs::write(&middle_path, "[[rules]]\nid='keep'\nregex='middle-token'\n").unwrap();
        std::fs::write(
            &base_path,
            format!(
                "[extend]\npath={}\n",
                serde_json::to_string(&middle_path.to_string_lossy()).unwrap()
            ),
        )
        .unwrap();
        assert!(import_custom_config(&child, "maximum-supported-depth").is_ok());
        std::fs::write(&last_path, "[[rules]]\nid='last'\nregex='last-token'\n").unwrap();
        std::fs::write(
            &middle_path,
            format!(
                "[extend]\npath={}\n",
                serde_json::to_string(&last_path.to_string_lossy()).unwrap()
            ),
        )
        .unwrap();
        assert!(
            format!("{:#}", import_custom_config(&child, "overdeep").unwrap_err())
                .contains("maximum depth of 2")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn v2_schema_errors_identify_the_invalid_field_or_rule() {
        for (source, expected) in [
            ("minVersion='future'", "invalid Betterleaks minVersion"),
            ("minVersion='v3.0.0'", "supported configuration major version is 2"),
            ("[[rules]]\nid='x'\nregex='token'\nvalidte='true'", "validte"),
            ("[[rules]]\nid='x'\nregex='token'\nrequired=[]", "required"),
            ("[[rules]]\nid='x'\nregex='token'\ncomponents=[{id='x'}]", "cannot reference itself"),
            (
                "[[rules]]\nid='x'\nregex='token'\n[[rules]]\nid='x'\nregex='other'",
                "duplicate Betterleaks rule ID",
            ),
            (
                "[[rules]]\nid='x'\nregex='token'\ncomponents=[{id='helper',within='bad'}]\n[[rules]]\nid='helper'\nregex='secret'",
                "invalid component within",
            ),
            ("[[rules]]\nid='x'\nregex='token'\nvalueGroup=-1", "valueGroup"),
        ] {
            let error = format!("{:#}", import_custom_config(source, "invalid").unwrap_err());
            assert!(error.contains(expected), "expected {expected:?} in {error}");
        }
        let blank_programs = "minVersion=''\nprefilter=' '\nfilter=''\n[[rules]]\nid='x'\nregex='token'\nvalidate=' '\nanalyze=''\nrevoke=''\nfilter=' '\n";
        assert!(import_custom_config(blank_programs, "blank-programs").is_ok());
    }

    #[test]
    fn extends_archived_defaults_without_network_or_kingfisher_overlays() {
        let yaml =
            import_custom_config("[extend]\nuseDefault=true\ndisabledRules=['github-pat']", "test")
                .unwrap();
        assert!(yaml.contains("id: custom.generic-api-key"));
        assert!(!yaml.contains("id: custom.github-pat\n"));
    }

    #[test]
    fn parser_handles_sequences_optional_chains_ranges_and_native_helpers() {
        for source in [
            "let a = 1; a; let b = 2; a + b",
            "components[\"id\"]?.captures[\"region\"] ?? \"default\"",
            "all(1..3, {# <= 3}) && 2 ** 3 == 8",
            "findLastIndex([1,2], {# == 2})",
        ] {
            let ast = parse_expression(source).unwrap();
            validate_validation_expression(&ast).unwrap();
        }
    }

    #[test]
    fn bare_preserves_flags_names_and_boundaries() {
        let generated =
            bare_pattern(r"(?i:provider)=(?P<secret>(?:pa|al)-[A-Z]{3})(?:[\s;]|$)", 1).unwrap();
        let re = regex::bytes::RegexBuilder::new(&generated).unicode(false).build().unwrap();
        for input in ["pa-ABC", "OTHER=pa-ABC", "pa-ABC # provider"] {
            assert_eq!(
                re.captures(input.as_bytes()).unwrap().name("secret").unwrap().as_bytes(),
                b"pa-ABC"
            );
        }
        for input in ["pa-abc", "PA-ABC", "xpa-ABC", "_pa-ABC", "-pa-ABC", "pa-ABCD", "pa-ABC_"] {
            assert!(!re.is_match(input.as_bytes()), "{input}");
        }
        let global = bare_pattern(r"(?i)provider=(sk-[a-f]{3})(?:[\s;]|$)", 0).unwrap();
        assert!(
            regex::bytes::RegexBuilder::new(&global)
                .unicode(false)
                .build()
                .unwrap()
                .is_match(b"SK-ABC")
        );
    }

    #[test]
    fn bare_preserves_already_bare_assertions() {
        let pattern = r"\b(token_[A-Za-z]{3})\b";
        let original = regex::bytes::Regex::new(pattern).unwrap();
        let bare = regex::bytes::RegexBuilder::new(&bare_pattern(pattern, 0).unwrap())
            .unicode(false)
            .build()
            .unwrap();
        for input in ["token_Abc", " token_Abc ", "-token_Abc", "xtoken_Abc", "token_Abcd"] {
            assert_eq!(
                original.is_match(input.as_bytes()),
                bare.is_match(input.as_bytes()),
                "{input}"
            );
        }
    }

    #[test]
    fn bare_rejects_unsupported_capture_layouts() {
        for pattern in [
            r"token_[a-z]+",
            r"(prefix)(secret)",
            r"prefix(?:(secret))?",
            r"prefix(?:(secret))+",
            r"prefix(secret)|other",
            r"prefix(a*)",
        ] {
            assert!(bare_pattern(pattern, 0).is_err(), "{pattern}");
        }
        assert!(bare_pattern(r"prefix(secret)", 2).is_err());
    }

    #[test]
    fn bare_overlay_only_changes_opted_in_patterns() {
        let source = r#"
[[rules]]
id = "example"
description = "Example"
regex = '''provider=(token_[a-z]{3})(?:\s|$)'''
secretGroup = 1
filter = '''entropy(finding["secret"]) <= 3.5'''
validate = '''{"result": "unknown"}'''
"#;
        let overlay = "version: 1\nrules:\n  example:\n    bare: true\n";
        let imported: serde_yaml::Value =
            serde_yaml::from_str(&import_config(source, "test", overlay).unwrap()).unwrap();
        let original: serde_yaml::Value =
            serde_yaml::from_str(&import_config(source, "test", EMPTY_CAPABILITIES).unwrap())
                .unwrap();
        let rule = &imported["rules"][0];
        assert!(
            regex::bytes::RegexBuilder::new(rule["pattern"].as_str().unwrap())
                .unicode(false)
                .build()
                .unwrap()
                .is_match(b"token_abc")
        );
        assert!(
            !regex::bytes::Regex::new(original["rules"][0]["pattern"].as_str().unwrap())
                .unwrap()
                .is_match(b"token_abc")
        );
        assert_eq!(rule["betterleaks_secret_group"].as_u64(), Some(1));
        for field in ["validation", "betterleaks_filter"] {
            assert_eq!(rule[field], original["rules"][0][field]);
        }
        let unsupported = source.replace("(token_[a-z]{3})", "(token_)([a-z]{3})");
        assert!(
            format!("{:#}", import_config(&unsupported, "test", overlay).unwrap_err())
                .contains("cannot apply bare to example")
        );
    }

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
        let source = r#"
[[rules]]
id = "capture-selection"
description = "Capture selection"
regex = '''(kind)-(?P<secret>[a-z]+)-([0-9]+)'''
secretGroup = 3
"#;
        for field in ["secretGroup", "valueGroup"] {
            let yaml =
                import_config(&source.replace("secretGroup", field), "test", EMPTY_CAPABILITIES)
                    .unwrap();
            assert!(yaml.contains("pattern: (kind)-(?P<secret>[a-z]+)-([0-9]+)"));
            assert!(yaml.contains("betterleaks_secret_group: 3"), "{field}");
        }
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
    fn keeps_source_prefilter_separate_and_preserves_candidate_keywords() {
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
        assert_eq!(snapshot["rules"][0]["keywords"][0], "token_");
    }

    #[test]
    fn rejects_candidate_verification_component_drift() {
        let error = import_config(
            r#"
[[rules]]
id = "composite"
description = "Composite"
regex = 'token_([a-z]+)'
validate = 'true'
"#,
            "test",
            "version: 1\nrules:\n  composite:\n    verify_candidates: [MISSING_SECRET]\n",
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing component variable MISSING_SECRET"));
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

    #[test]
    fn applies_google_api_key_access_map_handler() {
        let yaml = import_config(
            r#"
[[rules]]
id = "gcp-api-key"
description = "Google API key"
regex = '''(?P<secret>AIza[a-zA-Z0-9_-]{35})'''
validate = '''let r = http.get("https://example.test"); r.status == 200'''
"#,
            "test",
            r#"
version: 1
rules:
  gcp-api-key:
    access_map:
      handler: gcp_api_key
"#,
        )
        .unwrap();

        assert!(yaml.contains("handler: gcp_api_key"));
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
    fn private_key_structure_filter_is_explicit_and_preserves_legacy_rules() {
        let source = r#"
[[rules]]
id = "private-key"
description = "Private key"
regex = '''-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----'''
filter = '''finding.secret == "upstream placeholder"'''
"#;
        let yaml = import_config(
            source,
            "test",
            r#"
version: 1
rules:
  private-key:
    filter_override: 'malformedPrivateKey(finding["secret"])'
"#,
        )
        .unwrap();
        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let filter = serde_yaml::to_string(&snapshot["rules"][0]["betterleaks_filter"]).unwrap();
        assert!(filter.contains("malformedPrivateKey"));
        assert!(filter.contains("upstream placeholder"));
        let legacy = import_custom_config(source, "legacy.toml").unwrap();
        assert!(!legacy.contains("malformedPrivateKey"));
        assert!(legacy.contains("upstream placeholder"));
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
