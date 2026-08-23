use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

const RAW_BASE_URL: &str = "https://raw.githubusercontent.com/google/osv-scalibr";
const REGISTRY_PATH: &str = "extractor/filesystem/list/list.go";

#[derive(Debug, Deserialize)]
struct ImportConfig {
    version: u32,
    revision: String,
    rules: Vec<String>,
}

#[derive(Deserialize)]
struct CapabilityOverlay {
    version: u32,
    #[serde(default)]
    rules: BTreeMap<String, RuleCapabilities>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleCapabilities {
    revocation: Option<serde_yaml::Value>,
}

#[derive(Debug, Serialize)]
struct Snapshot {
    rules: Vec<ImportedRule>,
}

#[derive(Debug, Serialize)]
struct ImportedRule {
    name: String,
    id: String,
    pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation: Option<Validation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    depends_on_rule: Vec<DependsOnRule>,
    #[serde(skip_serializing_if = "is_true")]
    visible: bool,
    betterleaks_secret_group: usize,
    references: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DependsOnRule {
    rule_id: String,
    variable: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", content = "content")]
enum Validation {
    Http(HttpValidation),
    Raw(String),
}

#[derive(Debug, Serialize)]
struct HttpValidation {
    request: HttpRequest,
}

#[derive(Debug, Serialize)]
struct HttpRequest {
    method: String,
    url: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    response_matcher: Vec<ResponseMatcher>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ResponseMatcher {
    Status {
        #[serde(rename = "type")]
        kind: &'static str,
        status: Vec<u16>,
    },
    Word {
        #[serde(rename = "type")]
        kind: &'static str,
        words: Vec<String>,
        #[serde(skip_serializing_if = "is_false")]
        match_all_words: bool,
        #[serde(skip_serializing_if = "is_false")]
        negative: bool,
    },
    Json {
        #[serde(rename = "type")]
        kind: &'static str,
    },
}

trait SourceProvider {
    fn source(&mut self, path: &str) -> Result<String>;
}

struct DownloadSource<'a, F> {
    revision: &'a str,
    download: F,
    cache: BTreeMap<String, String>,
}

impl<'a, F> DownloadSource<'a, F>
where
    F: FnMut(&str) -> Result<String>,
{
    fn new(revision: &'a str, download: F) -> Self {
        Self { revision, download, cache: BTreeMap::new() }
    }
}

impl<F> SourceProvider for DownloadSource<'_, F>
where
    F: FnMut(&str) -> Result<String>,
{
    fn source(&mut self, path: &str) -> Result<String> {
        if let Some(contents) = self.cache.get(path) {
            return Ok(contents.clone());
        }
        let url = format!("{RAW_BASE_URL}/{}/{path}", self.revision);
        let contents = (self.download)(&url)?;
        self.cache.insert(path.to_string(), contents.clone());
        Ok(contents)
    }
}

pub fn import_config<F>(config: &str, capabilities: &str, mut download: F) -> Result<String>
where
    F: FnMut(&str) -> Result<String>,
{
    let config: ImportConfig =
        serde_yaml::from_str(config).context("invalid Veles import config")?;
    if config.version != 1 {
        bail!("unsupported Veles import config version {}", config.version);
    }
    if config.revision.len() != 40 || !config.revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("Veles revision must be a full 40-character commit hash");
    }
    if config.rules.is_empty() {
        bail!("Veles import config must select at least one rule");
    }
    let selected = config.rules.iter().collect::<BTreeSet<_>>();
    if selected.len() != config.rules.len() {
        bail!("Veles import config contains duplicate rule IDs");
    }
    let mut capability_overlay: CapabilityOverlay =
        serde_yaml::from_str(capabilities).context("invalid Veles capability overlay")?;
    if capability_overlay.version != 1 {
        bail!("unsupported Veles capability overlay version {}", capability_overlay.version);
    }
    for id in capability_overlay.rules.keys() {
        if !selected.contains(id) {
            bail!("Veles capability overlay references unselected rule {id}");
        }
    }

    let mut source = DownloadSource::new(&config.revision, &mut download);
    let registry = source.source(REGISTRY_PATH)?;
    let registry_ids = registry_rule_ids(&registry);
    let mut rules = Vec::new();
    for id in config.rules {
        if !registry_ids.contains(id.as_str()) {
            let path = filesystem_extractor_path(&id)
                .with_context(|| format!("configured Veles rule {id} is not registered"))?;
            let extractor = source.source(path)?;
            if !extractor.contains(&format!(r#"Name = "{id}""#)) {
                bail!("configured Veles rule {id} is not registered by {path}");
            }
        }
        let mut imported =
            import_rule(&id, &mut source).with_context(|| format!("import Veles rule {id}"))?;
        let capabilities = capability_overlay.rules.remove(&id).unwrap_or_default();
        let primary_id = format!("veles.{id}");
        let primary = imported
            .iter_mut()
            .find(|rule| rule.id == primary_id)
            .with_context(|| format!("Veles adapter {id} did not emit its primary rule"))?;
        primary.revocation = capabilities.revocation;
        for rule in &mut imported {
            for reference in &mut rule.references {
                *reference = reference.replace("{revision}", &config.revision);
            }
        }
        rules.extend(imported);
    }
    rules.sort_by(|left, right| left.id.cmp(&right.id));
    if !capability_overlay.rules.is_empty() {
        bail!(
            "Veles capability overlay references missing rules: {}",
            capability_overlay.rules.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }

    let yaml = serde_yaml::to_string(&Snapshot { rules })?;
    Ok(format!(
        "# Generated from pinned source {RAW_BASE_URL}/{}/; do not edit.\n\
         # Selected Veles plugin IDs are declared in data/veles-rules.yml.\n{yaml}",
        config.revision
    ))
}

fn import_rule(id: &str, source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let rules = match id {
        "secrets/bitwardenoauth2access" => import_bitwarden(source)?,
        "secrets/circleciproject" => vec![simple_http_rule(
            source,
            id,
            "CircleCI Project Token",
            "veles/secrets/circleci/detector.go",
            "circleCIProjectRe",
            "veles/secrets/circleci/validator.go",
            http(
                "GET",
                "https://circleci.com/api/v1.1/project/scalibr-validation-nonexistent-a8f3c2d9",
            )
            .header("Circle-Token", "{{ TOKEN }}")
            .valid_statuses(&[200, 404]),
        )?],
        "secrets/cloudflareapitoken" => import_cloudflare(source)?,
        "secrets/denopatorg" => vec![simple_http_rule(
            source,
            id,
            "Deno Organization Token",
            "veles/secrets/denopat/detector.go",
            "orgPatRe",
            "veles/secrets/denopat/validator.go",
            bearer_get("https://api.deno.com/organization").valid_statuses(&[200]),
        )?],
        "secrets/digitaloceanapikey" => vec![simple_http_rule(
            source,
            id,
            "DigitalOcean API Token",
            "veles/secrets/digitaloceanapikey/detector.go",
            "keyRe",
            "veles/secrets/digitaloceanapikey/validator.go",
            // Veles currently spells this endpoint with http. Do not send credentials in cleartext.
            bearer_get("https://api.digitalocean.com/v2/account").valid_statuses(&[200, 403]),
        )?],
        "secrets/discordbottoken" => context_rule(
            source,
            id,
            "Discord Bot Token",
            "veles/secrets/discordbottoken/detector.go",
            "tokenRe",
            "keywordRe",
            50,
            "veles/secrets/discordbottoken/validator.go",
            http("GET", "https://discord.com/api/v10/users/@me")
                .header("Authorization", "Bot {{ TOKEN }}")
                .valid_statuses(&[200]),
        )?,
        "secrets/dockerhubpat" => import_dockerhub(source)?,
        "secrets/gcshmackey" => import_gcs_hmac(source)?,
        "secrets/grokxaiapikey" => vec![simple_http_rule(
            source,
            id,
            "xAI API Key",
            "veles/secrets/grokxaiapikey/detector.go",
            "apiKeyRe",
            "veles/secrets/grokxaiapikey/validator.go",
            bearer_get("https://api.x.ai/v1/api-key")
                .valid_statuses(&[200])
                .word(&["\"api_key_blocked\":true", "\"api_key_disabled\":true"], false, true)
                .json(),
        )?],
        "secrets/hcpclientcredentials" => import_hcp(source)?,
        "secrets/herokuplatformkey" => import_heroku(source)?,
        "secrets/npmjsaccesstoken" => vec![simple_http_rule(
            source,
            id,
            "npm Access Token",
            "veles/secrets/npmjsaccesstoken/detector.go",
            "tokenRe",
            "veles/secrets/npmjsaccesstoken/validator.go",
            bearer_get("https://registry.npmjs.org/-/whoami").valid_statuses(&[200]),
        )?],
        "secrets/openrouter" => vec![simple_http_rule(
            source,
            id,
            "OpenRouter API Key",
            "veles/secrets/openrouter/detector.go",
            "keyRe",
            "veles/secrets/openrouter/validator.go",
            bearer_get("https://openrouter.ai/api/v1/auth/key").valid_statuses(&[200, 429]),
        )?],
        "secrets/packagistsecret" => import_packagist_secret(source)?,
        "secrets/packagistorgreadtoken" => {
            import_packagist_org(source, id, "Packagist Organization Read Token", "orgReadTokenRe")?
        }
        "secrets/packagistorgupdatetoken" => import_packagist_org(
            source,
            id,
            "Packagist Organization Update Token",
            "orgUpdateTokenRe",
        )?,
        "secrets/packagistuserupdatetoken" => import_packagist_user(source)?,
        "secrets/postmanapikey" => vec![simple_http_rule(
            source,
            id,
            "Postman API Key",
            "veles/secrets/postmanapikey/detector.go",
            "pmakRe",
            "veles/secrets/postmanapikey/validator.go",
            http("GET", "https://api.getpostman.com/me")
                .header("X-Api-Key", "{{ TOKEN }}")
                .valid_statuses(&[200]),
        )?],
        "secrets/postmancollectiontoken" => vec![simple_http_rule(
            source,
            id,
            "Postman Collection Access Token",
            "veles/secrets/postmanapikey/detector.go",
            "pmatRe",
            "veles/secrets/postmanapikey/validator.go",
            http(
                "GET",
                "https://api.postman.com/collections/aaaaaaaa-aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa?access_key={{ TOKEN | url_encode }}",
            )
            .valid_statuses(&[403])
            .word(&["\"name\":\"forbiddenError\""], false, false)
            .json(),
        )?],
        "secrets/sendgrid" => vec![simple_http_rule(
            source,
            id,
            "SendGrid API Key",
            "veles/secrets/sendgrid/detector.go",
            "keyRe",
            "veles/secrets/sendgrid/validator.go",
            bearer_get("https://api.sendgrid.com/v3/user/account").valid_statuses(&[200, 403]),
        )?],
        "secrets/slackappleveltoken" => {
            vec![slack_rule(source, id, "Slack App-Level Token", "appLevelTokenRe")?]
        }
        "secrets/slackappconfigaccesstoken" => vec![slack_rule(
            source,
            id,
            "Slack App Configuration Access Token",
            "appConfigAccessTokenRe",
        )?],
        "secrets/slackappconfigrefreshtoken" => vec![slack_rule(
            source,
            id,
            "Slack App Configuration Refresh Token",
            "appConfigRefreshTokenRe",
        )?],
        "secrets/telegrambotapitoken" => context_rule(
            source,
            id,
            "Telegram Bot API Token",
            "veles/secrets/telegrambotapitoken/detector.go",
            "tokenRe",
            "keywordRe",
            60,
            "veles/secrets/telegrambotapitoken/validator.go",
            http("POST", "https://api.telegram.org/bot{{ TOKEN }}/getMe").valid_statuses(&[200]),
        )?,
        "secrets/bitbucketcredentials" => {
            import_git_credentials(source, id, "Bitbucket Git Credentials", "bitbucket", &[200])?
        }
        "secrets/codecatalystcredentials" => import_git_credentials(
            source,
            id,
            "AWS CodeCatalyst Git Credentials",
            "codecatalyst",
            &[200],
        )?,
        "secrets/codecommitcredentials" => import_git_credentials(
            source,
            id,
            "AWS CodeCommit Git Credentials",
            "codecommit",
            &[200, 404],
        )?,
        "secrets/salesforceoauth2client" => import_salesforce_client(source)?,
        "secrets/salesforceoauth2refresh" => import_salesforce_refresh(source)?,
        other => bail!("Veles rule {other} has no supported import adapter"),
    };

    for rule in &rules {
        validate_rule(rule)?;
    }
    Ok(rules)
}

fn simple_http_rule(
    source: &mut impl SourceProvider,
    id: &str,
    name: &str,
    detector_path: &str,
    regex_name: &str,
    validator_path: &str,
    validation: HttpBuilder,
) -> Result<ImportedRule> {
    let detector = source.source(detector_path)?;
    let pattern = regex_literal(&detector, regex_name)?;
    source.source(validator_path)?;
    Ok(rule(
        id,
        name,
        format!("({pattern})"),
        Some(Validation::Http(validation.build())),
        vec![],
        source_references(&[detector_path, validator_path]),
    ))
}

#[allow(clippy::too_many_arguments)]
fn context_rule(
    source: &mut impl SourceProvider,
    id: &str,
    name: &str,
    detector_path: &str,
    token_name: &str,
    context_name: &str,
    max_distance: usize,
    validator_path: &str,
    validation: HttpBuilder,
) -> Result<Vec<ImportedRule>> {
    let detector = source.source(detector_path)?;
    let token = regex_literal(&detector, token_name)?;
    let context = regex_literal(&detector, context_name)?;
    source.source(validator_path)?;
    Ok(vec![
        rule(
            id,
            name,
            format!("({token})"),
            Some(Validation::Http(validation.build())),
            vec![dependency(&format!("veles.{id}-context"), "VELES_CONTEXT")],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            &format!("{id}-context"),
            &format!("{name} Context ({max_distance} byte Veles window)"),
            format!("({context})"),
            source_references(&[detector_path]),
        ),
    ])
}

fn import_bitwarden(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let detector_path = "veles/secrets/bitwardenoauth2access/detector.go";
    let validator_path = "veles/secrets/bitwardenoauth2access/validator.go";
    let detector = source.source(detector_path)?;
    let keyword = regex_literal(&detector, "keywordRe")?.replacen('(', "(?P<TOKEN_ID>", 1);
    let secret = regex_literal(&detector, "secretRe")?;
    source.source(validator_path)?;
    let pattern = format!(r#"(?s){keyword}.{{0,20}}?"(?P<TOKEN>[A-Za-z0-9]{{10,50}})""#);
    debug_assert_eq!(secret, r#""([A-Za-z0-9]{10,50})""#);
    let mut imported = rule(
        "secrets/bitwardenoauth2access",
        "Bitwarden OAuth2 Client Secret",
        pattern,
        Some(Validation::Http(
            http("POST", "https://identity.bitwarden.com/connect/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body("grant_type=client_credentials&scope=api&client_id=user.{{ TOKEN_ID | url_encode }}&client_secret={{ TOKEN | url_encode }}&deviceName=fireFox&twoFactorToken=0&deviceIdentifier=0&deviceType=0")
                .valid_statuses(&[200])
                .build(),
        )),
        vec![],
        source_references(&[detector_path, validator_path]),
    );
    imported.betterleaks_secret_group = 2;
    imported.path = Some("(?i)bitwarden[ _-]*cli(?:[\\/]+)data\\.json$".to_string());
    Ok(vec![imported])
}

fn import_cloudflare(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let detector_path = "veles/secrets/cloudflareapitoken/detector.go";
    let validator_path = "veles/secrets/cloudflareapitoken/validator.go";
    let detector = source.source(detector_path)?;
    let keyword = regex_literal(&detector, "keywordRe")?;
    let token = regex_literal(&detector, "tokenRe")?;
    source.source(validator_path)?;
    let imported = rule(
        "secrets/cloudflareapitoken",
        "Cloudflare API Token",
        format!("(?s){keyword}.{{0,20}}?({token})"),
        Some(Validation::Http(
            bearer_get("https://api.cloudflare.com/client/v4/zones").valid_statuses(&[200]).build(),
        )),
        vec![],
        source_references(&[detector_path, validator_path]),
    );
    Ok(vec![imported])
}

fn import_heroku(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let imported = simple_http_rule(
        source,
        "secrets/herokuplatformkey",
        "Heroku Platform Key",
        "veles/secrets/herokuplatformkey/detector.go",
        "keyRe",
        "veles/secrets/herokuplatformkey/validator.go",
        bearer_get("https://api.heroku.com/account")
            .header("Accept", "application/vnd.heroku+json; version=3")
            .valid_statuses(&[200]),
    )?;
    Ok(vec![imported])
}

fn import_dockerhub(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let detector_path = "veles/secrets/dockerhubpat/detector.go";
    let validator_path = "veles/secrets/dockerhubpat/validator.go";
    let detector = source.source(detector_path)?;
    let pat = regex_literal(&detector, "patRe")?;
    let username = regex_literal(&detector, "usernamePattern")?;
    source.source(validator_path)?;
    Ok(vec![
        rule(
            "secrets/dockerhubpat",
            "Docker Hub Personal Access Token",
            format!("({pat})"),
            Some(Validation::Http(
                http("POST", "https://hub.docker.com/v2/auth/token/")
                    .header("Content-Type", "application/json")
                    .body("{\"identifier\":{{ DOCKER_USERNAME | json_escape }},\"secret\":{{ TOKEN | json_escape }}}")
                    .valid_statuses(&[200])
                    .build(),
            )),
            vec![dependency("veles.secrets/dockerhubpat-username", "DOCKER_USERNAME")],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            "secrets/dockerhubpat-username",
            "Docker Hub Username",
            username,
            source_references(&[detector_path]),
        ),
    ])
}

fn import_gcs_hmac(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let detector_path = "veles/secrets/gcshmackey/detector.go";
    let validator_path = "veles/secrets/gcshmackey/validator.go";
    let detector = source.source(detector_path)?;
    let access_id = regex_literal(&detector, "accessIDPattern")?;
    let secret = regex_literal(&detector, "secretPattern")?;
    source.source(validator_path)?;
    Ok(vec![
        rule(
            "secrets/gcshmackey",
            "Google Cloud Storage HMAC Key",
            format!("({secret})"),
            Some(Validation::Raw("gcs_hmac".to_string())),
            vec![dependency("veles.secrets/gcshmackey-access-id", "GCS_ACCESS_ID")],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            "secrets/gcshmackey-access-id",
            "Google Cloud Storage HMAC Access ID",
            format!("({access_id})"),
            source_references(&[detector_path]),
        ),
    ])
}

fn import_hcp(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let detector_path = "veles/secrets/hcp/detector.go";
    let validator_path = "veles/secrets/hcp/validator.go";
    let detector = source.source(detector_path)?;
    let client_id = regex_literal(&detector, "reClientID")?;
    let secret = regex_literal(&detector, "reClientSec")?;
    source.source(validator_path)?;
    Ok(vec![
        rule(
            "secrets/hcpclientcredentials",
            "HashiCorp Cloud Platform Client Secret",
            secret,
            Some(Validation::Http(
                http("POST", "https://auth.idp.hashicorp.com/oauth2/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body("client_id={{ HCP_CLIENT_ID | url_encode }}&client_secret={{ TOKEN | url_encode }}&grant_type=client_credentials")
                    .valid_statuses(&[200])
                    .build(),
            )),
            vec![dependency("veles.secrets/hcpclientcredentials-client-id", "HCP_CLIENT_ID")],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            "secrets/hcpclientcredentials-client-id",
            "HashiCorp Cloud Platform Client ID",
            client_id,
            source_references(&[detector_path]),
        ),
    ])
}

fn import_packagist_secret(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let detector_path = "veles/secrets/packagist/detector.go";
    let validator_path = "veles/secrets/packagist/validator.go";
    let detector = source.source(detector_path)?;
    let api_key = regex_literal(&detector, "apiKeyRe")?;
    let api_secret = regex_literal(&detector, "apiSecretRe")?;
    source.source(validator_path)?;
    Ok(vec![
        rule(
            "secrets/packagistsecret",
            "Packagist API Secret",
            format!("({api_secret})"),
            Some(Validation::Http(
                http("GET", "https://packagist.com/api/packages/")
                    .header("Accept", "application/json")
                    .header(
                        "Authorization",
                        r#"{%- assign ts = "" | unix_timestamp -%}
{%- assign cnonce = "" | uuid -%}
{%- assign enc_cnonce = cnonce | url_encode -%}
{%- assign enc_key = PACKAGIST_KEY | url_encode -%}
{%- assign enc_ts = ts | url_encode -%}
{%- assign params = "cnonce=" | append: enc_cnonce | append: "&key=" | append: enc_key | append: "&timestamp=" | append: enc_ts -%}
{%- capture to_sign -%}GET
packagist.com
/api/packages/
{{ params }}{%- endcapture -%}
{%- assign sig = to_sign | hmac_sha256: TOKEN -%}
PACKAGIST-HMAC-SHA256 Key={{ PACKAGIST_KEY }}, Timestamp={{ ts }}, Cnonce={{ cnonce }}, Signature={{ sig }}"#,
                    )
                    .valid_statuses(&[200])
                    .json()
                    .build(),
            )),
            vec![dependency("veles.secrets/packagistsecret-api-key", "PACKAGIST_KEY")],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            "secrets/packagistsecret-api-key",
            "Packagist API Key",
            format!("({api_key})"),
            source_references(&[detector_path]),
        ),
    ])
}

fn import_packagist_org(
    source: &mut impl SourceProvider,
    id: &str,
    name: &str,
    token_name: &str,
) -> Result<Vec<ImportedRule>> {
    let detector_path = "veles/secrets/packagist/detector.go";
    let validator_path = "veles/secrets/packagist/validator.go";
    let detector = source.source(detector_path)?;
    let token = regex_literal(&detector, token_name)?;
    let repo = regex_literal(&detector, "repoURLRe")?;
    source.source(validator_path)?;
    let repo_id = format!("{id}-repository");
    Ok(vec![
        rule(
            id,
            name,
            format!("({token})"),
            Some(Validation::Http(
                http("GET", "{{ REPO_URL }}/packages.json")
                    .header("Accept", "application/json")
                    .header("Authorization", "Basic {{ 'token:' | append: TOKEN | b64enc }}")
                    .valid_statuses(&[200])
                    .json()
                    .build(),
            )),
            vec![dependency(&format!("veles.{repo_id}"), "REPO_URL")],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            &repo_id,
            &format!("{name} Repository URL"),
            format!("({repo})"),
            source_references(&[detector_path]),
        ),
    ])
}

fn import_packagist_user(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let id = "secrets/packagistuserupdatetoken";
    let detector_path = "veles/secrets/packagist/detector.go";
    let validator_path = "veles/secrets/packagist/validator.go";
    let detector = source.source(detector_path)?;
    let token = regex_literal(&detector, "userUpdateTokenRe")?;
    let username = regex_literal(&detector, "usernameRe")?;
    let repo = regex_literal(&detector, "repoURLRe")?;
    source.source(validator_path)?;
    Ok(vec![
        rule(
            id,
            "Packagist User Update Token",
            format!("({token})"),
            Some(Validation::Http(
                http("GET", "{{ REPO_URL }}/packages.json")
                    .header("Accept", "application/json")
                    .header(
                        "Authorization",
                        "Basic {{ PACKAGIST_USERNAME | append: ':' | append: TOKEN | b64enc }}",
                    )
                    .valid_statuses(&[200])
                    .json()
                    .build(),
            )),
            vec![
                dependency(&format!("veles.{id}-repository"), "REPO_URL"),
                dependency(&format!("veles.{id}-username"), "PACKAGIST_USERNAME"),
            ],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            &format!("{id}-repository"),
            "Packagist Repository URL",
            format!("({repo})"),
            source_references(&[detector_path]),
        ),
        helper_rule(
            &format!("{id}-username"),
            "Packagist Username",
            username,
            source_references(&[detector_path]),
        ),
    ])
}

fn slack_rule(
    source: &mut impl SourceProvider,
    id: &str,
    name: &str,
    regex_name: &str,
) -> Result<ImportedRule> {
    simple_http_rule(
        source,
        id,
        name,
        "veles/secrets/slacktoken/detector.go",
        regex_name,
        "veles/secrets/slacktoken/validator.go",
        http("POST", "https://slack.com/api/auth.test")
            .header("Authorization", "Bearer {{ TOKEN }}")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .word(&["\"ok\":true"], false, false)
            .json(),
    )
}

fn import_git_credentials(
    source: &mut impl SourceProvider,
    id: &str,
    name: &str,
    package: &str,
    valid_statuses: &[u16],
) -> Result<Vec<ImportedRule>> {
    let detector_path = format!("veles/secrets/gitbasicauth/{package}/detector.go");
    let validator_path = format!("veles/secrets/gitbasicauth/{package}/validator.go");
    let detector = source.source(&detector_path)?;
    let url = regex_literal(&detector, "urlPattern")?;
    let captures = url.replacen(
        r"https://[^:\s]+:[^\s@]+@",
        r"https://(?P<GIT_USERNAME>[^:\s]+):(?P<GIT_PASSWORD>[^\s@]+)@",
        1,
    );
    source.source(&validator_path)?;

    // Keep the whole credential-bearing URL as TOKEN for Veles parity, while named captures make
    // Basic authentication explicit because reqwest does not infer it from URL userinfo.
    let mut imported = rule(
        id,
        name,
        format!("(?P<TOKEN>{captures})"),
        Some(Validation::Http(
            http("GET", &git_validation_url(package))
                .header(
                    "Authorization",
                    "Basic {{ GIT_USERNAME | append: ':' | append: GIT_PASSWORD | b64enc }}",
                )
                .valid_statuses(valid_statuses)
                .build(),
        )),
        vec![],
        source_references(&[&detector_path, &validator_path]),
    );
    imported.path =
        Some(r"(?i)(?:\.git[/\\]config|(?:^|[/\\])\.git-credentials|_history)$".to_string());
    Ok(vec![imported])
}

fn git_validation_url(package: &str) -> String {
    match package {
        "bitbucket" => {
            "https://bitbucket.org/{{ TOKEN | split: '@bitbucket.org/' | last }}/info/refs?service=git-upload-pack".to_string()
        }
        "codecommit" => {
            "https://git-codecommit.{{ TOKEN | split: '@git-codecommit.' | last }}/info/refs?service=git-upload-pack".to_string()
        }
        "codecatalyst" => {
            "https://git.{{ TOKEN | split: '@git.' | last }}/info/refs?service=git-upload-pack".to_string()
        }
        _ => unreachable!("adapter only calls known Git credential packages"),
    }
}

fn import_salesforce_client(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let id = "secrets/salesforceoauth2client";
    let detector_path = "veles/secrets/salesforceoauth2client/detector.go";
    let validator_path = "veles/secrets/salesforceoauth2client/validator.go";
    let detector = source.source(detector_path)?;
    let client_id = regex_literal(&detector, "clientIDRe")?;
    let secret = regex_literal(&detector, "clientSecretRe")?;
    let instance = regex_literal(&detector, "instanceURLRe")?;
    source.source(validator_path)?;
    Ok(vec![
        rule(
            id,
            "Salesforce OAuth2 Client Secret",
            secret,
            Some(Validation::Http(
                http("POST", "https://{{ SALESFORCE_INSTANCE }}/services/oauth2/token")
                    .header(
                        "Authorization",
                        "Basic {{ SALESFORCE_CLIENT_ID | append: ':' | append: TOKEN | b64enc }}",
                    )
                    .body("grant_type=client_credentials")
                    .valid_statuses(&[200])
                    .build(),
            )),
            vec![
                dependency(&format!("veles.{id}-client-id"), "SALESFORCE_CLIENT_ID"),
                dependency(&format!("veles.{id}-instance"), "SALESFORCE_INSTANCE"),
            ],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            &format!("{id}-client-id"),
            "Salesforce OAuth2 Client ID",
            format!("({client_id})"),
            source_references(&[detector_path]),
        ),
        helper_rule(
            &format!("{id}-instance"),
            "Salesforce Instance",
            format!("({instance})"),
            source_references(&[detector_path]),
        ),
    ])
}

fn import_salesforce_refresh(source: &mut impl SourceProvider) -> Result<Vec<ImportedRule>> {
    let id = "secrets/salesforceoauth2refresh";
    let detector_path = "veles/secrets/salesforceoauth2refresh/detector.go";
    let validator_path = "veles/secrets/salesforceoauth2refresh/validator.go";
    let detector = source.source(detector_path)?;
    let client_id = regex_literal(&detector, "clientIDRe")?;
    let secret = regex_literal(&detector, "clientSecretRe")?;
    let refresh = regex_literal(&detector, "refreshRe")?;
    source.source(validator_path)?;
    Ok(vec![
        rule(
            id,
            "Salesforce OAuth2 Refresh Token",
            refresh,
            Some(Validation::Http(
                http("POST", "https://login.salesforce.com/services/oauth2/token")
                    .header(
                        "Authorization",
                        "Basic {{ SALESFORCE_CLIENT_ID | append: ':' | append: SALESFORCE_CLIENT_SECRET | b64enc }}",
                    )
                    .body("refresh_token={{ TOKEN }}")
                    .valid_statuses(&[200])
                    .build(),
            )),
            vec![
                dependency(&format!("veles.{id}-client-id"), "SALESFORCE_CLIENT_ID"),
                dependency(
                    &format!("veles.{id}-client-secret"),
                    "SALESFORCE_CLIENT_SECRET",
                ),
            ],
            source_references(&[detector_path, validator_path]),
        ),
        helper_rule(
            &format!("{id}-client-id"),
            "Salesforce OAuth2 Client ID",
            format!("({client_id})"),
            source_references(&[detector_path]),
        ),
        helper_rule(
            &format!("{id}-client-secret"),
            "Salesforce OAuth2 Client Secret",
            secret,
            source_references(&[detector_path]),
        ),
    ])
}

fn rule(
    id: &str,
    name: &str,
    pattern: String,
    validation: Option<Validation>,
    depends_on_rule: Vec<DependsOnRule>,
    references: Vec<String>,
) -> ImportedRule {
    ImportedRule {
        name: name.to_string(),
        id: format!("veles.{id}"),
        pattern,
        path: None,
        validation,
        revocation: None,
        depends_on_rule,
        visible: true,
        betterleaks_secret_group: 0,
        references,
    }
}

fn helper_rule(id: &str, name: &str, pattern: String, references: Vec<String>) -> ImportedRule {
    let mut imported = rule(id, name, pattern, None, vec![], references);
    imported.visible = false;
    imported
}

fn dependency(rule_id: &str, variable: &str) -> DependsOnRule {
    DependsOnRule { rule_id: rule_id.to_string(), variable: variable.to_string() }
}

fn source_references(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|path| format!("{RAW_BASE_URL}/{{revision}}/{path}")).collect()
}

fn validate_rule(rule: &ImportedRule) -> Result<()> {
    let compiled = regex::bytes::RegexBuilder::new(&rule.pattern)
        .unicode(false)
        .size_limit(16 * 1024 * 1024)
        .build()
        .with_context(|| format!("Veles rule {} is not Rust-regex compatible", rule.id))?;
    if compiled.captures_len() < 2 {
        bail!("Veles rule {} must capture the reported secret", rule.id);
    }
    if let Some(path) = rule.path.as_deref() {
        Regex::new(path).with_context(|| format!("invalid path regex on {}", rule.id))?;
    }
    Ok(())
}

fn registry_rule_ids(contents: &str) -> BTreeSet<String> {
    let re = Regex::new(r#"\"(secrets/[a-z0-9]+)\""#).expect("static registry regex compiles");
    re.captures_iter(contents).map(|capture| capture[1].to_string()).collect()
}

fn filesystem_extractor_path(id: &str) -> Option<&'static str> {
    Some(match id {
        "secrets/bitbucketcredentials" => {
            "extractor/filesystem/secrets/gitbasicauth/bitbucket/bitbucket.go"
        }
        "secrets/bitwardenoauth2access" => {
            "extractor/filesystem/secrets/bitwardenoauth2access/bitwardenoauth2access.go"
        }
        "secrets/cloudflareapitoken" => {
            "extractor/filesystem/secrets/cloudflareapitoken/cloudflareapitoken.go"
        }
        "secrets/codecatalystcredentials" => {
            "extractor/filesystem/secrets/gitbasicauth/codecatalyst/codecatalyst.go"
        }
        "secrets/codecommitcredentials" => {
            "extractor/filesystem/secrets/gitbasicauth/codecommit/codecommit.go"
        }
        _ => return None,
    })
}

fn regex_literal(contents: &str, name: &str) -> Result<String> {
    let escaped = regex::escape(name);
    let assignment = Regex::new(&format!(
        r#"(?s)(?:var\s+{escaped}|{escaped}\s*=).*?regexp\.MustCompile\(\s*`([^`]*)`\s*,?\s*\)"#
    ))?;
    assignment
        .captures(contents)
        .map(|capture| capture[1].to_string())
        .with_context(|| format!("could not extract regexp {name}"))
}

#[derive(Default)]
struct HttpBuilder {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    matchers: Vec<ResponseMatcher>,
}

impl HttpBuilder {
    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    fn body(mut self, body: &str) -> Self {
        self.body = Some(body.to_string());
        self
    }

    fn valid_statuses(mut self, statuses: &[u16]) -> Self {
        self.matchers
            .push(ResponseMatcher::Status { kind: "StatusMatch", status: statuses.to_vec() });
        self
    }

    fn word(mut self, words: &[&str], all: bool, negative: bool) -> Self {
        self.matchers.push(ResponseMatcher::Word {
            kind: "WordMatch",
            words: words.iter().map(|word| (*word).to_string()).collect(),
            match_all_words: all,
            negative,
        });
        self
    }

    fn json(mut self) -> Self {
        self.matchers.push(ResponseMatcher::Json { kind: "JsonValid" });
        self
    }

    fn build(self) -> HttpValidation {
        HttpValidation {
            request: HttpRequest {
                method: self.method,
                url: self.url,
                headers: self.headers,
                body: self.body,
                response_matcher: self.matchers,
            },
        }
    }
}

fn http(method: &str, url: &str) -> HttpBuilder {
    HttpBuilder { method: method.to_string(), url: url.to_string(), ..Default::default() }
}

fn bearer_get(url: &str) -> HttpBuilder {
    http("GET", url).header("Authorization", "Bearer {{ TOKEN }}")
}

fn is_true(value: &bool) -> bool {
    *value
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureSource(BTreeMap<String, String>);

    impl SourceProvider for FixtureSource {
        fn source(&mut self, path: &str) -> Result<String> {
            self.0.get(path).cloned().with_context(|| format!("missing fixture {path}"))
        }
    }

    #[test]
    fn extracts_go_regexp_literals() {
        let contents = r#"var keyRe = regexp.MustCompile(`token_[A-Za-z0-9]{20}`)"#;
        assert_eq!(regex_literal(contents, "keyRe").unwrap(), "token_[A-Za-z0-9]{20}");
    }

    #[test]
    fn imports_a_simple_http_rule_from_source() {
        let mut source = FixtureSource(BTreeMap::from([
            (
                "veles/secrets/npmjsaccesstoken/detector.go".to_string(),
                "var tokenRe = regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)".to_string(),
            ),
            ("veles/secrets/npmjsaccesstoken/validator.go".to_string(), "validator".to_string()),
        ]));
        let rule = import_rule("secrets/npmjsaccesstoken", &mut source).unwrap().remove(0);
        assert_eq!(rule.id, "veles.secrets/npmjsaccesstoken");
        assert_eq!(rule.name, "npm Access Token");
        assert_eq!(rule.pattern, "(npm_[a-zA-Z0-9]{36})");
        assert!(matches!(rule.validation, Some(Validation::Http(_))));
    }

    #[test]
    fn config_pins_and_selects_registered_rules() {
        let registry = r#"{npmjsaccesstoken.NewDetector(), "secrets/npmjsaccesstoken", 0}"#;
        let mut sources = BTreeMap::from([
            (REGISTRY_PATH.to_string(), registry.to_string()),
            (
                "veles/secrets/npmjsaccesstoken/detector.go".to_string(),
                "var tokenRe = regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)".to_string(),
            ),
            ("veles/secrets/npmjsaccesstoken/validator.go".to_string(), "validator".to_string()),
        ]);
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let yaml = import_config(
            &format!("version: 1\nrevision: {revision}\nrules:\n  - secrets/npmjsaccesstoken\n"),
            "version: 1\nrules: {}\n",
            |url| {
                let path = url
                    .strip_prefix(&format!("{RAW_BASE_URL}/{revision}/"))
                    .context("unexpected source URL")?;
                sources.remove(path).with_context(|| format!("missing source {path}"))
            },
        )
        .unwrap();

        assert!(yaml.contains("id: veles.secrets/npmjsaccesstoken"));
        assert!(yaml.contains(revision));
    }

    #[test]
    fn validates_filesystem_extractor_name_constants() {
        let id = "secrets/cloudflareapitoken";
        let extractor_path = filesystem_extractor_path(id).unwrap();
        let mut sources = BTreeMap::from([
            (REGISTRY_PATH.to_string(), "SecretExtractors = InitMap{}".to_string()),
            (extractor_path.to_string(), format!(r#"const Name = "{id}""#)),
            (
                "veles/secrets/cloudflareapitoken/detector.go".to_string(),
                r#"var (
keywordRe = regexp.MustCompile(`(?i)CF_API_TOKEN\s*=`)
tokenRe = regexp.MustCompile(`\b[A-Za-z0-9_-]{40}\b`)
)"#
                .to_string(),
            ),
            ("veles/secrets/cloudflareapitoken/validator.go".to_string(), "validator".to_string()),
        ]);
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let yaml = import_config(
            &format!("version: 1\nrevision: {revision}\nrules:\n  - {id}\n"),
            r#"
version: 1
rules:
  secrets/cloudflareapitoken:
    revocation:
      type: HttpMultiStep
      content:
        steps: []
"#,
            |url| {
                let path = url
                    .strip_prefix(&format!("{RAW_BASE_URL}/{revision}/"))
                    .context("unexpected source URL")?;
                sources.remove(path).with_context(|| format!("missing source {path}"))
            },
        )
        .unwrap();
        assert!(yaml.contains("revocation:"));
        assert!(yaml.contains("type: HttpMultiStep"));
    }

    #[test]
    fn imports_operational_replacement_adapters() {
        struct Adapter {
            id: &'static str,
            detector_path: &'static str,
            detector: &'static str,
            validator_path: &'static str,
        }

        let adapters = [
            Adapter {
                id: "secrets/npmjsaccesstoken",
                detector_path: "veles/secrets/npmjsaccesstoken/detector.go",
                detector: "var tokenRe = regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)",
                validator_path: "veles/secrets/npmjsaccesstoken/validator.go",
            },
            Adapter {
                id: "secrets/openrouter",
                detector_path: "veles/secrets/openrouter/detector.go",
                detector: "var keyRe = regexp.MustCompile(`sk-or-v[0-9]+-[A-Za-z0-9_-]{20,}`)",
                validator_path: "veles/secrets/openrouter/validator.go",
            },
            Adapter {
                id: "secrets/postmanapikey",
                detector_path: "veles/secrets/postmanapikey/detector.go",
                detector: "var pmakRe = regexp.MustCompile(`PMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}`)",
                validator_path: "veles/secrets/postmanapikey/validator.go",
            },
            Adapter {
                id: "secrets/postmancollectiontoken",
                detector_path: "veles/secrets/postmanapikey/detector.go",
                detector: "var pmatRe = regexp.MustCompile(`PMAT-[A-Za-z0-9]{26}`)",
                validator_path: "veles/secrets/postmanapikey/validator.go",
            },
            Adapter {
                id: "secrets/sendgrid",
                detector_path: "veles/secrets/sendgrid/detector.go",
                detector: "var keyRe = regexp.MustCompile(`SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}`)",
                validator_path: "veles/secrets/sendgrid/validator.go",
            },
        ];

        for adapter in adapters {
            let mut source = FixtureSource(BTreeMap::from([
                (adapter.detector_path.to_string(), adapter.detector.to_string()),
                (adapter.validator_path.to_string(), "validator".to_string()),
            ]));
            let rule = import_rule(adapter.id, &mut source).unwrap().remove(0);
            assert_eq!(rule.id, format!("veles.{}", adapter.id));
            assert!(rule.visible);
            assert!(matches!(rule.validation, Some(Validation::Http(_))));
        }
    }

    #[test]
    fn transfers_direct_revocation_to_the_visible_adapter() {
        let registry = r#"{npmjsaccesstoken.NewDetector(), "secrets/npmjsaccesstoken", 0}"#;
        let mut sources = BTreeMap::from([
            (REGISTRY_PATH.to_string(), registry.to_string()),
            (
                "veles/secrets/npmjsaccesstoken/detector.go".to_string(),
                "var tokenRe = regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)".to_string(),
            ),
            ("veles/secrets/npmjsaccesstoken/validator.go".to_string(), "validator".to_string()),
        ]);
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let yaml = import_config(
            &format!("version: 1\nrevision: {revision}\nrules:\n  - secrets/npmjsaccesstoken\n"),
            r#"
version: 1
rules:
  secrets/npmjsaccesstoken:
    revocation:
      type: HttpMultiStep
      content:
        steps: []
"#,
            |url| {
                let path = url
                    .strip_prefix(&format!("{RAW_BASE_URL}/{revision}/"))
                    .context("unexpected source URL")?;
                sources.remove(path).with_context(|| format!("missing source {path}"))
            },
        )
        .unwrap();

        let snapshot: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rule = &snapshot["rules"][0];
        assert_eq!(rule["id"], "veles.secrets/npmjsaccesstoken");
        assert!(rule["visible"].as_bool().unwrap_or(true));
        assert_eq!(rule["revocation"]["type"], "HttpMultiStep");
    }

    #[test]
    fn xai_adapter_requires_a_successful_json_response() {
        let mut source = FixtureSource(BTreeMap::from([
            (
                "veles/secrets/grokxaiapikey/detector.go".to_string(),
                "var apiKeyRe = regexp.MustCompile(`xai-[A-Za-z0-9]{80}`)".to_string(),
            ),
            ("veles/secrets/grokxaiapikey/validator.go".to_string(), "validator".to_string()),
        ]));
        let rule = import_rule("secrets/grokxaiapikey", &mut source).unwrap().remove(0);
        let Some(Validation::Http(validation)) = rule.validation else {
            panic!("xAI adapter should use HTTP validation");
        };
        assert!(matches!(
            validation.request.response_matcher.first(),
            Some(ResponseMatcher::Status { status, .. }) if status == &[200]
        ));
    }

    #[test]
    fn rejects_an_unadapted_registered_rule() {
        let mut source = FixtureSource(BTreeMap::new());
        let error = import_rule("secrets/unsupported", &mut source).unwrap_err();
        assert!(error.to_string().contains("no supported import adapter"));
    }

    #[test]
    fn rejects_capabilities_for_unselected_rules() {
        let error = import_config(
            "version: 1\nrevision: 0123456789abcdef0123456789abcdef01234567\nrules:\n  - secrets/npmjsaccesstoken\n",
            "version: 1\nrules:\n  secrets/cloudflareapitoken:\n    revocation: { type: Http }\n",
            |_| bail!("source download should not start"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("references unselected rule"));
    }
}
