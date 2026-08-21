//! Betterleaks- and Veles-derived default rules embedded in the kingfisher-rules crate.

use std::{io::Read, path::PathBuf, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;

use crate::rule::Confidence;
use crate::rules::Rules;

const BUNDLE_MAGIC: &[u8] = b"KFRULES\x01";
const DEFAULT_RULE_BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/builtin-rules.gz"));
type BuiltinRuleFiles = Vec<(PathBuf, Vec<u8>)>;
type CachedBuiltinRuleFiles = Result<BuiltinRuleFiles, String>;

static BUILTIN_RULE_FILES: OnceLock<CachedBuiltinRuleFiles> = OnceLock::new();

/// Return the generated snapshot entries containing the embedded built-in rules.
///
/// The returned paths are relative to the bundled rules directory.
pub fn get_builtin_rule_files() -> Result<Vec<(PathBuf, Vec<u8>)>> {
    Ok(builtin_rule_files()?.to_vec())
}

fn builtin_rule_files() -> Result<&'static [(PathBuf, Vec<u8>)]> {
    BUILTIN_RULE_FILES
        .get_or_init(|| load_rule_files(DEFAULT_RULE_BUNDLE).map_err(|err| format!("{err:#}")))
        .as_deref()
        .map_err(|err| anyhow!("failed to load embedded builtin rules: {err}"))
}

/// Compatibility alias for [`get_builtin_rule_files`].
pub fn get_betterleaks_rule_files() -> Result<Vec<(PathBuf, Vec<u8>)>> {
    get_builtin_rule_files()
}

fn load_rule_files(bundle: &[u8]) -> Result<BuiltinRuleFiles> {
    let mut decoded = Vec::new();
    GzDecoder::new(bundle)
        .read_to_end(&mut decoded)
        .context("failed to decompress embedded rule bundle")?;

    let mut cursor = BundleCursor::new(&decoded);
    if cursor.take(BUNDLE_MAGIC.len())? != BUNDLE_MAGIC {
        bail!("embedded rule bundle has an invalid header");
    }

    let mut files = Vec::new();
    loop {
        let path_len = usize::try_from(cursor.u32()?)
            .map_err(|_| anyhow!("embedded rule path length exceeds platform limits"))?;
        if path_len == 0 {
            break;
        }
        let contents_len = usize::try_from(cursor.u64()?)
            .map_err(|_| anyhow!("embedded rule contents length exceeds platform limits"))?;
        let path = std::str::from_utf8(cursor.take(path_len)?)
            .context("embedded rule bundle contains a non-UTF-8 path")?;
        files.push((PathBuf::from(path), cursor.take(contents_len)?.to_vec()));
    }
    if !cursor.is_empty() {
        bail!("embedded rule bundle has trailing data");
    }
    Ok(files)
}

/// Load Kingfisher's built-in Betterleaks and Veles rules.
///
/// This loads all rules that meet or exceed the given confidence level.
/// If no confidence is specified, defaults to `Confidence::Medium`.
pub fn get_builtin_rules(confidence: Option<Confidence>) -> Result<Rules> {
    let confidence = confidence.unwrap_or(Confidence::Medium);
    let files = builtin_rule_files()?;
    Rules::from_paths_and_contents(
        files.iter().map(|(path, contents)| (path.as_path(), contents.as_slice())),
        confidence,
    )
}

/// Compatibility alias for [`get_builtin_rules`].
pub fn get_betterleaks_rules(confidence: Option<Confidence>) -> Result<Rules> {
    get_builtin_rules(confidence)
}

struct BundleCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> BundleCursor<'a> {
    fn new(contents: &'a [u8]) -> Self {
        Self { remaining: contents }
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if self.remaining.len() < length {
            bail!("embedded rule bundle is truncated");
        }
        let (result, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(result)
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("slice length is checked");
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("slice length is checked");
        Ok(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        BetterleaksAccessMapHandler, EthereumValidation, Revocation, TlsMode, Validation,
        betterleaks_filter::{BetterleaksFilterContext, evaluate_filter},
    };

    fn filter_discards(
        rule: &crate::RuleSyntax,
        path: &str,
        secret: &str,
        full_match: &str,
        captures: &[(&str, &str)],
    ) -> bool {
        evaluate_filter(
            rule.betterleaks_filter.as_ref().expect("rule should have a filter"),
            &BetterleaksFilterContext {
                path,
                secret,
                full_match,
                line: full_match,
                fragment_raw: full_match,
                match_start_idx: 0,
                match_end_idx: full_match.len(),
                match_line_start_idx: 0,
                match_line_end_idx: full_match.len(),
                rule_id: &rule.id,
                description: &rule.name,
                captures: captures
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                    .collect(),
            },
        )
        .unwrap()
        .discard
    }

    #[test]
    fn test_get_default_rules() {
        assert!(get_builtin_rules(None).unwrap().num_rules() >= 400);
    }

    #[test]
    fn bundled_rule_files_are_sorted_and_complete() {
        let files = get_builtin_rule_files().unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    }

    #[test]
    fn builtin_rule_files_are_cached() {
        assert!(std::ptr::eq(builtin_rule_files().unwrap(), builtin_rule_files().unwrap()));
    }

    #[test]
    fn default_rules_are_namespaced_upstream_rules() {
        let rules = get_builtin_rules(Some(Confidence::Low)).unwrap();

        assert!(rules.num_rules() >= 400);
        // `kingfisher.` is permitted because the 1.x catalog is still loadable via
        // `--rules-path`, and callers may merge it with the built-ins. The built-in
        // bundle itself only ships `betterleaks.`/`veles.` rules today.
        assert!(rules.rules.keys().all(|id| {
            id.starts_with("betterleaks.")
                || id.starts_with("veles.")
                || id.starts_with("kingfisher.")
        }));
        for rule in rules.rules.values() {
            for dependency in rule.depends_on_rule.iter().flatten() {
                assert!(
                    rules.rules.contains_key(&dependency.rule_id),
                    "{} depends on missing Betterleaks rule {}",
                    rule.id,
                    dependency.rule_id
                );
            }
        }

        let app_config = rules
            .rules
            .get("betterleaks.azure-app-configuration-connection-string")
            .expect("generated Betterleaks rule should exist");
        let regex = app_config.as_regex().unwrap();
        let captures = regex
            .captures(
                b"Endpoint=https://demo.azconfig.io;Id=abcde;Secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            )
            .expect("generated Betterleaks rule should match");
        assert_eq!(
            captures.get(app_config.betterleaks_secret_group.unwrap()).unwrap().as_bytes(),
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        );

        assert!(rules.betterleaks_prefilter.is_some());
        let aws = rules.rules.get("betterleaks.aws-access-token").unwrap();
        assert!(matches!(aws.revocation, Some(Revocation::AWS)));
        let Some(Validation::Betterleaks(aws_validation)) = &aws.validation else {
            panic!("AWS should use Betterleaks validation");
        };
        assert_eq!(
            aws_validation.capabilities.access_map.as_ref().unwrap().handler,
            BetterleaksAccessMapHandler::Aws
        );
        let bindings = aws_validation.capabilities.revocation_bindings.as_ref().unwrap();
        assert_eq!(bindings.secret, "components.aws-secret-access-key");
        assert_eq!(bindings.variables["AKID"], "finding.secret");

        let gcp = rules.rules.get("betterleaks.gcp-service-account").unwrap();
        assert!(matches!(gcp.revocation, Some(Revocation::GCP)));

        for id in ["generic-api-key", "generic-password", "generic-username"] {
            assert!(!rules.rules.contains_key(&format!("betterleaks.{id}")), "unexpected {id}");
        }

        let mongodb = rules.rules.get("betterleaks.mongodb-connection-string").unwrap();
        assert!(matches!(mongodb.validation, Some(Validation::MongoDB)));
        // Self-managed / RDS-style clusters commonly present private-CA certs.
        // Only honored when the operator also passes `--tls-mode lax`.
        assert_eq!(mongodb.tls_mode, Some(TlsMode::Lax));

        let jwt = rules.rules.get("betterleaks.jwt").unwrap();
        assert!(matches!(jwt.validation, Some(Validation::JWT)));
        // Self-hosted IdPs commonly serve JWKS from a private CA.
        assert_eq!(jwt.tls_mode, Some(TlsMode::Lax));

        let private_key = rules.rules.get("betterleaks.private-key").unwrap();
        assert!(matches!(private_key.validation, Some(Validation::Assumed)));

        let polymarket = rules.rules.get("betterleaks.polymarket-private-key").unwrap();
        assert!(matches!(
            polymarket.validation,
            Some(Validation::Ethereum(EthereumValidation::PrivateKey))
        ));

        for id in [
            "generic-credential-uri",
            "gitlab-incoming-mail-address-token",
            "circleci-project-token",
            "cloudflare-api-key",
            "digitalocean-pat",
            "heroku-api-key-v2",
            "npm-access-token",
            "openrouter-api-key",
            "postman-api-token",
            "pypi-upload-token",
            "sendgrid-api-token",
            "slack-app-token",
            "slack-config-access-token",
            "slack-config-refresh-token",
            "xai-api-key",
        ] {
            assert!(rules.rules.contains_key(&format!("betterleaks.{id}")), "missing {id}");
        }

        let hcp = rules.rules.get("veles.secrets/hcpclientcredentials").unwrap();
        assert!(matches!(hcp.validation, Some(Validation::Http(_))));

        for id in [
            "betterleaks.doppler-api-token",
            "betterleaks.heroku-api-key",
            "betterleaks.heroku-api-key-v2",
            "betterleaks.slack-legacy-token",
            "betterleaks.slack-user-token",
            "betterleaks.twitch-api-token",
            "betterleaks.vercel-app-access-token",
            "betterleaks.vercel-app-refresh-token",
        ] {
            assert!(rules.rules[id].revocation.is_some(), "{id} should support revocation");
        }

        for id in [
            "veles.secrets/bitbucketcredentials",
            "veles.secrets/circleciproject",
            "veles.secrets/cloudflareapitoken",
            "veles.secrets/codecatalystcredentials",
            "veles.secrets/codecommitcredentials",
            "veles.secrets/digitaloceanapikey",
            "veles.secrets/grokxaiapikey",
            "veles.secrets/herokuplatformkey",
            "veles.secrets/npmjsaccesstoken",
            "veles.secrets/openrouter",
            "veles.secrets/postmanapikey",
            "veles.secrets/postmancollectiontoken",
            "veles.secrets/sendgrid",
            "veles.secrets/slackappconfigaccesstoken",
            "veles.secrets/slackappconfigrefreshtoken",
            "veles.secrets/slackappleveltoken",
        ] {
            let rule = &rules.rules[id];
            assert!(rule.visible, "{id} should be the visible detector for its format");
            assert!(matches!(rule.validation, Some(Validation::Http(_))));
        }

        for id in [
            "veles.secrets/cloudflareapitoken",
            "veles.secrets/digitaloceanapikey",
            "veles.secrets/herokuplatformkey",
            "veles.secrets/npmjsaccesstoken",
            "veles.secrets/slackappleveltoken",
        ] {
            assert!(rules.rules[id].revocation.is_some(), "{id} should support revocation");
        }

        for id in [
            "betterleaks.cloudflare-api-key",
            "betterleaks.digitalocean-pat",
            "betterleaks.generic-credential-uri",
            "betterleaks.heroku-api-key-v2",
            "betterleaks.npm-access-token",
            "betterleaks.openrouter-api-key",
            "betterleaks.postman-api-token",
            "betterleaks.sendgrid-api-token",
            "betterleaks.slack-app-token",
            "betterleaks.slack-config-access-token",
            "betterleaks.slack-config-refresh-token",
            "betterleaks.xai-api-key",
        ] {
            assert!(
                rules.rules[id].betterleaks_filter.is_some(),
                "{id} should retain a Veles source-precedence filter"
            );
        }

        assert!(matches!(
            rules.rules["betterleaks.circleci-project-token"].validation,
            Some(Validation::Betterleaks(_))
        ));

        let npm = &rules.rules["betterleaks.npm-access-token"];
        assert!(filter_discards(
            npm,
            "config.env",
            "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            &[],
        ));

        let cloudflare = &rules.rules["betterleaks.cloudflare-api-key"];
        let token = ["aB3dE5fG", "7hJ9kL2m", "N4pQ6rS8", "tU0vW1xY", "-z_C9dEf"].concat();
        assert!(filter_discards(
            cloudflare,
            "cloudflare.env",
            &token,
            &format!("CF_API_TOKEN={token}"),
            &[],
        ));
        assert!(filter_discards(
            cloudflare,
            "application.env",
            &token,
            &format!("CLOUDFLARE_API_TOKEN={token}"),
            &[],
        ));

        let uri = &rules.rules["betterleaks.generic-credential-uri"];
        let git_uri = "https://user:password@bitbucket.org/team/repo.git";
        let uri_captures = [("uri", git_uri), ("host", "bitbucket.org"), ("password", "password")];
        assert!(filter_discards(uri, "project/.git/config", "password", git_uri, &uri_captures,));
        assert!(!filter_discards(uri, "README.md", "password", git_uri, &uri_captures));
    }

    /// Coverage drift guard.
    ///
    /// `assert!(num_rules() >= 400)` only catches a wholesale collapse of the
    /// catalog. This asserts that every provider Kingfisher 1.x covered and that
    /// we claim to still cover is *actually* still present, so an upstream
    /// release that drops a provider fails the build instead of silently
    /// reducing detection coverage.
    ///
    /// If this fails, either the alias target needs updating for an upstream
    /// rename, or coverage genuinely regressed and the alias entry should be
    /// removed in the same change (and noted in the changelog).
    #[test]
    fn legacy_aliases_all_resolve_against_the_builtin_catalog() {
        let rules = get_builtin_rules(Some(Confidence::Low)).unwrap();
        let ids: Vec<&str> = rules.rules.keys().map(String::as_str).collect();

        let mut unresolved = Vec::new();
        for (family, selectors) in crate::legacy_aliases::legacy_aliases() {
            for selector in selectors {
                let matched = ids.iter().any(|id| {
                    *id == selector
                        || (id.starts_with(selector.as_str())
                            && matches!(id.as_bytes().get(selector.len()), Some(b'.' | b'-')))
                });
                if !matched {
                    unresolved.push(format!("{family} -> {selector}"));
                }
            }
        }

        assert!(
            unresolved.is_empty(),
            "legacy rule aliases no longer resolve against the built-in catalog \
             (upstream rename, or coverage regression):\n  {}",
            unresolved.join("\n  ")
        );
    }
}
