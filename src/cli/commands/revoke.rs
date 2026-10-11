use clap::{Args, ValueEnum, ValueHint};
use std::path::PathBuf;

/// AWS access-key operation to perform during direct revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AwsRevocationActionArg {
    /// Mark the access key inactive (reversible).
    Deactivate,
    /// Permanently delete the access key (irreversible).
    Delete,
}

fn parse_nonblank_aws_value(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        Err("value must not be empty".to_string())
    } else {
        Ok(value.to_string())
    }
}

/// Directly revoke a known secret against a rule's revocation config
#[derive(Args, Debug, Clone)]
pub struct RevokeArgs {
    /// Rule ID or prefix to use for revocation (for example, a custom legacy rule ID).
    /// The `betterleaks.` prefix is optional for built-in rules.
    #[arg(long, required = true)]
    pub rule: String,

    /// The secret value to revoke (use '-' to read from stdin)
    #[arg(value_name = "SECRET")]
    pub secret: Option<String>,

    /// Additional values for revocation, auto-assigned to template variables.
    /// Values are assigned to non-TOKEN variables in alphabetical order.
    /// Example: --arg AKIAEXAMPLE assigns to the first required variable.
    #[arg(long = "arg", value_name = "VALUE")]
    pub args: Vec<String>,

    /// Named variables for revocation template (e.g., --var AKID=xxx).
    /// Use when you know the exact variable name. Overrides --arg assignments.
    #[arg(long = "var", value_name = "NAME=VALUE")]
    pub variables: Vec<String>,

    /// Timeout for HTTP and AWS revocation requests in seconds (1-60)
    #[arg(
        long = "timeout",
        default_value_t = 10,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..=60)
    )]
    pub timeout: u64,

    /// Retries for explicit HTTP 429 responses (0-5); ambiguous failures are never retried
    #[arg(
        long = "retries",
        default_value_t = 0,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(0..=5)
    )]
    pub retries: u32,

    /// AWS profile to use as a separately authorized revocation identity
    #[arg(
        long = "aws-profile",
        value_name = "PROFILE",
        value_parser = parse_nonblank_aws_value,
        conflicts_with = "aws_use_default_credentials"
    )]
    pub aws_profile: Option<String>,

    /// Use the default AWS credential chain as a separately authorized revocation identity
    #[arg(long = "aws-use-default-credentials", conflicts_with = "aws_profile")]
    pub aws_use_default_credentials: bool,

    /// IAM user that owns the AWS access key (normally resolved automatically)
    #[arg(
        long = "aws-user-name",
        value_name = "USER",
        value_parser = parse_nonblank_aws_value
    )]
    pub aws_user_name: Option<String>,

    /// AWS region for STS and IAM requests (defaults to the responder config or us-east-1)
    #[arg(
        long = "aws-region",
        value_name = "REGION",
        value_parser = parse_nonblank_aws_value
    )]
    pub aws_region: Option<String>,

    /// AWS revocation action (defaults to deactivate); deletion must be explicitly selected
    #[arg(long = "aws-action", value_enum)]
    pub aws_action: Option<AwsRevocationActionArg>,

    /// Path to custom rules file or directory
    #[arg(long = "rules-path", value_hint = ValueHint::AnyPath)]
    pub rules_path: Vec<PathBuf>,

    /// Skip loading builtin rules (use only custom rules from --rules-path)
    #[arg(long = "no-builtins", default_value_t = false)]
    pub no_builtins: bool,

    /// Output format: text, json, or toon (`toon` is recommended for LLMs)
    #[arg(long, default_value = "text", value_parser = ["text", "json", "toon"])]
    pub format: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        revoke: RevokeArgs,
    }

    #[test]
    fn aws_revocation_defaults_to_self_deactivation() {
        let parsed = TestCli::try_parse_from(["test", "--rule", "aws", "secret"]).unwrap();

        assert!(parsed.revoke.aws_action.is_none());
        assert!(parsed.revoke.aws_profile.is_none());
        assert!(!parsed.revoke.aws_use_default_credentials);
        assert!(parsed.revoke.aws_user_name.is_none());
    }

    #[test]
    fn aws_responder_credential_sources_conflict() {
        let error = TestCli::try_parse_from([
            "test",
            "--rule",
            "aws",
            "--aws-profile",
            "incident-response",
            "--aws-use-default-credentials",
            "secret",
        ])
        .unwrap_err();

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn aws_delete_must_be_selected_explicitly() {
        let parsed =
            TestCli::try_parse_from(["test", "--rule", "aws", "--aws-action", "delete", "secret"])
                .unwrap();

        assert_eq!(parsed.revoke.aws_action, Some(AwsRevocationActionArg::Delete));
    }

    #[test]
    fn aws_string_options_reject_blank_values() {
        for option in ["--aws-profile", "--aws-user-name", "--aws-region"] {
            let error = TestCli::try_parse_from(["test", "--rule", "aws", option, "   ", "secret"])
                .unwrap_err();

            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        }
    }
}
