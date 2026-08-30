use std::path::PathBuf;

use clap::{Args, ValueHint};

/// Map one known credential to its effective identity and blast radius.
#[derive(Args, Debug, Clone)]
pub struct BlastRadiusArgs {
    /// Rule ID or prefix to use for direct blast-radius mapping
    #[arg(long)]
    pub rule: Option<String>,

    /// Secret for direct mapping, or provider for standalone credential-file mapping
    #[arg(value_name = "SECRET_OR_PROVIDER")]
    pub input: Option<String>,

    /// Credential artifact for standalone provider mapping
    #[arg(value_name = "CREDENTIAL", conflicts_with = "rule")]
    pub credential_path: Option<PathBuf>,

    /// Additional values for mapping, auto-assigned to rule component variables
    #[arg(long = "arg", value_name = "VALUE", requires = "rule")]
    pub args: Vec<String>,

    /// Named variables for mapping templates (for example, `--var AKID=VALUE`)
    #[arg(long = "var", value_name = "NAME=VALUE", requires = "rule")]
    pub variables: Vec<String>,

    /// Path to custom rules file or directory
    #[arg(long = "rules-path", value_hint = ValueHint::AnyPath, requires = "rule")]
    pub rules_path: Vec<PathBuf>,

    /// Skip loading builtin rules (use only custom rules from --rules-path)
    #[arg(long = "no-builtins", default_value_t = false, requires = "rule")]
    pub no_builtins: bool,

    /// Output format (direct: text, json, toon, html; standalone: json, html)
    #[arg(
        long,
        short = 'f',
        default_value = "json",
        value_parser = ["text", "json", "toon", "html"]
    )]
    pub format: String,

    /// Write output to the specified path
    #[arg(long, short = 'o', value_hint = ValueHint::FilePath)]
    pub output: Option<PathBuf>,

    /// Open the result in the embedded interactive HTML report viewer
    #[arg(long, default_value_t = false, conflicts_with = "output")]
    pub view_report: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::global::CommandLineArgs;

    #[test]
    fn direct_blast_radius_accepts_rule_and_stdin_secret() {
        let args = CommandLineArgs::try_parse_from([
            "kingfisher",
            "blast-radius",
            "--rule",
            "betterleaks.github-pat",
            "-",
            "--format",
            "json",
        ])
        .unwrap();

        match args.command {
            crate::cli::global::Command::BlastRadius(args) => {
                assert_eq!(args.rule.as_deref(), Some("betterleaks.github-pat"));
                assert_eq!(args.input.as_deref(), Some("-"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn direct_blast_radius_accepts_view_report() {
        let args = CommandLineArgs::try_parse_from([
            "kingfisher",
            "blast-radius",
            "--rule",
            "betterleaks.github-pat",
            "ghp_example",
            "--view-report",
        ])
        .unwrap();

        match args.command {
            crate::cli::global::Command::BlastRadius(args) => {
                assert!(args.view_report);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn blast_radius_preserves_short_format_flag() {
        let args =
            CommandLineArgs::try_parse_from(["kingfisher", "blast-radius", "aws", "-f", "html"])
                .unwrap();

        match args.command {
            crate::cli::global::Command::BlastRadius(args) => {
                assert_eq!(args.input.as_deref(), Some("aws"));
                assert_eq!(args.format, "html");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn direct_only_options_require_a_rule() {
        let error = CommandLineArgs::try_parse_from([
            "kingfisher",
            "blast-radius",
            "aws",
            "--rules-path",
            "custom-rules.yml",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("--rule"));
    }

    #[test]
    fn view_report_rejects_silently_ignored_output_path() {
        let error = CommandLineArgs::try_parse_from([
            "kingfisher",
            "blast-radius",
            "--rule",
            "betterleaks.github-pat",
            "ghp_example",
            "--view-report",
            "--output",
            "report.json",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("cannot be used with"));
    }
}
