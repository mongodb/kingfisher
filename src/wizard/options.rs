//! Use Clap's option catalog so descriptions, choices, and validation stay in sync with the CLI.
use crate::cli::global::CommandLineArgs;
use clap::{ArgAction, CommandFactory};

#[derive(Clone)]
pub struct OptionSpec {
    pub flag: String,
    pub group: String,
    pub help: String,
    pub placeholder: String,
    pub boolean: bool,
    pub repeatable: bool,
    pub choices: Vec<String>,
}
pub fn catalog() -> Vec<OptionSpec> {
    let mut command = CommandLineArgs::command();
    command.build();
    let scan = command.find_subcommand("scan").expect("scan command");
    let mut options = Vec::new();
    for arg in scan.get_arguments() {
        let Some(flag) = arg.get_long() else { continue };
        // The workspace owns its report destination and lifecycle. The basic form owns these
        // toggles. Update/help/version are actions, not scan configuration.
        if arg.is_hide_set()
            || matches!(
                flag,
                "help"
                    | "version"
                    | "self-update"
                    | "no-update-check"
                    | "format"
                    | "output"
                    | "no-validate"
                    | "redact"
                    | "blast-radius"
                    | "rule"
                    | "rules-path"
                    | "load-builtins"
                    | "exclude"
                    | "git-history"
                    | "view-report"
                    | "view-report-port"
                    | "view-report-address"
                    | "view"
                    | "open"
                    | "serve"
            )
        {
            continue;
        }
        let choices = arg
            .get_value_parser()
            .possible_values()
            .map(|values| {
                values
                    .filter(|v| !v.is_hide_set())
                    .map(|v| v.get_name().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let defaults = arg
            .get_default_values()
            .iter()
            .map(|v| v.to_string_lossy())
            .collect::<Vec<_>>()
            .join(", ");
        let placeholder = if !choices.is_empty() {
            choices.join(" · ")
        } else if !defaults.is_empty() {
            format!("Default: {defaults}")
        } else {
            "Not set".into()
        };
        options.push(OptionSpec {
            flag: flag.into(),
            group: arg.get_help_heading().unwrap_or("Scan options").into(),
            help: arg.get_help().map(ToString::to_string).unwrap_or_default(),
            placeholder,
            boolean: matches!(arg.get_action(), ArgAction::SetTrue),
            repeatable: matches!(arg.get_action(), ArgAction::Append),
            // GlobalArgs::verbose documents three useful verbosity levels; higher
            // clap Count values map to the same tracing level.
            choices: if flag == "verbose" {
                vec!["0".into(), "1".into(), "2".into(), "3".into()]
            } else {
                choices
            },
        });
    }
    options.sort_by(|a, b| (&a.group, &a.flag).cmp(&(&b.group, &b.flag)));
    options
}

/// Preserve explicitly supplied global options when launching the wizard.
pub fn global_values(matches: &clap::ArgMatches) -> Vec<(String, String)> {
    let command = CommandLineArgs::command();
    let mut values = Vec::new();
    for arg in command.get_arguments().filter(|arg| arg.is_global_set()) {
        let id = arg.get_id().as_str();
        if matches.value_source(id) != Some(clap::parser::ValueSource::CommandLine) {
            continue;
        }
        let Some(flag) = arg.get_long() else { continue };
        match arg.get_action() {
            ArgAction::Count => values.push((flag.into(), matches.get_count(id).to_string())),
            ArgAction::SetTrue => values.push((flag.into(), matches.get_flag(id).to_string())),
            _ => {
                if let Some(raw) = matches.get_raw(id) {
                    values.extend(
                        raw.map(|value| (flag.into(), value.to_string_lossy().into_owned())),
                    );
                }
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_includes_scan_and_global_options_without_workspace_actions() {
        let options = catalog();
        for flag in [
            "jobs",
            "validation-timeout",
            "confidence",
            "config",
            "tls-mode",
            "endpoint",
            "allow-internal-ips",
        ] {
            assert!(options.iter().any(|o| o.flag == flag), "missing {flag}");
        }
        assert!(options.iter().all(|o| {
            !["output", "format", "self-update", "view-report"].contains(&o.flag.as_str())
        }));
        assert!(options.iter().find(|o| o.flag == "endpoint").unwrap().repeatable);
        assert!(
            options
                .iter()
                .find(|o| o.flag == "tls-mode")
                .unwrap()
                .choices
                .contains(&"strict".into())
        );
    }
    #[test]
    fn startup_preserves_explicit_repeated_global_flags() {
        let matches = CommandLineArgs::command()
            .try_get_matches_from([
                "kingfisher",
                "wizard",
                "--tls-mode",
                "strict",
                "--endpoint",
                "github=https://one.invalid",
                "--endpoint",
                "gitlab=https://two.invalid",
                "-vv",
                "--allow-internal-ips",
            ])
            .unwrap();
        let values = global_values(&matches);
        assert_eq!(values.iter().filter(|(key, _)| key == "endpoint").count(), 2);
        assert!(values.contains(&("tls-mode".into(), "strict".into())));
        assert!(values.contains(&("verbose".into(), "2".into())));
        assert!(values.contains(&("allow-internal-ips".into(), "true".into())));
    }
}

/// Task-oriented groups, independent of Clap's help ordering.
pub fn section(option: &OptionSpec) -> &'static str {
    let flag = option.flag.as_str();
    if option.group == "Output Options" || flag == "audit-log" {
        "Reporting"
    } else if flag.contains("validat") || flag == "only-valid" {
        "Validation"
    } else if flag.contains("rule")
        || ["confidence", "no-base64", "include-hidden-findings"].contains(&flag)
    {
        "Detection"
    } else if option.group == "Git Options"
        || flag.starts_with("git-")
        || [
            "repo-clone-limit",
            "include-contributors",
            "scan-nested-repos",
            "max-file-size",
            "no-extract-archives",
            "extraction-depth",
            "no-binary",
        ]
        .contains(&flag)
    {
        "Git & files"
    } else if option.group.to_lowercase().contains("global") {
        "Network & global"
    } else {
        "Scan"
    }
}
pub const SECTIONS: &[&str] =
    &["Scan", "Detection", "Validation", "Git & files", "Reporting", "Network & global"];

pub fn title(flag: &str) -> String {
    match flag {
        "no-base64" => "Skip Base64 decoding".into(),
        "no-binary" => "Skip binary files".into(),
        "no-extract-archives" => "Skip archive contents".into(),
        "no-rule-cache" => "Disable rule cache".into(),
        "no-ignore" => "Ignore .gitignore exclusions".into(),
        "no-ignore-if-contains" => "Disable content exclusions".into(),
        "only-valid" => "Only report active credentials".into(),
        "disk-offload" => "Use disk for large scans".into(),
        "validation-rps" => "Validation requests per second".into(),
        "max-file-size" => "Maximum file size (MB)".into(),
        "validation-timeout" => "Request timeout (seconds)".into(),
        "jobs" => "Parallel workers".into(),
        "config" => "Configuration file".into(),
        "tls-mode" => "TLS verification".into(),
        "no-dedup" => "Keep duplicate occurrences".into(),
        "exclude-rule" => "Exclude detector".into(),
        _ => {
            let mut text = flag.replace('-', " ");
            if let Some(first) = text.get_mut(..1) {
                first.make_ascii_uppercase();
            }
            text
        }
    }
}
