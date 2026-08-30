//! Direct blast-radius mapping of a known secret without pattern matching.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use tracing::debug;

use crate::{
    access_map::{AccessMapAttempt, AccessMapResult, map_request_attempts},
    cli::{commands::blast_radius::BlastRadiusArgs, global::GlobalArgs},
    direct_validate::{
        build_globals, create_minimal_scan_args, extract_validation_vars, find_rules_by_selector,
        get_global_var, read_secret,
    },
    provider_endpoints::ProviderEndpointOverrides,
    reporter::{
        FindingRecordData, FindingReporterRecord, ReportEnvelope, RuleMetadata, ScanReportMetadata,
        ScanReportSummary, ValidationInfo, access_map_entry_from_result,
    },
    rule_loader::RuleLoader,
    rules::Validation,
    scanner::direct_access_map_requests,
    util::get_writer_for_file_or_stdout,
};

fn record_mapping_attempt(
    rule_id: &str,
    rule_name: &str,
    attempt: AccessMapAttempt,
    results: &mut Vec<DirectAccessMapResult>,
    failures: &mut Vec<String>,
) {
    if attempt.succeeded {
        let mut result = attempt.result;
        // Direct mappings are not tied to a scan finding. The request uses a synthetic
        // fingerprint internally for collector deduplication, but exposing it would make every
        // direct result appear to have the same real fingerprint. The viewer assigns its own
        // per-result correlation fingerprint when needed.
        result.fingerprint = None;
        results.push(DirectAccessMapResult {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            result,
        });
        return;
    }
    let detail =
        attempt.result.risk_notes.first().map(String::as_str).unwrap_or("identity mapping failed");
    failures.push(format!("{rule_id}: {detail}"));
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectAccessMapResult {
    pub rule_id: String,
    pub rule_name: String,
    pub result: AccessMapResult,
}

pub async fn run_direct_access_map(
    args: &BlastRadiusArgs,
    global_args: &GlobalArgs,
) -> Result<Vec<DirectAccessMapResult>> {
    let rule_selector = args
        .rule
        .as_deref()
        .ok_or_else(|| anyhow!("--rule is required for direct blast-radius mapping"))?;
    if args.credential_path.is_some() {
        bail!("a credential path cannot be used with --rule");
    }

    let secret = read_secret(args.input.as_deref())?;
    if secret.is_empty() {
        bail!("Secret cannot be empty");
    }

    let loader = RuleLoader::new()
        .load_builtins(!args.no_builtins)
        .additional_rule_load_paths(&args.rules_path);
    let loaded = loader.load(&create_minimal_scan_args())?;
    let matching_rules = find_rules_by_selector(rule_selector, loaded.id_to_rule())?;
    let endpoint_overrides = ProviderEndpointOverrides::from_global_args(global_args)?;
    let mut results = Vec::new();
    let mut failures = Vec::new();

    for rule in matching_rules {
        let Some(validation) = rule.syntax().validation.as_ref() else {
            continue;
        };

        let mut template_vars = extract_validation_vars(validation);
        if matches!(validation, Validation::AWS)
            && crate::validation::is_aws_session_token_rule(rule)
        {
            template_vars.insert("AWS_SECRET_ACCESS_KEY".to_string());
        }

        let globals = build_globals(
            rule.id(),
            &secret,
            &args.args,
            &args.variables,
            &template_vars,
            &endpoint_overrides,
        )?;
        let variables = template_vars
            .into_iter()
            .filter(|name| name != "TOKEN")
            .filter_map(|name| get_global_var(&globals, &name).map(|value| (name, value)))
            .collect::<BTreeMap<_, _>>();

        let requests = direct_access_map_requests(Arc::new(rule.clone()), &secret, variables);
        if requests.is_empty() {
            continue;
        }

        for attempt in map_request_attempts(requests).await {
            record_mapping_attempt(rule.id(), rule.name(), attempt, &mut results, &mut failures);
        }
    }

    if results.is_empty() {
        if !failures.is_empty() {
            bail!(
                "Blast-radius mapping failed for all rules matching '{}':\n- {}",
                rule_selector,
                failures.join("\n- ")
            );
        }
        bail!(
            "No supported blast-radius mapping found for rule '{}'. Check the rule and provide any required --arg or --var values.",
            rule_selector
        );
    }
    if !failures.is_empty() {
        debug!(
            selector = rule_selector,
            failures = ?failures,
            "Some matching rules failed blast-radius mapping"
        );
    }

    Ok(results)
}

pub fn print_results(
    results: &[DirectAccessMapResult],
    format: &str,
    output: Option<&Path>,
) -> Result<()> {
    let mut writer = get_writer_for_file_or_stdout(output)?;
    match format {
        "json" => writeln!(writer, "{}", serde_json::to_string_pretty(results)?)?,
        "toon" => writeln!(
            writer,
            "{}",
            crate::toon::encode_llm_friendly(&serde_json::to_value(results)?)?
        )?,
        "html" => {
            let access_map_results =
                results.iter().map(|result| result.result.clone()).collect::<Vec<_>>();
            writeln!(
                writer,
                "{}",
                crate::access_map::report::render_html_report_multi(&access_map_results)?
            )?;
        }
        _ => {
            for (index, result) in results.iter().enumerate() {
                if index > 0 {
                    writeln!(writer)?;
                }
                writeln!(writer, "Rule: {} ({})", result.rule_name, result.rule_id)?;
                writeln!(writer, "{}", serde_json::to_string_pretty(&result.result)?)?;
            }
        }
    }
    Ok(())
}

/// Build an interactive viewer envelope for direct blast-radius results.
pub fn build_viewer_report_bytes(results: &[DirectAccessMapResult]) -> Result<Vec<u8>> {
    let generated_at = chrono::Local::now().to_rfc3339();
    let mut findings = Vec::with_capacity(results.len());
    let mut access_map = Vec::with_capacity(results.len());

    for (index, result) in results.iter().enumerate() {
        let fingerprint = format!("direct-{}-{index}", result.rule_id);
        findings.push(FindingReporterRecord {
            rule: RuleMetadata {
                title: result.rule_id.clone(),
                name: result.rule_name.clone(),
                id: result.rule_id.clone(),
                description: result.rule_name.clone(),
            },
            finding: FindingRecordData {
                snippet: "[credential supplied directly]".to_string(),
                fingerprint: fingerprint.clone(),
                confidence: "high".to_string(),
                entropy: "0.00".to_string(),
                validation: ValidationInfo {
                    outcome: kingfisher_core::ValidationOutcome::VerifiedActive,
                    status: "Active Credential".to_string(),
                    response: "Direct blast-radius mapping completed".to_string(),
                },
                language: "Direct input".to_string(),
                line: 0,
                column_start: 0,
                column_end: 0,
                path: "direct input".to_string(),
                encoding: None,
                git_metadata: None,
                validate_command: None,
                revoke_command: None,
                blast_radius_command: None,
            },
        });

        let mut mapped = result.result.clone();
        mapped.fingerprint = Some(fingerprint);
        access_map.push(access_map_entry_from_result(&mapped));
    }

    let finding_count = findings.len();
    let envelope = ReportEnvelope {
        findings,
        access_map: Some(access_map),
        metadata: Some(ScanReportMetadata {
            generated_at: generated_at.clone(),
            scan_timestamp: generated_at,
            target: Some("direct blast-radius mapping".to_string()),
            command_line_args: vec!["kingfisher".to_string(), "blast-radius".to_string()],
            kingfisher_version: env!("CARGO_PKG_VERSION").to_string(),
            latest_version_available: None,
            update_check_status: None,
            summary: ScanReportSummary {
                findings: finding_count,
                active_findings: finding_count,
                inactive_findings: 0,
                locally_derived_findings: 0,
                invalid_material_findings: 0,
                unknown_validation_findings: 0,
                access_map_identities: finding_count,
                rules_applied: None,
                confidence_level: "high".to_string(),
                custom_rules_used: false,
                successful_validations: Some(finding_count),
                failed_validations: Some(0),
                skipped_validations: Some(0),
                blobs_scanned: None,
                bytes_scanned: None,
                scan_duration_seconds: None,
            },
        }),
    };

    Ok(serde_json::to_vec_pretty(&envelope)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_map::{AccessSummary, PermissionSummary, Severity};
    use tempfile::tempdir;

    #[test]
    fn viewer_report_correlates_direct_results_with_findings() {
        let result = DirectAccessMapResult {
            rule_id: "custom.example".to_string(),
            rule_name: "Example credential".to_string(),
            result: AccessMapResult {
                cloud: "example".to_string(),
                fingerprint: None,
                identity: AccessSummary {
                    id: "example-user".to_string(),
                    access_type: "user".to_string(),
                    project: None,
                    tenant: None,
                    account_id: None,
                },
                roles: Vec::new(),
                permissions: PermissionSummary::default(),
                resources: Vec::new(),
                severity: Severity::Low,
                recommendations: Vec::new(),
                risk_notes: Vec::new(),
                token_details: None,
                provider_metadata: None,
            },
        };

        let report: serde_json::Value =
            serde_json::from_slice(&build_viewer_report_bytes(&[result]).unwrap()).unwrap();
        assert_eq!(report["findings"][0]["finding"]["fingerprint"], "direct-custom.example-0");
        assert_eq!(report["access_map"][0]["fingerprint"], "direct-custom.example-0");
        assert_eq!(report["access_map"][0]["account"], "example-user");
    }

    #[test]
    fn direct_results_honor_output_path() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("report.json");
        let result = DirectAccessMapResult {
            rule_id: "custom.example".to_string(),
            rule_name: "Example credential".to_string(),
            result: AccessMapResult {
                cloud: "example".to_string(),
                fingerprint: None,
                identity: AccessSummary {
                    id: "example-user".to_string(),
                    access_type: "user".to_string(),
                    project: None,
                    tenant: None,
                    account_id: None,
                },
                roles: Vec::new(),
                permissions: PermissionSummary::default(),
                resources: Vec::new(),
                severity: Severity::Low,
                recommendations: Vec::new(),
                risk_notes: Vec::new(),
                token_details: None,
                provider_metadata: None,
            },
        };

        print_results(&[result], "json", Some(&output)).unwrap();

        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(report[0]["rule_id"], "custom.example");
    }

    #[test]
    fn mixed_mapping_attempts_keep_successes_and_failure_diagnostics() {
        let failed_attempt = AccessMapAttempt {
            result: AccessMapResult {
                cloud: "example".to_string(),
                fingerprint: None,
                identity: AccessSummary {
                    id: "token".to_string(),
                    access_type: "unknown".to_string(),
                    project: None,
                    tenant: None,
                    account_id: None,
                },
                roles: Vec::new(),
                permissions: PermissionSummary::default(),
                resources: Vec::new(),
                severity: Severity::Medium,
                recommendations: Vec::new(),
                risk_notes: vec!["Identity mapping failed: unauthorized".to_string()],
                token_details: None,
                provider_metadata: None,
            },
            succeeded: false,
        };
        let successful_attempt = AccessMapAttempt {
            result: AccessMapResult {
                cloud: "example".to_string(),
                fingerprint: Some("0".to_string()),
                identity: AccessSummary {
                    id: "valid-token".to_string(),
                    access_type: "user".to_string(),
                    project: None,
                    tenant: None,
                    account_id: None,
                },
                roles: Vec::new(),
                permissions: PermissionSummary::default(),
                resources: Vec::new(),
                severity: Severity::Low,
                recommendations: Vec::new(),
                risk_notes: Vec::new(),
                token_details: None,
                provider_metadata: None,
            },
            succeeded: true,
        };

        let mut results = Vec::new();
        let mut failures = Vec::new();
        record_mapping_attempt(
            "custom.first",
            "First rule",
            failed_attempt,
            &mut results,
            &mut failures,
        );
        record_mapping_attempt(
            "custom.second",
            "Second rule",
            successful_attempt,
            &mut results,
            &mut failures,
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "custom.second");
        assert_eq!(results[0].result.fingerprint, None);
        assert_eq!(failures, ["custom.first: Identity mapping failed: unauthorized"]);
    }
}
