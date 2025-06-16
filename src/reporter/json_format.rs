use http::StatusCode;
use serde_json::json;

use super::*;
use crate::bstring_escape::Escaped;

impl DetailsReporter {
    pub fn deduplicate_matches(
        &self,
        matches: Vec<ReportMatch>,
        no_dedup: bool,
    ) -> Vec<ReportMatch> {
        if no_dedup {
            return matches;
        }

        use std::collections::HashMap;
        let mut by_fp: HashMap<u64, ReportMatch> = HashMap::new();

        for rm in matches {
            let fp = rm.m.finding_fingerprint;
            if let Some(existing) = by_fp.get_mut(&fp) {
                // merge origin sets (keep first origin, append the rest)
                for o in rm.origin.iter() {
                    if !existing.origin.iter().any(|e| e == o) {
                        existing.origin = OriginSet::new(
                            existing.origin.first().clone(),
                            existing
                                .origin
                                .iter()
                                .skip(1)
                                .cloned()
                                .chain(std::iter::once(o.clone()))
                                .collect(),
                        );
                    }
                }
                continue;
            }
            by_fp.insert(fp, rm);
        }
        by_fp.into_values().collect()
    }

    pub fn gather_json_findings(
        &self,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<Vec<serde_json::Value>> {
        let mut matches = self.get_filtered_matches()?;
        if !args.no_dedup {
            matches = self.deduplicate_matches(matches, args.no_dedup);
        }

        let mut json_findings = Vec::new();
        for rm in matches {
            let source_span = &rm.m.location.source_span;
            let line_num = source_span.start.line;

            let snippet = Escaped(
                rm.m.groups
                    .captures
                    .get(1)
                    .or_else(|| rm.m.groups.captures.get(0))
                    .map(|capture| capture.value.as_bytes())
                    .unwrap_or_default(),
            )
            .to_string();

            let validation_status = if rm.validation_success {
                "Active Credential"
            } else if rm.validation_response_status == StatusCode::CONTINUE.as_u16() {
                "Not Attempted"
            } else {
                "Inactive Credential"
            };

            const MAX_RESPONSE_LENGTH: usize = 512;
            let truncated_body: String =
                rm.validation_response_body.chars().take(MAX_RESPONSE_LENGTH).collect();
            let ellipsis =
                if rm.validation_response_body.len() > MAX_RESPONSE_LENGTH { "..." } else { "" };
            let response_body = format!("{}{}", truncated_body, ellipsis);

            // Call extract_git_metadata on each GitRepo origin and take the first non-null result.
            let git_metadata_val = rm
                .origin
                .iter()
                .filter_map(|origin| {
                    if let Origin::GitRepo(e) = origin {
                        self.extract_git_metadata(e, source_span)
                    } else {
                        None
                    }
                })
                .next()
                .unwrap_or(serde_json::Value::Null);

            // Collect a file path from an Origin::File, if available.
            let file_path = rm
                .origin
                .iter()
                .find_map(|origin| {
                    if let Origin::File(e) = origin {
                        Some(e.path.display().to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let match_json = json!({
                "rule": {
                    "name": rm.m.rule_name,
                    "id": rm.m.rule_text_id,
                },
                "finding": {
                    "snippet": snippet,
                    "fingerprint": rm.m.finding_fingerprint.to_string(),
                    "confidence": rm.match_confidence.to_string(),
                    "entropy": format!("{:.2}", rm.m.calculated_entropy),
                    "validation": {
                        "status": validation_status,
                        "response": response_body,
                    },
                    "language": rm.blob_metadata.language.clone().unwrap_or_else(|| "Unknown".to_string()),
                    "line": line_num,
                    "column_start": source_span.start.column,
                    "column_end": source_span.end.column,
                    "path": file_path,
                    "git_metadata": git_metadata_val
                }
            });

            let finding_json = json!({
                "id": rm.m.rule_text_id,
                "matches": [ match_json ]
            });
            json_findings.push(finding_json);
        }
        Ok(json_findings)
    }
    pub fn json_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let mut findings = Vec::new();

        // Get filtered matches
        let mut matches = self.get_filtered_matches()?;

        // Apply deduplication only if requested
        if !args.no_dedup {
            matches = self.deduplicate_matches(matches, args.no_dedup);
        }

        // For each match, handle it based on the no_dedup flag
        for rm in matches {
            if args.no_dedup && rm.origin.len() > 1 {
                // For no_dedup and multiple origins, create separate findings for each origin
                for origin in rm.origin.iter() {
                    // Create a single-origin version of this match
                    let single_origin_rm = ReportMatch {
                        origin: OriginSet::new(origin.clone(), Vec::new()),
                        blob_metadata: rm.blob_metadata.clone(),
                        m: rm.m.clone(),
                        comment: rm.comment.clone(),
                        visible: rm.visible,
                        match_confidence: rm.match_confidence,
                        validation_response_body: rm.validation_response_body.clone(),
                        validation_response_status: rm.validation_response_status,
                        validation_success: rm.validation_success,
                    };

                    // Process this single-origin match into a JSON finding
                    let json_finding = self.process_match_to_json(&single_origin_rm)?;
                    findings.push(json_finding);
                }
            } else {
                // Process normally for deduped matches or matches with only one origin
                let json_finding = self.process_match_to_json(&rm)?;
                findings.push(json_finding);
            }
        }

        // Write the JSON output
        if !findings.is_empty() {
            serde_json::to_writer_pretty(&mut writer, &findings)?;
            writeln!(writer)?;
        }
        Ok(())
    }

    // Add a helper method to convert a ReportMatch to a JSON finding
    pub fn process_match_to_json(&self, rm: &ReportMatch) -> Result<serde_json::Value> {
        // Extract the relevant data from the match as you already do in your current implementation
        let source_span = &rm.m.location.source_span;
        let line_num = source_span.start.line;

        let snippet = Escaped(
            rm.m.groups
                .captures
                .get(1)
                .or_else(|| rm.m.groups.captures.get(0))
                .map(|capture| capture.value.as_bytes())
                .unwrap_or_default(),
        )
        .to_string();

        let validation_status = if rm.validation_success {
            "Active Credential"
        } else if rm.validation_response_status == StatusCode::CONTINUE.as_u16() {
            "Not Attempted"
        } else {
            "Inactive Credential"
        };

        const MAX_RESPONSE_LENGTH: usize = 512;
        let truncated_body: String =
            rm.validation_response_body.chars().take(MAX_RESPONSE_LENGTH).collect();
        let ellipsis =
            if rm.validation_response_body.len() > MAX_RESPONSE_LENGTH { "..." } else { "" };
        let response_body = format!("{}{}", truncated_body, ellipsis);

        // Call extract_git_metadata on each GitRepo origin and take the first non-null result.
        let git_metadata_val = rm
            .origin
            .iter()
            .filter_map(|origin| {
                if let Origin::GitRepo(e) = origin {
                    self.extract_git_metadata(e, source_span)
                } else {
                    None
                }
            })
            .next()
            .unwrap_or(serde_json::Value::Null);

        // Collect a file path from an Origin::File, if available.
        let file_path = rm
            .origin
            .iter()
            .find_map(|origin| {
                if let Origin::File(e) = origin {
                    Some(e.path.display().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let match_json = json!({
            "rule": {
                "name": rm.m.rule_name,
                "id": rm.m.rule_text_id,
            },
            "finding": {
                "snippet": snippet,
                "fingerprint": rm.m.finding_fingerprint.to_string(),
                "confidence": rm.match_confidence.to_string(),
                "entropy": format!("{:.2}", rm.m.calculated_entropy),
                "validation": {
                    "status": validation_status,
                    "response": response_body,
                },
                "language": rm.blob_metadata.language.clone().unwrap_or_else(|| "Unknown".to_string()),
                "line": line_num,
                "column_start": source_span.start.column,
                "column_end": source_span.end.column,
                "path": file_path,
                "git_metadata": git_metadata_val
            }
        });

        let finding_json = json!({
            "id": rm.m.rule_text_id,
            "matches": [ match_json ]
        });

        Ok(finding_json)
    }
    // // Modified JSON format to pass args to gather_json_findings
    // pub fn json_format<W: std::io::Write>(
    //     &self,
    //     mut writer: W,
    //     args: &cli::commands::scan::ScanArgs,
    // ) -> Result<()> {
    //     let findings = self.gather_json_findings(args)?;
    //     if !findings.is_empty() {
    //         serde_json::to_writer_pretty(&mut writer, &findings)?;
    //         writeln!(writer)?;
    //     }
    //     Ok(())
    // }

    pub fn jsonl_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        // Get filtered matches
        let mut matches = self.get_filtered_matches()?;

        // Apply deduplication only if requested
        if !args.no_dedup {
            matches = self.deduplicate_matches(matches, args.no_dedup);
        }

        // For each match, handle it based on the no_dedup flag
        for rm in matches {
            if args.no_dedup && rm.origin.len() > 1 {
                // For no_dedup and multiple origins, create separate findings for each origin
                for origin in rm.origin.iter() {
                    // Create a single-origin version of this match
                    let single_origin_rm = ReportMatch {
                        origin: OriginSet::new(origin.clone(), Vec::new()),
                        blob_metadata: rm.blob_metadata.clone(),
                        m: rm.m.clone(),
                        comment: rm.comment.clone(),
                        visible: rm.visible,
                        match_confidence: rm.match_confidence,
                        validation_response_body: rm.validation_response_body.clone(),
                        validation_response_status: rm.validation_response_status,
                        validation_success: rm.validation_success,
                    };

                    // Process this single-origin match into a JSON finding and write it
                    let json_finding = self.process_match_to_json(&single_origin_rm)?;
                    serde_json::to_writer(&mut writer, &json_finding)?;
                    writeln!(writer)?;
                }
            } else {
                // Process normally for deduped matches or matches with only one origin
                let json_finding = self.process_match_to_json(&rm)?;
                serde_json::to_writer(&mut writer, &json_finding)?;
                writeln!(writer)?;
            }
        }
        Ok(())
    }
    // // Modified JSONL format to pass args to gather_json_findings
    // pub fn jsonl_format<W: std::io::Write>(
    //     &self,
    //     mut writer: W,
    //     args: &cli::commands::scan::ScanArgs,
    // ) -> Result<()> {
    //     let findings = self.gather_json_findings(args)?;
    //     for finding in findings {
    //         serde_json::to_writer(&mut writer, &finding)?;
    //         writeln!(writer)?;
    //     }
    //     Ok(())
    // }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use anyhow::Result;
    use serde_json::Value;
    use url::Url;

    use super::*;
    use crate::{
        blob::BlobId,
        cli::commands::{
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::OutputArgs,
            rules::RuleSpecifierArgs,
            scan::ConfidenceLevel,
        },
        findings_store::FindingsStore,
        location::{Location, OffsetSpan, SourcePoint, SourceSpan},
        matcher::{Match, SerializableCapture, SerializableCaptures},
        origin::{Origin, OriginSet},
        reporter::{ReportMatch, Styles},
        rules::rule::Confidence,
        util::intern,
    };
    fn create_default_args() -> cli::commands::scan::ScanArgs {
        use crate::cli::commands::gitlab::GitLabRepoType; // bring enum into scope

        cli::commands::scan::ScanArgs {
            num_jobs: 1,
            no_dedup: false,
            rules: RuleSpecifierArgs {
                rules_path: Vec::new(),
                rule: vec!["all".into()],
                load_builtins: true,
            },
            input_specifier_args: InputSpecifierArgs {
                // local path / git URL inputs
                path_inputs: Vec::new(),
                git_url: Vec::new(),

                // GitHub
                github_user: Vec::new(),
                github_organization: Vec::new(),
                all_github_organizations: false,
                github_api_url: Url::parse("https://api.github.com/").unwrap(),
                github_repo_type: GitHubRepoType::Source,

                // GitLab
                gitlab_user: Vec::new(),
                gitlab_group: Vec::new(),
                all_gitlab_groups: false,
                gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
                gitlab_repo_type: GitLabRepoType::Owner,

                // clone / history options
                git_clone: GitCloneMode::Bare,
                git_history: GitHistoryMode::Full,
                scan_nested_repos: true,
                commit_metadata: true,
            },
            content_filtering_args: ContentFilteringArgs {
                max_file_size_mb: 25.0,
                no_extract_archives: false,
                extraction_depth: 2,
                ignore: Vec::new(),
                no_binary: true,
            },
            confidence: ConfidenceLevel::Medium,
            no_validate: false,
            rule_stats: false,
            only_valid: false,
            min_entropy: None,
            redact: false,
            git_repo_timeout: 1800, // 30 minutes
            output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
            snippet_length: 256,
        }
    }

    // Helper function to create a mock Match
    fn create_mock_match(
        rule_name: &str,
        rule_text_id: &str,
        rule_finding_fingerprint: &str,
        validation_success: bool,
    ) -> Match {
        Match {
            location: Location {
                offset_span: OffsetSpan { start: 10, end: 20 },
                source_span: SourceSpan {
                    start: SourcePoint { line: 5, column: 10 },
                    end: SourcePoint { line: 5, column: 20 },
                },
            },
            groups: SerializableCaptures {
                captures: vec![SerializableCapture {
                    name: Some("token".to_string()),
                    match_number: 1,
                    start: 10,
                    end: 20,
                    value: "mock_token".into(),
                }],
            },
            blob_id: BlobId::new(b"mock_blob"),
            finding_fingerprint: 0123,
            rule_finding_fingerprint: intern(rule_finding_fingerprint),
            rule_text_id: intern(rule_text_id),
            rule_name: intern(rule_name), //.to_string(),
            rule_confidence: Confidence::Medium,
            validation_response_body: "validation response".to_string(),
            validation_response_status: 200,
            validation_success,
            calculated_entropy: 4.5,
            visible: true,
        }
    }

    // Helper function to create a mock DetailsReporter
    fn setup_mock_reporter(matches: Vec<ReportMatch>) -> DetailsReporter {
        let mut datastore = FindingsStore::new(PathBuf::from("/tmp"));
        // Create mock origin and blob metadata for the first test match
        if !matches.is_empty() {
            let blob_metadata = BlobMetadata {
                id: BlobId::new(b"mock_blob"),
                num_bytes: 1024,
                mime_essence: Some("text/plain".to_string()),
                charset: Some("UTF-8".to_string()),
                language: Some("Rust".to_string()),
            };
            let dedup = true;
            // Add matches to datastore
            for m in matches.clone() {
                datastore.record(
                    vec![(
                        Arc::new(OriginSet::new(
                            // OriginSet -- Arc<…>
                            Origin::from_file(PathBuf::from("/mock/path/file.rs")),
                            vec![],
                        )),
                        Arc::new(blob_metadata.clone()), // BlobMetadata -- Arc<…>
                        m.m.clone(),
                    )],
                    dedup,
                );
            }
        }
        DetailsReporter {
            datastore: Arc::new(Mutex::new(datastore)),
            styles: Styles::new(false),
            only_valid: false,
        }
    }
    #[test]
    fn test_json_format() -> Result<()> {
        // Create a mock match with successful validation
        let mock_match =
            create_mock_match("MockRule", "mock_rule_1", "mock_finding_fingerprint", true);
        let matches = vec![ReportMatch {
            origin: OriginSet::new(Origin::from_file(PathBuf::from("/mock/path/file.rs")), vec![]),
            blob_metadata: BlobMetadata {
                id: BlobId::new(b"mock_blob"),
                num_bytes: 1024,
                mime_essence: Some("text/plain".to_string()),
                charset: Some("UTF-8".to_string()),
                language: Some("Rust".to_string()),
            },
            m: mock_match,
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: "validation response".to_string(),
            validation_response_status: 200,
            validation_success: true,
        }];
        let reporter = setup_mock_reporter(matches);
        let mut output = Cursor::new(Vec::new());
        // Call the json_format method
        reporter.json_format(&mut output, &create_default_args())?;
        // Parse and validate JSON output
        let json_output: Vec<Value> = serde_json::from_slice(&output.into_inner())?;
        assert!(!json_output.is_empty(), "JSON output should not be empty");
        let first_finding = &json_output[0];
        assert!(first_finding.get("id").is_some(), "Finding should have an 'id'");
        assert!(first_finding.get("matches").is_some(), "Finding should have 'matches'");
        // Validate the structure of the first match
        let matches = first_finding.get("matches").unwrap().as_array().unwrap();
        let first_match = &matches[0];
        assert_eq!(first_match.get("rule").unwrap().get("name").unwrap(), "MockRule");
        assert_eq!(first_match.get("finding").unwrap().get("language").unwrap(), "Rust");
        Ok(())
    }

    // #[test]
    // fn test_jsonl_format() -> Result<()> {
    //     // Create a mock match with successful validation
    //     let mock_match =
    //         create_mock_match("MockRule", "mock_rule_1", "mock_finding_fingerprint", true);
    //     let matches = vec![ReportMatch {
    //         origin: OriginSet::new(
    //             Origin::from_file(PathBuf::from("/mock/path/file.rs")),
    //             vec![],
    //         ),
    //         blob_metadata: BlobMetadata {
    //             id: BlobId::new(b"mock_blob"),
    //             num_bytes: 1024,
    //             mime_essence: Some("text/plain".to_string()),
    //             charset: Some("UTF-8".to_string()),
    //             language: Some("Rust".to_string()),
    //         },
    //         m: mock_match,
    //         comment: None,
    //         match_confidence: Confidence::Medium,
    //         visible: true,
    //         validation_response_body: "validation response".to_string(),
    //         validation_response_status: 200,
    //         validation_success: true,
    //     }];
    //     let reporter = setup_mock_reporter(matches);
    //     let mut output = Cursor::new(Vec::new());
    //     // Call the jsonl_format method
    //     reporter.jsonl_format(&mut output, &create_default_args())?;
    //     // Split output into lines and validate
    //     let jsonl_output = String::from_utf8(output.into_inner())?;
    //     let lines: Vec<&str> = jsonl_output.lines().collect();
    //     assert!(!lines.is_empty(), "JSONL output should not be empty");
    //     for line in &lines {
    //         let json_value: serde_json::Value = serde_json::from_str(line)?;
    //         assert!(
    //             json_value.get("rule_name").is_some(),
    //             "Each line should have a 'rule_name'"
    //         );
    //         assert!(
    //             json_value.get("matches").is_some(),
    //             "Each line should have 'matches'"
    //         );
    //     }
    //     Ok(())
    // }

    #[test]
    fn test_validation_status_in_json() -> Result<()> {
        // Test validation status in JSON output
        let test_cases = vec![(true, "Active Credential"), (false, "Inactive Credential")];
        for (validation_success, expected_status) in test_cases {
            let mock_match = create_mock_match(
                "MockRule",
                "mock_rule_1",
                "mock_finding_fingerprint",
                validation_success,
            );
            let matches = vec![ReportMatch {
                origin: OriginSet::new(
                    Origin::from_file(PathBuf::from("/mock/path/file.rs")),
                    vec![],
                ),
                blob_metadata: BlobMetadata {
                    id: BlobId::new(b"mock_blob"),
                    num_bytes: 1024,
                    mime_essence: Some("text/plain".to_string()),
                    charset: Some("UTF-8".to_string()),
                    language: Some("Rust".to_string()),
                },
                m: mock_match,
                comment: None,
                match_confidence: Confidence::Medium,
                visible: true,
                validation_response_body: "validation response".to_string(),
                validation_response_status: 200,
                validation_success,
            }];
            let reporter = setup_mock_reporter(matches);
            let mut output = Cursor::new(Vec::new());
            // Call the json_format method
            reporter.json_format(&mut output, &create_default_args())?;
            // Parse and validate JSON output
            let json_output: Vec<Value> = serde_json::from_slice(&output.into_inner())?;
            assert!(!json_output.is_empty(), "JSON output should not be empty");
            let first_finding = &json_output[0];
            let matches = first_finding.get("matches").unwrap().as_array().unwrap();
            let first_match = &matches[0];
            let validation_status = first_match
                .get("finding")
                .unwrap()
                .get("validation")
                .unwrap()
                .get("status")
                .unwrap()
                .as_str()
                .unwrap();
            assert_eq!(validation_status, expected_status);
        }
        Ok(())
    }
}
