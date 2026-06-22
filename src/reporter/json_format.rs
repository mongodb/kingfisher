use super::*;

impl DetailsReporter {
    pub fn json_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        if !envelope.findings.is_empty() || envelope.access_map.is_some() {
            // Compact one-envelope-per-line so streaming emits (parallel
            // scan path: one envelope per repo) concatenate into valid
            // JSONL that `kingfisher view` can parse. Pipe through `jq .`
            // for human-readable pretty output.
            //
            // Serialize into a single buffer and emit via a single
            // `write_all` so callers that need cross-thread atomicity
            // (e.g. the parallel scan path emitting one envelope per repo
            // to stdout) can synchronize at the call site by holding
            // `std::io::stdout().lock()` around this call. We intentionally
            // do NOT acquire the stdout lock here because this method is
            // generic over any `Write` and is also called with file
            // writers and `Cursor<Vec<u8>>` in tests. Flushing is the
            // caller's responsibility — flushing here would defeat
            // upstream `BufWriter` buffering and turn an otherwise-benign
            // BrokenPipe into a hard error.
            let mut buf = Vec::with_capacity(8 * 1024);
            serde_json::to_writer(&mut buf, &envelope)?;
            buf.push(b'\n');
            writer.write_all(&buf)?;
        }
        Ok(())
    }

    pub fn jsonl_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        for record in envelope.findings {
            serde_json::to_writer(&mut writer, &record)?;
            writeln!(writer)?;
        }

        if let Some(access_map) = envelope.access_map {
            let payload = serde_json::json!({ "access_map": access_map });
            serde_json::to_writer(&mut writer, &payload)?;
            writeln!(writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::commands::github::GitCloneMode;
    use crate::cli::commands::github::GitHistoryMode;
    use crate::cli::commands::rules::{RuleCacheArgs, RuleSpecifierArgs};
    use crate::matcher::{SerializableCapture, SerializableCaptures};
    use crate::rules::rule::{Confidence, Rule, RuleSyntax};
    use crate::util::intern;
    use crate::{
        blob::BlobId,
        cli::commands::azure::AzureRepoType,
        cli::commands::bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
        cli::commands::gitea::GiteaRepoType,
        cli::commands::github::GitHubRepoType,
        cli::commands::inputs::ContentFilteringArgs,
        cli::commands::inputs::InputSpecifierArgs,
        cli::commands::output::{OutputArgs, ReportOutputFormat},
        cli::commands::scan::ConfidenceLevel,
        findings_store::FindingsStore,
        location::{Location, OffsetSpan, SourcePoint, SourceSpan},
        matcher::Match,
        origin::Origin,
        reporter::styles::Styles,
        validation_body,
    };
    use smallvec::smallvec;
    use std::{
        io::Cursor,
        path::PathBuf,
        sync::{Arc, Mutex},
    };
    use url::Url;
    fn create_default_args() -> cli::commands::scan::ScanArgs {
        use crate::cli::commands::gitlab::GitLabRepoType; // bring enum into scope

        cli::commands::scan::ScanArgs {
            num_jobs: 1,
            no_dedup: false,
            view_report: false,
            rules: RuleSpecifierArgs {
                rules_path: Vec::new(),
                rule: vec!["all".into()],
                load_builtins: true,
            },
            rule_cache: RuleCacheArgs::default(),
            input_specifier_args: InputSpecifierArgs {
                // local path / git URL inputs
                path_inputs: Vec::new(),
                git_url: Vec::new(),
                git_clone_dir: None,
                keep_clones: false,
                repo_clone_limit: None,
                include_contributors: false,

                // GitHub
                github_user: Vec::new(),
                github_organization: Vec::new(),
                github_exclude: Vec::new(),
                all_github_organizations: false,
                github_api_url: Url::parse("https://api.github.com/").unwrap(),
                github_repo_type: GitHubRepoType::Source,

                // GitLab
                gitlab_user: Vec::new(),
                gitlab_group: Vec::new(),
                gitlab_exclude: Vec::new(),
                all_gitlab_groups: false,
                gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
                gitlab_repo_type: GitLabRepoType::All,
                gitlab_include_subgroups: false,

                // Hugging Face
                huggingface_user: Vec::new(),
                huggingface_organization: Vec::new(),
                huggingface_model: Vec::new(),
                huggingface_dataset: Vec::new(),
                huggingface_space: Vec::new(),
                huggingface_exclude: Vec::new(),

                // Gitea
                gitea_user: Vec::new(),
                gitea_organization: Vec::new(),
                gitea_exclude: Vec::new(),
                all_gitea_organizations: false,
                gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
                gitea_repo_type: GiteaRepoType::Source,

                // Bitbucket
                bitbucket_user: Vec::new(),
                bitbucket_workspace: Vec::new(),
                bitbucket_project: Vec::new(),
                bitbucket_exclude: Vec::new(),
                all_bitbucket_workspaces: false,
                bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/").unwrap(),
                bitbucket_repo_type: BitbucketRepoType::Source,
                bitbucket_auth: BitbucketAuthArgs::default(),
                // Azure DevOps
                azure_organization: Vec::new(),
                azure_project: Vec::new(),
                azure_exclude: Vec::new(),
                all_azure_projects: false,
                azure_base_url: Url::parse("https://dev.azure.com/").unwrap(),
                azure_repo_type: AzureRepoType::Source,
                // Jira options
                jira_url: None,
                jql: None,
                jira_include_comments: false,
                jira_include_changelog: false,
                // Confluence options
                confluence_url: None,
                cql: None,
                max_results: 100,
                // Slack options
                slack_query: None,
                slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
                teams_query: None,
                teams_api_url: Url::parse("https://graph.microsoft.com/").unwrap(),
                postman_workspaces: Vec::new(),
                postman_collections: Vec::new(),
                postman_environments: Vec::new(),
                postman_all: false,
                postman_include_mocks_monitors: false,
                postman_api_url: Url::parse("https://api.getpostman.com/").unwrap(),
                // s3
                s3_bucket: None,
                s3_prefix: None,
                role_arn: None,
                aws_local_profile: None,
                gcs_bucket: None,
                gcs_prefix: None,
                gcs_service_account: None,

                docker_image: Vec::new(),
                docker_archive: Vec::new(),
                // clone / history options
                git_clone: GitCloneMode::Bare,
                git_history: GitHistoryMode::Full,
                commit_metadata: true,
                repo_artifacts: false,
                scan_nested_repos: true,
                since_commit: None,
                branch: None,
                branch_root: false,
                branch_root_commit: None,
                staged: false,
            },
            extra_ignore_comments: Vec::new(),
            content_filtering_args: ContentFilteringArgs {
                max_file_size_mb: 25.0,
                no_extract_archives: false,
                extraction_depth: 2,
                exclude: Vec::new(), // Exclude patterns
                no_binary: true,
            },
            confidence: ConfidenceLevel::Medium,
            no_validate: false,
            access_map: false,
            rule_stats: false,
            only_valid: false,
            min_entropy: None,
            redact: false,
            git_repo_timeout: 1800, // 30 minutes
            output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
            baseline_file: None,
            manage_baseline: false,
            skip_regex: Vec::new(),
            skip_word: Vec::new(),
            skip_aws_account: Vec::new(),
            skip_aws_account_file: None,
            no_base64: false,
            turbo: false,
            no_inline_ignore: false,
            no_ignore_if_contains: false,
            view_report_port: 7890,
            view_report_address: "127.0.0.1".to_string(),
            validation_timeout: 10,
            validation_retries: 1,
            validation_rps: None,
            validation_rps_rule: Vec::new(),
            full_validation_response: false,
            max_validation_response_length: 2048,
            alert_webhook: Vec::new(),
            alert_format: None,
            alert_on: crate::alerts::AlertOn::Findings,
            alert_min_confidence: cli::commands::scan::ConfidenceLevel::Medium,
            alert_include_secret: false,
            alert_report_url: None,
            alert_detail: crate::alerts::AlertDetail::Auto,
            config_webhook_overrides: Vec::new(),
        }
    }

    fn create_mock_match(rule_name: &str, rule_text_id: &str, validation_success: bool) -> Match {
        let syntax = RuleSyntax {
            name: rule_name.to_string(),
            id: rule_text_id.to_string(),
            pattern: "dummy".to_string(),
            min_entropy: 0.0,
            confidence: Confidence::Medium,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
        };
        let rule = Arc::new(Rule::new(syntax));
        Match {
            location: Location::with_source_span(
                OffsetSpan { start: 10, end: 20 },
                Some(SourceSpan {
                    start: SourcePoint { line: 5, column: 10 },
                    end: SourcePoint { line: 5, column: 20 },
                }),
            ),
            groups: SerializableCaptures {
                captures: smallvec![SerializableCapture {
                    name: Some("token"),
                    match_number: 1,
                    start: 10,
                    end: 20,
                    value: intern("mock_token"),
                }],
            },
            blob_id: BlobId::new(b"mock_blob"),
            finding_fingerprint: 123,
            rule,
            validation_response_body: validation_body::from_string("validation response"),
            validation_response_status: 200,
            validation_success,
            calculated_entropy: 4.5,
            visible: true,
            is_base64: false,
            dependent_captures: std::collections::BTreeMap::new(),
        }
    }

    fn setup_mock_reporter(matches: Vec<ReportMatch>) -> DetailsReporter {
        let mut datastore = FindingsStore::new(PathBuf::from("/tmp"));
        if !matches.is_empty() {
            let blob_metadata = BlobMetadata {
                id: BlobId::new(b"mock_blob"),
                num_bytes: 1024,
                mime_essence: Some("text/plain".to_string()),
                language: Some("Rust".to_string()),
            };
            let dedup = true;
            for m in matches.clone() {
                datastore.record(
                    vec![(
                        Arc::new(OriginSet::new(
                            Origin::from_file(PathBuf::from("/mock/path/file.rs")),
                            vec![],
                        )),
                        Arc::new(blob_metadata.clone()),
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
            audit_context: None,
        }
    }

    #[test]
    fn test_json_format() -> Result<()> {
        let mock_match = create_mock_match("MockRule", "mock_rule_1", true);
        let matches = vec![ReportMatch {
            origin: OriginSet::new(Origin::from_file(PathBuf::from("/mock/path/file.rs")), vec![]),
            blob_metadata: BlobMetadata {
                id: BlobId::new(b"mock_blob"),
                num_bytes: 1024,
                mime_essence: Some("text/plain".to_string()),
                language: Some("Rust".to_string()),
            },
            m: mock_match,
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: validation_body::from_string("validation response"),
            validation_response_status: 200,
            validation_success: true,
        }];
        let reporter = setup_mock_reporter(matches);
        let mut output = Cursor::new(Vec::new());
        reporter.json_format(&mut output, &create_default_args())?;
        let json_output: serde_json::Value = serde_json::from_slice(&output.into_inner())?;
        let findings =
            json_output.get("findings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        assert!(!findings.is_empty(), "JSON output should not be empty");
        let first = &findings[0];
        assert_eq!(first["rule"]["name"], "MockRule");
        assert_eq!(first["finding"]["language"], "Rust");
        Ok(())
    }

    #[test]
    fn test_validation_status_in_json() -> Result<()> {
        let test_cases = vec![(true, "Active Credential"), (false, "Inactive Credential")];
        for (validation_success, expected_status) in test_cases {
            let mock_match = create_mock_match("MockRule", "mock_rule_1", validation_success);
            let matches = vec![ReportMatch {
                origin: OriginSet::new(
                    Origin::from_file(PathBuf::from("/mock/path/file.rs")),
                    vec![],
                ),
                blob_metadata: BlobMetadata {
                    id: BlobId::new(b"mock_blob"),
                    num_bytes: 1024,
                    mime_essence: Some("text/plain".to_string()),
                    language: Some("Rust".to_string()),
                },
                m: mock_match,
                comment: None,
                match_confidence: Confidence::Medium,
                visible: true,
                validation_response_body: validation_body::from_string("validation response"),
                validation_response_status: 200,
                validation_success,
            }];
            let reporter = setup_mock_reporter(matches);
            let mut output = Cursor::new(Vec::new());
            reporter.json_format(&mut output, &create_default_args())?;
            let json_output: serde_json::Value = serde_json::from_slice(&output.into_inner())?;
            let findings =
                json_output.get("findings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            assert!(!findings.is_empty(), "JSON output should not be empty");
            let first = &findings[0];
            let validation_status = first["finding"]["validation"]["status"].as_str().unwrap();
            assert_eq!(validation_status, expected_status);
        }
        Ok(())
    }
}
