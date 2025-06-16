use std::fmt::{Display, Formatter, Result as FmtResult};

use http::StatusCode;

use super::*;
use crate::{
    bstring_escape::Escaped,
    origin::{get_repo_url, GitRepoOrigin},
};
impl DetailsReporter {
    // Modified pretty format to use deduplicate_matches helper
    pub fn pretty_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let mut matches = self.get_filtered_matches()?;
        let num_findings = matches.len();

        if !args.no_dedup {
            matches = self.deduplicate_matches(matches, args.no_dedup);
        }

        for (index, rm) in matches.into_iter().enumerate() {
            // When no_dedup is true, we'll handle each origin separately
            if args.no_dedup && rm.origin.len() > 1 {
                // For each origin, create a separate "finding"
                for origin in rm.origin.iter() {
                    // Create a new ReportMatch with just this single origin
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

                    self.write_finding(
                        &mut writer,
                        &single_origin_rm,
                        index + 1,
                        num_findings,
                        args,
                    )?;
                }
            } else {
                // Normal processing for deduped matches or matches with only one origin
                self.write_finding(&mut writer, &rm, index + 1, num_findings, args)?;
            }
        }
        Ok(())
    }

    fn write_finding<W: std::io::Write>(
        &self,
        writer: &mut W,
        rm: &ReportMatch,
        _finding_num: usize,
        _num_findings: usize,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let lock_icon = if rm.validation_success { "🔓 " } else { "" };
        let formatted_heading = format!(
            "{}{} => [{}]",
            lock_icon,
            rm.m.rule_name.to_uppercase(),
            rm.m.rule_text_id.to_uppercase()
        );
        if rm.validation_success {
            writeln!(writer, "{}", self.style_finding_active_heading(formatted_heading))?;
        } else {
            writeln!(writer, "{}", self.style_finding_heading(formatted_heading))?;
        }
        writeln!(writer, "{}", PrettyFinding(self, rm, args))?;
        writeln!(writer)?;
        Ok(())
    }

    fn write_git_metadata(
        &self,
        f: &mut Formatter<'_>,
        e: &GitRepoOrigin,
        _args: &cli::commands::scan::ScanArgs,
        line_num: usize,
    ) -> FmtResult {
        // Check if this is a remote git scan
        // let mut is_remote_git_scan = !args.input_specifier_args.git_url.is_empty();
        // let mut git_url_string = String::new();
        let repo_url = get_repo_url(&e.repo_path)
            .unwrap_or_else(|_| e.repo_path.to_string_lossy().to_string().into());
        let mut git_url_string = repo_url.clone();
        if git_url_string.ends_with(".git") {
            git_url_string = git_url_string.strip_suffix(".git").unwrap().to_string().into();
        }
        writeln!(f, " |Git Repo......: {}", self.style_metadata(&git_url_string),)?;
        if let Some(cs) = &e.first_commit {
            let cmd = &cs.commit_metadata;

            let atime =
                cmd.committer_timestamp.format(gix::date::time::format::SHORT.clone()).to_string();

            let commit_id = &cmd.commit_id;
            let commit_url = format!("{}/commit/{}", &git_url_string, commit_id);
            // Write Commit Information
            writeln!(f, " |__Commit......: {}", self.style_metadata(&commit_url))?;
            writeln!(
                indented(f).with_str(" |__"),
                "Committer...: {} <{}>",
                cmd.committer_name,
                cmd.committer_email
            )?;
            writeln!(indented(f).with_str(" |__"), "Date........: {}", atime)?;
            // writeln!(indented(f).with_str(" |__"), "Summary.....: {}", msg)?;
            writeln!(indented(f).with_str(" |__"), "Path........: {}", cs.blob_path)?;
            // Construct Git Command
            let git_link =
                format!("{}/blob/{}/{}#L{}", &git_url_string, commit_id, cs.blob_path, line_num);
            let git_command =
                format!("git -C {} show {}:{}", e.repo_path.display(), commit_id, cs.blob_path);
            writeln!(
                indented(f).with_str(" |__"),
                "Git Link....: {}",
                self.style_metadata(&git_link)
            )?;
            writeln!(
                indented(f).with_str(" |__"),
                "Git Command.: {}",
                self.style_metadata(&git_command)
            )?;
        }
        Ok(())
    }
}
// pub struct PrettyFinding<'a>(&'a DetailsReporter, &'a Finding);
pub struct PrettyFinding<'a>(
    &'a DetailsReporter,
    &'a ReportMatch,
    &'a cli::commands::scan::ScanArgs,
);
impl<'a> Display for PrettyFinding<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let PrettyFinding(reporter, rm, args) = self;
        // Use Box<dyn Fn(&str) -> String> to store the closure
        let style_fn: Box<dyn Fn(&str) -> String> = if rm.validation_success {
            Box::new(|s: &str| reporter.style_active_creds(s).to_string()) // Convert StyledObject
                                                                           // to String
        } else {
            Box::new(|s: &str| reporter.style_match(s).to_string()) // Convert StyledObject  to
                                                                    // String
        };
        let matching_finding =
            rm.m.groups
                .captures
                .get(1)
                .or_else(|| rm.m.groups.captures.get(0))
                .map(|capture| capture.value.as_bytes())
                .unwrap_or(&[]);
        writeln!(f, " |Finding.......: {}", style_fn(&Escaped(matching_finding).to_string()))?;
        writeln!(f, " |Fingerprint...: {}", rm.m.finding_fingerprint)?;
        writeln!(f, " |Confidence....: {}", rm.match_confidence.to_string())?;
        writeln!(f, " |Entropy.......: {:.2}", rm.m.calculated_entropy)?;
        let validation_status = if rm.validation_response_status == StatusCode::CONTINUE.as_u16() {
            "Not Attempted".to_string()
        } else if rm.validation_success {
            "Active Credential".to_string()
        } else {
            "Inactive Credential".to_string()
        };
        writeln!(
            f,
            " |Validation....: {}",
            if rm.validation_success {
                reporter.style_finding_active_heading(&validation_status).to_string()
            // Convert StyledObject to String
            } else {
                (&validation_status).to_string()
            }
        )?;
        const MAX_RESPONSE_LENGTH: usize = 512;
        if rm.validation_response_status != StatusCode::CONTINUE.as_u16() {
            let truncated_body: String =
                rm.validation_response_body.chars().take(MAX_RESPONSE_LENGTH).collect();
            let ellipsis =
                if rm.validation_response_body.len() > MAX_RESPONSE_LENGTH { "..." } else { "" };
            writeln!(
                f,
                " |__Response....: {}{}",
                if rm.validation_success {
                    reporter.style_active_creds(&truncated_body).to_string() // Convert StyledObject
                                                                             // to String
                } else {
                    reporter.style_metadata(&truncated_body).to_string() // Convert StyledObject to
                                                                         // String
                },
                ellipsis
            )?;
        }
        writeln!(
            f,
            " |Language......: {}",
            rm.blob_metadata.language.clone().unwrap_or_else(|| "Unknown".to_string())
        )?;

        let source_span = &rm.m.location.source_span;
        writeln!(f, " |Line Num......: {}", source_span.start.line)?;

        //print all the other areas where this was seen
        for p in rm.origin.iter() {
            match p {
                Origin::File(e) => {
                    writeln!(
                        f,
                        " |Path..........: {}",
                        if rm.validation_success {
                            reporter.style_active_creds(e.path.display()).to_string().to_string()
                        // Convert StyledObject to String
                        } else {
                            e.path.display().to_string()
                        }
                    )?;
                }
                Origin::GitRepo(e) => {
                    reporter.write_git_metadata(f, e, args, source_span.start.line)?;
                }
                Origin::Extended(e) => {
                    writeln!(f, " |Extended......: {}", reporter.style_metadata(e).to_string())?;
                    // Convert StyledObject to String
                }
            }
        }
        Ok(())
    }
}

#[test]
fn test_pretty_format_with_nan_entropy_panics() {
    use std::{
        io::Cursor,
        sync::{Arc, Mutex},
    };

    use http::StatusCode;
    use url::Url;

    use crate::{
        blob::BlobMetadata,
        cli::commands::{
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            gitlab::GitLabRepoType,
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::RuleSpecifierArgs,
            scan::{ConfidenceLevel, ScanArgs},
        },
        location::{Location, OffsetSpan, SourcePoint, SourceSpan},
        matcher::{Match, SerializableCaptures},
        origin::{Origin, OriginSet},
        reporter::{DetailsReporter, Styles},
    };

    // Construct a fake match with NaN entropy
    let m = Match {
        rule_name: "dummy_rule".into(),
        rule_text_id: "dummy.id".into(),
        finding_fingerprint: 123456789,
        rule_finding_fingerprint: "abc".into(),
        location: Location {
            offset_span: OffsetSpan { start: 0, end: 1 },
            source_span: SourceSpan {
                start: SourcePoint { line: 1, column: 0 },
                end: SourcePoint { line: 1, column: 10 },
            },
        },
        blob_id: crate::blob::BlobId::default(),
        groups: SerializableCaptures { captures: vec![] },
        rule_confidence: crate::rules::rule::Confidence::Medium,
        validation_success: true,
        validation_response_status: StatusCode::OK.as_u16(),
        validation_response_body: "OK".into(),
        calculated_entropy: f32::NAN, // Here's the trigger
        visible: true,
    };

    let _rm = crate::reporter::ReportMatch {
        origin: OriginSet::new(Origin::from_file("dummy.txt".into()), vec![]),
        blob_metadata: BlobMetadata {
            id: m.blob_id,
            num_bytes: 1,
            mime_essence: None,
            charset: None,
            language: Some("Rust".into()),
        },
        m,
        comment: None,
        visible: true,
        match_confidence: crate::rules::rule::Confidence::Medium,
        validation_response_body: "OK".into(),
        validation_response_status: StatusCode::OK.as_u16(),
        validation_success: true,
    };

    let store = Arc::new(Mutex::new(crate::findings_store::FindingsStore::new(".".into())));
    let reporter =
        DetailsReporter { datastore: store, styles: Styles::new(false), only_valid: false };

    let mut buf = Cursor::new(Vec::new());
    let args = ScanArgs {
        // core execution / performance
        num_jobs: 1,
        no_dedup: false,

        // rule selection
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },

        // input discovery
        input_specifier_args: InputSpecifierArgs {
            path_inputs: Vec::new(),
            git_url: Vec::new(),
            github_user: Vec::new(),
            github_organization: Vec::new(),
            all_github_organizations: false,
            github_api_url: url::Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            // new GitLab defaults
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
            gitlab_repo_type: GitLabRepoType::Owner,

            // git clone / history options
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::Full,
            scan_nested_repos: true,
            commit_metadata: true,
        },

        // content filtering
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 25.0,
            no_extract_archives: false,
            extraction_depth: 2,
            ignore: Vec::new(),
            no_binary: true,
        },

        // scanning behaviour
        confidence: ConfidenceLevel::Medium,
        no_validate: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: None,
        redact: false,
        git_repo_timeout: 1800, // 30 minutes

        // output
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },

        // display
        snippet_length: 256,
    };

    // This will panic if the entropy isn't checked for NaN
    let _result = reporter.pretty_format(&mut buf, &args);
    // assert!(result.is_err() || result.is_ok(), "Should not crash"); // remove this line if panic
    // is expected pre-fix
}
