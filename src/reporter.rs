use std::{
    fmt::Write,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use http::StatusCode;
use indenter::indented;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    blob::BlobMetadata,
    cli,
    cli::global::GlobalArgs,
    finding_data, findings_store,
    matcher::Match,
    origin::{Origin, OriginSet},
    rules::rule::Confidence,
};
mod bson_format;
mod json_format;
mod pretty_format;
mod sarif_format;
pub mod styles;
use std::{hash::Hash, io::IsTerminal};

use styles::{StyledObject, Styles};

use crate::{
    cli::commands::output::ReportOutputFormat,
    location::SourceSpan,
    origin::{get_repo_url, GitRepoOrigin},
};

pub fn run(
    global_args: &GlobalArgs,
    ds: Arc<Mutex<findings_store::FindingsStore>>,
    args: &cli::commands::scan::ScanArgs,
) -> Result<()> {
    global_args.use_color(std::io::stdout());
    let stdout_is_tty = std::io::stdout().is_terminal();
    let use_color = stdout_is_tty && !args.output_args.has_output();
    let styles = Styles::new(use_color);

    let ds_clone = Arc::clone(&ds);
    // Initialize the reporter
    let reporter = DetailsReporter { datastore: ds_clone, styles, only_valid: args.only_valid };
    let writer = args.output_args.get_writer()?;
    // Generate and write the report in the specified format
    reporter.report(args.output_args.format, writer, args)
}
pub struct DetailsReporter {
    pub datastore: Arc<Mutex<findings_store::FindingsStore>>,
    pub styles: Styles,
    pub only_valid: bool,
}

impl DetailsReporter {
    pub fn extract_git_metadata(
        &self,
        prov: &GitRepoOrigin,
        source_span: &SourceSpan,
    ) -> Option<serde_json::Value> {
        let repo_url = get_repo_url(&prov.repo_path)
            .unwrap_or_else(|_| prov.repo_path.to_string_lossy().to_string().into());
        let repo_url = repo_url.trim_end_matches(".git").to_string();
        if let Some(cs) = &prov.first_commit {
            let cmd = &cs.commit_metadata;
            // let msg =
            //     String::from_utf8_lossy(cmd.message.lines().next().unwrap_or(&[],),).
            // into_owned();

            let atime =
                cmd.committer_timestamp.format(gix::date::time::format::SHORT.clone()).to_string();

            let git_metadata = serde_json::json!({
                "repository_url": repo_url,
                "commit": {
                    "id": cmd.commit_id.to_string(),
                    "url": format!("{}/commit/{}", repo_url, cmd.commit_id),
                    "date": atime,
                    // "author": {
                    //     "name": String::from_utf8_lossy(&cmd.author_name),
                    //     "email": String::from_utf8_lossy(&cmd.author_email),
                    // },
                    // "message": msg,
                },
                "file": {
                    "path": String::from_utf8_lossy(&cs.blob_path),
                    "url": format!(
                        "{}/blob/{}/{}#L{}",
                        repo_url,
                        cmd.commit_id,
                        String::from_utf8_lossy(&cs.blob_path),
                        source_span.start.line
                    ),
                    "git_command": format!(
                        "git -C {} show {}:{}",
                        prov.repo_path.display(),
                        cmd.commit_id,
                        String::from_utf8_lossy(&cs.blob_path)
                    )
                }
            });
            Some(git_metadata)
        } else {
            None
        }
    }
    fn gather_findings(&self) -> Result<Vec<Finding>> {
        let metadata_list = self.get_finding_data()?;
        let all_matches = self.get_filtered_matches()?;
        let mut findings = Vec::new();
        for md in metadata_list {
            // Filter matches that belong to this metadata if needed
            let matches_for_md =
                all_matches.iter().filter(|m| m.m.rule_name == md.rule_name).cloned().collect();
            findings.push(Finding::new(md.clone(), matches_for_md));
        }
        Ok(findings)
    }

    fn process_matches(&self, only_valid: bool, filter_visible: bool) -> Result<Vec<ReportMatch>> {
        let datastore = self.datastore.lock().unwrap();
        Ok(datastore
            .get_matches()
            .iter()
            .filter(|msg| {
                let (_origin, _blob_metadata, match_item) = &***msg;
                if only_valid {
                    // If filter_visible is true, require the match to be visible.
                    if filter_visible {
                        match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                            && match_item.visible
                    } else {
                        // Do not filter by visibility when not needed (for validation)
                        match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                    }
                } else {
                    // When not filtering by only_valid, use visibility if desired.
                    if filter_visible {
                        match_item.visible
                    } else {
                        true
                    }
                }
            })
            .map(|msg| {
                let (origin, blob_metadata, match_item) = &**msg;
                ReportMatch {
                    origin: (**origin).clone(),
                    blob_metadata: (**blob_metadata).clone(),
                    m: match_item.clone(),
                    comment: None,
                    visible: match_item.visible,
                    match_confidence: match_item.rule_confidence,
                    validation_response_body: match_item.validation_response_body.clone(),
                    validation_response_status: match_item.validation_response_status,
                    validation_success: match_item.validation_success,
                }
            })
            .collect())
    }

    // fn process_matches(&self, only_valid: bool) -> Result<Vec<ReportMatch>> {
    //     let datastore = self.datastore.lock().unwrap();
    //     Ok(datastore
    //         .get_matches()
    //         .iter()
    //         .filter(|msg| {
    //             let (_origin, _blob_metadata, match_item) = &***msg;
    //             if only_valid {
    //                 match_item.validation_success
    //                     && match_item.validation_response_status != StatusCode::CONTINUE.as_u16()
    //                     && match_item.visible
    //             } else {
    //                 match_item.visible
    //             }
    //         })
    //         .map(|msg| {
    //             let (origin, blob_metadata, match_item) = &**msg;
    //             ReportMatch {
    //                 origin: origin.clone(),
    //                 blob_metadata: blob_metadata.clone(),
    //                 m: match_item.clone(),
    //                 comment: None,
    //                 visible: match_item.visible,
    //                 match_confidence: match_item.rule_confidence,
    //                 validation_response_body: match_item.validation_response_body.clone(),
    //                 validation_response_status: match_item.validation_response_status,
    //                 validation_success: match_item.validation_success,
    //             }
    //         })
    //         .collect())
    // }

    pub fn get_filtered_matches(&self) -> Result<Vec<ReportMatch>> {
        self.process_matches(self.only_valid, true)
    }

    pub fn get_unfiltered_matches(&self, only_valid: Option<bool>) -> Result<Vec<ReportMatch>> {
        self.process_matches(only_valid.unwrap_or(self.only_valid), false)
    }

    fn get_finding_data(&self) -> Result<Vec<finding_data::FindingMetadata>> {
        let datastore = self.datastore.lock().unwrap();
        Ok(datastore
            .get_finding_data_iter()
            .filter(|metadata| {
                if self.only_valid {
                    datastore.get_matches().iter().any(|msg| {
                        let (_, _, match_item) = &**msg;
                        match_item.rule_name == metadata.rule_name
                            && match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                    })
                } else {
                    true
                }
            })
            .collect())
    }

    fn style_finding_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_finding_heading.apply_to(val)
    }

    fn style_finding_active_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_finding_active_heading.apply_to(val)
    }

    #[allow(dead_code)]
    fn style_rule<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_rule.apply_to(val)
    }

    #[allow(dead_code)]
    fn style_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_heading.apply_to(val)
    }

    fn style_match<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_match.apply_to(val)
    }

    fn style_metadata<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_metadata.apply_to(val)
    }

    fn style_active_creds<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_active_creds.apply_to(val)
    }
}
/// A trait for things that can be output as a document.
///
/// This trait is used to factor output-related code, such as friendly handling
/// of buffering, into one place.
pub trait Reportable {
    type Format;
    fn report<W: std::io::Write>(
        &self,
        format: Self::Format,
        writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()>;
}
impl Reportable for DetailsReporter {
    type Format = ReportOutputFormat;

    fn report<W: std::io::Write>(
        &self,
        format: Self::Format,
        writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        match format {
            ReportOutputFormat::Pretty => self.pretty_format(writer, args),
            ReportOutputFormat::Json => self.json_format(writer, args),
            ReportOutputFormat::Jsonl => self.jsonl_format(writer, args),
            ReportOutputFormat::Bson => self.bson_format(writer, args),
            ReportOutputFormat::Sarif => self.sarif_format(writer, args.no_dedup),
        }
    }
}
/// A group of matches that all have the same rule and capture group content
#[derive(Serialize, JsonSchema)]
pub(crate) struct Finding {
    #[serde(flatten)]
    metadata: finding_data::FindingMetadata,
    matches: Vec<ReportMatch>,
}
/// A match produced by one of kingfisher's rules.
/// This corresponds to a single location.
#[derive(Serialize, JsonSchema, Clone)]
pub struct ReportMatch {
    pub origin: OriginSet,

    #[serde(rename = "blob_metadata")]
    pub blob_metadata: BlobMetadata,

    #[serde(flatten)]
    pub m: Match,

    /// An optional score assigned to the match
    // #[validate(range(min = 0.0, max = 1.0))]
    // score: Option<f64>,

    /// An optional comment assigned to the match
    pub comment: Option<String>,

    pub match_confidence: Confidence,

    pub visible: bool,
    /// An optional status assigned to the match
    // status: Option<finding_data::Status>,

    /// Validation Body
    pub validation_response_body: String,

    /// Validation Status Code
    pub validation_response_status: u16,

    /// Validation Success
    pub validation_success: bool,
}
impl From<finding_data::FindingDataEntry> for ReportMatch {
    fn from(e: finding_data::FindingDataEntry) -> Self {
        ReportMatch {
            origin: e.origin,
            blob_metadata: e.blob_metadata,
            m: e.match_val,
            comment: e.match_comment,
            visible: e.visible,
            match_confidence: e.match_confidence,
            validation_response_body: e.validation_response_body.clone(),
            validation_response_status: e.validation_response_status,
            validation_success: e.validation_success,
        }
    }
}
impl Finding {
    fn new(metadata: finding_data::FindingMetadata, matches: Vec<ReportMatch>) -> Self {
        Self { metadata, matches }
    }
}
