use std::collections::HashMap;

use rayon::prelude::*;
use serde_sarif::sarif;

use super::*;
use crate::{bstring_escape::Escaped, defaults::get_builtin_rules, origin::get_repo_url};
#[derive(Hash, Eq, PartialEq)]
struct LocationKey {
    file_path: String,
    line: usize,
    column_start: usize,
    column_end: usize,
    text: String,
}
impl DetailsReporter {
    fn make_sarif_result(&self, finding: &Finding, no_dedup: bool) -> Result<sarif::Result> {
        // Deduplicate exactly as in the JSON reporter
        // let matches = self.deduplicate_matches(finding.matches.clone(), no_dedup);
        // Deduplicate exactly as in the JSON reporter - but only if no_dedup is false
        let matches = if no_dedup {
            finding.matches.clone()
        } else {
            self.deduplicate_matches(finding.matches.clone(), no_dedup)
        };

        let metadata = &finding.metadata;

        let mut location_map: HashMap<LocationKey, Vec<(&OriginSet, &Match)>> = HashMap::new();
        for rm in &matches {
            let source_span = &rm.m.location.source_span;
            let snippet =
                rm.m.groups
                    .captures
                    .get(1)
                    .or_else(|| rm.m.groups.captures.get(0))
                    .map(|capture| capture.value.as_bytes())
                    .unwrap_or(&[]);
            let key = LocationKey {
                file_path: rm
                    .origin
                    .first()
                    .blob_path()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                line: source_span.start.line,
                column_start: source_span.start.column,
                column_end: source_span.end.column,
                text: Escaped(snippet).to_string(),
            };
            location_map.entry(key).or_default().push((&rm.origin, &rm.m));
        }

        let mut fpu64: u64 = 0;

        let locations: Vec<sarif::Location> = location_map
            .into_iter()
            .filter_map(|(key, matches)| {
                let (prov, m) = matches[0];
                let source_span = &m.location.source_span;
                let mut artifact_locations = Vec::new();
                let mut git_metadata_list = Vec::new();

                fpu64 = m.finding_fingerprint;

                for p in prov.iter() {
                    match p {
                        Origin::File(e) => {
                            artifact_locations.push(
                                sarif::ArtifactLocationBuilder::default()
                                    .uri(e.path.display().to_string())
                                    .build()
                                    .ok()?,
                            );
                        }
                        Origin::GitRepo(e) => {
                            // Extract and store Git metadata
                            if let Some(git_metadata) = self.extract_git_metadata(e, source_span) {
                                git_metadata_list.push(git_metadata);
                            }

                            // Build Git artifact location
                            if let Some(cs) = &e.first_commit {
                                let repo_url = get_repo_url(&e.repo_path)
                                    .unwrap_or_else(|_| {
                                        e.repo_path.to_string_lossy().to_string().into()
                                    })
                                    .trim_end_matches(".git")
                                    .to_string();
                                let git_url = format!(
                                    "{}/blob/{}/{}#L{}",
                                    repo_url,
                                    cs.commit_metadata.commit_id,
                                    cs.blob_path,
                                    source_span.start.line
                                );
                                artifact_locations.push(
                                    sarif::ArtifactLocationBuilder::default()
                                        .uri(git_url)
                                        .build()
                                        .ok()?,
                                );
                            }
                        }
                        Origin::Extended(_) => (),
                    }
                }

                if artifact_locations.is_empty() {
                    return None;
                }

                let region = sarif::RegionBuilder::default()
                    .start_line(key.line as i64)
                    .start_column(key.column_start as i64)
                    .end_line(key.line as i64)
                    .end_column(key.column_end as i64)
                    .snippet(sarif::ArtifactContentBuilder::default().text(key.text).build().ok()?)
                    .build()
                    .ok()?;

                let logical_location = sarif::LogicalLocationBuilder::default()
                    .kind("blob")
                    .name(m.finding_fingerprint.to_string())
                    .build()
                    .ok()?;

                let validation_status =
                    if m.validation_response_status == StatusCode::CONTINUE.as_u16() {
                        "Not Attempted"
                    } else if m.validation_success {
                        "Active Credential"
                    } else {
                        "Inactive Credential"
                    };

                // Build combined properties including Git metadata and fingerprint
                let mut props = std::collections::BTreeMap::new();
                props.insert("validation_status".to_string(), serde_json::json!(validation_status));

                props.insert(
                    "entropy".to_string(),
                    serde_json::json!(format!("{:.2}", m.calculated_entropy)),
                );

                // Add the fingerprint property from the match
                props.insert("fingerprint".to_string(), serde_json::json!(m.finding_fingerprint));

                if !git_metadata_list.is_empty() {
                    props.insert("git_metadata".to_string(), serde_json::json!(git_metadata_list));
                }

                let properties = sarif::PropertyBagBuilder::default()
                    .additional_properties(props)
                    .build()
                    .ok()?;

                // Create locations for each artifact location
                let locations = artifact_locations
                    .into_iter()
                    .map(|artifact_location| {
                        sarif::LocationBuilder::default()
                            .physical_location(
                                sarif::PhysicalLocationBuilder::default()
                                    .artifact_location(artifact_location)
                                    .region(region.clone())
                                    .build()
                                    .ok()?,
                            )
                            .logical_locations(vec![logical_location.clone()])
                            .properties(properties.clone())
                            .build()
                            .ok()
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some(locations)
            })
            .flatten()
            .collect();
        // let message = sarif::MessageBuilder::default()
        //     .text(format!(
        //         "Rule {} found {} unique {}.\nFirst blob id matched: {}",
        //         metadata.rule_name,
        //         locations.len(),
        //         if locations.len() == 1 { "match" } else { "matches" },
        //         first_match_blob_id
        //     ))
        //     .build()?;
        // Create detailed message from first location's information
        let detailed_msg = if let Some(first_match) = matches.first() {
            let mut msg = format!(
                "Rule {} found {} unique {}.\n",
                metadata.rule_name,
                locations.len(),
                if locations.len() == 1 { "match" } else { "matches" }
            );
            // Add file or Git information based on origin
            // Get first origin of first match - we know this exists
            let p = first_match.origin.first();
            match p {
                Origin::File(e) => {
                    msg.push_str(&format!("Location: {}\n", e.path.display()));
                }
                Origin::GitRepo(e) => {
                    if let Some(cs) = &e.first_commit {
                        let repo_url = get_repo_url(&e.repo_path)
                            .unwrap_or_else(|_| e.repo_path.to_string_lossy().to_string().into())
                            .trim_end_matches(".git")
                            .to_string();
                        // Add commit and author information
                        let cmd = &cs.commit_metadata;
                        msg.push_str(&format!("Repository: {}\n", repo_url));
                        msg.push_str(&format!("Commit: {}\n", cmd.commit_id));
                        msg.push_str(&format!(
                            "Committer: {} <{}>\n",
                            String::from_utf8_lossy(&cmd.committer_name),
                            String::from_utf8_lossy(&cmd.committer_email)
                        ));
                        msg.push_str(&format!("File: {}", cs.blob_path));
                    }
                }
                Origin::Extended(e) => {
                    msg.push_str(&format!("Extended: {}\n", e));
                }
            }
            msg
        } else {
            format!("Rule {} found {} unique matches.", metadata.rule_name, locations.len(),)
        };
        let message = sarif::MessageBuilder::default().text(detailed_msg).build()?;
        let fingerprint_name = "fingerprint".to_string();
        let fingerprint = fpu64.to_string();

        let result = sarif::ResultBuilder::default()
            .rule_id(&metadata.rule_name)
            .message(message)
            .kind(sarif::ResultKind::Review.to_string())
            .locations(locations)
            .level(sarif::ResultLevel::Warning.to_string())
            .partial_fingerprints([(fingerprint_name, fingerprint)])
            .build()?;
        Ok(result)
    }

    pub fn sarif_format<W: std::io::Write>(&self, mut writer: W, no_dedup: bool) -> Result<()> {
        // Gather findings first
        let mut findings = self.gather_findings()?;

        // If no_dedup is true, expand findings with multiple origins into separate findings
        if no_dedup {
            let mut expanded_findings = Vec::new();
            for finding in findings {
                // Check matches with multiple origins
                let matches_with_multiple_origins: Vec<_> =
                    finding.matches.iter().filter(|rm| rm.origin.len() > 1).collect();

                if !matches_with_multiple_origins.is_empty() {
                    // For each match with multiple origins, create separate findings
                    for rm in matches_with_multiple_origins {
                        for origin in rm.origin.iter() {
                            // Create a single-origin match
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

                            // Create a new finding with just this single-origin match
                            let new_finding =
                                Finding::new(finding.metadata.clone(), vec![single_origin_rm]);
                            expanded_findings.push(new_finding);
                        }
                    }
                } else {
                    // If the finding has no matches with multiple origins, keep it as is
                    expanded_findings.push(finding);
                }
            }
            findings = expanded_findings;
        }

        // Filter only rules relevant to the findings
        let finding_rule_ids: std::collections::HashSet<_> =
            findings.iter().map(|f| f.metadata.rule_name.clone()).collect();
        let rules: Vec<sarif::ReportingDescriptor> = get_builtin_rules(None)?
            .iter_rules()
            .par_bridge()
            .filter_map(|rule| {
                if finding_rule_ids.contains(&rule.name) {
                    let help = sarif::MultiformatMessageStringBuilder::default()
                        .text(&rule.references.join("\n"))
                        .build()
                        .ok()?;
                    let description = sarif::MultiformatMessageStringBuilder::default()
                        .text(&rule.name)
                        .build()
                        .ok()?;
                    sarif::ReportingDescriptorBuilder::default()
                        .id(&rule.name)
                        .short_description(description)
                        .help(help)
                        .build()
                        .ok()
                } else {
                    None
                }
            })
            .collect();
        let tool = sarif::ToolBuilder::default()
            .driver(
                sarif::ToolComponentBuilder::default()
                    .name(env!("CARGO_PKG_NAME").to_string())
                    .semantic_version(env!("CARGO_PKG_VERSION").to_string())
                    .full_name(format!("Kingfisher {}", env!("CARGO_PKG_VERSION")))
                    .information_uri(env!("CARGO_PKG_HOMEPAGE").to_string())
                    .download_uri(env!("CARGO_PKG_REPOSITORY").to_string())
                    .short_description(
                        sarif::MultiformatMessageStringBuilder::default()
                            .text(env!("CARGO_PKG_DESCRIPTION"))
                            .build()?,
                    )
                    .rules(rules)
                    .build()?,
            )
            .build()?;
        let sarif_results: Vec<sarif::Result> =
            findings.par_iter().filter_map(|f| self.make_sarif_result(f, no_dedup).ok()).collect();
        let run = sarif::RunBuilder::default().tool(tool).results(sarif_results).build()?;
        let sarif = sarif::SarifBuilder::default()
            .version(sarif::Version::V2_1_0.to_string())
            .schema(sarif::SCHEMA_URL)
            .runs(vec![run])
            .build()?;
        serde_json::to_writer_pretty(&mut writer, &sarif)?;
        writeln!(writer)?;
        Ok(())
    }
}
