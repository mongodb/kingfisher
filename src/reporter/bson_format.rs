use bson::Document;
use serde_json::Value;

use super::*;
impl DetailsReporter {
    /// Formats findings as BSON and writes them to the provided writer.
    /// For testing purposes, prints the full JSON for each finding before converting.
    pub fn bson_format<W: std::io::Write>(
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

        let mut bson_findings = Vec::new();

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

                    // Process to JSON first, then convert to BSON
                    let json_finding = self.process_match_to_json(&single_origin_rm)?;
                    if let Ok(bson_doc) = json_to_bson_document(&json_finding) {
                        bson_findings.push(bson_doc);
                    }
                }
            } else {
                // Process normally for deduped matches or matches with only one origin
                let json_finding = self.process_match_to_json(&rm)?;
                if let Ok(bson_doc) = json_to_bson_document(&json_finding) {
                    bson_findings.push(bson_doc);
                }
            }
        }

        // Write each BSON document
        for doc in bson_findings {
            doc.to_writer(&mut writer)?;
        }
        Ok(())
    }
    // pub fn bson_format<W: std::io::Write>(
    //     &self,
    //     mut writer: W,
    //     args: &cli::commands::scan::ScanArgs,
    // ) -> Result<()> {
    //     let findings = self.gather_json_findings(args)?;

    //     // Print the full JSON for each finding
    //     for finding in &findings {
    //         println!("Full JSON:\n{}", serde_json::to_string_pretty(finding)?);
    //     }

    //     let bson_findings: Vec<Document> = findings
    //         .into_iter()
    //         .filter_map(|finding| json_to_bson_document(&finding).ok())
    //         .collect();
    //     for doc in bson_findings {
    //         doc.to_writer(&mut writer)?;
    //     }
    //     Ok(())
    // }
}

fn json_to_bson_document(json: &Value) -> Result<Document> {
    match bson::to_bson(json)? {
        bson::Bson::Document(doc) => Ok(doc),
        _ => Err(anyhow::anyhow!("Failed to convert JSON to BSON document")),
    }
}
