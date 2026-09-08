use super::*;
use mongodb::bson;

impl DetailsReporter {
    /// Formats findings as BSON and writes them to the provided writer.
    pub fn bson_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        for record in envelope.findings {
            let doc = bson::to_document(&record)?;
            doc.to_writer(&mut writer)?;
        }

        if let Some(access_map) = envelope.access_map {
            let doc = bson::to_document(&serde_json::json!({ "access_map": access_map }))?;
            doc.to_writer(&mut writer)?;
        }
        if let Some(audit) = envelope.audit {
            let doc = bson::to_document(&serde_json::json!({ "audit": audit }))?;
            doc.to_writer(&mut writer)?;
        }
        Ok(())
    }
}
