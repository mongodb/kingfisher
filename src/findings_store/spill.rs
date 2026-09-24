//! Private, temporary storage for completed repository findings. This is deliberately
//! independent of report serialization: redaction must never alter validator inputs.
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use super::FindingsStoreMessage;
use crate::{
    blob::{BlobId, BlobMetadata},
    location::{CompactSourceSpan, Location, OffsetSpan},
    matcher::{Match, SerializableCapture, SerializableCaptures},
    origin::{Origin, OriginSet},
    rules::rule::Rule,
    util::intern,
};

pub(super) struct FindingsSpill {
    file: File,
    count: usize,
    #[cfg(test)]
    pub(super) write_failure: Option<(usize, std::io::ErrorKind)>,
}

pub(super) enum AppendOutcome {
    Written,
    StorageFull,
}

pub(super) fn is_storage_full(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::StorageFull)
}

fn write_records(writer: impl Write, messages: &[Arc<FindingsStoreMessage>]) -> Result<()> {
    let mut writer = BufWriter::new(writer);
    for message in messages {
        serde_json::to_writer(&mut writer, &SpillMessage(message)).map_err(std::io::Error::from)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
struct FailingWriter<'a> {
    file: &'a mut File,
    remaining: usize,
    kind: std::io::ErrorKind,
}

#[cfg(test)]
impl Write for FailingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(self.kind.into());
        }
        let written = self.file.write(&bytes[..bytes.len().min(self.remaining)])?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl FindingsSpill {
    pub(super) fn new() -> Result<Self> {
        // tempfile creates a private file and removes it automatically, including on errors.
        Ok(Self {
            file: tempfile::tempfile()?,
            count: 0,
            #[cfg(test)]
            write_failure: None,
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(super) fn append(
        &mut self,
        messages: &[Arc<FindingsStoreMessage>],
    ) -> Result<AppendOutcome> {
        let offset = self.file.seek(SeekFrom::End(0))?;
        #[cfg(not(test))]
        let result = write_records(&mut self.file, messages);
        #[cfg(test)]
        let result = match self.write_failure.take() {
            Some((remaining, kind)) => {
                write_records(FailingWriter { file: &mut self.file, remaining, kind }, messages)
            }
            None => write_records(&mut self.file, messages),
        };
        if let Err(error) = result {
            // Restore the last complete batch before permitting any in-memory fallback.
            // A rollback failure is fatal: the file may contain a partial record.
            self.file.set_len(offset).context("Failed to roll back temporary findings storage")?;
            if is_storage_full(&error) {
                return Ok(AppendOutcome::StorageFull);
            }
            return Err(error);
        }
        self.count += messages.len();
        Ok(AppendOutcome::Written)
    }

    pub(super) fn read_batches(
        &mut self,
        rules: &[Arc<Rule>],
        mut consume: impl FnMut(Vec<FindingsStoreMessage>),
    ) -> Result<()> {
        self.file.rewind()?;
        let rules_by_id = rules.iter().map(|rule| (rule.id(), rule)).collect();
        let mut reader = BufReader::new(&mut self.file);
        let mut line = String::new();
        let mut batch = Vec::with_capacity(1024);
        let mut count = 0;
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let record: Record = serde_json::from_str(&line)?;
            batch.push(record.into_message(&rules_by_id)?);
            count += 1;
            if batch.len() == 1024 {
                consume(std::mem::replace(&mut batch, Vec::with_capacity(1024)));
            }
        }
        anyhow::ensure!(count == self.count, "Incomplete findings spill");
        if !batch.is_empty() {
            consume(batch);
        }
        Ok(())
    }

    pub(super) fn clear(&mut self) -> Result<()> {
        self.file.rewind()?;
        self.file.set_len(0)?;
        self.count = 0;
        Ok(())
    }
}

#[derive(Deserialize)]
struct Capture {
    name: Option<String>,
    match_number: i32,
    start: usize,
    end: usize,
    value: String,
}

#[derive(Deserialize)]
struct Record {
    origins: Vec<Origin>,
    blob_id: BlobId,
    num_bytes: usize,
    mime_essence: Option<String>,
    language: Option<String>,
    rule_id: String,
    match_blob_id: BlobId,
    offset_span: OffsetSpan,
    source_span: Option<CompactSourceSpan>,
    captures: Vec<Capture>,
    finding_fingerprint: u64,
    validation_response_body: crate::validation_body::ValidationResponseBody,
    validation_response_status: u16,
    validation_success: bool,
    validation_outcome: kingfisher_core::ValidationOutcome,
    calculated_entropy: f32,
    visible: bool,
    is_base64: bool,
    dependent_captures: std::collections::BTreeMap<String, String>,
    ambiguous_dependencies: std::collections::BTreeMap<String, usize>,
    #[serde(default)]
    dependency_candidates: std::collections::BTreeMap<String, Vec<String>>,
}

/// Serialize the internal values by reference. Report serializers can redact
/// captures, and cloning a large response just to spill it would raise the peak.
struct SpillMessage<'a>(&'a FindingsStoreMessage);

#[derive(Serialize)]
struct CaptureRef<'a> {
    name: Option<&'a str>,
    match_number: i32,
    start: usize,
    end: usize,
    value: &'a str,
}

impl Serialize for SpillMessage<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let (origins, blob, m) = self.0;
        let captures: smallvec::SmallVec<[CaptureRef<'_>; 2]> = m
            .groups
            .captures
            .iter()
            .map(|c| CaptureRef {
                name: c.name,
                match_number: c.match_number,
                start: c.start,
                end: c.end,
                value: c.raw_value(),
            })
            .collect();
        let mut record = serializer.serialize_struct("Record", 21)?;
        record.serialize_field("origins", origins)?;
        record.serialize_field("blob_id", &blob.id)?;
        record.serialize_field("num_bytes", &blob.num_bytes)?;
        record.serialize_field("mime_essence", &blob.mime_essence)?;
        record.serialize_field("language", &blob.language)?;
        record.serialize_field("rule_id", m.rule.id())?;
        record.serialize_field("match_blob_id", &m.blob_id)?;
        record.serialize_field("offset_span", &m.location.offset_span)?;
        record.serialize_field("source_span", &m.location.source_span)?;
        record.serialize_field("captures", &captures)?;
        record.serialize_field("finding_fingerprint", &m.finding_fingerprint)?;
        record.serialize_field("validation_response_body", &m.validation_response_body)?;
        record.serialize_field("validation_response_status", &m.validation_response_status)?;
        record.serialize_field("validation_success", &m.validation_success)?;
        record.serialize_field("validation_outcome", &m.validation_outcome)?;
        record.serialize_field("calculated_entropy", &m.calculated_entropy)?;
        record.serialize_field("visible", &m.visible)?;
        record.serialize_field("is_base64", &m.is_base64)?;
        record.serialize_field("dependent_captures", &m.dependent_captures)?;
        record.serialize_field("ambiguous_dependencies", &m.ambiguous_dependencies)?;
        record.serialize_field("dependency_candidates", &m.dependency_candidates)?;
        record.end()
    }
}

impl Record {
    fn into_message(self, rules: &FxHashMap<&str, &Arc<Rule>>) -> Result<FindingsStoreMessage> {
        let rule = rules
            .get(self.rule_id.as_str())
            .copied()
            .ok_or_else(|| anyhow!("Spilled finding references unknown rule {}", self.rule_id))?;
        let origins = OriginSet::try_from_iter(self.origins)
            .ok_or_else(|| anyhow!("Spilled finding has no origin"))?;
        let blob = BlobMetadata {
            id: self.blob_id,
            num_bytes: self.num_bytes,
            mime_essence: self.mime_essence,
            language: self.language,
        };
        let m = Match {
            rule: Arc::clone(rule),
            blob_id: self.match_blob_id,
            location: Location { offset_span: self.offset_span, source_span: self.source_span },
            groups: SerializableCaptures {
                captures: self
                    .captures
                    .into_iter()
                    .map(|c| SerializableCapture {
                        name: c.name.as_deref().map(intern),
                        match_number: c.match_number,
                        start: c.start,
                        end: c.end,
                        value: c.value.into(),
                    })
                    .collect(),
            },
            finding_fingerprint: self.finding_fingerprint,
            validation_response_body: self.validation_response_body,
            validation_response_status: self.validation_response_status,
            validation_success: self.validation_success,
            validation_outcome: self.validation_outcome,
            calculated_entropy: self.calculated_entropy,
            visible: self.visible,
            is_base64: self.is_base64,
            dependent_captures: self.dependent_captures,
            ambiguous_dependencies: self.ambiguous_dependencies,
            dependency_candidates: self.dependency_candidates,
        };
        Ok((Arc::new(origins), Arc::new(blob), m))
    }
}
