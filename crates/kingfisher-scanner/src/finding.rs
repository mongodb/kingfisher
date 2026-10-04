//! Finding types representing detected secrets.

use std::collections::HashMap;
use std::sync::Arc;

use kingfisher_core::{BlobId, Location};
use kingfisher_rules::{Confidence, Rule};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// A secret finding detected by the scanner.
///
/// This is the main output type from scanning operations. It contains all
/// information about a detected secret, including location, rule metadata,
/// and capture groups.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Finding {
    /// The rule that matched.
    #[serde(skip_serializing)]
    #[schemars(skip)]
    pub rule: Arc<Rule>,

    /// The rule's unique identifier.
    pub rule_id: String,

    /// The rule's human-readable name.
    pub rule_name: String,

    /// The matched secret value (may be redacted).
    pub secret: String,

    /// Location information (byte offsets and line/column).
    pub location: FindingLocation,

    /// Confidence level of the finding.
    pub confidence: Confidence,

    /// Shannon entropy of the matched secret.
    pub entropy: f32,

    /// Content-based fingerprint for deduplication.
    pub fingerprint: u64,

    /// Named capture groups from the regex match.
    #[serde(default)]
    pub captures: HashMap<String, String>,

    /// Whether the secret was found in Base64-encoded content.
    pub is_base64_encoded: bool,

    /// The blob ID where this finding was detected.
    pub blob_id: BlobId,
}

impl Finding {
    /// Returns the rule that produced this finding.
    pub fn rule(&self) -> &Rule {
        &self.rule
    }

    /// Returns true if this is a high-confidence finding.
    pub fn is_high_confidence(&self) -> bool {
        self.confidence == Confidence::High
    }

    /// Returns the start line (1-indexed).
    pub fn line(&self) -> usize {
        self.location.line
    }

    /// Returns the start byte column (0-indexed).
    pub fn column(&self) -> usize {
        self.location.column
    }
}

/// Location information for a finding.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FindingLocation {
    /// Start byte offset (0-indexed).
    pub start_offset: usize,

    /// End byte offset (exclusive).
    pub end_offset: usize,

    /// Start line number (1-indexed).
    pub line: usize,

    /// Start byte column (0-indexed).
    pub column: usize,

    /// End line number (1-indexed).
    pub end_line: usize,

    /// End byte column (0-indexed).
    pub end_column: usize,
}

impl FindingLocation {
    /// Creates a location from an offset span and optional source span.
    pub fn from_location(location: &Location) -> Self {
        let source_span = location.resolved_source_span();
        Self {
            start_offset: location.offset_span.start,
            end_offset: location.offset_span.end,
            line: source_span.start.line,
            column: source_span.start.column,
            end_line: source_span.end.line,
            end_column: source_span.end.column,
        }
    }

    /// Creates a location from raw offset span values.
    pub fn from_offsets(start: usize, end: usize) -> Self {
        Self {
            start_offset: start,
            end_offset: end,
            line: 0,
            column: 0,
            end_line: 0,
            end_column: 0,
        }
    }

    /// Creates a location with full source information.
    pub fn new(
        start_offset: usize,
        end_offset: usize,
        line: usize,
        column: usize,
        end_line: usize,
        end_column: usize,
    ) -> Self {
        Self { start_offset, end_offset, line, column, end_line, end_column }
    }
}

impl From<&Location> for FindingLocation {
    fn from(location: &Location) -> Self {
        Self::from_location(location)
    }
}

/// A serializable representation of a single regex capture.
#[derive(Debug, Clone, JsonSchema)]
pub struct SerializableCapture {
    /// The name of the capture group (if named).
    pub name: Option<String>,
    /// The capture group number (1-indexed for explicit groups).
    pub match_number: i32,
    /// Start byte offset of the capture.
    pub start: usize,
    /// End byte offset of the capture.
    pub end: usize,
    /// The owned captured value, released when the capture is dropped.
    pub value: String,
}

impl SerializableCapture {
    /// Returns the raw captured value.
    pub fn raw_value(&self) -> &str {
        &self.value
    }

    /// Returns the value for display (may be redacted).
    pub fn display_value(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed(&self.value)
    }
}

impl serde::Serialize for SerializableCapture {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("SerializableCapture", 5)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("match_number", &self.match_number)?;
        state.serialize_field("start", &self.start)?;
        state.serialize_field("end", &self.end)?;
        let value = self.display_value();
        state.serialize_field("value", &value)?;
        state.end()
    }
}

/// A collection of serializable captures from a regex match.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SerializableCaptures {
    /// All captures from the match.
    #[schemars(with = "Vec<SerializableCapture>")]
    pub captures: SmallVec<[SerializableCapture; 2]>,
}

impl SerializableCaptures {
    /// Create SerializableCaptures from regex captures.
    pub fn from_captures(
        captures: &regex::bytes::Captures,
        _input: &[u8],
        re: &regex::bytes::Regex,
    ) -> Self {
        let mut serialized_captures: SmallVec<[SerializableCapture; 2]> = SmallVec::new();

        let capture_names: SmallVec<[Option<String>; 4]> =
            re.capture_names().map(|name| name.map(str::to_owned)).collect();

        // If there are explicit capture groups, serialize those
        if captures.len() > 1 {
            for i in 1..captures.len() {
                if let Some(cap) = captures.get(i) {
                    let raw_value = String::from_utf8_lossy(cap.as_bytes());
                    let value = raw_value.into_owned();
                    let name = capture_names.get(i).and_then(Clone::clone);

                    serialized_captures.push(SerializableCapture {
                        name,
                        match_number: i32::try_from(i).unwrap_or(0),
                        start: cap.start(),
                        end: cap.end(),
                        value,
                    });
                }
            }
        } else if captures.len() == 1 {
            // Only full match exists, serialize that
            if let Some(cap) = captures.get(0) {
                let raw_value = String::from_utf8_lossy(cap.as_bytes());
                let value = raw_value.into_owned();
                let name = capture_names.first().and_then(Clone::clone);

                serialized_captures.push(SerializableCapture {
                    name,
                    match_number: 0,
                    start: cap.start(),
                    end: cap.end(),
                    value,
                });
            }
        }

        SerializableCaptures { captures: serialized_captures }
    }
}
