use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    blob::BlobMetadata, findings_store, matcher::Match, origin::OriginSet, rules::rule::Confidence,
};
// -------------------------------------------------------------------------------------------------
// FindingData
// -------------------------------------------------------------------------------------------------
/// A set of match data entries
pub type FindingData = Vec<FindingDataEntry>;
// -------------------------------------------------------------------------------------------------
// FindingDataEntry
// -------------------------------------------------------------------------------------------------
/// Data for a single `Match`
#[derive(Debug)]
pub struct FindingDataEntry {
    pub origin: OriginSet,
    pub blob_metadata: BlobMetadata,
    pub match_id: findings_store::MatchIdInt,
    pub match_val: Match,
    pub match_comment: Option<String>,
    pub match_confidence: Confidence,
    pub visible: bool,
    /// Validation Body
    pub validation_response_body: String,

    /// Validation Status Code
    pub validation_response_status: u16,

    /// Validation Success
    pub validation_success: bool,
}
// -------------------------------------------------------------------------------------------------
// FindingMetadata
// -------------------------------------------------------------------------------------------------
/// Metadata for a group of matches that have identical rule name and match
/// content.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct FindingMetadata {
    /// The content-based finding identifier for this group of matches
    pub finding_id: String,

    /// The name of the rule that detected each match
    pub rule_name: String,

    /// The textual identifier of the rule that detected each match
    pub rule_text_id: String,

    /// The structural identifier of the rule that detected each match
    pub rule_finding_fingerprint: String,

    /// Determines if a match is displayed to the user
    pub visible: bool,

    /// The number of matches in the group
    pub num_matches: usize,

    /// A comment assigned to this finding
    pub comment: Option<String>,
}
