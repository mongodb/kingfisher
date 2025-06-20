use std::{
    borrow::Cow,
    // collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    io::Write,
    str,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use bstr::BString;
use http::StatusCode;
use lazy_static::lazy_static;
use regex::bytes::Regex;
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use schemars::{
    gen::SchemaGenerator,
    schema::{ArrayValidation, InstanceType, Schema},
    JsonSchema,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use smallvec::SmallVec;
use tracing::debug;
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    blob::{Blob, BlobId, BlobIdMap},
    entropy::calculate_shannon_entropy,
    location::{Location, LocationMapping, OffsetSpan},
    origin::OriginSet,
    parser,
    parser::{Checker, Language},
    rule_profiling::{ConcurrentRuleProfiler, RuleStats},
    rules::rule::Rule,
    rules_database::RulesDatabase,
    safe_list::is_safe_match,
    scanner_pool::ScannerPool,
    snippet::Base64BString,
    util::{intern, redact_value},
};

// -------------------------------------------------------------------------------------------------
// RawMatch
// -------------------------------------------------------------------------------------------------
/// A raw match, as recorded by a callback to Vectorscan.
///
/// When matching with Vectorscan, we simply collect all matches into a
/// preallocated `Vec`, and then go through them all after scanning is complete.
#[derive(PartialEq, Eq, Debug, Clone)]
struct RawMatch {
    rule_id: u32,
    start_idx: u64,
    end_idx: u64,
}
#[derive(Clone)]
pub struct OwnedBlobMatch {
    pub rule: Arc<Rule>,
    pub blob_id: BlobId,
    /// The unique content-based identifier of this match
    pub finding_fingerprint: u64,
    // pub matching_input: Vec<u8,>,
    pub matching_input_offset_span: OffsetSpan,
    pub captures: SerializableCaptures,
    pub validation_response_body: String,
    pub validation_response_status: StatusCode,
    pub validation_success: bool,
    pub calculated_entropy: f32,
}
impl<'a> Matcher<'a> {
    pub fn get_profiling_report(&self) -> Option<Vec<RuleStats>> {
        self.profiler.as_ref().map(|p| p.generate_report())
    }
}
impl OwnedBlobMatch {
    pub fn convert_match_to_owned_blobmatch(m: &Match, rule: Arc<Rule>) -> OwnedBlobMatch {
        OwnedBlobMatch {
            rule,
            blob_id: m.blob_id,
            finding_fingerprint: m.finding_fingerprint,
            // matching_input: m.snippet.matching.0.to_vec(),
            matching_input_offset_span: m.location.offset_span.clone(),
            captures: m.groups.clone(),
            validation_response_body: m.validation_response_body.clone(),
            validation_response_status: StatusCode::from_u16(m.validation_response_status)
                .unwrap_or(StatusCode::CONTINUE),
            validation_success: m.validation_success,
            calculated_entropy: m.calculated_entropy,
        }
    }

    pub fn from_blob_match(blob_match: BlobMatch) -> Self {
        // Get the matching value from capture group 1 (or 0 if not available)
        let matching_finding = blob_match
            .captures
            .captures
            .get(1)
            .or_else(|| blob_match.captures.captures.get(0))
            .map(|capture| capture.value.as_bytes().to_vec())
            .unwrap_or_else(Vec::new);

        let mut owned_blob_match = OwnedBlobMatch {
            rule: blob_match.rule,
            blob_id: blob_match.blob_id.clone(),
            matching_input_offset_span: blob_match.matching_input_offset_span,
            captures: blob_match.captures.clone(),
            validation_response_body: blob_match.validation_response_body,
            validation_response_status: blob_match.validation_response_status,
            validation_success: blob_match.validation_success,
            calculated_entropy: blob_match.calculated_entropy,
            finding_fingerprint: 0, //default
        };

        // Convert matching_finding to a &str (using lossy conversion if needed)
        let finding_value = std::str::from_utf8(&matching_finding).unwrap_or("");
        // Use blob_id as the file/commit identifier
        let file_or_commit = &blob_match.blob_id.to_string();

        let offset_start: u64 =
            owned_blob_match.matching_input_offset_span.start.try_into().unwrap();
        let offset_end: u64 = owned_blob_match.matching_input_offset_span.end.try_into().unwrap();

        owned_blob_match.finding_fingerprint =
            compute_finding_fingerprint(finding_value, file_or_commit, offset_start, offset_end);

        owned_blob_match
    }
}
// -------------------------------------------------------------------------------------------------
// BlobMatch
// -------------------------------------------------------------------------------------------------
/// A `BlobMatch` is the result type from `Matcher::scan_blob`.
///
/// It is mostly made up of references and small data.
/// For a representation that is more friendly for human consumption, see
/// `Match`.
pub struct BlobMatch<'a> {
    /// The rule that was matched
    pub rule: Arc<Rule>, // Changed from `&'a Rule` to `Arc<Rule

    /// The blob that was matched
    pub blob_id: &'a BlobId,

    /// The matching input in `blob.input`
    pub matching_input: &'a [u8],

    /// The location of the matching input in `blob.input`
    pub matching_input_offset_span: OffsetSpan,

    /// The capture groups from the match
    pub captures: SerializableCaptures, // regex::bytes::Captures<'a>,

    pub validation_response_body: String,
    pub validation_response_status: StatusCode,

    pub validation_success: bool,
    pub calculated_entropy: f32,
}
#[derive(Clone)]
struct UserData {
    /// A scratch vector for raw matches from Vectorscan, to minimize allocation
    raw_matches_scratch: Vec<RawMatch>,

    /// The length of the input being scanned
    input_len: u64,
}
// -------------------------------------------------------------------------------------------------
// Matcher
// -------------------------------------------------------------------------------------------------
/// A `Matcher` is able to scan inputs for matches from rules in a
/// `RulesDatabase`.
///
/// If doing multi-threaded scanning, use a separate `Matcher` for each thread.
#[derive(Clone)]
pub struct Matcher<'a> {
    /// Thread-local pool that hands out a &mut BlockScanner
    scanner_pool: std::sync::Arc<crate::scanner_pool::ScannerPool>,

    /// The rules database used for matching
    rules_db: &'a RulesDatabase,

    /// Local statistics for this `Matcher`
    local_stats: MatcherStats,

    /// Global statistics, updated with the local statsistics when this
    /// `Matcher` is dropped
    global_stats: Option<&'a Mutex<MatcherStats>>,

    /// The set of blobs that have been seen
    seen_blobs: &'a BlobIdMap<bool>,

    /// Data passed to the Vectorscan callback
    user_data: UserData,

    /// Rule profiler for measuring performance of individual rules
    profiler: Option<Arc<ConcurrentRuleProfiler>>,
}
/// This `Drop` implementation updates the `global_stats` with the local stats
impl<'a> Drop for Matcher<'a> {
    fn drop(&mut self) {
        if let Some(global_stats) = self.global_stats {
            let mut global_stats = global_stats.lock().unwrap();
            global_stats.update(&self.local_stats);
        }
    }
}
pub enum ScanResult<'a> {
    SeenWithMatches,
    SeenSansMatches,
    New(Vec<BlobMatch<'a>>),
}
impl<'a> Matcher<'a> {
    /// Create a new `Matcher` from the given `RulesDatabase`.
    ///
    /// If `global_stats` is provided, it will be updated with the local stats
    /// from this `Matcher` when it is dropped.
    pub fn new(
        rules_db: &'a RulesDatabase,
        scanner_pool: Arc<ScannerPool>,
        seen_blobs: &'a BlobIdMap<bool>,
        global_stats: Option<&'a Mutex<MatcherStats>>,
        enable_profiling: bool,
        shared_profiler: Option<Arc<ConcurrentRuleProfiler>>,
    ) -> Result<Self> {
        // Changed: removed `with_capacity(16384)` so we don't pre-allocate a large Vec
        let raw_matches_scratch = Vec::new();
        let user_data = UserData { raw_matches_scratch, input_len: 0 };
        // let vs_scanner = vectorscan_rs::BlockScanner::new(&rules_db.vsdb)?;
        // pool is created once per scan run (see Scanner section below)
        let profiler = shared_profiler.or_else(|| {
            if enable_profiling {
                Some(Arc::new(ConcurrentRuleProfiler::new()))
            } else {
                None
            }
        });
        Ok(Matcher {
            scanner_pool,
            rules_db,
            local_stats: MatcherStats::default(),
            global_stats,
            seen_blobs,
            user_data,
            profiler,
        })
    }

    fn scan_bytes_raw(&mut self, input: &[u8], _filename: &str) -> Result<()> {
        // Remember previous peak automatically
        let prev_capacity = self.user_data.raw_matches_scratch.capacity();
        self.user_data.raw_matches_scratch.clear();
        self.user_data.raw_matches_scratch.reserve(prev_capacity.max(64));

        self.user_data.input_len = input.len() as u64;
        // self.vs_scanner.scan(input, |rid, from, to, _flags| {
        self.scanner_pool.with(|scanner| {
            scanner.scan(input, |rule_id, from, to, _flags| {
                self.user_data.raw_matches_scratch.push(RawMatch {
                    rule_id,
                    start_idx: from,
                    end_idx: to,
                });
                vectorscan_rs::Scan::Continue
            })
        })?;

        Ok(())
    }

    pub fn scan_blob<'b>(
        &mut self,
        blob: &'b Blob,
        origin: &OriginSet,
        lang: Option<String>,
        redact: bool,
        no_dedup: bool,
    ) -> Result<ScanResult<'b>>
    where
        'a: 'b,
    {
        // Update local stats
        self.local_stats.blobs_seen += 1;
        self.local_stats.bytes_seen += blob.bytes().len() as u64;
        self.local_stats.blobs_scanned += 1;
        self.local_stats.bytes_scanned += blob.bytes().len() as u64;

        // Check if blob was already seen and respect no_dedup flag
        if !no_dedup {
            if let Some(had_matches) = self.seen_blobs.get(&blob.id) {
                return Ok(if had_matches {
                    ScanResult::SeenWithMatches
                } else {
                    ScanResult::SeenSansMatches
                });
            }
        }

        // Extract filename from origin
        let filename = origin
            .first()
            .blob_path()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("unknown_file")
            .to_string();
        // Perform the scan
        self.scan_bytes_raw(&blob.bytes(), &filename)?;

        // Early exit if no matches found
        if self.user_data.raw_matches_scratch.is_empty() {
            // Only record in seen_blobs if deduplication is enabled
            if !no_dedup {
                return Ok(match self.seen_blobs.insert(blob.id, false) {
                    None => ScanResult::New(Vec::new()),
                    Some(true) => ScanResult::SeenWithMatches,
                    Some(false) => ScanResult::SeenSansMatches,
                });
            } else {
                return Ok(ScanResult::New(Vec::new()));
            }
        }

        let rules_db = self.rules_db;
        let mut seen_matches = FxHashSet::default();
        let mut previous_matches = Vec::new();
        let tree_sitter_result = lang.and_then(|lang_str| {
            get_language_and_queries(&lang_str).and_then(|(language, queries)| {
                let checker = Checker { language, rules: queries };
                match checker.check(&blob.bytes()) {
                    Ok(results) => Some(results),
                    Err(e) => {
                        println!("Error in checker.check: {}", e);
                        None
                    }
                }
            })
        });
        // Process matches
        let mut matches = Vec::new();
        let owned_ts_results = tree_sitter_result.map(|ts_results| {
            ts_results
                .into_iter()
                .filter(|match_result| match_result.is_base64_decoded)
                .map(|match_result| {
                    (
                        match_result.range,
                        match_result.text,
                        match_result.is_base64_decoded,
                        match_result.original_base64,
                    )
                })
                .collect::<Vec<_>>()
        });
        let mut previous_raw_matches: Vec<(usize, OffsetSpan)> = Vec::new();
        for &RawMatch { rule_id, start_idx, end_idx } in
            self.user_data.raw_matches_scratch.iter().rev()
        {
            let rule_id_usize: usize = rule_id as usize;
            // let rule = &rules_db.rules[rule_id_usize];
            let rule = Arc::clone(&rules_db.rules[rule_id_usize]);
            let re = &rules_db.anchored_regexes[rule_id_usize];
            let start_idx_usize = start_idx as usize;
            let end_idx_usize = end_idx as usize;
            let current_span = OffsetSpan::from_range(start_idx_usize..end_idx_usize);
            // Skip if fully contained in a previous match
            if previous_raw_matches.iter().any(|(prev_id, prev_span): &(usize, OffsetSpan)| {
                *prev_id == rule_id_usize
                    && (prev_span.fully_contains(&current_span)
                        || current_span.fully_contains(prev_span))
            }) {
                continue;
            }
            let matching_input_offset_span = OffsetSpan::from_range(start_idx_usize..end_idx_usize);
            previous_raw_matches.push((rule_id_usize, matching_input_offset_span));
            filter_match(
                blob,
                rule,
                re,
                start_idx_usize,
                end_idx_usize,
                &mut matches,
                &mut previous_matches,
                rule_id_usize,
                &mut seen_matches,
                origin,
                None,
                redact,
            );
        }
        // If tree-sitter produced base64-decoded matches, try them against all rules
        if let Some(ref ts_results) = owned_ts_results {
            for (ts_range, ts_match, is_base64_decoded, _original_base64) in ts_results.iter() {
                if *is_base64_decoded {
                    for (rule_id_usize, rule) in rules_db.rules.iter().enumerate() {
                        let re = &rules_db.anchored_regexes[rule_id_usize];
                        filter_match(
                            blob,
                            rule.clone(),
                            re,
                            ts_range.start,
                            ts_range.end,
                            &mut matches,
                            &mut previous_matches,
                            rule_id_usize,
                            &mut seen_matches,
                            origin,
                            Some(ts_match.clone()),
                            redact,
                        );
                    }
                }
            }
        }
        // Finalize
        // Only record in seen_blobs if deduplication is enabled
        if !no_dedup {
            self.seen_blobs.insert(blob.id, !matches.is_empty());
        }

        // --- opportunistic capacity cap ---------------------------------
        if self.user_data.raw_matches_scratch.capacity()
            > self.user_data.raw_matches_scratch.len() * 4
        {
            // Vec::shrink_to_fit may re-allocate, but we’re about to leave scan_blob
            // so the cost is hidden off the hot path.
            self.user_data.raw_matches_scratch.shrink_to_fit();
        }

        Ok(ScanResult::New(matches))
        // Ok(result)
    }
}

#[inline]
fn compute_match_key(content: &[u8], rule_id: &[u8], start: usize, end: usize) -> u64 {
    let mut hasher = FxHasher::default();
    // Hash each component directly without allocation
    content.hash(&mut hasher);
    rule_id.hash(&mut hasher);
    start.hash(&mut hasher);
    end.hash(&mut hasher);
    hasher.finish()
}
fn filter_match<'b>(
    blob: &'b Blob,
    // rule: &'b Rule,
    rule: Arc<Rule>,
    re: &Regex,
    start: usize,
    end: usize,
    matches: &mut Vec<BlobMatch<'b>>,
    previous_matches: &mut Vec<(usize, OffsetSpan)>,
    rule_id: usize,
    seen_matches: &mut FxHashSet<u64>,
    _origin: &OriginSet,
    ts_match: Option<String>,
    redact: bool,
) {
    // Use Cow to avoid unnecessary copying when ts_match is None
    let byte_slice: Cow<[u8]> = match ts_match {
        Some(ts_match_value) => Cow::Owned(ts_match_value.into_bytes()),
        None => Cow::Borrowed(&blob.bytes()[start..end]),
    };
    for captures in re.captures_iter(byte_slice.as_ref()) {
        let matching_input = captures.get(1).or_else(|| captures.get(0)).unwrap();
        // let str_input = std::str::from_utf8(matching_input.as_bytes()).unwrap_or("");
        // let calculated_entropy = calculate_shannon_entropy(str_input);
        // if calculated_entropy <= rule.min_entropy() || is_safe_match(str_input) {
        //     continue;
        // }
        let min_entropy = rule.min_entropy();
        let mi_bytes = matching_input.as_bytes();
        let calculated_entropy = calculate_shannon_entropy(mi_bytes);
        if calculated_entropy <= min_entropy || is_safe_match(mi_bytes) {
            debug!(
                "Skipping match with entropy {} <= {} or safe match",
                calculated_entropy, min_entropy
            );
            continue;
        }
        let matching_input_offset_span = OffsetSpan::from_range(
            (start + matching_input.start())..(start + matching_input.end()),
        );
        let match_key = compute_match_key(
            matching_input.as_bytes(),
            rule.id().as_bytes(),
            matching_input_offset_span.start,
            matching_input_offset_span.end,
        );
        if !seen_matches.insert(match_key) {
            continue;
        }
        if previous_matches.iter().any(|(prev_rule_id, prev_loc)| {
            *prev_rule_id == rule_id
                && (prev_loc.fully_contains(&matching_input_offset_span)
                    || matching_input_offset_span.fully_contains(prev_loc))
        }) {
            continue;
        }
        let only_matching_input =
            &blob.bytes()[matching_input_offset_span.start..matching_input_offset_span.end];
        let groups =
            SerializableCaptures::from_captures(&captures, byte_slice.as_ref(), re, redact);
        matches.push(BlobMatch {
            rule: Arc::clone(&rule),
            blob_id: &blob.id,
            matching_input: only_matching_input,
            matching_input_offset_span,
            captures: groups,
            validation_response_body: String::new(),
            validation_response_status: StatusCode::from_u16(0).unwrap_or(StatusCode::CONTINUE),
            validation_success: false,
            calculated_entropy,
        });
        previous_matches.push((rule_id, matching_input_offset_span));
    }
}
fn get_language_and_queries(lang: &str) -> Option<(Language, FxHashMap<String, String>)> {
    match lang.to_lowercase().as_str() {
        "bash" | "shell" => Some((Language::Bash, parser::queries::bash::get_bash_queries())),
        "c" => Some((Language::C, parser::queries::c::get_c_queries())),
        "c#" | "csharp" => Some((Language::CSharp, parser::queries::csharp::get_csharp_queries())),
        "c++" | "cpp" => Some((Language::Cpp, parser::queries::cpp::get_cpp_queries())),
        "css" => Some((Language::Css, parser::queries::css::get_css_queries())),
        "go" => Some((Language::Go, parser::queries::go::get_go_queries())),
        "html" => Some((Language::Html, parser::queries::html::get_html_queries())),
        "java" => Some((Language::Java, parser::queries::java::get_java_queries())),
        "javascript" | "js" => {
            Some((Language::JavaScript, parser::queries::javascript::get_javascript_queries()))
        }
        // "kotlin" => Some((
        //     Language::Kotlin,
        //     parser::queries::kotlin::get_kotlin_queries(),
        // )),
        "php" => Some((Language::Php, parser::queries::php::get_php_queries())),
        "python" | "py" | "starlark" => {
            Some((Language::Python, parser::queries::python::get_python_queries()))
        }
        "ruby" => Some((Language::Ruby, parser::queries::ruby::get_ruby_queries())),
        "rust" => Some((Language::Rust, parser::queries::rust::get_rust_queries())),
        "toml" => Some((Language::Toml, parser::queries::toml::get_toml_queries())),
        "typescript" | "ts" => {
            Some((Language::TypeScript, parser::queries::typescript::get_typescript_queries()))
        }
        "yaml" => Some((Language::Yaml, parser::queries::yaml::get_yaml_queries())),
        _ => None,
    }
}
// -------------------------------------------------------------------------------------------------
// MatchStats
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Default, Clone)]
pub struct MatcherStats {
    pub blobs_seen: u64,
    pub blobs_scanned: u64,
    pub bytes_seen: u64,
    pub bytes_scanned: u64,
    // #[cfg(feature = "rule_profiling")]
    // pub rule_stats: crate::rule_profiling::RuleProfile,
}
impl MatcherStats {
    pub fn update(&mut self, other: &Self) {
        self.blobs_seen += other.blobs_seen;
        self.blobs_scanned += other.blobs_scanned;
        self.bytes_seen += other.bytes_seen;
        self.bytes_scanned += other.bytes_scanned;

        // #[cfg(feature = "rule_profiling")]
        // self.rule_stats.update(&other.rule_stats);
    }
}
// -------------------------------------------------------------------------------------------------
// Group
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct Group(pub Base64BString);
impl Group {
    pub fn new(m: regex::bytes::Match<'_>) -> Self {
        Self(Base64BString(BString::from(m.as_bytes())))
    }
}
// -------------------------------------------------------------------------------------------------
// Groups
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Groups(pub SmallVec<[Group; 1]>);
impl JsonSchema for Groups {
    fn schema_name() -> String {
        "Groups".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        let group_schema = gen.subschema_for::<Group>();
        Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(InstanceType::Array.into()),
            array: Some(Box::new(ArrayValidation {
                items: Some(group_schema.into()),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}
// #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
// pub struct SerializableCapture {
//     pub name: Option<String>, // Named group (if available)
//     pub match_number: i32,
//     pub start: usize,  // Start position of the match
//     pub end: usize,    // End position of the match
//     pub value: String, // The actual captured value
// }
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SerializableCapture {
    pub name: Option<String>,
    pub match_number: i32,
    pub start: usize,
    pub end: usize,
    // Instead of storing an owned String, store a borrowed or interned value.
    // Here we use Cow to allow either borrowing or owning as needed.
    pub value: std::borrow::Cow<'static, str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SerializableCaptures {
    pub captures: Vec<SerializableCapture>, // All captures (named and unnamed)
}
impl SerializableCaptures {
    pub fn from_captures(
        captures: &regex::bytes::Captures,
        _input: &[u8],
        re: &Regex,
        redact: bool,
    ) -> Self {
        let mut serialized_captures = Vec::new();
        // Process named captures
        for name in re.capture_names().flatten() {
            if let Some(capture) = captures.name(name) {
                let value = if redact {
                    redact_value(&String::from_utf8_lossy(capture.as_bytes()))
                } else {
                    String::from_utf8_lossy(capture.as_bytes()).to_string()
                };
                serialized_captures.push(SerializableCapture {
                    name: Some(name.to_string()),
                    match_number: -1,
                    start: capture.start(),
                    end: capture.end(),
                    value: value.into(),
                });
            }
        }
        // Process unnamed captures (numbered groups)
        for i in 0..captures.len() {
            if let Some(capture) = captures.get(i) {
                let value = if redact {
                    redact_value(&String::from_utf8_lossy(capture.as_bytes()))
                } else {
                    String::from_utf8_lossy(capture.as_bytes()).to_string()
                };
                serialized_captures.push(SerializableCapture {
                    name: None,
                    match_number: i32::try_from(i).unwrap_or(0),
                    start: capture.start(),
                    end: capture.end(),
                    value: value.into(),
                });
            }
        }
        SerializableCaptures { captures: serialized_captures }
    }
}
// -------------------------------------------------------------------------------------------------
// Match
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Match {
    /// The blob this match comes from
    // pub blob_id: BlobId,

    /// The location of the entire matching content
    pub location: Location,

    /// The capture groups
    // pub groups: Groups,
    pub groups: SerializableCaptures, // Store serialized captures

    /// unique identifier of file / blob where this match was found
    pub blob_id: BlobId,

    /// The unique content-based identifier of this match
    pub finding_fingerprint: u64,

    /// The rule that produced this match
    pub rule_finding_fingerprint: &'static str,

    /// The text identifier of the rule that produced this match
    pub rule_text_id: &'static str,

    /// The name of the rule that produced this match
    pub rule_name: &'static str,

    /// The confidence property of the rule that produced this match
    pub rule_confidence: crate::rules::rule::Confidence,

    /// Validation Body
    pub validation_response_body: String,

    /// Validation Status Code
    pub validation_response_status: u16,

    /// Validation Success
    pub validation_success: bool,

    /// Validation Success
    pub calculated_entropy: f32,

    pub visible: bool,
}
impl Match {
    #[inline]
    pub fn convert_owned_blobmatch_to_match<'a>(
        loc_mapping: &'a LocationMapping,
        owned_blob_match: &'a OwnedBlobMatch,
        origin_type: &'a str,
    ) -> Self {
        let offset_span = owned_blob_match.matching_input_offset_span;
        // Extract the matched secret content. Use capture group 1 if it exists, otherwise fall back to group 0.
        let matching_finding_bytes = owned_blob_match
            .captures
            .captures
            .get(1)
            .or_else(|| owned_blob_match.captures.captures.get(0))
            .map(|capture| capture.value.as_bytes())
            .unwrap_or_default();

        // The fingerprint will be based on the content of the secret.
        let finding_value_for_fp = std::str::from_utf8(matching_finding_bytes).unwrap_or("");

        let source_span = loc_mapping.get_source_span(&offset_span);
        let rule_finding_fingerprint = owned_blob_match.rule.finding_sha1_fingerprint().to_owned();

        let offset_start: u64 =
            owned_blob_match.matching_input_offset_span.start.try_into().unwrap();
        let offset_end: u64 = owned_blob_match.matching_input_offset_span.end.try_into().unwrap();

        let finding_fingerprint = compute_finding_fingerprint(
            finding_value_for_fp,
            origin_type, // file_or_commit,
            offset_start,
            offset_end,
        );

        // matching_snippet
        Match {
            rule_finding_fingerprint: intern(&rule_finding_fingerprint),
            rule_name: intern(owned_blob_match.rule.name()),
            rule_confidence: owned_blob_match.rule.confidence(),
            rule_text_id: intern(owned_blob_match.rule.id()),
            visible: owned_blob_match.rule.visible().to_owned(),
            location: Location { offset_span, source_span: source_span.clone() },
            groups: owned_blob_match.captures.clone(),
            blob_id: owned_blob_match.blob_id,
            finding_fingerprint,
            validation_response_body: owned_blob_match.validation_response_body.clone(),
            validation_response_status: owned_blob_match.validation_response_status.as_u16(),
            validation_success: owned_blob_match.validation_success,
            calculated_entropy: owned_blob_match.calculated_entropy,
        }
    }

    /// Returns the `blob_id` of the match.
    pub fn get_blob_id(&self) -> BlobId {
        self.blob_id.clone()
    }

    pub fn finding_id(&self) -> String {
        let mut h = Sha1::new();
        write!(&mut h, "{}\0", self.rule_finding_fingerprint)
            .expect("should be able to write to memory");
        serde_json::to_writer(&mut h, &self.groups)
            .expect("should be able to serialize groups as JSON");
        let hash: sha2::digest::generic_array::GenericArray<
            u8,
            sha2::digest::typenum::UInt<
                sha2::digest::typenum::UInt<
                    sha2::digest::typenum::UInt<
                        sha2::digest::typenum::UInt<
                            sha2::digest::typenum::UInt<
                                sha2::digest::typenum::UTerm,
                                sha2::digest::consts::B1,
                            >,
                            sha2::digest::consts::B0,
                        >,
                        sha2::digest::consts::B1,
                    >,
                    sha2::digest::consts::B0,
                >,
                sha2::digest::consts::B0,
            >,
        > = h.finalize();
        // Take the first 8 bytes of the hash
        let mut num = u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);
        // Ensure the number is positive and within i64 range
        num &= 0x7FFF_FFFF_FFFF_FFFF; // Clear the sign bit to make it positive
                                      // Convert to string
        num.to_string()
    }
}
#[derive(Debug, Clone)]
pub struct DecodedData {
    pub original: String,
    pub decoded: String,
    pub pos_start: usize,
    pub pos_end: usize,
}
pub fn get_base64_strings(input: &[u8]) -> Vec<DecodedData> {
    lazy_static! {
        static ref RE_BASE64: Regex =
            Regex::new(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap();
    }
    let mut results = Vec::new();
    for capture in RE_BASE64.captures_iter(input) {
        let base64_match = capture.get(0).unwrap();

        if base64_match.is_empty() {
            continue;
        }

        let start = base64_match.start();
        let end = base64_match.end();
        let base64_string = &input[start..end];
        // Check if the length is a multiple of 4
        if base64_string.len() % 4 != 0 {
            continue;
        }
        if let Ok(decoded) = general_purpose::STANDARD.decode(base64_string) {
            // Check if the decoded string is valid UTF-8
            if let Ok(decoded_str) = std::str::from_utf8(&decoded) {
                if decoded_str.is_ascii() {
                    results.push(DecodedData {
                        original: String::from_utf8_lossy(base64_string).into_owned(),
                        decoded: decoded_str.to_string(),
                        pos_start: start,
                        pos_end: end,
                    });
                }
            }
        }
    }
    results
}

pub fn compute_finding_fingerprint(
    finding_value: &str,
    file_or_commit: &str,
    offset_start: u64,
    offset_end: u64,
) -> u64 {
    // Combine all into a byte buffer and hash it directly:
    let mut buf = Vec::with_capacity(
        finding_value.len() + file_or_commit.len() + 2 * std::mem::size_of::<u64>(),
    );
    buf.extend_from_slice(finding_value.as_bytes());
    buf.extend_from_slice(file_or_commit.as_bytes());
    buf.extend_from_slice(&offset_start.to_le_bytes());
    buf.extend_from_slice(&offset_end.to_le_bytes());

    xxh3_64(&buf)
}

// -------------------------------------------------------------------------------------------------
// test
// -------------------------------------------------------------------------------------------------
#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use pretty_assertions::assert_eq;
    // ---------------------------------------------------------------------
    // proptest: raw-match dedup + entropy gate
    // ---------------------------------------------------------------------
    use proptest::prelude::*;

    use super::*;
    use crate::rules::rule::{DependsOnRule, HttpRequest, HttpValidation, RuleSyntax, Validation};

    proptest! {
        #[test]
        fn prop_no_dupes_and_entropy(
            // random ASCII up to 300 bytes
            mut noise in proptest::collection::vec(any::<u8>().prop_filter("ascii", |b| b.is_ascii()), 0..300),
            // 0-4 random insertion points
            inserts in proptest::collection::vec(0usize..300, 0..5)
        ) {
            // Constant high-entropy secret token that matches the rule below
            const TOKEN: &[u8] = b"secret_abcd1234";

            // Splice the token at the requested offsets
            for &idx in &inserts {
                let pos = idx.min(noise.len());
                noise.splice(pos..pos, TOKEN.iter().copied());
            }

            // ── build a single test rule ──────────────────────────────────
            use crate::rules::rule::{RuleSyntax, Validation, Confidence};

            let rule = Rule::new(RuleSyntax {
                id: "prop.secret".into(),
                name: "prop secret".into(),
                pattern: "secret_[a-z]{4}[0-9]{4}".into(),
                confidence: Confidence::Low,
                min_entropy: 3.0,
                visible: true,
                examples: vec![],
                negative_examples: vec![],
                prevalidated: false,
                references: vec![],
                validation: None::<Validation>,          // no HTTP validation needed
                depends_on_rule: vec![],
            });

            let rules_db  = RulesDatabase::from_rules(vec![rule]).unwrap();
            let seen      = BlobIdMap::new();
            let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
            let mut m     = Matcher::new(&rules_db, scanner_pool, &seen, None, false, None).unwrap();

            // ── run the scan ──────────────────────────────────────────────
            m.scan_bytes_raw(&noise, "buf").unwrap();

            // ── property 1: dedup – each (rule,start,end) is unique ──────

            let mut coords = FxHashSet::default();
            for RawMatch{rule_id, start_idx, end_idx} in &m.user_data.raw_matches_scratch {
                assert!(
                    coords.insert((*rule_id, *start_idx, *end_idx)),
                    "duplicate raw-match detected for coords ({rule_id},{start_idx},{end_idx})"
                );

                // ── property 2: entropy gate held ────────────────────────
                let slice = &noise[*start_idx as usize .. *end_idx as usize];
                let ent   = calculate_shannon_entropy(slice);
                assert!(ent > 3.0, "entropy {ent} ≤ min_entropy, gate failed");
            }
        }
    }

    #[test]
    pub fn test_simple() -> Result<()> {
        let rules = vec![Rule::new(RuleSyntax {
            id: "test.1".to_string(),
            name: "test".to_string(),
            pattern: "test".to_string(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 1.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            prevalidated: false,
            references: vec![],
            validation: Some(Validation::Http(HttpValidation {
                request: HttpRequest {
                    method: "GET".to_string(),
                    url: "https://example.com".to_string(),
                    headers: BTreeMap::new(),
                    response_matcher: vec![],
                    multipart: None,
                    response_is_html: false,
                },
                multipart: None,
            })),
            depends_on_rule: vec![
                Some(DependsOnRule {
                    rule_id: "d8f3c34b-015f-4cd6-b411-b1366493104c".to_string(),
                    variable: "email".to_string(),
                }),
                Some(DependsOnRule {
                    rule_id: "8910f364-7718-4a27-a435-d2da13e6ba9e".to_string(),
                    variable: "domain".to_string(),
                }),
            ],
        })];
        let rules_db = RulesDatabase::from_rules(rules)?;
        let input = "some test data for vectorscan";
        let seen_blobs: BlobIdMap<bool> = BlobIdMap::new();
        let enable_rule_profiling = true;
        // let mut matcher = Matcher::new(&rules_db, &seen_blobs, None,
        // enable_rule_profiling)?;
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
        let mut matcher = Matcher::new(
            &rules_db,
            scanner_pool,
            &seen_blobs,
            None,
            enable_rule_profiling,
            None, // Pass the shared profiler
        )?;
        matcher.scan_bytes_raw(input.as_bytes(), "fname")?;
        assert_eq!(
            matcher.user_data.raw_matches_scratch,
            vec![RawMatch { rule_id: 0, start_idx: 0, end_idx: 9 },]
        );
        Ok(())
    }

    // ---------------------------------------------------------------------
    // additional deterministic unit-tests
    // ---------------------------------------------------------------------

    /// `get_base64_strings` should recognise a well-formed token, decode it,
    /// and report correct byte-offsets.
    #[test]
    fn test_get_base64_strings_basic() {
        let raw = b"foo SGVsbG8gV29ybGQ= bar"; // "Hello World"
        let hits = get_base64_strings(raw);
        assert_eq!(hits.len(), 1);
        let item = &hits[0];
        assert_eq!(item.decoded, "Hello World");
        assert_eq!(item.original, "SGVsbG8gV29ybGQ=");
        // "foo␠" is 4 bytes, so the start offset is 4
        assert_eq!((item.pos_start, item.pos_end), (4, 4 + item.original.len()));
    }

    /// `compute_finding_fingerprint` must be stable (same input ⇒ same output)
    /// and sensitive to any input component.
    #[test]
    fn test_finding_fingerprint_stability_and_uniqueness() {
        let a = compute_finding_fingerprint("secret", "fileA", 0, 6);
        let b = compute_finding_fingerprint("secret", "fileA", 0, 6);
        assert_eq!(a, b, "fingerprint should be deterministic");

        // changing any parameter should perturb the hash
        let c = compute_finding_fingerprint("secret", "fileA", 1, 7); // offsets differ
        let d = compute_finding_fingerprint("secret", "fileB", 0, 6); // file id differs
        let e = compute_finding_fingerprint("different", "fileA", 0, 6); // content differs
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
    }

    /// The (private) `compute_match_key` helper is the linchpin of the raw-dedup
    /// path.  It should return identical keys for identical inputs and different
    /// keys as soon as *anything* changes.
    #[test]
    fn test_compute_match_key_uniqueness() {
        use super::compute_match_key;

        let k1 = compute_match_key(b"abc", b"rule-1", 0, 3);
        let k2 = compute_match_key(b"abc", b"rule-1", 0, 3);
        assert_eq!(k1, k2);

        // mutate each component in turn
        let diff_content = compute_match_key(b"abcd", b"rule-1", 0, 4);
        let diff_rule = compute_match_key(b"abc", b"rule-2", 0, 3);
        let diff_span = compute_match_key(b"abc", b"rule-1", 1, 4);
        assert_ne!(k1, diff_content);
        assert_ne!(k1, diff_rule);
        assert_ne!(k1, diff_span);
    }

    /// Running `scan_bytes_raw` twice over the *same* input should never record
    /// duplicate entries in `raw_matches_scratch`.
    #[test]
    fn test_scan_bytes_raw_no_duplicate_raw_matches() -> Result<()> {
        // simple rule: literal "dup"
        let rule = Rule::new(RuleSyntax {
            id: "dup.check".into(),
            name: "dup".into(),
            pattern: "dup".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            prevalidated: false,
            references: vec![],
            validation: None::<Validation>,
            depends_on_rule: vec![],
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));
        let mut m = Matcher::new(&rules_db, scanner_pool, &seen, None, false, None)?;

        let buf = b"dup dup"; // two literal hits, same rule

        // first scan
        m.scan_bytes_raw(buf, "buf1")?;
        let first_len = m.user_data.raw_matches_scratch.len();

        // second scan over the same buffer
        m.scan_bytes_raw(buf, "buf1")?;
        let second_len = m.user_data.raw_matches_scratch.len();

        // we should still only have two unique raw matches recorded
        assert_eq!(first_len, 2);
        assert_eq!(second_len, 2);
        Ok(())
    }
}
