use std::{
    hash::{Hash, Hasher},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::Result;
use bloomfilter::Bloom;
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    blob::{BlobId, BlobMetadata},
    finding_data,
    git_url::GitUrl,
    location::OffsetSpan,
    matcher::Match,
    origin::{Origin, OriginSet},
    rules::rule::Rule,
};

// share with Arc so every blob/origin is materialised once
pub type FindingsStoreMessage = (Arc<OriginSet>, Arc<BlobMetadata>, Match);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct MatchIdInt(i64);
impl FromStr for MatchIdInt {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<i64>().map(MatchIdInt)
    }
}

fn origin_fp(os: &OriginSet) -> u64 {
    let mut h = FxHasher::default();
    // OriginSet is iterable – hash each contained Origin
    for o in os.iter() {
        o.hash(&mut h);
    }
    h.finish()
}

pub struct FindingsStore {
    rules: Vec<Arc<Rule>>,
    matches: Vec<Arc<FindingsStoreMessage>>,
    index_map: FxHashMap<(BlobId, OffsetSpan), usize>,
    blobs: FxHashSet<BlobId>,
    clone_dir: PathBuf,
    seen_bloom: Bloom<u64>,
    bloom_items: usize,
    blob_meta: FxHashMap<BlobId, Arc<BlobMetadata>>,
    origin_meta: FxHashMap<u64, Arc<OriginSet>>,
}
impl FindingsStore {
    pub fn new(clone_dir: PathBuf) -> Self {
        let expected_items = 10_000_000; // tune to your largest scan
        let fp_rate = 0.001; // 0.1 % false-positive rate
        let seen_bloom = Bloom::new_for_fp_rate(expected_items, fp_rate)
            .expect("Bloom filter size params are valid");
        Self {
            rules: Vec::new(),
            matches: Vec::new(),
            blobs: FxHashSet::default(),
            index_map: FxHashMap::default(),
            blob_meta: FxHashMap::default(),
            origin_meta: FxHashMap::default(),
            clone_dir,
            seen_bloom,
            bloom_items: 0,
        }
    }

    pub fn update_matches_in_place(&mut self, updated_matches: Vec<Arc<FindingsStoreMessage>>) {
        for updated_match in updated_matches {
            let (_, _, updated) = &*updated_match;
            // Construct the same key used in record()
            let key = (updated.blob_id, updated.location.offset_span);
            // If we have an existing match, update it in-place
            if let Some(&idx) = self.index_map.get(&key) {
                // Get the Arc in self.matches at position idx
                let arc_in_store = &mut self.matches[idx];
                // Arc::make_mut lets us mutate the inner tuple as long as this Arc is not shared
                let (_, _, existing) = Arc::make_mut(arc_in_store);
                existing.validation_success = updated.validation_success;
                existing.validation_response_status = updated.validation_response_status;
                existing.validation_response_body = updated.validation_response_body.clone();
            }
        }
    }

    /// Replaces all stored matches with the new deduplicated matches.
    /// It also rebuilds the index map and the blobs set accordingly.
    pub fn replace_matches(&mut self, new_matches: Vec<Arc<FindingsStoreMessage>>) {
        self.matches = new_matches;
        self.index_map.clear();
        self.blobs.clear();
        for (i, message) in self.matches.iter().enumerate() {
            let blob_id = message.1.id;
            let offset_span = message.2.location.offset_span;
            self.index_map.insert((blob_id, offset_span), i);
            self.blobs.insert(blob_id);
        }
    }

    pub fn get_rules(&self) -> Result<Vec<Arc<Rule>>> {
        Ok(self.rules.clone())
    }

    pub fn get_matches(&self) -> &[Arc<FindingsStoreMessage>] {
        &self.matches
    }

    pub fn get_matches_mut(&mut self) -> &mut Vec<Arc<FindingsStoreMessage>> {
        &mut self.matches
    }

    pub fn record_rules(&mut self, rules: &[Arc<Rule>]) {
        // Clear existing data and extend in place
        self.rules.clear();
        self.rules.extend_from_slice(rules);
    }

    /// Insert a batch of findings.  
    /// Returns the number of *new blobs* discovered in this batch.
    ///
    /// * `dedup == true` -- Bloom-filter gate is applied.
    /// * Side-tables (`blob_meta`, `origin_meta`) guarantee only one Arc per distinct
    ///   `BlobMetadata` / `OriginSet`, so no more huge copies.
    pub fn record(&mut self, batch: Vec<FindingsStoreMessage>, dedup: bool) -> usize {
        let mut added = 0;

        for (origin, blob_md, m) in batch {
            /*───────────────────────────────────────────────────────────────┐
            │ 1. Optional duplicate filter (unchanged)                      │
            └───────────────────────────────────────────────────────────────*/
            if dedup {
                let snippet = m
                    .groups
                    .captures
                    .get(1)
                    .or_else(|| m.groups.captures.get(0))
                    .map_or("", |c| c.value.as_ref());

                let origin_kind = match origin.first() {
                    Origin::GitRepo(_) => "git",
                    Origin::File(_) => "file",
                    Origin::Extended(_) => "ext",
                };

                let key = xxh3_64(
                    format!("{}|{}|{}", m.rule_text_id.to_uppercase(), origin_kind, snippet)
                        .as_bytes(),
                );

                if self.seen_bloom.check(&key) {
                    continue; // very likely a duplicate
                }
                self.seen_bloom.set(&key);
                self.bloom_items += 1;
            }

            /*───────────────────────────────────────────────────────────────┐
            │ 2.  Intern / pool the heavy structs                           │
            └───────────────────────────────────────────────────────────────*/
            // one Arc<BlobMetadata> per BlobId
            let blob_arc =
                self.blob_meta.entry(blob_md.id).or_insert_with(|| blob_md.clone()).clone();

            // one Arc<OriginSet> per (hashed) OriginSet
            let fp = origin_fp(&origin); // helper: u64 hash of OriginSet
            let origin_arc = self.origin_meta.entry(fp).or_insert_with(|| origin.clone()).clone();

            /*───────────────────────────────────────────────────────────────┐
            │ 3.  Core bookkeeping                                          │
            └───────────────────────────────────────────────────────────────*/
            if self.blobs.insert(blob_arc.id) {
                added += 1; // first time we see this blob
            }

            let msg = Arc::new((origin_arc, blob_arc, m));
            self.matches.push(msg);

            let idx = self.matches.len() - 1;
            let blob_id = self.matches[idx].1.id;
            let offset_span = self.matches[idx].2.location.offset_span;
            self.index_map.insert((blob_id, offset_span), idx);
        }

        /* ─────────────────────────────────────────────────────────────────── */
        // Periodically rebuild Bloom filter to bound the FP rate
        if dedup && self.bloom_items > 5_000_000 {
            self.seen_bloom = Bloom::new_for_fp_rate(5_000_000, 0.001).unwrap();
            self.bloom_items = 0;
        }

        added
    }

    // pub fn record(&mut self, batch: Vec<FindingsStoreMessage>, dedup: bool) -> usize {
    //     let mut added = 0;

    //     for message in batch {
    //         if dedup {
    //             let snippet = message
    //                 .2
    //                 .groups
    //                 .captures
    //                 .get(1)
    //                 .or_else(|| message.2.groups.captures.get(0))
    //                 .map_or("", |c| c.value.as_ref());

    //             let origin_kind = match message.0.first() {
    //                 Origin::GitRepo(_) => "git",
    //                 Origin::File(_) => "file",
    //                 Origin::Extended(_) => "ext",
    //             };

    //             // 64-bit key (fast, cheap, good dispersion)
    //             let key = xxh3_64(
    //                 format!(
    //                     "{}|{}|{}",
    //                     message.2.rule_text_id.to_uppercase(),
    //                     origin_kind,
    //                     snippet
    //                 )
    //                 .as_bytes(),
    //             );

    //             // Bloom gate: 1. check, 2. insert (if new)
    //             if self.seen_bloom.check(&key) {
    //                 continue; // very likely a duplicate
    //             }
    //             self.seen_bloom.set(&key);
    //             self.bloom_items += 1;
    //         }

    //         // ── existing blob / index bookkeeping ───────────
    //         if self.blobs.insert(message.1.id) {
    //             added += 1;
    //         }
    //         self.matches.push(Arc::new(message));
    //         let idx = self.matches.len() - 1;
    //         let blob_id = self.matches[idx].1.id;
    //         let offset_span = self.matches[idx].2.location.offset_span;
    //         self.index_map.insert((blob_id, offset_span), idx);
    //     }

    //     // Optional : re-create filter after N inserts to bound FP rate
    //     if dedup && self.bloom_items > 5_000_000 {
    //         self.seen_bloom = Bloom::new_for_fp_rate(5_000_000, 0.001).unwrap();
    //         self.bloom_items = 0;
    //     }

    //     added
    // }

    pub fn get_num_matches(&self) -> usize {
        // only count visible matches
        self.matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = &***msg;
                match_item.visible
            })
            .count()
    }

    pub fn get_summary(&self) -> FxHashMap<&'static str, usize> {
        self.matches.iter().fold(FxHashMap::default(), |mut acc, msg| {
            let (_, _, m) = &**msg;
            *acc.entry(m.rule_name).or_insert(0) += 1; // borrow, no alloc
            acc
        })
    }

    pub fn clone_destination(&self, repo_url: &GitUrl) -> PathBuf {
        let repo_identifier = repo_url.to_string().replace(['/', ':'], "_");
        self.clone_dir.join(repo_identifier)
    }

    pub fn get_finding_data_iter(
        &self,
    ) -> impl Iterator<Item = finding_data::FindingMetadata> + '_ {
        self.matches.iter().map(|msg| {
            let (_, _, match_item) = &**msg;
            finding_data::FindingMetadata {
                rule_name: match_item.rule_name.to_string(),
                num_matches: 1,
                comment: None,
                visible: match_item.visible,
                finding_id: match_item.finding_id(),
                rule_finding_fingerprint: match_item.rule_finding_fingerprint.to_string(),
                rule_text_id: match_item.rule_text_id.to_string(),
            }
        })
    }

    pub fn get_finding_metadata(
        &self,
        metadata: &finding_data::FindingMetadata,
        _max_matches: Option<usize>,
    ) -> Result<Vec<finding_data::FindingDataEntry>> {
        self.matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = &***msg;
                match_item.rule_name == metadata.rule_name
            })
            .map(|msg| {
                let (origin, blob_metadata, match_item) = &**msg;
                Ok(finding_data::FindingDataEntry {
                    origin: (**origin).clone(),
                    blob_metadata: (**blob_metadata).clone(),
                    match_val: match_item.clone(),
                    match_id: MatchIdInt::from_str(&match_item.finding_id())?,
                    match_comment: None,
                    visible: match_item.visible,
                    match_confidence: match_item.rule_confidence,
                    validation_response_body: match_item.validation_response_body.clone(),
                    validation_response_status: match_item.validation_response_status,
                    validation_success: match_item.validation_success,
                })
            })
            .collect()
    }

    /// Return an iterator that yields `chunk_size` matches at a time.
    /// Clones the `Arc` wrappers only – zero extra allocation for Match bodies.
    pub fn cursor(
        &self,
        chunk_size: usize,
    ) -> impl Iterator<Item = Vec<std::sync::Arc<FindingsStoreMessage>>> + '_ {
        self.matches.chunks(chunk_size).map(|slice| slice.to_vec()) // keep Arc pointers
    }
}
