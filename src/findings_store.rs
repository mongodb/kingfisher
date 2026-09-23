use std::{
    hash::{Hash, Hasher},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};

mod spill;
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};

use crate::{
    access_map::ScanAccessMapResult,
    blob::{BlobId, BlobMetadata},
    finding_data,
    git_url::GitUrl,
    location::OffsetSpan,
    matcher::Match,
    origin::{Origin, OriginSet},
    rules::rule::Rule,
    scan_audit::ScanAuditManifest,
    util::intern,
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

fn dedup_origin_kind(origin: &OriginSet) -> &'static str {
    if origin.iter().any(|o| matches!(o, Origin::Extended(_))) { "ext" } else { "file_git" }
}

pub struct FindingsStore {
    spill: Option<spill::FindingsSpill>,
    rules: Vec<Arc<Rule>>,
    matches: Vec<Arc<FindingsStoreMessage>>,
    index_map: FxHashMap<(BlobId, OffsetSpan), usize>,
    blobs: FxHashSet<BlobId>,
    clone_dir: PathBuf,
    // Deduplicate with full cryptographic digests, without retaining another
    // copy of each secret. Storage is fixed-size per unique finding.
    dedup_exact: FxHashSet<[u8; 32]>,
    blob_scoped_dependency_rule_ids: FxHashSet<String>,
    blob_meta: FxHashMap<BlobId, Arc<BlobMetadata>>,
    origin_meta: FxHashMap<u64, Arc<OriginSet>>,
    docker_images: FxHashMap<PathBuf, String>,
    slack_links: FxHashMap<PathBuf, String>,
    teams_links: FxHashMap<PathBuf, String>,
    confluence_links: FxHashMap<PathBuf, String>,
    postman_links: FxHashMap<PathBuf, String>,
    s3_buckets: FxHashMap<PathBuf, String>,
    repo_links: FxHashMap<PathBuf, String>,
    access_map_results: Vec<ScanAccessMapResult>,
    scan_audit: Option<ScanAuditManifest>,
}

impl FindingsStore {
    pub fn new(clone_dir: PathBuf) -> Self {
        Self {
            spill: None,
            rules: Vec::new(),
            matches: Vec::new(),
            blobs: FxHashSet::default(),
            index_map: FxHashMap::default(),
            blob_meta: FxHashMap::default(),
            origin_meta: FxHashMap::default(),
            clone_dir,
            dedup_exact: FxHashSet::default(),
            blob_scoped_dependency_rule_ids: FxHashSet::default(),
            docker_images: FxHashMap::default(),
            slack_links: FxHashMap::default(),
            teams_links: FxHashMap::default(),
            confluence_links: FxHashMap::default(),
            postman_links: FxHashMap::default(),
            s3_buckets: FxHashMap::default(),
            repo_links: FxHashMap::default(),
            access_map_results: Vec::new(),
            scan_audit: None,
        }
    }

    /// Opt-in storage for findings accumulated between repository scans. Working
    /// sets for validation, deduplication, and reporting are restored explicitly.
    pub fn enable_spilling(&mut self) -> Result<()> {
        if self.spill.is_none() {
            match spill::FindingsSpill::new() {
                Ok(file) => self.spill = Some(file),
                Err(error) if spill::is_storage_full(&error) => {
                    tracing::warn!(
                        "Temporary storage is full; --disk-offload is disabled for this scan. Continuing in memory; memory use may increase."
                    );
                }
                Err(error) => {
                    return Err(error.context("Failed to create temporary findings storage"));
                }
            }
        }
        Ok(())
    }

    pub fn spill_pending(&mut self) -> Result<()> {
        let Some(spill) = &mut self.spill else {
            return Ok(());
        };
        if self.matches.is_empty() {
            return Ok(());
        }
        if matches!(
            spill.append(&self.matches).context("Failed to store accumulated findings on disk")?,
            spill::AppendOutcome::StorageFull
        ) {
            tracing::warn!(
                "Temporary storage is full; restoring accumulated findings to memory and disabling --disk-offload for the remainder of this scan. Memory use may increase."
            );
            self.restore_spilled_with_cleanup(false).context(
                "Temporary storage filled up and findings could not be restored to memory",
            )?;
            self.spill = None;
            return Ok(());
        }
        self.matches = Vec::new();
        self.index_map = FxHashMap::default();
        self.blob_meta = FxHashMap::default();
        self.origin_meta = FxHashMap::default();
        // Keep digest and blob sets so later repositories retain global dedup semantics.
        Ok(())
    }

    pub fn restore_spilled(&mut self) -> Result<()> {
        self.restore_spilled_with_cleanup(true)
    }

    fn restore_spilled_with_cleanup(&mut self, truncate: bool) -> Result<()> {
        let Some(spill) = &mut self.spill else {
            return Ok(());
        };
        if spill.is_empty() {
            return Ok(());
        }
        // Build a replacement working set in batches, pooling metadata as it is
        // read. On any read error both the original spill and pending rows survive.
        let mut restored = Self::new(self.clone_dir.clone());
        spill
            .read_batches(&self.rules, |batch| {
                restored.record(batch, false);
            })
            .context("Failed to restore accumulated findings")?;
        if truncate {
            spill.clear()?;
        }
        let pending = std::mem::take(&mut self.matches);
        for message in pending {
            restored.record(vec![Arc::unwrap_or_clone(message)], false);
        }
        self.matches = restored.matches;
        self.index_map = restored.index_map;
        self.blob_meta = restored.blob_meta;
        self.origin_meta = restored.origin_meta;
        Ok(())
    }

    fn assert_restored(&self) {
        assert!(
            self.spill.as_ref().is_none_or(spill::FindingsSpill::is_empty),
            "restore spilled findings before reading or modifying the working set"
        );
    }

    pub fn update_matches_in_place(&mut self, updated_matches: Vec<Arc<FindingsStoreMessage>>) {
        self.assert_restored();
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
                existing.validation_outcome = updated.validation_outcome;
                existing.validation_response_body = updated.validation_response_body.clone();
            }
        }
    }

    /// Replaces all stored matches with the new deduplicated matches.
    /// It also rebuilds the index map and the blobs set accordingly.
    pub fn replace_matches(&mut self, new_matches: Vec<Arc<FindingsStoreMessage>>) {
        self.assert_restored();
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
        self.assert_restored();
        &self.matches
    }

    pub fn get_matches_mut(&mut self) -> &mut Vec<Arc<FindingsStoreMessage>> {
        self.assert_restored();
        &mut self.matches
    }

    pub(crate) fn set_access_map_results(&mut self, results: Vec<ScanAccessMapResult>) {
        self.access_map_results = results;
    }

    pub(crate) fn access_map_results(&self) -> &[ScanAccessMapResult] {
        &self.access_map_results
    }

    pub fn set_scan_audit(&mut self, audit: ScanAuditManifest) {
        self.scan_audit = Some(audit);
    }

    pub fn scan_audit(&self) -> Option<&ScanAuditManifest> {
        self.scan_audit.as_ref()
    }

    pub fn record_rules(&mut self, rules: &[Arc<Rule>]) {
        // Clear existing data and extend in place
        self.rules.clear();
        self.rules.extend_from_slice(rules);
        self.blob_scoped_dependency_rule_ids.clear();
        for rule in rules {
            for dependency in rule.syntax().depends_on_rule.iter().flatten() {
                let Some(dependency_rule) =
                    rules.iter().find(|candidate| candidate.id() == dependency.rule_id)
                else {
                    continue;
                };

                // Helper rules must remain available for each blob so a nearby credential can
                // use them during validation. Visible findings, however, retain the normal
                // global content deduplication; making them blob-scoped turns one historical
                // secret into a finding for every revision that contains it.
                if !dependency_rule.syntax().visible {
                    self.blob_scoped_dependency_rule_ids.insert(dependency.rule_id.to_uppercase());
                }
            }
        }
    }

    /// Insert a batch of findings.  
    /// Returns the number of *new blobs* discovered in this batch.
    ///
    /// * `dedup == true` -- full cryptographic digests suppress duplicate findings.
    /// * Side-tables (`blob_meta`, `origin_meta`) guarantee only one Arc per distinct
    ///   `BlobMetadata` / `OriginSet`, so no more huge copies.
    pub fn record(&mut self, batch: Vec<FindingsStoreMessage>, dedup: bool) -> usize {
        let mut added = 0;

        for (origin, blob_md, m) in batch {
            /*───────────────────────────────────────────────────────────────┐
            │ 1. Optional duplicate filter                                  │
            └───────────────────────────────────────────────────────────────*/
            if dedup {
                // Prefer the full unnamed match (index 0). Fall back to a named TOKEN capture
                // before using whatever capture is available.
                let snippet = m
                    .groups
                    .captures
                    .iter()
                    .find(|c| c.name.is_none() && c.match_number == 0)
                    .map(|c| c.raw_value())
                    .or_else(|| {
                        m.groups
                            .captures
                            .iter()
                            .find(|c| matches!(c.name, Some("TOKEN")))
                            .map(|c| c.raw_value())
                    })
                    .or_else(|| m.groups.captures.first().map(|c| c.raw_value()))
                    .unwrap_or("");

                let origin_kind = dedup_origin_kind(&origin);

                let rule_id = m.rule.id().to_uppercase();
                let mut key_string = if self.blob_scoped_dependency_rule_ids.contains(&rule_id) {
                    format!("{}|{}|{}|{}", rule_id, origin_kind, snippet, blob_md.id.hex())
                } else {
                    format!("{}|{}|{}", rule_id, origin_kind, snippet)
                };
                // Association is resolved before storage: keep distinct validation contexts,
                // including a bare occurrence followed by a fully paired occurrence.
                if !m.rule.syntax().depends_on_rule.is_empty() {
                    key_string.push_str(
                        &serde_json::to_string(&(&m.dependent_captures, &m.ambiguous_dependencies))
                            .expect("dependency maps serialize"),
                    );
                }
                let digest = *blake3::hash(key_string.as_bytes()).as_bytes();

                if !self.dedup_exact.insert(digest) {
                    continue; // duplicate confirmed by its cryptographic digest
                }
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

        added
    }

    pub fn get_num_matches(&self) -> usize {
        self.assert_restored();
        // only count visible matches
        self.matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = msg.as_ref();
                match_item.visible
            })
            .count()
    }

    pub fn get_summary(&self, include_hidden_findings: bool) -> FxHashMap<&'static str, usize> {
        self.assert_restored();
        self.matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = &***msg;
                include_hidden_findings || match_item.visible
            })
            .fold(FxHashMap::default(), |mut acc, msg| {
                let (_, _, m) = &**msg;
                *acc.entry(intern(m.rule.name())).or_insert(0) += 1;
                acc
            })
    }

    pub fn clone_destination(&self, repo_url: &GitUrl) -> PathBuf {
        let repo_identifier = repo_url.to_string().replace(['/', ':'], "_");
        self.clone_dir.join(repo_identifier)
    }

    /// Return the directory used to store cloned repositories and other
    /// temporary artifacts.
    pub fn clone_root(&self) -> PathBuf {
        self.clone_dir.clone()
    }

    pub fn register_docker_image(&mut self, dir: PathBuf, image: String) {
        self.docker_images.insert(dir, image);
    }

    pub fn docker_images(&self) -> &FxHashMap<PathBuf, String> {
        &self.docker_images
    }

    pub fn register_slack_message(&mut self, path: PathBuf, permalink: String) {
        self.slack_links.insert(path, permalink);
    }

    pub fn slack_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.slack_links
    }

    pub fn register_teams_message(&mut self, path: PathBuf, url: String) {
        self.teams_links.insert(path, url);
    }

    pub fn teams_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.teams_links
    }

    pub fn register_confluence_page(&mut self, path: PathBuf, link: String) {
        self.confluence_links.insert(path, link);
    }

    pub fn confluence_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.confluence_links
    }

    pub fn register_postman_resource(&mut self, path: PathBuf, link: String) {
        self.postman_links.insert(path, link);
    }

    pub fn postman_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.postman_links
    }

    pub fn register_repo_link(&mut self, path: PathBuf, link: String) {
        self.repo_links.insert(path, link);
    }

    pub fn repo_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.repo_links
    }

    pub fn register_s3_bucket(&mut self, dir: PathBuf, bucket: String) {
        self.s3_buckets.insert(dir, bucket);
    }

    pub fn s3_buckets(&self) -> &FxHashMap<PathBuf, String> {
        &self.s3_buckets
    }

    pub fn merge_from(&mut self, other: &FindingsStore, dedup: bool) {
        if let Some(audit) = other.scan_audit() {
            self.scan_audit = Some(audit.clone());
        }
        for (dir, link) in other.repo_links() {
            self.repo_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        for (dir, bucket) in other.s3_buckets() {
            self.s3_buckets.entry(dir.clone()).or_insert_with(|| bucket.clone());
        }

        for (dir, image) in other.docker_images() {
            self.docker_images.entry(dir.clone()).or_insert_with(|| image.clone());
        }

        for (dir, link) in other.slack_links() {
            self.slack_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        for (dir, link) in other.teams_links() {
            self.teams_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        for (dir, link) in other.confluence_links() {
            self.confluence_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        for (dir, link) in other.postman_links() {
            self.postman_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        for chunk in other.get_matches().chunks(1024) {
            let batch = chunk
                .iter()
                .map(|msg| {
                    let (origin, blob_md, m) = msg.as_ref();
                    (Arc::clone(origin), Arc::clone(blob_md), m.clone())
                })
                .collect();
            self.record(batch, dedup);
        }
    }

    pub fn get_finding_data_iter(
        &self,
    ) -> impl Iterator<Item = finding_data::FindingMetadata> + '_ {
        self.assert_restored();
        self.matches.iter().map(|msg| {
            let (_, _, match_item) = &**msg;
            finding_data::FindingMetadata {
                rule_name: match_item.rule.name().to_string(),
                num_matches: 1,
                comment: None,
                visible: match_item.visible,
                finding_id: match_item.finding_id(),
                rule_finding_fingerprint: match_item.rule.finding_sha1_fingerprint().to_string(),
                rule_text_id: match_item.rule.id().to_string(),
            }
        })
    }

    pub fn get_finding_metadata(
        &self,
        metadata: &finding_data::FindingMetadata,
        _max_matches: Option<usize>,
    ) -> Result<Vec<finding_data::FindingDataEntry>> {
        self.assert_restored();
        self.matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = msg.as_ref();
                match_item.rule.name() == metadata.rule_name
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
                    match_confidence: match_item.rule.confidence(),
                    validation_response_body: match_item.validation_response_body.clone(),
                    validation_response_status: match_item.validation_response_status,
                    validation_success: match_item.validation_success,
                    validation_outcome: match_item.validation_outcome,
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
        self.assert_restored();
        self.matches.chunks(chunk_size).map(|slice| slice.to_vec()) // keep Arc pointers
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::FindingsStore;
    use crate::rules::rule::{DependsOnRule, Rule, RuleSyntax};

    fn rule(id: &str, visible: bool, depends_on_rule: Vec<Option<DependsOnRule>>) -> Arc<Rule> {
        Arc::new(Rule::new(RuleSyntax {
            name: id.to_owned(),
            id: id.to_owned(),
            pattern: String::new(),
            min_entropy: 0.0,
            confidence: Default::default(),
            visible,
            examples: Vec::new(),
            negative_examples: Vec::new(),
            references: Vec::new(),
            validation: None,
            revocation: None,
            depends_on_rule,
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        }))
    }

    #[test]
    fn visible_dependency_rules_keep_global_content_deduplication() {
        let helper = rule("custom.test.helper", false, Vec::new());
        let visible_secret = rule("custom.test.secret", true, Vec::new());
        let consumer = rule(
            "custom.test.consumer",
            true,
            vec![
                Some(DependsOnRule {
                    rule_id: helper.id().to_owned(),
                    variable: "HELPER".to_owned(),
                    optional: false,
                    within: None,
                }),
                Some(DependsOnRule {
                    rule_id: visible_secret.id().to_owned(),
                    variable: "SECRET".to_owned(),
                    optional: false,
                    within: None,
                }),
            ],
        );

        let mut store = FindingsStore::new(std::env::temp_dir());
        store.record_rules(&[helper, visible_secret, consumer]);

        assert!(store.blob_scoped_dependency_rule_ids.contains("CUSTOM.TEST.HELPER"));
        assert!(!store.blob_scoped_dependency_rule_ids.contains("CUSTOM.TEST.SECRET"));
    }

    fn spill_message(rule: Arc<Rule>, token: &str, offset: usize) -> super::FindingsStoreMessage {
        use crate::{
            blob::{BlobId, BlobMetadata},
            location::{Location, OffsetSpan},
            matcher::{Match, SerializableCapture, SerializableCaptures},
            origin::{Origin, OriginSet},
        };
        let id = BlobId::new(token.as_bytes());
        (
            Arc::new(OriginSet::single(Origin::from_file("fixture.txt".into()))),
            Arc::new(BlobMetadata {
                id,
                num_bytes: token.len(),
                mime_essence: Some("text/plain".into()),
                language: None,
            }),
            Match {
                rule,
                blob_id: id,
                location: Location {
                    offset_span: OffsetSpan { start: offset, end: offset + token.len() },
                    source_span: None,
                },
                groups: SerializableCaptures {
                    captures: smallvec::smallvec![SerializableCapture {
                        name: Some("TOKEN"),
                        match_number: 0,
                        start: offset,
                        end: offset + token.len(),
                        value: token.into()
                    }],
                },
                finding_fingerprint: 123,
                validation_response_body: Some("response body".into()),
                validation_response_status: 200,
                validation_success: true,
                validation_outcome: kingfisher_core::ValidationOutcome::VerifiedActive,
                calculated_entropy: 4.5,
                visible: true,
                is_base64: true,
                dependent_captures: [("HOST".into(), "fixture.invalid".into())].into(),
                ambiguous_dependencies: [("USER".into(), 2)].into(),
            },
        )
    }

    #[test]
    fn spill_round_trip_releases_payloads_and_preserves_dedup_and_validation() -> anyhow::Result<()>
    {
        let rule = rule("custom.spill", true, Vec::new());
        let mut store = FindingsStore::new(std::env::temp_dir());
        store.record_rules(&[Arc::clone(&rule)]);
        store.enable_spilling()?;
        let message = spill_message(Arc::clone(&rule), "private-test-token", 3);
        let value = Arc::downgrade(&message.2.groups.captures[0].value);
        store.record(vec![message], true);
        store.spill_pending()?;
        assert!(store.matches.is_empty());
        assert!(value.upgrade().is_none(), "spilling must actually release captured values");
        // Same credential in a later repository stays deduplicated across spill boundaries.
        store.record(vec![spill_message(Arc::clone(&rule), "private-test-token", 9)], true);
        assert!(store.matches.is_empty());
        store.record(vec![spill_message(Arc::clone(&rule), "second-test-token", 20)], true);
        store.spill_pending()?;
        store.restore_spilled()?;
        assert_eq!(store.get_matches().len(), 2);
        let restored = &store.get_matches()[0].2;
        assert_eq!(restored.groups.captures[0].raw_value(), "private-test-token");
        assert_eq!(restored.location.offset_span.start, 3);
        assert!(restored.location.source_span.is_none());
        assert_eq!(restored.finding_fingerprint, 123);
        assert_eq!(restored.validation_response_body.as_deref(), Some("response body"));
        assert_eq!(restored.validation_outcome, kingfisher_core::ValidationOutcome::VerifiedActive);
        assert_eq!(restored.validation_response_status, 200);
        assert!(restored.validation_success && restored.is_base64);
        assert_eq!(restored.dependent_captures["HOST"], "fixture.invalid");
        assert_eq!(restored.ambiguous_dependencies["USER"], 2);
        assert!(Arc::ptr_eq(&restored.rule, &rule));
        store.restore_spilled()?;
        assert_eq!(store.get_matches().len(), 2, "restoring twice must not duplicate findings");
        Ok(())
    }

    #[test]
    fn spill_preserves_git_commit_context_and_rebuilds_metadata_sharing() -> anyhow::Result<()> {
        let rule = rule("private.spill.git", true, Vec::new());
        let mut store = FindingsStore::new(std::env::temp_dir());
        store.record_rules(&[Arc::clone(&rule)]);
        store.enable_spilling()?;
        let mut message = spill_message(Arc::clone(&rule), "git-test-token", 7);
        message.0 = Arc::new(crate::origin::OriginSet::single(
            crate::origin::Origin::from_git_repo_with_first_commit(
                Arc::new("repository".into()),
                Arc::new(crate::git_commit_metadata::CommitMetadata {
                    commit_id: gix::ObjectId::from_hex(
                        b"0123456789abcdef0123456789abcdef01234567",
                    )?,
                    committer_name: "Fixture Author".into(),
                    committer_email: "fixture@example.invalid".into(),
                    committer_timestamp: gix::date::Time::new(1_700_000_000, -25_200),
                }),
                "nested/credential.txt".into(),
            ),
        ));
        let expected_origin = serde_json::to_value(&message.0)?;
        store.record(vec![message.clone(), message], false);
        store.spill_pending()?;
        store.restore_spilled()?;
        let messages = store.get_matches();
        assert_eq!(messages.len(), 2);
        assert_eq!(serde_json::to_value(&messages[0].0)?, expected_origin);
        assert!(Arc::ptr_eq(&messages[0].0, &messages[1].0));
        assert!(Arc::ptr_eq(&messages[0].1, &messages[1].1));
        Ok(())
    }

    #[test]
    fn failed_spill_restore_keeps_the_original_records() -> anyhow::Result<()> {
        let rule = rule("custom.spill", true, Vec::new());
        let mut store = FindingsStore::new(std::env::temp_dir());
        store.enable_spilling()?;
        store.record(vec![spill_message(Arc::clone(&rule), "test-token", 0)], false);
        store.spill_pending()?;
        assert!(store.restore_spilled().is_err());
        store.record_rules(&[rule]);
        store.restore_spilled()?;
        assert_eq!(store.get_matches().len(), 1);
        Ok(())
    }
    #[test]
    fn disk_full_restores_completed_batches_and_keeps_pending_findings() -> anyhow::Result<()> {
        for dedup in [false, true] {
            for bytes_before_failure in [0, 16, 10_000] {
                let rule = rule("custom.disk-full", true, Vec::new());
                let mut store = FindingsStore::new(std::env::temp_dir());
                store.record_rules(&[Arc::clone(&rule)]);
                store.enable_spilling()?;
                for index in 0..1025 {
                    store.record(
                        vec![spill_message(Arc::clone(&rule), &format!("saved-{index}"), index)],
                        dedup,
                    );
                }
                store.spill_pending()?;
                let token = "pending-value-".repeat(2000);
                store.record(vec![spill_message(Arc::clone(&rule), &token, 2000)], dedup);
                store.spill.as_mut().unwrap().write_failure =
                    Some((bytes_before_failure, std::io::ErrorKind::StorageFull));
                store.spill_pending()?;
                assert!(store.spill.is_none(), "disk writes must stay disabled after fallback");
                assert_eq!(store.get_matches().len(), 1026);
                assert_eq!(store.get_matches()[0].2.groups.captures[0].raw_value(), "saved-0");
                assert_eq!(store.get_matches()[1025].2.groups.captures[0].raw_value(), token);
                assert_eq!(store.get_matches()[0].2.dependent_captures["HOST"], "fixture.invalid");
                assert!(store.get_matches()[0].2.validation_success);
                store.record(vec![spill_message(Arc::clone(&rule), "saved-0", 3000)], dedup);
                store.spill_pending()?;
                store.restore_spilled()?;
                assert_eq!(store.get_matches().len(), if dedup { 1026 } else { 1027 });
            }
        }
        Ok(())
    }

    #[test]
    fn disk_full_on_first_write_keeps_findings_in_memory() -> anyhow::Result<()> {
        let rule = rule("custom.disk-full", true, Vec::new());
        let mut store = FindingsStore::new(std::env::temp_dir());
        store.record_rules(&[Arc::clone(&rule)]);
        store.enable_spilling()?;
        store.record(vec![spill_message(rule, "pending-token", 0)], false);
        store.spill.as_mut().unwrap().write_failure = Some((16, std::io::ErrorKind::StorageFull));
        store.spill_pending()?;
        assert!(store.spill.is_none());
        assert_eq!(store.get_matches()[0].2.groups.captures[0].raw_value(), "pending-token");
        Ok(())
    }

    #[test]
    fn other_disk_errors_fail_without_losing_findings() -> anyhow::Result<()> {
        let rule = rule("custom.disk-error", true, Vec::new());
        let mut store = FindingsStore::new(std::env::temp_dir());
        store.record_rules(&[Arc::clone(&rule)]);
        store.enable_spilling()?;
        store.record(vec![spill_message(Arc::clone(&rule), "saved-token", 0)], false);
        store.spill_pending()?;
        store.record(vec![spill_message(rule, "pending-token", 10)], false);
        store.spill.as_mut().unwrap().write_failure =
            Some((16, std::io::ErrorKind::PermissionDenied));
        assert!(store.spill_pending().is_err());
        assert!(store.spill.is_some());
        store.restore_spilled()?;
        assert_eq!(store.get_matches().len(), 2);
        Ok(())
    }

    #[test]
    fn disk_full_with_failed_restore_does_not_discard_the_file_or_pending_findings()
    -> anyhow::Result<()> {
        let rule = rule("custom.disk-full", true, Vec::new());
        let mut store = FindingsStore::new(std::env::temp_dir());
        store.enable_spilling()?;
        store.record(vec![spill_message(Arc::clone(&rule), "saved-token", 0)], false);
        store.spill_pending()?;
        store.record(vec![spill_message(Arc::clone(&rule), "pending-token", 10)], false);
        store.spill.as_mut().unwrap().write_failure = Some((16, std::io::ErrorKind::StorageFull));
        // Missing rule prevents decoding: fallback must fail instead of continuing with partial data.
        assert!(store.spill_pending().is_err());
        assert!(store.spill.is_some());
        assert_eq!(store.matches.len(), 1);
        store.record_rules(&[rule]);
        store.restore_spilled()?;
        assert_eq!(store.get_matches().len(), 2);
        Ok(())
    }
}
