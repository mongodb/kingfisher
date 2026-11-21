use std::{
    cell::RefCell, collections::BinaryHeap, hash::BuildHasher, path::Path, sync::Arc, time::Instant,
};

use anyhow::{Context, Result, bail};
use bstr::{BStr, BString, ByteSlice};
use fixedbitset::FixedBitSet;
use gix::{
    ObjectId,
    hashtable::{
        HashMap, hash_map,
        hash_table::{self, HashTable},
    },
    object::Kind,
    objs::tree::EntryKind,
    prelude::*,
};
use globset::GlobSet;

use crate::{
    git_candidates::{GitContentCandidate, GitContentFilter, RetainedGitBlob},
    git_repo_enumerator::MIN_SCANNABLE_BLOB_SIZE,
    input::scan_repo_from_sync,
};
use petgraph::{
    graph::{DiGraph, EdgeIndex, IndexType, NodeIndex},
    prelude::*,
    visit::Visitable,
};
use rayon::prelude::*;
use roaring::RoaringBitmap;
use smallvec::SmallVec;
use tracing::{debug, error_span, trace, warn};

use crate::bstring_table::BStringTable;

type Symbol = crate::bstring_table::Symbol<u32>;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone, Default, Debug)]
pub(crate) struct CommitGraphIdx(NodeIndex);
unsafe impl IndexType for CommitGraphIdx {
    #[inline(always)]
    fn new(x: usize) -> Self {
        Self(NodeIndex::new(x))
    }
    #[inline(always)]
    fn index(&self) -> usize {
        self.0.index()
    }
    #[inline(always)]
    fn max() -> Self {
        Self(<NodeIndex as IndexType>::max())
    }
}

type CommitNodeIdx = NodeIndex<CommitGraphIdx>;
type CommitEdgeIdx = EdgeIndex<CommitGraphIdx>;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone, Default, Debug)]
pub(crate) struct ObjectIdx(u32);
impl ObjectIdx {
    pub(crate) fn new(x: usize) -> Self {
        Self(x.try_into().unwrap())
    }
    pub(crate) fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CommitMetadata {
    pub(crate) oid: ObjectId,
    pub(crate) tree_idx: Option<ObjectIdx>,
}

const TREE_SHARD_BITS: u32 = 16;
const TREE_SHARD_SIZE: usize = 1 << TREE_SHARD_BITS;
const MIN_SHARDED_TREE_COUNT: usize = 4 * TREE_SHARD_SIZE;

#[derive(Clone, Debug)]
enum SeenTrees {
    Small(RoaringBitmap),
    // Dense object indices use one Roaring container's worth of values per
    // independently shared shard. Forks only copy shards that actually change.
    Sharded(Vec<Option<Arc<RoaringBitmap>>>),
}

impl SeenTrees {
    fn shard(id: u32) -> (usize, u32) {
        ((id >> TREE_SHARD_BITS) as usize, id & (TREE_SHARD_SIZE as u32 - 1))
    }

    fn contains(&self, id: u32) -> bool {
        match self {
            Self::Small(trees) => trees.contains(id),
            Self::Sharded(shards) => {
                let (index, local_id) = Self::shard(id);
                shards
                    .get(index)
                    .and_then(Option::as_ref)
                    .is_some_and(|trees| trees.contains(local_id))
            }
        }
    }

    fn insert(&mut self, id: u32) -> bool {
        match self {
            Self::Small(trees) => trees.insert(id),
            Self::Sharded(shards) => {
                let (index, local_id) = Self::shard(id);
                if index >= shards.len() {
                    shards.resize_with(index + 1, || None);
                }
                Arc::make_mut(shards[index].get_or_insert_with(Arc::default)).insert(local_id)
            }
        }
    }

    fn union_update(&mut self, other: &Self) {
        match (self, other) {
            (Self::Small(trees), Self::Small(other)) => *trees |= other,
            (Self::Sharded(shards), Self::Sharded(other)) => {
                if other.len() > shards.len() {
                    shards.resize_with(other.len(), || None);
                }
                for (shard, source) in shards.iter_mut().zip(other) {
                    let Some(source) = source else { continue };
                    if let Some(destination) = shard {
                        if !Arc::ptr_eq(destination, source) {
                            *Arc::make_mut(destination) |= source.as_ref();
                        }
                    } else {
                        *shard = Some(Arc::clone(source));
                    }
                }
            }
            _ => unreachable!("ancestry sets for one repository share the same layout"),
        }
    }
}

#[derive(Clone, Debug)]
struct SeenObjectSet {
    seen_trees: Arc<SeenTrees>,
    seen_blobs: Arc<RoaringBitmap>,
}
impl SeenObjectSet {
    pub(crate) fn new(tree_count: usize) -> Self {
        let seen_trees = if tree_count >= MIN_SHARDED_TREE_COUNT {
            SeenTrees::Sharded(Vec::new())
        } else {
            SeenTrees::Small(RoaringBitmap::new())
        };
        Self { seen_trees: Arc::new(seen_trees), seen_blobs: Arc::default() }
    }
    fn insert(set: &mut Arc<RoaringBitmap>, idx: ObjectIdx) -> Result<bool> {
        let idx = idx.as_usize().try_into()?;
        if set.contains(idx) {
            return Ok(false);
        }
        Ok(Arc::make_mut(set).insert(idx))
    }
    fn contains(set: &RoaringBitmap, idx: ObjectIdx) -> Result<bool> {
        Ok(set.contains(idx.as_usize().try_into()?))
    }
    pub(crate) fn insert_tree(&mut self, idx: ObjectIdx) -> Result<bool> {
        let idx = idx.as_usize().try_into()?;
        if self.seen_trees.contains(idx) {
            return Ok(false);
        }
        Ok(Arc::make_mut(&mut self.seen_trees).insert(idx))
    }
    pub(crate) fn contains_tree(&self, idx: ObjectIdx) -> Result<bool> {
        Ok(self.seen_trees.contains(idx.as_usize().try_into()?))
    }
    pub(crate) fn insert_blob(&mut self, idx: ObjectIdx) -> Result<bool> {
        Self::insert(&mut self.seen_blobs, idx)
    }
    pub(crate) fn contains_blob(&self, idx: ObjectIdx) -> Result<bool> {
        Self::contains(&self.seen_blobs, idx)
    }
    pub(crate) fn union_update(&mut self, other: &Self) {
        // A fork shares its large ancestor bitmaps until a child actually changes
        // them. Keep trees and blobs separate so clean commits can continue sharing
        // the blob bitmap even while their root trees change.
        if !Arc::ptr_eq(&self.seen_blobs, &other.seen_blobs) {
            *Arc::make_mut(&mut self.seen_blobs) |= other.seen_blobs.as_ref();
        }
        if !Arc::ptr_eq(&self.seen_trees, &other.seen_trees) {
            Arc::make_mut(&mut self.seen_trees).union_update(other.seen_trees.as_ref());
        }
    }
}

struct ObjectIdBimap {
    // Store only indexes in the table; compare full IDs in the dense vector.
    oid_to_idx: HashTable<ObjectIdx>,
    idx_to_oid: Vec<ObjectId>,
}
impl ObjectIdBimap {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            oid_to_idx: HashTable::with_capacity(capacity),
            idx_to_oid: Vec::with_capacity(capacity),
        }
    }
    fn insert(&mut self, oid: ObjectId) -> bool {
        let ids = &mut self.idx_to_oid;
        let hasher = gix::hashtable::hash::Builder;
        match self.oid_to_idx.entry(
            hasher.hash_one(oid),
            |idx| ids[idx.as_usize()] == oid,
            |idx| hasher.hash_one(ids[idx.as_usize()]),
        ) {
            hash_table::Entry::Occupied(_) => false,
            hash_table::Entry::Vacant(e) => {
                let idx = ObjectIdx::new(ids.len());
                ids.push(oid);
                e.insert(idx);
                true
            }
        }
    }
    fn get_oid(&self, idx: ObjectIdx) -> Option<&gix::oid> {
        self.idx_to_oid.get(idx.as_usize()).map(|v| v.as_ref())
    }
    fn get_idx(&self, oid: &gix::oid) -> Option<ObjectIdx> {
        self.oid_to_idx
            .find(gix::hashtable::hash::Builder.hash_one(oid), |idx| {
                self.idx_to_oid[idx.as_usize()].as_ref() == oid
            })
            .copied()
    }
    fn len(&self) -> usize {
        self.idx_to_oid.len()
    }
}

type Symbols = SmallVec<[Symbol; 6]>;
type TreeWorklistItem = (Symbols, ObjectId);
type TreeWorklist = Vec<TreeWorklistItem>;

pub(crate) struct RepositoryIndex {
    trees: ObjectIdBimap,
    tree_bytes: u64,
    commits: ObjectIdBimap,
    blobs: ObjectIdBimap,
    // Same dense order as blobs.idx_to_oid, including after candidate compaction.
    blob_sizes: Vec<u64>,
    // Used only before candidate compaction to rank the inflated-blob handoff.
    blob_delta_bands: Vec<u8>,
    tags: ObjectIdBimap,
    candidate_trees: Option<FixedBitSet>,
    content_filtered: bool,
    candidate_summaries: Option<crate::git_candidate_summaries::CandidateSummaries>,
}
impl RepositoryIndex {
    pub(crate) fn new_with_deadline(
        repo: &gix::ThreadSafeRepository,
        deadline: Option<Instant>,
        repo_path: &Path,
    ) -> Result<Self> {
        use gix::{odb::store::iter::Ordering, prelude::*};
        // Object header lookups are independent but can require pack-file I/O. Use the
        // existing bounded Rayon pool to overlap lookups in small batches. Batch boundaries
        // retain ODB order, and cap temporary IDs/results to bound extra memory.
        // Keep each worker's handle across batches. `map_init` creates a new
        // handle for each Rayon job, repeatedly discarding pack lookup state.
        let repositories = thread_local::ThreadLocal::new();
        const BATCH_SIZE: usize = 4096;
        let mut object_iter = repo
            .to_thread_local()
            .objects
            .iter()
            .context("Failed to iterate object database")?
            .with_ordering(Ordering::PackAscendingOffsetThenLooseLexicographical);

        let mut trees = ObjectIdBimap::with_capacity(0);
        let mut tree_bytes = 0_u64;
        let mut commits = ObjectIdBimap::with_capacity(0);
        let mut blobs = ObjectIdBimap::with_capacity(0);
        let mut blob_sizes = Vec::new();
        let mut blob_delta_bands = Vec::new();
        let mut tags = ObjectIdBimap::with_capacity(0);
        loop {
            check_deadline(deadline, "repository object indexing", repo_path)?;
            let batch = object_iter.by_ref().take(BATCH_SIZE).collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            let indexed_objects: Vec<Result<_>> = batch
                .into_par_iter()
                .with_min_len(64)
                .map(|oid_result| {
                    check_deadline(deadline, "repository object indexing", repo_path)?;
                    let local_repo = repositories.get_or(|| repo.to_thread_local());
                    let oid = match oid_result {
                        Ok(oid) => oid,
                        Err(e) => {
                            debug!("Failed to read object id: {e}");
                            return Ok(None);
                        }
                    };
                    let hdr = match local_repo.objects.header(oid) {
                        Ok(hdr) => hdr,
                        Err(e) => {
                            debug!("Failed to read object header for {oid}: {e}");
                            return Ok(None);
                        }
                    };
                    let kind = hdr.kind();
                    let size = hdr.size();
                    if kind == Kind::Blob && size < MIN_SCANNABLE_BLOB_SIZE {
                        return Ok(None);
                    }
                    Ok(Some((oid, hdr)))
                })
                .collect();
            // Indexed parallel collection preserves ODB order, including
            // skipped entries, without sorting or changing dense object IDs.
            for result in indexed_objects {
                let Some((oid, hdr)) = result? else { continue };
                let size = hdr.size();
                match hdr.kind() {
                    Kind::Tree => {
                        if trees.insert(oid) {
                            tree_bytes = tree_bytes.saturating_add(size);
                        }
                    }
                    Kind::Blob => {
                        if blobs.insert(oid) {
                            blob_sizes.push(size);
                            // Broad depth bands estimate reconstruction work per byte
                            // without churning the cache for small priority changes.
                            let depth = hdr.num_deltas().unwrap_or_default();
                            blob_delta_bands.push(depth.saturating_add(1).ilog2() as u8);
                        }
                    }
                    Kind::Commit => {
                        commits.insert(oid);
                    }
                    Kind::Tag => {
                        tags.insert(oid);
                    }
                }
            }
        }
        Ok(Self {
            trees,
            tree_bytes,
            commits,
            blobs,
            blob_sizes,
            blob_delta_bands,
            tags,
            candidate_trees: None,
            content_filtered: false,
            candidate_summaries: None,
        })
    }
    pub(crate) fn num_commits(&self) -> usize {
        self.commits.len()
    }
    pub(crate) fn num_blobs(&self) -> usize {
        self.blobs.len()
    }
    pub(crate) fn num_trees(&self) -> usize {
        self.trees.len()
    }
    pub(crate) fn tree_bytes(&self) -> u64 {
        self.tree_bytes
    }
    pub(crate) fn num_tags(&self) -> usize {
        self.tags.len()
    }
    pub(crate) fn num_objects(&self) -> usize {
        self.num_commits() + self.num_blobs() + self.num_tags() + self.num_trees()
    }
    pub(crate) fn get_tree_oid(&self, idx: ObjectIdx) -> Option<&gix::oid> {
        self.trees.get_oid(idx)
    }
    pub(crate) fn get_tree_index(&self, oid: &gix::oid) -> Option<ObjectIdx> {
        self.trees.get_idx(oid)
    }
    pub(crate) fn is_candidate_tree(&self, idx: ObjectIdx) -> bool {
        self.candidate_trees.as_ref().is_none_or(|trees| trees.contains(idx.as_usize()))
    }
    pub(crate) fn get_blob_index(&self, oid: &gix::oid) -> Option<ObjectIdx> {
        self.blobs.get_idx(oid)
    }
    pub(crate) fn into_blob_parts(self) -> (Vec<ObjectId>, Vec<u64>, HashTable<ObjectIdx>) {
        (self.blobs.idx_to_oid, self.blob_sizes, self.blobs.oid_to_idx)
    }
    pub(crate) fn commits(&self) -> &[ObjectId] {
        &self.commits.idx_to_oid
    }

    pub(crate) fn retain_content_candidates(
        &mut self,
        repo: &gix::ThreadSafeRepository,
        filter: &GitContentFilter<'_>,
        deadline: Option<Instant>,
        repo_path: &Path,
    ) -> Result<Vec<(ObjectId, Arc<RetainedGitBlob>)>> {
        const BATCH_SIZE: usize = 1024;
        const MAX_RETAINED_BUFFER: usize = 8 * 1024 * 1024;
        const MAX_PREPASS_BLOB_BYTES: u64 = 4 * 1024 * 1024;
        let started = Instant::now();
        let num_blobs = self.blobs.len();
        let handoff = filter.blob_handoff();
        // Keep pack lookup state and a reusable, bounded scratch buffer per worker,
        // not per Rayon job. Only candidates can hold onto bytes for the final scan.
        let workers = thread_local::ThreadLocal::new();
        let batches: Result<Vec<_>> = self
            .blobs
            .idx_to_oid
            .par_chunks(BATCH_SIZE)
            .zip(self.blob_sizes.par_chunks(BATCH_SIZE))
            .zip(self.blob_delta_bands.par_chunks(BATCH_SIZE))
            .enumerate()
            .map(|(batch, ((ids, sizes), bands))| {
                let worker =
                    workers.get_or(|| RefCell::new((scan_repo_from_sync(repo), Vec::new())));
                let mut worker = worker.borrow_mut();
                let (repo, buffer) = &mut *worker;
                let mut selected = FixedBitSet::with_capacity(ids.len());
                let mut base64_only = 0usize;
                let (mut clean_blobs, mut clean_bytes) = (0, 0);
                for (i, ((oid, &size), &band)) in ids.iter().zip(sizes).zip(bands).enumerate() {
                    check_deadline(deadline, "Git content candidate prepass", repo_path)?;
                    // Enforce the scan limit before this prepass can inflate a blob.
                    // Skipped objects are not scanned or counted as clean content.
                    if filter.exceeds_max_blob_size(size) {
                        continue;
                    }
                    // Large blobs are expensive to inflate twice. Retain allowed
                    // ones conservatively and let normal loading read them once.
                    if size > MAX_PREPASS_BLOB_BYTES {
                        selected.insert(i);
                        continue;
                    }
                    let keep = match repo.objects.find_blob(oid, buffer) {
                        Ok(blob) => {
                            let candidate = filter.classify(blob.data)?;
                            let keep = candidate != GitContentCandidate::Clean;
                            if keep {
                                base64_only +=
                                    usize::from(candidate == GitContentCandidate::Base64Only);
                                handoff.offer(batch * BATCH_SIZE + i, band, blob.data, candidate);
                            }
                            keep
                        }
                        // Let normal loading report unreadable candidate objects rather
                        // than classifying an I/O/decode failure as a clean blob.
                        Err(_) => true,
                    };
                    if keep {
                        selected.insert(i);
                    } else {
                        clean_blobs += 1;
                        clean_bytes += buffer.len() as u64;
                    }
                    if buffer.capacity() > MAX_RETAINED_BUFFER {
                        *buffer = Vec::new();
                    }
                }
                filter.record_clean(clean_blobs, clean_bytes);
                Ok((selected, base64_only))
            })
            .collect();
        let batches = batches?;
        // Release worker delta caches before the serial metadata phase starts.
        drop(workers);
        let retained = handoff.into_blobs(&self.blobs.idx_to_oid);
        let selected = batches.iter().map(|(bits, _)| bits.count_ones(..)).sum();
        self.retain_blob_indexes(selected, |i| batches[i / BATCH_SIZE].0.contains(i % BATCH_SIZE));
        debug!(
            "Git content prepass retained {selected}/{num_blobs} blobs in {:.6}s",
            started.elapsed().as_secs_f64()
        );
        debug!(
            "Git prepass handed off {} inflated blobs ({} bytes)",
            retained.len(),
            retained.iter().map(|(_, blob)| blob.len()).sum::<usize>()
        );
        debug!(
            base64_only = batches.iter().map(|(_, count)| count).sum::<usize>(),
            retained_proofs = retained.iter().filter(|(_, blob)| blob.native_negative()).count(),
            "Git prepass completed native scans"
        );
        Ok(retained)
    }

    fn retain_blob_indexes(&mut self, selected: usize, keep: impl Fn(usize) -> bool) {
        let old = std::mem::replace(&mut self.blobs, ObjectIdBimap::with_capacity(0));
        drop(old.oid_to_idx);
        let mut candidates = ObjectIdBimap::with_capacity(selected);
        let old_sizes = std::mem::replace(&mut self.blob_sizes, Vec::with_capacity(selected));
        let old_bands = std::mem::replace(&mut self.blob_delta_bands, Vec::with_capacity(selected));
        for (i, ((oid, size), band)) in
            old.idx_to_oid.into_iter().zip(old_sizes).zip(old_bands).enumerate()
        {
            if keep(i) {
                candidates.insert(oid);
                self.blob_sizes.push(size);
                self.blob_delta_bands.push(band);
            }
        }
        self.blobs = candidates;
        self.content_filtered = true;
    }

    pub(crate) fn prepare_candidate_trees(
        &mut self,
        repo: &gix::ThreadSafeRepository,
        deadline: Option<Instant>,
        repo_path: &Path,
    ) -> Result<()> {
        let started = Instant::now();
        let summaries = crate::git_candidate_summaries::CandidateSummaries::build(
            self, repo, deadline, repo_path,
        )?;
        self.candidate_trees = Some(summaries.relevant());
        self.candidate_summaries = Some(summaries);
        debug!("Prepared bounded candidate summaries in {:.6}s", started.elapsed().as_secs_f64());
        Ok(())
    }

    fn tree_is_covered(&self, idx: ObjectIdx, seen: &SeenObjectSet) -> bool {
        self.candidate_summaries.as_ref().is_some_and(|summaries| {
            summaries.covered(idx, self.get_tree_oid(idx).unwrap(), &seen.seen_blobs)
        })
    }

    pub(crate) fn compact_candidate_trees(&mut self, graph: &mut GitMetadataGraph) {
        let Some(selected) = self.candidate_trees.take() else { return };
        let original_count = self.trees.len();
        let selected_count = selected.count_ones(..);
        if selected_count == original_count {
            return;
        }
        // Reserve u32::MAX as a temporary "not selected" sentinel. Keep the
        // bitmap-based pruning path for repositories too large for that sentinel.
        if u32::try_from(original_count).is_err() {
            self.candidate_trees = Some(selected);
            return;
        }
        let started = Instant::now();
        if let Some(summaries) = &mut self.candidate_summaries {
            summaries.retain(&selected);
        }
        let old = std::mem::replace(&mut self.trees, ObjectIdBimap::with_capacity(0));
        drop(old.oid_to_idx);
        let mut remap = vec![u32::MAX; original_count];
        let mut trees = ObjectIdBimap::with_capacity(selected_count);
        for (i, oid) in old.idx_to_oid.into_iter().enumerate() {
            if selected.contains(i) {
                remap[i] = ObjectIdx::new(trees.len()).0;
                trees.insert(oid);
            }
        }
        self.trees = trees;
        // Build the commit graph against the complete index first, preserving
        // missing-tree behavior and every parent edge. Irrelevant snapshots lose
        // only their tree lookup; they must still propagate ancestor blob state.
        for commit in graph.commits.node_weights_mut() {
            commit.tree_idx = commit.tree_idx.and_then(|old| {
                let new = remap[old.as_usize()];
                (new != u32::MAX).then_some(ObjectIdx(new))
            });
        }
        debug!(
            "Compacted historical tree index from {original_count} to {selected_count} entries in {:.6}s",
            started.elapsed().as_secs_f64()
        );
    }
}

pub(crate) struct GitMetadataGraph {
    commit_oid_to_node_idx: HashMap<ObjectId, CommitNodeIdx>,
    commits: DiGraph<CommitMetadata, (), CommitGraphIdx>,
}
impl GitMetadataGraph {
    pub(crate) fn with_capacity(num_commits: usize) -> Self {
        let commit_edges_capacity = num_commits * 2;
        Self {
            commit_oid_to_node_idx: HashMap::with_capacity_and_hasher(
                num_commits,
                Default::default(),
            ),
            commits: DiGraph::with_capacity(num_commits, commit_edges_capacity),
        }
    }
    #[inline]
    pub(crate) fn get_commit_metadata(&self, idx: CommitNodeIdx) -> &CommitMetadata {
        self.commits.node_weight(idx).unwrap()
    }
    pub(crate) fn get_commit_idx(
        &mut self,
        oid: ObjectId,
        tree_idx: Option<ObjectIdx>,
    ) -> CommitNodeIdx {
        match self.commit_oid_to_node_idx.entry(oid) {
            hash_map::Entry::Occupied(e) => {
                let idx = *e.get();
                if let Some(t) = tree_idx {
                    self.commits.node_weight_mut(idx).unwrap().tree_idx = Some(t);
                }
                idx
            }
            hash_map::Entry::Vacant(e) => {
                let idx = self.commits.add_node(CommitMetadata { oid, tree_idx });
                *e.insert(idx)
            }
        }
    }
    pub(crate) fn add_commit_edge(
        &mut self,
        parent_idx: CommitNodeIdx,
        child_idx: CommitNodeIdx,
    ) -> CommitEdgeIdx {
        self.commits.add_edge(parent_idx, child_idx, ())
    }
}

// Most commits introduce few blobs; keep the per-commit inline allocation small.
pub(crate) type IntroducedBlobs = SmallVec<[(ObjectId, BString); 1]>;
pub(crate) struct CommitBlobMetadata {
    pub(crate) commit_oid: ObjectId,
    pub(crate) introduced_blobs: IntroducedBlobs,
}

impl GitMetadataGraph {
    pub(crate) fn get_repo_metadata_with_deadline(
        mut self,
        repo_index: &RepositoryIndex,
        repo: &gix::Repository,
        exclude_globset: Option<&GlobSet>,
        deadline: Option<Instant>,
    ) -> Result<Vec<CommitBlobMetadata>> {
        let _span =
            error_span!("get_repo_metadata", path = repo.path().display().to_string()).entered();
        let t1 = Instant::now();
        // Graph construction is complete; traversal addresses nodes by index.
        drop(std::mem::take(&mut self.commit_oid_to_node_idx));
        let cg = &self.commits;
        let num_commits = cg.node_count();
        let mut seen_sets: Vec<Option<SeenObjectSet>> = vec![None; num_commits];
        let mut blobs_introduced: Vec<IntroducedBlobs> = vec![SmallVec::new(); num_commits];
        let mut visited_commit_edges = FixedBitSet::with_capacity(cg.edge_count());
        let mut visited_commits = cg.visit_map();
        let mut commit_worklist =
            BinaryHeap::<(std::cmp::Reverse<u32>, CommitNodeIdx)>::with_capacity(num_commits);
        let mut symbols = BStringTable::with_capacity(32 * 1024, 1024 * 1024);
        for root_idx in
            cg.node_indices().filter(|idx| cg.neighbors_directed(*idx, Incoming).count() == 0)
        {
            let out_deg = cg.neighbors_directed(root_idx, Outgoing).count() as u32;
            commit_worklist.push((std::cmp::Reverse(out_deg), root_idx));
            seen_sets[root_idx.index()] = Some(SeenObjectSet::new(repo_index.num_trees()));
        }
        let mut tree_worklist = Vec::with_capacity(32 * 1024);
        let mut tree_buf = Vec::with_capacity(1024 * 1024);
        let mut blobs_encountered = Vec::with_capacity(16 * 1024);
        let (mut max_frontier_size, mut num_blobs_introduced, mut num_trees_introduced) = (0, 0, 0);
        let (mut num_commits_visited, mut num_live_seen_sets, mut max_live_seen_sets) =
            (0, commit_worklist.len(), 0);

        while let Some((_, commit_idx)) = commit_worklist.pop() {
            check_deadline(deadline, "repository metadata computation", repo.path())?;
            if visited_commits.put(commit_idx.index()) {
                warn!("found duplicate commit node {}", commit_idx.index());
                continue;
            }
            let introduced = &mut blobs_introduced[commit_idx.index()];
            let mut seen = seen_sets[commit_idx.index()].take().unwrap();
            num_live_seen_sets -= 1;
            num_commits_visited += 1;
            max_frontier_size = max_frontier_size.max(commit_worklist.len() + 1);
            max_live_seen_sets = max_live_seen_sets.max(num_live_seen_sets);
            if let Some(tree_idx) = self.get_commit_metadata(commit_idx).tree_idx {
                if repo_index.is_candidate_tree(tree_idx)
                    && !repo_index.tree_is_covered(tree_idx, &seen)
                    && seen.insert_tree(tree_idx)?
                {
                    tree_worklist.push((
                        SmallVec::new(),
                        repo_index.get_tree_oid(tree_idx).unwrap().to_owned(),
                    ));
                    visit_tree(
                        repo,
                        &mut symbols,
                        exclude_globset,
                        repo_index,
                        &mut num_trees_introduced,
                        &mut num_blobs_introduced,
                        &mut seen,
                        introduced,
                        &mut tree_buf,
                        &mut tree_worklist,
                        &mut blobs_encountered,
                        deadline,
                    )?;
                }
            } else if !repo_index.content_filtered {
                debug!(
                    "No tree index for {}; blob metadata may be incomplete",
                    self.get_commit_metadata(commit_idx).oid
                );
            }
            // Move the state into the last child without constructing replacement
            // Arc bitmaps on every linear-history commit.
            let mut seen = Some(seen);
            let mut edges = cg.edges_directed(commit_idx, Outgoing).peekable();
            while let Some(edge) = edges.next() {
                let edge_index = edge.id().index();
                if visited_commit_edges.put(edge_index) {
                    debug!("Edge {edge_index} visited more than once");
                    continue;
                }
                let child_idx = edge.target();
                let child_seen = &mut seen_sets[child_idx.index()];
                if let Some(child_seen) = child_seen {
                    child_seen.union_update(seen.as_ref().unwrap());
                } else {
                    num_live_seen_sets += 1;
                    if edges.peek().is_none() {
                        *child_seen = seen.take();
                    } else {
                        *child_seen = seen.clone();
                    }
                }
                let has_unvisited_parents = cg
                    .edges_directed(child_idx, Incoming)
                    .any(|e| !visited_commit_edges.contains(e.id().index()));
                if !has_unvisited_parents {
                    let out_deg = cg.neighbors_directed(child_idx, Outgoing).count() as u32;
                    commit_worklist.push((std::cmp::Reverse(out_deg), child_idx));
                }
            }
        }
        if visited_commit_edges.count_ones(..) != visited_commit_edges.len() {
            bail!("Topological traversal failed: a commit cycle was detected");
        }
        let result: Vec<CommitBlobMetadata> = cg
            .node_weights()
            .zip(blobs_introduced)
            .filter_map(|(md, introduced_blobs)| {
                (!introduced_blobs.is_empty())
                    .then_some(CommitBlobMetadata { commit_oid: md.oid, introduced_blobs })
            })
            .collect();
        debug!(
            "{} commits visited; max frontier size: {}; max live sets: {}; introduced {} trees \
             and {} blobs; {:.6}s",
            num_commits_visited,
            max_frontier_size,
            max_live_seen_sets,
            num_trees_introduced,
            num_blobs_introduced,
            t1.elapsed().as_secs_f64()
        );
        if repo_index.content_filtered {
            debug!(
                "Resolved candidate metadata across {num_commits_visited} commits and \
                 {num_trees_introduced} tree visits in {:.6}s",
                t1.elapsed().as_secs_f64()
            );
        }
        Ok(result)
    }
}

#[inline]
fn path_is_excluded(path: &BString, exclude_globset: Option<&GlobSet>) -> bool {
    let Some(gs) = exclude_globset else {
        return false;
    };
    match path.to_path() {
        Ok(p) => gs.is_match(p),
        Err(_) => false,
    }
}

#[inline]
fn tree_path_is_excluded(path: &BString, exclude_globset: Option<&GlobSet>) -> bool {
    if path_is_excluded(path, exclude_globset) {
        return true;
    }
    let Some(gs) = exclude_globset else {
        return false;
    };
    let mut dir_path = path.clone();
    dir_path.push(b'/');
    match dir_path.to_path() {
        Ok(p) => gs.is_match(p),
        Err(_) => false,
    }
}

#[inline]
fn render_symbol_path(symbols: &BStringTable, path: &[Symbol]) -> BString {
    let mut buf = Vec::new();
    if let Some(first) = path.first() {
        buf.extend_from_slice(symbols.resolve(*first));
        for s in &path[1..] {
            buf.push(b'/');
            buf.extend_from_slice(symbols.resolve(*s));
        }
    }
    BString::from(buf)
}

#[expect(clippy::too_many_arguments)]
fn visit_tree(
    repo: &gix::Repository,
    symbols: &mut BStringTable,
    exclude_globset: Option<&GlobSet>,
    repo_index: &RepositoryIndex,
    num_trees_introduced: &mut usize,
    num_blobs_introduced: &mut usize,
    seen: &mut SeenObjectSet,
    introduced: &mut IntroducedBlobs,
    tree_buf: &mut Vec<u8>,
    tree_worklist: &mut TreeWorklist,
    blobs_encountered: &mut Vec<ObjectIdx>,
    deadline: Option<Instant>,
) -> Result<()> {
    blobs_encountered.clear();
    while let Some((name_path, tree_oid)) = tree_worklist.pop() {
        check_deadline(deadline, "repository tree traversal", repo.path())?;
        let mut visit_child = |oid: &gix::oid,
                               filename: &BStr,
                               symbols: &mut BStringTable,
                               seen: &mut SeenObjectSet|
         -> Result<()> {
            let Some(child_idx) = repo_index.get_tree_index(oid) else {
                if !repo_index.content_filtered {
                    debug!("No index for {oid} in tree {tree_oid}");
                }
                return Ok(());
            };
            if !repo_index.is_candidate_tree(child_idx)
                || repo_index.tree_is_covered(child_idx, seen)
            {
                return Ok(());
            }
            // Excluded trees must not be marked seen before path filtering.
            if exclude_globset.is_none() {
                if !seen.insert_tree(child_idx)? {
                    return Ok(());
                }
            } else if seen.contains_tree(child_idx)? {
                return Ok(());
            }
            let mut new_path = name_path.clone();
            new_path.push(symbols.get_or_intern(filename.into()));
            if exclude_globset.is_some() {
                let path = render_symbol_path(symbols, &new_path);
                if tree_path_is_excluded(&path, exclude_globset) {
                    return Ok(());
                }
                seen.insert_tree(child_idx)?;
            }
            tree_worklist.push((new_path, oid.to_owned()));
            Ok(())
        };
        let summaries = repo_index.candidate_summaries.as_ref();
        if let Some(children) = summaries
            .and_then(|summaries| summaries.cached_tree_children(&tree_oid, &seen.seen_blobs))
        {
            // Direct blobs are already accounted for. Traverse every child in
            // its original order, with ordinary path and ancestry handling.
            *num_trees_introduced += 1;
            for child in children {
                check_deadline(deadline, "repository tree traversal", repo.path())?;
                visit_child(&child.oid, child.name.as_bstr(), symbols, seen)?;
            }
            continue;
        }
        let mut record_blob =
            |child_idx, oid: &gix::oid, filename: &BStr, symbols: &mut BStringTable| {
                let mut new_path = name_path.clone();
                new_path.push(symbols.get_or_intern(filename.into()));
                let path = render_symbol_path(symbols, &new_path);
                if !path_is_excluded(&path, exclude_globset) {
                    blobs_encountered.push(child_idx);
                    *num_blobs_introduced += 1;
                    introduced.push((oid.to_owned(), path));
                }
            };
        if let Some(entries) = summaries.and_then(|summaries| summaries.cached_flat_tree(&tree_oid))
        {
            // Replay the relevant entries of a fully decoded flat tree in its
            // original order. Blob membership is updated after the entire
            // commit walk, preserving duplicate paths within one commit.
            *num_trees_introduced += 1;
            for entry in entries {
                check_deadline(deadline, "repository tree traversal", repo.path())?;
                if !seen.contains_blob(entry.blob)? {
                    let oid = repo_index.blobs.get_oid(entry.blob).unwrap();
                    record_blob(entry.blob, oid, entry.name.as_bstr(), symbols);
                }
            }
            continue;
        }
        let tree_iter = match repo.objects.find_tree_iter(&tree_oid, tree_buf) {
            Ok(iter) => iter,
            Err(e) => {
                debug!("Failed to find tree {tree_oid}: {e}");
                continue;
            }
        };
        *num_trees_introduced += 1;
        for child_res in tree_iter {
            check_deadline(deadline, "repository tree traversal", repo.path())?;
            let child = match child_res {
                Ok(child) => child,
                Err(e) => {
                    debug!("Failed reading entry from {tree_oid}: {e}");
                    continue;
                }
            };
            match child.mode.kind() {
                EntryKind::Link | EntryKind::Commit => {}
                EntryKind::Tree => visit_child(child.oid, child.filename, symbols, seen)?,
                EntryKind::Blob | EntryKind::BlobExecutable => {
                    let Some(child_idx) = repo_index.get_blob_index(child.oid) else {
                        if !repo_index.content_filtered {
                            // A normal tree can have thousands of deliberately unindexed small blobs.
                            trace!("No blob index for {} in tree {tree_oid}", child.oid);
                        }
                        continue;
                    };
                    if !seen.contains_blob(child_idx)? {
                        record_blob(child_idx, child.oid, child.filename, symbols);
                    }
                }
            }
        }
    }
    for idx in blobs_encountered.drain(..) {
        seen.insert_blob(idx)?;
    }
    Ok(())
}

#[inline]
fn check_deadline(deadline: Option<Instant>, phase: &str, repo_path: &Path) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() > deadline) {
        bail!("{phase} timed out for {}", repo_path.display())
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::git_test_fixture as fixture;

    use std::{fs, path::Path, sync::Arc};

    use anyhow::{Result, bail};
    use bstr::ByteSlice;
    use gix::{open::Options, open_opts};
    use globset::GlobSetBuilder;
    use tempfile::tempdir;

    use crate::git_repo_enumerator::{GitBlobSource, GitRepoWithMetadataEnumerator};

    #[test]
    fn ancestry_bitmaps_share_forks_until_their_contents_change() -> Result<()> {
        use super::{ObjectIdx, SeenObjectSet};

        let mut parent = SeenObjectSet::new(2);
        parent.insert_tree(ObjectIdx::new(1))?;
        parent.insert_blob(ObjectIdx::new(4))?;
        let mut child = parent.clone();
        assert!(Arc::ptr_eq(&parent.seen_trees, &child.seen_trees));
        assert!(Arc::ptr_eq(&parent.seen_blobs, &child.seen_blobs));
        assert!(!child.insert_tree(ObjectIdx::new(1))?);
        assert!(!child.insert_blob(ObjectIdx::new(4))?);
        assert!(Arc::ptr_eq(&parent.seen_trees, &child.seen_trees));
        assert!(Arc::ptr_eq(&parent.seen_blobs, &child.seen_blobs));

        child.insert_tree(ObjectIdx::new(2))?;
        assert!(!Arc::ptr_eq(&parent.seen_trees, &child.seen_trees));
        assert!(Arc::ptr_eq(&parent.seen_blobs, &child.seen_blobs));
        assert!(!parent.contains_tree(ObjectIdx::new(2))?);
        child.insert_blob(ObjectIdx::new(5))?;
        assert!(!parent.contains_blob(ObjectIdx::new(5))?);

        let mut merged = parent.clone();
        merged.union_update(&parent);
        assert!(Arc::ptr_eq(&parent.seen_trees, &merged.seen_trees));
        assert!(Arc::ptr_eq(&parent.seen_blobs, &merged.seen_blobs));
        merged.union_update(&child);
        assert!(merged.contains_tree(ObjectIdx::new(2))?);
        assert!(merged.contains_blob(ObjectIdx::new(5))?);
        assert!(!parent.contains_tree(ObjectIdx::new(2))?);
        assert!(!parent.contains_blob(ObjectIdx::new(5))?);
        Ok(())
    }

    #[test]
    fn sharded_tree_ancestry_shares_unchanged_shards_and_merges_exactly() -> Result<()> {
        use super::{MIN_SHARDED_TREE_COUNT, ObjectIdx, SeenObjectSet, SeenTrees, TREE_SHARD_SIZE};

        let first = ObjectIdx::new(9);
        let changed = ObjectIdx::new(10);
        let sibling = ObjectIdx::new(TREE_SHARD_SIZE + 9);
        let distant = ObjectIdx::new(3 * TREE_SHARD_SIZE + 9);
        let mut parent = SeenObjectSet::new(MIN_SHARDED_TREE_COUNT);
        parent.insert_tree(first)?;
        parent.insert_tree(sibling)?;

        let mut child = parent.clone();
        assert!(!child.insert_tree(first)?);
        assert!(Arc::ptr_eq(&parent.seen_trees, &child.seen_trees));
        child.insert_tree(changed)?;
        child.insert_tree(distant)?;
        let (SeenTrees::Sharded(parent_shards), SeenTrees::Sharded(child_shards)) =
            (&*parent.seen_trees, &*child.seen_trees)
        else {
            bail!("expected sharded ancestry");
        };
        assert!(!Arc::ptr_eq(
            parent_shards[0].as_ref().unwrap(),
            child_shards[0].as_ref().unwrap(),
        ));
        assert!(
            Arc::ptr_eq(parent_shards[1].as_ref().unwrap(), child_shards[1].as_ref().unwrap(),)
        );
        assert!(!parent.contains_tree(changed)?);
        assert!(!parent.contains_tree(distant)?);

        let mut merged = parent.clone();
        merged.union_update(&child);
        for idx in [first, changed, sibling, distant] {
            assert!(merged.contains_tree(idx)?);
        }
        assert!(!merged.contains_tree(ObjectIdx::new(2 * TREE_SHARD_SIZE + 9))?);
        assert!(!parent.contains_tree(changed)?);
        let SeenTrees::Sharded(merged_shards) = &*merged.seen_trees else {
            bail!("expected sharded ancestry");
        };
        assert!(
            Arc::ptr_eq(merged_shards[3].as_ref().unwrap(), child_shards[3].as_ref().unwrap(),)
        );
        Ok(())
    }

    #[test]
    fn cached_wide_trees_preserve_blob_aliases_exclusions_and_ancestry() -> Result<()> {
        use super::{GitMetadataGraph, RepositoryIndex};

        let temp = tempdir()?;
        let git = gix::init_bare(temp.path())?;
        let candidate = git.write_blob(b"candidate contents of a scannable size")?.detach();
        let inherited =
            git.write_blob(b"previous candidate contents of a scannable size")?.detach();
        let child_blob = git.write_blob(b"new candidate below the wide tree")?.detach();
        let short = git.write_blob(b"short filler")?.detach();
        let mut old = git.empty_tree().edit()?;
        fixture::insert(&mut old, "inherited.txt", inherited, 0o100644)?;
        let old_tree = old.write()?.detach();
        let mut wide = git.empty_tree().edit()?;
        fixture::insert(&mut wide, "a-excluded.txt", candidate, 0o100644)?;
        fixture::insert(&mut wide, "a-visible.txt", candidate, 0o100644)?;
        fixture::insert(&mut wide, "copy-of-inherited.txt", inherited, 0o100644)?;
        for i in 0..8_000 {
            fixture::insert(&mut wide, format!("filler-entry-{i:05}"), short, 0o100644)?;
        }
        fixture::insert(&mut wide, "z-visible.txt", candidate, 0o100644)?;
        let flat_tree = wide.write()?.detach();
        let mut nested = git.empty_tree().edit()?;
        fixture::insert(&mut nested, "new.txt", child_blob, 0o100644)?;
        let nested = nested.write()?.detach();
        fixture::insert(&mut wide, "nested", nested, 0o040000)?;
        let nonflat_tree = wide.write()?.detach();

        let signature = fixture::signature("tester", "tester@example.com");
        let old_commit =
            fixture::commit(&git, None, &signature, &signature, "initial", &old_tree, &[])?;
        let new_commit = fixture::commit(
            &git,
            None,
            &signature,
            &signature,
            "wide tree",
            &flat_tree,
            &[&old_commit],
        )?;
        let nested_commit = fixture::commit(
            &git,
            Some("HEAD"),
            &signature,
            &signature,
            "wide tree with a new child",
            &nonflat_tree,
            &[&new_commit],
        )?;

        let mut exclusions = GlobSetBuilder::new();
        exclusions.add(globset::Glob::new("a-excluded.txt")?);
        let exclusions = exclusions.build()?;
        let repo_path = temp.path();
        let git = open_opts(repo_path, Options::isolated().open_path_as_is(true))?;
        let sync_git = git.clone().into_sync();
        let scan = |cached| -> Result<Vec<_>> {
            let mut index = RepositoryIndex::new_with_deadline(&sync_git, None, repo_path)?;
            let mut graph = GitMetadataGraph::with_capacity(3);
            let old = graph.get_commit_idx(old_commit, index.get_tree_index(&old_tree));
            let new = graph.get_commit_idx(new_commit, index.get_tree_index(&flat_tree));
            let nested = graph.get_commit_idx(nested_commit, index.get_tree_index(&nonflat_tree));
            graph.add_commit_edge(old, new);
            graph.add_commit_edge(new, nested);
            if cached {
                index.prepare_candidate_trees(&sync_git, None, repo_path)?;
                let summaries = index.candidate_summaries.as_ref().unwrap();
                assert_eq!(summaries.cached_flat_tree(&flat_tree).unwrap().len(), 4);
                assert!(summaries.cached_flat_tree(&nonflat_tree).is_none());
                let mut seen = roaring::RoaringBitmap::new();
                assert!(summaries.cached_tree_children(&nonflat_tree, &seen).is_none());
                for oid in [candidate, inherited] {
                    seen.insert(index.get_blob_index(&oid).unwrap().as_usize() as u32);
                }
                assert_eq!(summaries.cached_tree_children(&nonflat_tree, &seen).unwrap().len(), 1);
                index.compact_candidate_trees(&mut graph);
            }
            Ok(graph
                .get_repo_metadata_with_deadline(&index, &git, Some(&exclusions), None)?
                .into_iter()
                .map(|entry| (entry.commit_oid, entry.introduced_blobs))
                .collect())
        };
        let eager = scan(false)?;
        assert_eq!(eager[1].0, new_commit);
        assert_eq!(
            eager[1].1.as_slice(),
            &[
                (candidate, bstr::BString::from("a-visible.txt")),
                (candidate, bstr::BString::from("z-visible.txt")),
            ],
        );
        assert_eq!(eager[2].0, nested_commit);
        assert_eq!(eager[2].1.as_slice(), &[(child_blob, bstr::BString::from("nested/new.txt"))],);
        assert_eq!(scan(true)?, eager);
        Ok(())
    }

    #[test]
    fn parallel_object_index_matches_serial_pack_and_loose_order() -> Result<()> {
        use super::{ObjectIdBimap, RepositoryIndex};
        use gix::{object::Kind, odb::store::iter::Ordering, prelude::*};

        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let mut packed_ids = Vec::new();
        // Cross a batch boundary, with skipped small blobs interspersed among
        // scannable blobs. Packing below also leaves loose copies of the IDs.
        for i in 0..4200 {
            let contents = if i % 3 == 0 {
                format!("{i}")
            } else {
                format!("scannable blob contents number {i}")
            };
            packed_ids.push(repo.write_blob(contents.as_bytes())?.detach());
        }
        for size in [19, 20, 21] {
            packed_ids.push(repo.write_blob(vec![b'x'; size])?.detach());
        }
        let tree_id = repo.empty_tree().edit()?.write()?.detach();
        let tree = tree_id;
        let signature = fixture::signature("tester", "tester@example.com");
        let commit =
            fixture::commit(&repo, Some("HEAD"), &signature, &signature, "initial", &tree, &[])?;
        let tag = fixture::tag(&repo, "v1", commit, &signature, "tag")?;
        packed_ids.extend([tree_id, commit]);
        packed_ids.push(tag);

        for packed in [false, true] {
            if packed {
                fixture::pack(&repo, &packed_ids)?;
            }
            let repo = open_opts(temp.path(), Options::isolated().open_path_as_is(true))?;
            let mut expected = std::array::from_fn::<_, 4, _>(|_| ObjectIdBimap::with_capacity(0));
            for oid in repo
                .objects
                .iter()?
                .with_ordering(Ordering::PackAscendingOffsetThenLooseLexicographical)
            {
                let oid = oid?;
                let header = repo.objects.header(oid)?;
                let slot = match header.kind() {
                    Kind::Blob if header.size() < super::MIN_SCANNABLE_BLOB_SIZE => continue,
                    Kind::Blob => 0,
                    Kind::Tree => 1,
                    Kind::Commit => 2,
                    Kind::Tag => 3,
                };
                expected[slot].insert(oid);
            }
            let repo = repo.into_sync();
            for threads in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
                let actual =
                    pool.install(|| RepositoryIndex::new_with_deadline(&repo, None, temp.path()))?;
                assert_eq!(actual.blobs.len(), 2802);
                assert_eq!(actual.trees.len(), 1);
                assert_eq!(actual.commits.len(), 1);
                assert_eq!(actual.tags.len(), 1);
                for (actual, expected) in
                    [&actual.blobs, &actual.trees, &actual.commits, &actual.tags]
                        .into_iter()
                        .zip(&expected)
                {
                    assert_eq!(
                        actual.idx_to_oid, expected.idx_to_oid,
                        "packed={packed}, threads={threads}"
                    );
                }
                assert!(
                    pool.install(|| RepositoryIndex::new_with_deadline(
                        &repo,
                        Some(std::time::Instant::now()),
                        temp.path()
                    ))
                    .is_err()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn object_index_preserves_ids_through_collisions_and_growth() {
        use super::{ObjectIdBimap, ObjectIdx};

        let mut index = ObjectIdBimap::with_capacity(0);
        // gix hashes the first eight bytes. Keep those equal to exercise full-ID
        // comparisons, including when growth rehashes the stored indexes.
        let ids: Vec<_> = (0u32..1024)
            .map(|i| {
                let mut bytes = [0x42; 20];
                bytes[16..].copy_from_slice(&i.to_be_bytes());
                gix::ObjectId::from_bytes_or_panic(&bytes)
            })
            .collect();
        for &oid in &ids {
            index.insert(oid);
            index.insert(oid);
        }
        assert_eq!(index.len(), ids.len());
        for (i, oid) in ids.iter().enumerate() {
            assert_eq!(index.get_idx(oid), Some(ObjectIdx::new(i)));
            assert_eq!(index.get_oid(ObjectIdx::new(i)), Some(oid.as_ref()));
        }
        let mut missing = [0x42; 20];
        missing[16..].copy_from_slice(&1024u32.to_be_bytes());
        assert_eq!(index.get_idx(&gix::ObjectId::from_bytes_or_panic(&missing)), None);
        assert_eq!(index.get_oid(ObjectIdx::new(ids.len())), None);
    }

    #[test]
    fn commit_identities_are_interned_across_commits() -> Result<()> {
        let temp = tempdir()?;
        let repo_path = temp.path().join("repo");
        let repo = gix::init(&repo_path)?;
        let signature = fixture::signature("shared committer", "shared@example.com");

        fs::write(repo_path.join("first.txt"), b"first secret-like value long enough")?;
        let mut index = fixture::index(&repo)?;
        fixture::stage(&repo, &mut index, Path::new("first.txt"))?;
        let tree_id = fixture::write_tree(&repo, &index)?;
        let tree = tree_id;
        let first_commit =
            fixture::commit(&repo, Some("HEAD"), &signature, &signature, "first", &tree, &[])?;

        fs::write(repo_path.join("second.txt"), b"second secret-like value long enough")?;
        let mut index = fixture::index(&repo)?;
        fixture::stage(&repo, &mut index, Path::new("second.txt"))?;
        let tree_id = fixture::write_tree(&repo, &index)?;
        let tree = tree_id;
        fixture::commit(
            &repo,
            Some("HEAD"),
            &signature,
            &signature,
            "second",
            &tree,
            &[&first_commit],
        )?;

        let git_dir = repo_path.join(".git");
        let gix_repo = open_opts(&git_dir, Options::isolated().open_path_as_is(true))?;
        let result = GitRepoWithMetadataEnumerator::new(&repo_path, gix_repo, None).run()?;
        let blobs = match result.blobs {
            GitBlobSource::Precomputed(blobs) => blobs,
            GitBlobSource::StreamFromOdb => {
                bail!("expected precomputed metadata blobs from metadata enumerator")
            }
        };

        let metadata_for = |path: &str| {
            blobs
                .iter()
                .flat_map(|blob| &blob.first_seen)
                .find(|appearance| appearance.path.to_str_lossy() == path)
                .map(|appearance| Arc::clone(&appearance.commit_metadata))
                .unwrap_or_else(|| panic!("missing appearance for {path}"))
        };
        let first = metadata_for("first.txt");
        let second = metadata_for("second.txt");

        assert_ne!(first.commit_id, second.commit_id);
        assert!(Arc::ptr_eq(&first.committer_name, &second.committer_name));
        assert!(Arc::ptr_eq(&first.committer_email, &second.committer_email));

        Ok(())
    }

    #[test]
    fn excluded_blob_path_does_not_hide_later_included_blob() -> Result<()> {
        let temp = tempdir()?;
        let repo_path = temp.path().join("repo");
        let repo = gix::init(&repo_path)?;
        let signature = fixture::signature("tester", "tester@example.com");
        let shared_contents = b"shared-secret-content-that-is-long-enough";

        let excluded_dir = repo_path.join("excluded");
        fs::create_dir_all(&excluded_dir)?;
        fs::write(excluded_dir.join("secret.txt"), shared_contents)?;

        let mut index = fixture::index(&repo)?;
        fixture::stage(&repo, &mut index, Path::new("excluded/secret.txt"))?;
        let tree_id = fixture::write_tree(&repo, &index)?;
        let tree = tree_id;
        let first_commit = fixture::commit(
            &repo,
            Some("HEAD"),
            &signature,
            &signature,
            "excluded only",
            &tree,
            &[],
        )?;

        fs::remove_file(excluded_dir.join("secret.txt"))?;
        let visible_path = repo_path.join("visible.txt");
        fs::write(&visible_path, shared_contents)?;

        let mut index = fixture::index(&repo)?;
        fixture::unstage(&mut index, Path::new("excluded/secret.txt"))?;
        fixture::stage(&repo, &mut index, Path::new("visible.txt"))?;
        let tree_id = fixture::write_tree(&repo, &index)?;
        let tree = tree_id;
        fixture::commit(
            &repo,
            Some("HEAD"),
            &signature,
            &signature,
            "visible path",
            &tree,
            &[&first_commit],
        )?;

        let git_dir = repo_path.join(".git");
        let gix_repo = open_opts(&git_dir, Options::isolated().open_path_as_is(true))?;

        let mut builder = GlobSetBuilder::new();
        builder.add(globset::Glob::new("excluded/**")?);
        let exclude_globset = Arc::new(builder.build()?);

        let result = GitRepoWithMetadataEnumerator::new(
            &repo_path,
            gix_repo,
            Some(Arc::clone(&exclude_globset)),
        )
        .run()?;

        let blobs = match result.blobs {
            GitBlobSource::Precomputed(blobs) => blobs,
            GitBlobSource::StreamFromOdb => {
                bail!("expected precomputed metadata blobs from metadata enumerator")
            }
        };

        let matching: Vec<_> = blobs
            .into_iter()
            .filter(|blob| {
                blob.first_seen
                    .iter()
                    .any(|appearance| appearance.path.to_str_lossy() == "visible.txt")
            })
            .collect();

        assert_eq!(matching.len(), 1);
        assert!(
            matching[0]
                .first_seen
                .iter()
                .all(|appearance| appearance.path.to_str_lossy() != "excluded/secret.txt")
        );

        Ok(())
    }

    #[test]
    fn content_prepass_compacts_in_order_across_batches_and_keeps_large_blobs() -> Result<()> {
        use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern};

        use super::RepositoryIndex;
        use crate::{
            git_candidates::GitContentFilter, limits::ResourceLimits, scanner_pool::ScannerPool,
        };

        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let mut expected_sizes = std::collections::HashMap::new();
        for i in 0..2300 {
            let candidate = i % 17 == 0;
            let contents = if candidate {
                format!("candidate_secret_{i:016x}")
            } else {
                format!("ordinary source file number {i} with no token")
            };
            let oid = repo.write_blob(contents.as_bytes()).map(gix::Id::detach)?;
            if candidate {
                expected_sizes.insert(oid, contents.len() as u64);
            }
        }
        let large_size = 4 * 1024 * 1024 + 1;
        let large = repo.write_blob(vec![b' '; large_size]).map(gix::Id::detach)?;
        expected_sizes.insert(large, large_size as u64);
        let repo = open_opts(temp.path(), Options::isolated())?.into_sync();
        let filter = GitContentFilter::new(
            Arc::new(ScannerPool::new(Arc::new(BlockDatabase::new(vec![Pattern::new(
                b"candidate_secret_[a-z0-9]{16}".to_vec(),
                Flag::default(),
                Some(0),
            )])?))),
            1,
            false,
            true,
            ResourceLimits::default(),
        );
        let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build()?;
        pool.install(|| -> Result<()> {
            let mut index = RepositoryIndex::new_with_deadline(&repo, None, temp.path())?;
            let expected: Vec<_> = index
                .blobs
                .idx_to_oid
                .iter()
                .filter(|oid| expected_sizes.contains_key(*oid))
                .copied()
                .collect();
            let retained = index.retain_content_candidates(&repo, &filter, None, temp.path())?;
            assert_eq!(index.blobs.idx_to_oid, expected);
            assert_eq!(index.blobs.len(), expected_sizes.len());
            assert!(
                retained
                    .iter()
                    .map(|(oid, _)| oid)
                    .eq(expected.iter().filter(|&oid| *oid != large))
            );
            for (oid, blob) in retained {
                let (data, _) = super::RetainedGitBlob::into_data(blob).unwrap();
                assert_eq!(
                    gix::ObjectId::from(crate::blob::BlobId::compute_from_bytes(&data)),
                    oid
                );
            }
            assert_eq!(
                index.blob_sizes,
                expected.iter().map(|oid| expected_sizes[oid]).collect::<Vec<_>>()
            );
            assert_eq!(
                filter.clean_stats().blobs_scanned,
                2300 - (expected_sizes.len() - 1) as u64
            );

            let mut index = RepositoryIndex::new_with_deadline(&repo, None, temp.path())?;
            assert!(
                index
                    .retain_content_candidates(
                        &repo,
                        &filter,
                        Some(std::time::Instant::now()),
                        temp.path(),
                    )
                    .is_err()
            );
            assert_eq!(index.blobs.len(), 2301);
            Ok(())
        })
    }

    #[test]
    fn candidate_tree_summary_is_transitive_path_independent_and_bounded() -> Result<()> {
        use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern};

        use super::RepositoryIndex;
        use crate::{
            git_candidates::GitContentFilter, limits::ResourceLimits, scanner_pool::ScannerPool,
        };

        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let candidate =
            repo.write_blob(b"candidate_secret_0123456789abcdef").map(gix::Id::detach)?;
        let clean = repo
            .write_blob(b"ordinary source file without matching credentials")
            .map(gix::Id::detach)?;
        let mut builder = repo.empty_tree().edit()?;
        fixture::insert(&mut builder, "secret.txt", candidate, 0o100644)?;
        let relevant_leaf = builder.write()?.detach();
        let mut builder = repo.empty_tree().edit()?;
        fixture::insert(&mut builder, "clean.txt", clean, 0o100644)?;
        let clean_leaf = builder.write()?.detach();
        let mut builder = repo.empty_tree().edit()?;
        fixture::insert(&mut builder, "link", candidate, 0o120000)?;
        let links_only = builder.write()?.detach();
        let mut parent = relevant_leaf;
        let mut relevant = vec![relevant_leaf];
        for _ in 0..80 {
            let mut builder = repo.empty_tree().edit()?;
            fixture::insert(&mut builder, "child", parent, 0o040000)?;
            fixture::insert(&mut builder, "clean", clean_leaf, 0o040000)?;
            parent = builder.write()?.detach();
            relevant.push(parent);
        }
        let repo = open_opts(temp.path(), Options::isolated())?.into_sync();
        for threads in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build()?;
            pool.install(|| -> Result<()> {
                let filter = GitContentFilter::new(
                    Arc::new(ScannerPool::new(Arc::new(BlockDatabase::new(vec![Pattern::new(
                        b"candidate_secret_[a-z0-9]{16}".to_vec(),
                        Flag::default(),
                        Some(0),
                    )])?))),
                    1,
                    false,
                    false,
                    ResourceLimits::default(),
                );
                let mut index = RepositoryIndex::new_with_deadline(&repo, None, temp.path())?;
                index.retain_content_candidates(&repo, &filter, None, temp.path())?;
                index.prepare_candidate_trees(&repo, None, temp.path())?;
                for oid in &relevant {
                    let oid = gix::ObjectId::from_hex(oid.to_string().as_bytes())?;
                    assert!(index.is_candidate_tree(index.get_tree_index(&oid).unwrap()));
                }
                for oid in [clean_leaf, links_only] {
                    let oid = gix::ObjectId::from_hex(oid.to_string().as_bytes())?;
                    assert!(!index.is_candidate_tree(index.get_tree_index(&oid).unwrap()));
                }
                let mut graph = super::GitMetadataGraph::with_capacity(relevant.len() + 2);
                let mut relevant_nodes = Vec::new();
                // Synthetic graph IDs suffice here: only tree-index remapping is tested.
                for oid in &relevant {
                    let oid = gix::ObjectId::from_hex(oid.to_string().as_bytes())?;
                    let node = graph.get_commit_idx(oid, index.get_tree_index(&oid));
                    relevant_nodes.push((node, oid));
                }
                let mut clean_nodes = Vec::new();
                for oid in [clean_leaf, links_only] {
                    let oid = gix::ObjectId::from_hex(oid.to_string().as_bytes())?;
                    clean_nodes.push(graph.get_commit_idx(oid, index.get_tree_index(&oid)));
                }
                index.compact_candidate_trees(&mut graph);
                assert_eq!(index.num_trees(), relevant.len());
                for (node, oid) in relevant_nodes {
                    let tree = graph.get_commit_metadata(node).tree_idx.unwrap();
                    assert_eq!(index.get_tree_oid(tree), Some(oid.as_ref()));
                }
                for node in clean_nodes {
                    assert!(graph.get_commit_metadata(node).tree_idx.is_none());
                }
                assert!(
                    index
                        .prepare_candidate_trees(
                            &repo,
                            Some(std::time::Instant::now()),
                            temp.path()
                        )
                        .is_err()
                );
                Ok(())
            })?;
        }
        Ok(())
    }
}
