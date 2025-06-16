use std::{collections::BinaryHeap, time::Instant};

use anyhow::{bail, Context, Result};
use bstr::BString;
use fixedbitset::FixedBitSet;
use gix::{
    hashtable::{hash_map, HashMap},
    object::Kind,
    objs::tree::EntryKind,
    prelude::*,
    ObjectId, OdbHandle,
};
use petgraph::{
    graph::{DiGraph, EdgeIndex, IndexType, NodeIndex},
    prelude::*,
    visit::Visitable,
};
use roaring::RoaringBitmap;
use smallvec::SmallVec;
use tracing::{debug, error_span, warn};

use crate::{bstring_table::BStringTable, unwrap_ok_or_continue, unwrap_some_or_continue};

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

#[derive(Clone, Debug, Default)]
struct SeenObjectSet {
    seen_trees: RoaringBitmap,
    seen_blobs: RoaringBitmap,
}
impl SeenObjectSet {
    pub(crate) fn new() -> Self {
        Self { seen_trees: RoaringBitmap::new(), seen_blobs: RoaringBitmap::new() }
    }
    fn insert(set: &mut RoaringBitmap, idx: ObjectIdx) -> Result<bool> {
        Ok(set.insert(idx.as_usize().try_into()?))
    }
    fn contains(set: &RoaringBitmap, idx: ObjectIdx) -> Result<bool> {
        Ok(set.contains(idx.as_usize().try_into()?))
    }
    pub(crate) fn insert_tree(&mut self, idx: ObjectIdx) -> Result<bool> {
        Self::insert(&mut self.seen_trees, idx)
    }
    pub(crate) fn insert_blob(&mut self, idx: ObjectIdx) -> Result<bool> {
        Self::insert(&mut self.seen_blobs, idx)
    }
    pub(crate) fn contains_blob(&self, idx: ObjectIdx) -> Result<bool> {
        Self::contains(&self.seen_blobs, idx)
    }
    pub(crate) fn union_update(&mut self, other: &Self) {
        self.seen_blobs |= &other.seen_blobs;
        self.seen_trees |= &other.seen_trees;
    }
}

struct ObjectIdBimap {
    oid_to_idx: HashMap<ObjectId, ObjectIdx>,
    idx_to_oid: Vec<ObjectId>,
}
impl ObjectIdBimap {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            oid_to_idx: HashMap::with_capacity_and_hasher(capacity, Default::default()),
            idx_to_oid: Vec::with_capacity(capacity),
        }
    }
    fn insert(&mut self, oid: ObjectId) {
        match self.oid_to_idx.entry(oid) {
            hash_map::Entry::Occupied(_) => {}
            hash_map::Entry::Vacant(e) => {
                let idx = ObjectIdx::new(self.idx_to_oid.len());
                self.idx_to_oid.push(*e.key());
                e.insert(idx);
            }
        }
    }
    fn get_oid(&self, idx: ObjectIdx) -> Option<&gix::oid> {
        self.idx_to_oid.get(idx.as_usize()).map(|v| v.as_ref())
    }
    fn get_idx(&self, oid: &gix::oid) -> Option<ObjectIdx> {
        self.oid_to_idx.get(oid).copied()
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
    commits: ObjectIdBimap,
    blobs: ObjectIdBimap,
    tags: ObjectIdBimap,
}
impl RepositoryIndex {
    pub(crate) fn new(odb: &OdbHandle) -> Result<Self> {
        use gix::{odb::store::iter::Ordering, prelude::*};
        let mut num_tags = 0;
        let mut num_trees = 0;
        let mut num_blobs = 0;
        let mut num_commits = 0;
        let count = 0;

        for oid in odb
            .iter()
            .context("Failed to iterate object database")?
            .with_ordering(Ordering::PackLexicographicalThenLooseLexicographical)
        {
            let oid = unwrap_ok_or_continue!(oid, |e| debug!("Failed to read object id: {e}"));
            if count % 100000 == 0 {
                debug!("Indexed {} objects in RepositoryIndex::new", count);
            }
            let hdr = unwrap_ok_or_continue!(odb.header(oid), |e| {
                debug!("Failed to read object header for {oid}: {e}")
            });
            match hdr.kind() {
                Kind::Tree => num_trees += 1,
                Kind::Blob => num_blobs += 1,
                Kind::Commit => num_commits += 1,
                Kind::Tag => num_tags += 1,
            }
        }
        debug!("Total objects to map in RepositoryIndex::new: {}", count);

        let mut trees = ObjectIdBimap::with_capacity(num_trees);
        let mut commits = ObjectIdBimap::with_capacity(num_commits);
        let mut blobs = ObjectIdBimap::with_capacity(num_blobs);
        let mut tags = ObjectIdBimap::with_capacity(num_tags);
        for oid in odb
            .iter()
            .context("Failed to iterate object database")?
            .with_ordering(Ordering::PackAscendingOffsetThenLooseLexicographical)
        {
            let oid = unwrap_ok_or_continue!(oid, |e| debug!("Failed to read object id: {e}"));
            let hdr = unwrap_ok_or_continue!(odb.header(oid), |e| {
                debug!("Failed to read object header for {oid}: {e}")
            });
            match hdr.kind() {
                Kind::Tree => trees.insert(oid),
                Kind::Blob => blobs.insert(oid),
                Kind::Commit => commits.insert(oid),
                Kind::Tag => tags.insert(oid),
            }
        }
        Ok(Self { trees, commits, blobs, tags })
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
    pub(crate) fn get_blob_index(&self, oid: &gix::oid) -> Option<ObjectIdx> {
        self.blobs.get_idx(oid)
    }
    pub(crate) fn into_blobs(self) -> Vec<ObjectId> {
        self.blobs.idx_to_oid
    }
    pub(crate) fn commits(&self) -> &[ObjectId] {
        &self.commits.idx_to_oid
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

pub(crate) type IntroducedBlobs = SmallVec<[(ObjectId, BString); 4]>;
pub(crate) struct CommitBlobMetadata {
    pub(crate) commit_oid: ObjectId,
    pub(crate) introduced_blobs: IntroducedBlobs,
}

impl GitMetadataGraph {
    pub(crate) fn get_repo_metadata(
        self,
        repo_index: &RepositoryIndex,
        repo: &gix::Repository,
    ) -> Result<Vec<CommitBlobMetadata>> {
        let _span =
            error_span!("get_repo_metadata", path = repo.path().display().to_string()).entered();
        let t1 = Instant::now();
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
            seen_sets[root_idx.index()] = Some(SeenObjectSet::new());
        }
        let mut tree_worklist = Vec::with_capacity(32 * 1024);
        let mut tree_buf = Vec::with_capacity(1024 * 1024);
        let mut blobs_encountered = Vec::with_capacity(16 * 1024);
        let (mut max_frontier_size, mut num_blobs_introduced, mut num_trees_introduced) = (0, 0, 0);
        let (mut num_commits_visited, mut num_live_seen_sets, mut max_live_seen_sets) =
            (0, commit_worklist.len(), 0);

        while let Some((_, commit_idx)) = commit_worklist.pop() {
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
                if seen.insert_tree(tree_idx)? {
                    tree_worklist.push((
                        SmallVec::new(),
                        repo_index.get_tree_oid(tree_idx).unwrap().to_owned(),
                    ));
                    visit_tree(
                        repo,
                        &mut symbols,
                        repo_index,
                        &mut num_trees_introduced,
                        &mut num_blobs_introduced,
                        &mut seen,
                        introduced,
                        &mut tree_buf,
                        &mut tree_worklist,
                        &mut blobs_encountered,
                    )?;
                }
            } else {
                debug!(
                    "No tree index for {}; blob metadata may be incomplete",
                    self.get_commit_metadata(commit_idx).oid
                );
            }
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
                    child_seen.union_update(&seen);
                } else {
                    num_live_seen_sets += 1;
                    if edges.peek().is_none() {
                        *child_seen = Some(std::mem::take(&mut seen));
                    } else {
                        *child_seen = Some(seen.clone());
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
            .map(|(md, introduced_blobs)| CommitBlobMetadata {
                commit_oid: md.oid,
                introduced_blobs,
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
        Ok(result)
    }
}

#[allow(clippy::too_many_arguments)]
fn visit_tree(
    repo: &gix::Repository,
    symbols: &mut BStringTable,
    repo_index: &RepositoryIndex,
    num_trees_introduced: &mut usize,
    num_blobs_introduced: &mut usize,
    seen: &mut SeenObjectSet,
    introduced: &mut IntroducedBlobs,
    tree_buf: &mut Vec<u8>,
    tree_worklist: &mut TreeWorklist,
    blobs_encountered: &mut Vec<ObjectIdx>,
) -> Result<()> {
    blobs_encountered.clear();
    while let Some((name_path, tree_oid)) = tree_worklist.pop() {
        let tree_iter = unwrap_ok_or_continue!(
            repo.objects.find_tree_iter(&tree_oid, tree_buf),
            |e| debug!("Failed to find tree {tree_oid}: {e}")
        );
        *num_trees_introduced += 1;
        for child_res in tree_iter {
            let child = unwrap_ok_or_continue!(child_res, |e| {
                debug!("Failed reading entry from {tree_oid}: {e}")
            });
            match child.mode.kind() {
                EntryKind::Link | EntryKind::Commit => {}
                EntryKind::Tree => {
                    let child_idx =
                        unwrap_some_or_continue!(repo_index.get_tree_index(child.oid), || {
                            debug!("No index for {} in tree {tree_oid}", child.oid)
                        });
                    if seen.insert_tree(child_idx)? {
                        let mut new_path = name_path.clone();
                        new_path.push(symbols.get_or_intern(child.filename.into()));
                        tree_worklist.push((new_path, child.oid.to_owned()));
                    }
                }
                EntryKind::Blob | EntryKind::BlobExecutable => {
                    let child_idx =
                        unwrap_some_or_continue!(repo_index.get_blob_index(child.oid), || {
                            debug!("No blob index for {} in tree {tree_oid}", child.oid)
                        });
                    if !seen.contains_blob(child_idx)? {
                        blobs_encountered.push(child_idx);
                        *num_blobs_introduced += 1;
                        let mut new_path = name_path.clone();
                        new_path.push(symbols.get_or_intern(child.filename.into()));
                        let mut buf = Vec::new();
                        if let Some(first) = new_path.first() {
                            buf.extend_from_slice(symbols.resolve(*first));
                            for s in &new_path[1..] {
                                buf.push(b'/');
                                buf.extend_from_slice(symbols.resolve(*s));
                            }
                        }
                        introduced.push((child.oid.to_owned(), BString::from(buf)));
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
