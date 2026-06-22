use std::{collections::BinaryHeap, path::Path, time::Instant};

use anyhow::{Context, Result, bail};
use bstr::{BString, ByteSlice};
use fixedbitset::FixedBitSet;
use gix::{
    ObjectId, OdbHandle,
    hashtable::{HashMap, hash_map},
    object::Kind,
    objs::tree::EntryKind,
    prelude::*,
};
use globset::GlobSet;

use crate::git_repo_enumerator::MIN_SCANNABLE_BLOB_SIZE;
use petgraph::{
    graph::{DiGraph, EdgeIndex, IndexType, NodeIndex},
    prelude::*,
    visit::Visitable,
};
use roaring::RoaringBitmap;
use smallvec::SmallVec;
use tracing::{debug, error_span, warn};

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
    pub(crate) fn new_with_deadline(
        odb: &OdbHandle,
        deadline: Option<Instant>,
        repo_path: &Path,
    ) -> Result<Self> {
        use gix::{odb::store::iter::Ordering, prelude::*};
        let mut trees = ObjectIdBimap::with_capacity(0);
        let mut commits = ObjectIdBimap::with_capacity(0);
        let mut blobs = ObjectIdBimap::with_capacity(0);
        let mut tags = ObjectIdBimap::with_capacity(0);

        for oid_result in odb
            .iter()
            .context("Failed to iterate object database")?
            .with_ordering(Ordering::PackAscendingOffsetThenLooseLexicographical)
        {
            check_deadline(deadline, "repository object indexing", repo_path)?;
            let oid = match oid_result {
                Ok(oid) => oid,
                Err(e) => {
                    debug!("Failed to read object id: {e}");
                    continue;
                }
            };
            let hdr = match odb.header(oid) {
                Ok(hdr) => hdr,
                Err(e) => {
                    debug!("Failed to read object header for {oid}: {e}");
                    continue;
                }
            };
            match hdr.kind() {
                Kind::Tree => trees.insert(oid),
                Kind::Blob if hdr.size() >= MIN_SCANNABLE_BLOB_SIZE => blobs.insert(oid),
                Kind::Blob => {}
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
    pub(crate) fn get_repo_metadata_with_deadline(
        self,
        repo_index: &RepositoryIndex,
        repo: &gix::Repository,
        exclude_globset: Option<&GlobSet>,
        deadline: Option<Instant>,
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
                if seen.insert_tree(tree_idx)? {
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
                EntryKind::Tree => {
                    let Some(child_idx) = repo_index.get_tree_index(child.oid) else {
                        debug!("No index for {} in tree {tree_oid}", child.oid);
                        continue;
                    };
                    let mut new_path = name_path.clone();
                    new_path.push(symbols.get_or_intern(child.filename.into()));
                    if exclude_globset.is_some() {
                        let path = render_symbol_path(symbols, &new_path);
                        if tree_path_is_excluded(&path, exclude_globset) {
                            continue;
                        }
                    }
                    if seen.insert_tree(child_idx)? {
                        tree_worklist.push((new_path, child.oid.to_owned()));
                    }
                }
                EntryKind::Blob | EntryKind::BlobExecutable => {
                    let Some(child_idx) = repo_index.get_blob_index(child.oid) else {
                        debug!("No blob index for {} in tree {tree_oid}", child.oid);
                        continue;
                    };
                    if !seen.contains_blob(child_idx)? {
                        let mut new_path = name_path.clone();
                        new_path.push(symbols.get_or_intern(child.filename.into()));
                        let path = render_symbol_path(symbols, &new_path);
                        if path_is_excluded(&path, exclude_globset) {
                            continue;
                        }
                        blobs_encountered.push(child_idx);
                        *num_blobs_introduced += 1;
                        introduced.push((child.oid.to_owned(), path));
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
    use std::{fs, path::Path, sync::Arc};

    use anyhow::{Result, bail};
    use bstr::ByteSlice;
    use git2::{Repository as Git2Repository, Signature};
    use gix::{open::Options, open_opts};
    use globset::GlobSetBuilder;
    use tempfile::tempdir;

    use crate::git_repo_enumerator::{GitBlobSource, GitRepoWithMetadataEnumerator};

    #[test]
    fn excluded_blob_path_does_not_hide_later_included_blob() -> Result<()> {
        let temp = tempdir()?;
        let repo_path = temp.path().join("repo");
        let repo = Git2Repository::init(&repo_path)?;
        let signature = Signature::now("tester", "tester@example.com")?;
        let shared_contents = b"shared-secret-content-that-is-long-enough";

        let excluded_dir = repo_path.join("excluded");
        fs::create_dir_all(&excluded_dir)?;
        fs::write(excluded_dir.join("secret.txt"), shared_contents)?;

        let mut index = repo.index()?;
        index.add_path(Path::new("excluded/secret.txt"))?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let first_commit =
            repo.commit(Some("HEAD"), &signature, &signature, "excluded only", &tree, &[])?;
        let first_commit = repo.find_commit(first_commit)?;

        fs::remove_file(excluded_dir.join("secret.txt"))?;
        let visible_path = repo_path.join("visible.txt");
        fs::write(&visible_path, shared_contents)?;

        let mut index = repo.index()?;
        index.remove_path(Path::new("excluded/secret.txt"))?;
        index.add_path(Path::new("visible.txt"))?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        repo.commit(Some("HEAD"), &signature, &signature, "visible path", &tree, &[&first_commit])?;

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
}
