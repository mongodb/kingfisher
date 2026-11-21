//! Bounded exact candidate sets for skipping candidate-unchanged subtrees.
//! A subtree may be skipped only when every candidate it contains is already in
//! the current commit's ancestor blob set. Presence in another branch is insufficient.

use crate::{
    git_metadata_graph::{ObjectIdx, RepositoryIndex},
    input::scan_repo_from_sync,
};
use anyhow::{Result, bail};
use bstr::BString;
use fixedbitset::FixedBitSet;
use gix::{objs::tree::EntryKind, prelude::*};
use parking_lot::RwLock;
use rayon::prelude::*;
use roaring::RoaringBitmap;
use smallvec::SmallVec;
use std::{
    cell::RefCell,
    collections::HashMap,
    path::Path,
    sync::atomic::{AtomicU32, Ordering},
    time::Instant,
};
use tracing::debug;

const UNKNOWN: u32 = 0;
const CLEAN: u32 = 1;
const OVERFLOW: u32 = 2;
const MULTI: u32 = 1 << 31;
const LIMIT: usize = 24;
const MAX_INTERNED_SET_BYTES: usize = 64 * 1024 * 1024;
const WIDE_TREE_BYTES: usize = 256 * 1024;
const MAX_WIDE_TREE_ENTRIES: usize = 256;
const MAX_WIDE_TREE_SUBTREES: usize = 128;
const MAX_WIDE_TREE_BLOB_INDEXES: usize = 64 * 1024;
const WIDE_TREE_CACHE_BYTES: usize = 64 * 1024 * 1024;
type Candidates = SmallVec<[u32; 4]>;

pub(crate) struct WideTreeEntry {
    pub(crate) blob: ObjectIdx,
    pub(crate) name: BString,
}

pub(crate) struct WideTreeChild {
    pub(crate) oid: gix::ObjectId,
    pub(crate) name: BString,
}

struct WideTree {
    blobs: FixedBitSet,
    entries: Option<Vec<WideTreeEntry>>,
    subtrees: Vec<WideTreeChild>,
}

impl WideTree {
    fn direct_blobs_covered(&self, ancestors: &RoaringBitmap) -> bool {
        self.blobs.ones().all(|id| ancestors.contains(id as u32))
    }
}

#[derive(Default)]
struct Intern {
    ids: HashMap<Candidates, u32>,
    sets: Vec<Candidates>,
    set_bytes: usize,
    wide_trees: gix::hashtable::HashMap<gix::ObjectId, WideTree>,
    wide_tree_bytes: usize,
}

pub(crate) struct CandidateSummaries {
    trees: Vec<u32>,
    sets: Vec<Candidates>,
    wide_trees: gix::hashtable::HashMap<gix::ObjectId, WideTree>,
}

impl CandidateSummaries {
    pub(crate) fn build(
        index: &RepositoryIndex,
        repo: &gix::ThreadSafeRepository,
        deadline: Option<Instant>,
        path: &Path,
    ) -> Result<Self> {
        let states: Vec<_> = (0..index.num_trees()).map(|_| AtomicU32::new(UNKNOWN)).collect();
        let intern = RwLock::new(Intern::default());
        let workers = thread_local::ThreadLocal::new();
        (0..states.len()).into_par_iter().with_min_len(128).try_for_each(|i| {
            let worker = workers.get_or(|| RefCell::new((scan_repo_from_sync(repo), Vec::new())));
            let mut worker = worker.borrow_mut();
            let (repo, buffer) = &mut *worker;
            summarize(index, ObjectIdx::new(i), repo, &states, &intern, buffer, 0, deadline, path)?;
            if buffer.capacity() > 8 * 1024 * 1024 {
                *buffer = Vec::new();
            }
            Ok::<_, anyhow::Error>(())
        })?;
        let intern = intern.into_inner();
        debug!(
            trees = intern.wide_trees.len(),
            bytes = intern.wide_tree_bytes,
            "Cached wide Git trees"
        );
        debug!(sets = intern.sets.len(), bytes = intern.set_bytes, "Interned Git candidate sets");
        Ok(Self {
            trees: states.iter().map(|state| state.load(Ordering::Relaxed)).collect(),
            sets: intern.sets,
            wide_trees: intern.wide_trees,
        })
    }

    pub(crate) fn cached_flat_tree(&self, oid: &gix::oid) -> Option<&[WideTreeEntry]> {
        self.wide_trees.get(oid)?.entries.as_deref()
    }

    pub(crate) fn cached_tree_children(
        &self,
        oid: &gix::oid,
        ancestors: &RoaringBitmap,
    ) -> Option<&[WideTreeChild]> {
        let wide = self.wide_trees.get(oid)?;
        (!wide.subtrees.is_empty() && wide.direct_blobs_covered(ancestors))
            .then_some(wide.subtrees.as_slice())
    }

    pub(crate) fn relevant(&self) -> FixedBitSet {
        let mut bits = FixedBitSet::with_capacity(self.trees.len());
        for (i, &state) in self.trees.iter().enumerate() {
            if state != CLEAN {
                bits.insert(i);
            }
        }
        bits
    }

    pub(crate) fn retain(&mut self, selected: &FixedBitSet) {
        let mut i = 0;
        self.trees.retain(|_| {
            let keep = selected.contains(i);
            i += 1;
            keep
        });
        self.trees.shrink_to_fit();
    }

    pub(crate) fn covered(
        &self,
        tree: ObjectIdx,
        tree_oid: &gix::oid,
        ancestors: &RoaringBitmap,
    ) -> bool {
        match self.trees[tree.as_usize()] {
            UNKNOWN => false,
            OVERFLOW => self.wide_trees.get(tree_oid).is_some_and(|tree| {
                tree.subtrees.is_empty() && tree.direct_blobs_covered(ancestors)
            }),
            CLEAN => true,
            id if id & MULTI == 0 => ancestors.contains(id - 3),
            id => self.sets[(id & !MULTI) as usize].iter().all(|id| ancestors.contains(*id)),
        }
    }
}

fn merge(state: u32, out: &mut Candidates, intern: &RwLock<Intern>) -> bool {
    match state {
        UNKNOWN | OVERFLOW => return false,
        CLEAN => {}
        id if id & MULTI == 0 => out.push(id - 3),
        id => out.extend_from_slice(&intern.read().sets[(id & !MULTI) as usize]),
    }
    out.sort_unstable();
    out.dedup();
    out.len() <= LIMIT
}

#[allow(clippy::too_many_arguments)]
fn summarize(
    index: &RepositoryIndex,
    tree: ObjectIdx,
    repo: &gix::Repository,
    states: &[AtomicU32],
    intern: &RwLock<Intern>,
    buffer: &mut Vec<u8>,
    depth: usize,
    deadline: Option<Instant>,
    path: &Path,
) -> Result<u32> {
    let cached = states[tree.as_usize()].load(Ordering::Relaxed);
    if cached != UNKNOWN {
        return Ok(cached);
    }
    if deadline.is_some_and(|d| Instant::now() > d) {
        bail!("candidate summary preparation timed out for {}", path.display());
    }
    if depth >= 64 {
        return Ok(OVERFLOW);
    }
    let mut children = SmallVec::<[ObjectIdx; 8]>::new();
    let mut ids = Candidates::new();
    let mut overflow = false;
    let oid = index.get_tree_oid(tree).unwrap();
    let object = repo.objects.find(oid, buffer).ok();
    let mut wide_tree = object
        .filter(|object| {
            object.data.len() >= WIDE_TREE_BYTES && index.num_blobs() <= MAX_WIDE_TREE_BLOB_INDEXES
        })
        .map(|_| WideTree {
            blobs: FixedBitSet::with_capacity(index.num_blobs()),
            entries: Some(Vec::new()),
            subtrees: Vec::new(),
        });
    match object.and_then(|object| object.try_into_tree_iter()) {
        None => overflow = true,
        Some(entries) => {
            for entry in entries {
                if deadline.is_some_and(|d| Instant::now() > d) {
                    bail!("candidate summary preparation timed out for {}", path.display());
                }
                let Ok(entry) = entry else {
                    overflow = true;
                    wide_tree = None;
                    break;
                };
                match entry.mode.kind() {
                    EntryKind::Blob | EntryKind::BlobExecutable => {
                        if let Some(blob) = index.get_blob_index(entry.oid) {
                            let id = blob.as_usize();
                            if let Some(wide) = &mut wide_tree {
                                wide.blobs.insert(id);
                                if let Some(entries) = &mut wide.entries {
                                    if entries.len() < MAX_WIDE_TREE_ENTRIES
                                        && entry.filename.len() <= 1024
                                    {
                                        entries.push(WideTreeEntry {
                                            blob,
                                            name: entry.filename.into(),
                                        });
                                    } else {
                                        wide.entries = None;
                                    }
                                }
                            }
                            if !overflow {
                                overflow = id >= (MULTI - 3) as usize
                                    || !merge(id as u32 + 3, &mut ids, intern);
                            }
                        }
                    }
                    EntryKind::Tree => {
                        if let Some(id) = index.get_tree_index(entry.oid) {
                            children.push(id);
                            if let Some(wide) = &mut wide_tree {
                                wide.entries = None;
                                if wide.subtrees.len() < MAX_WIDE_TREE_SUBTREES
                                    && entry.filename.len() <= 1024
                                {
                                    wide.subtrees.push(WideTreeChild {
                                        oid: entry.oid.to_owned(),
                                        name: entry.filename.into(),
                                    });
                                } else {
                                    wide_tree = None;
                                }
                            }
                        }
                    }
                    EntryKind::Link | EntryKind::Commit => {}
                }
                if overflow && wide_tree.is_none() {
                    break;
                }
            }
            if let Some(mut wide) = wide_tree.filter(|_| !ids.is_empty() || overflow) {
                // A complete parse proves direct blob coverage. Preserve the order and
                // paths of child directories, or of every blob for a sparse flat tree.
                let mut bytes = 128 + size_of_val(wide.blobs.as_slice());
                wide.subtrees.shrink_to_fit();
                bytes += wide
                    .subtrees
                    .iter()
                    .map(|entry| size_of::<WideTreeChild>() + entry.name.len())
                    .sum::<usize>();
                if let Some(entries) = &mut wide.entries {
                    entries.shrink_to_fit();
                    bytes += entries
                        .iter()
                        .map(|e| size_of::<WideTreeEntry>() + e.name.len())
                        .sum::<usize>();
                }
                let mut intern = intern.write();
                if intern.wide_tree_bytes + bytes <= WIDE_TREE_CACHE_BYTES
                    && !intern.wide_trees.contains_key(oid)
                {
                    intern.wide_tree_bytes += bytes;
                    intern.wide_trees.insert(oid.to_owned(), wide);
                }
            }
        }
    }
    if !overflow {
        for child in children {
            let child =
                summarize(index, child, repo, states, intern, buffer, depth + 1, deadline, path)?;
            if !merge(child, &mut ids, intern) {
                overflow = true;
                break;
            }
        }
    }
    let result = if overflow {
        OVERFLOW
    } else if ids.is_empty() {
        CLEAN
    } else if ids.len() == 1 {
        ids[0] + 3
    } else {
        let mut intern = intern.write();
        if let Some(&id) = intern.ids.get(&ids) {
            id
        } else {
            // Account for both copies and their table overhead. A set that
            // cannot be interned retains the ordinary traversal fallback.
            let bytes = 128 + 2 * ids.capacity() * size_of::<u32>();
            if intern.set_bytes + bytes > MAX_INTERNED_SET_BYTES {
                OVERFLOW
            } else {
                let id = MULTI | intern.sets.len() as u32;
                intern.set_bytes += bytes;
                intern.sets.push(ids.clone());
                intern.ids.insert(ids, id);
                id
            }
        }
    };
    states[tree.as_usize()].store(result, Ordering::Relaxed);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::git_test_fixture as fixture;

    use super::*;
    #[test]
    fn only_exact_ancestor_coverage_allows_skipping() {
        let summaries = CandidateSummaries {
            trees: vec![CLEAN, OVERFLOW, 3, MULTI],
            sets: vec![smallvec::smallvec![0, 1]],
            wide_trees: Default::default(),
        };
        let oid = gix::ObjectId::null(gix::hash::Kind::Sha1);
        let mut seen = RoaringBitmap::new();
        assert!(summaries.covered(ObjectIdx::new(0), &oid, &seen));
        assert!(!summaries.covered(ObjectIdx::new(1), &oid, &seen));
        assert!(!summaries.covered(ObjectIdx::new(2), &oid, &seen));
        seen.insert(0);
        assert!(summaries.covered(ObjectIdx::new(2), &oid, &seen));
        assert!(!summaries.covered(ObjectIdx::new(3), &oid, &seen));
        seen.insert(1);
        assert!(summaries.covered(ObjectIdx::new(3), &oid, &seen));
        assert!(!summaries.covered(ObjectIdx::new(1), &oid, &seen));
    }

    #[test]
    fn real_tree_summaries_bound_unique_sets_and_retain_malformed_trees() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let git = gix::init_bare(temp.path())?;
        let blobs: Vec<_> = (0..=LIMIT)
            .map(|i| {
                git.write_blob(format!("candidate contents long enough number {i}").as_bytes())
                    .map(gix::Id::detach)
            })
            .collect::<std::result::Result<_, _>>()?;
        let tree = |count: usize| -> Result<_> {
            let mut builder = git.empty_tree().edit()?;
            for (i, oid) in blobs.iter().take(count).enumerate() {
                fixture::insert(&mut builder, format!("file-{i}"), *oid, 0o100644)?;
            }
            Ok(builder.write()?.detach())
        };
        let single = tree(1)?;
        let bounded = tree(LIMIT)?;
        let overflow = tree(LIMIT + 1)?;
        let mut builder = git.empty_tree().edit()?;
        for i in 0..8 {
            fixture::insert(&mut builder, format!("alias-{i}"), single, 0o040000)?;
        }
        let aliases = builder.write()?.detach();
        let mut builder = git.empty_tree().edit()?;
        for i in 0..8_000 {
            fixture::insert(
                &mut builder,
                format!("wide-tree-entry-{i:05}"),
                blobs[i % blobs.len()],
                0o100644,
            )?;
        }
        let wide = builder.write()?.detach();
        use gix::prelude::Write;
        let malformed = git.objects.write_buf(gix::objs::Kind::Tree, b"not a valid tree entry")?;
        let repo = gix::open_opts(temp.path(), gix::open::Options::isolated())?.into_sync();
        let index = RepositoryIndex::new_with_deadline(&repo, None, temp.path())?;
        let summaries = CandidateSummaries::build(&index, &repo, None, temp.path())?;
        let covered = |id: &gix::oid, seen: &RoaringBitmap| {
            summaries.covered(index.get_tree_index(id).unwrap(), id, seen)
        };
        let mut seen = RoaringBitmap::new();
        assert!(!covered(&single, &seen));
        seen.insert(index.get_blob_index(&blobs[0]).unwrap().as_usize() as u32);
        assert!(covered(&single, &seen));
        assert!(covered(&aliases, &seen));
        assert!(!covered(&bounded, &seen));
        assert!(!covered(&wide, &seen));
        assert!(summaries.cached_flat_tree(&wide).is_none());
        for blob in blobs {
            seen.insert(index.get_blob_index(&blob).unwrap().as_usize() as u32);
        }
        assert!(covered(&bounded, &seen));
        assert!(!covered(&overflow, &seen));
        assert!(covered(&wide, &seen));
        assert!(!covered(&malformed, &seen));
        Ok(())
    }
}
