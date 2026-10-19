//! Bounded exact candidate sets for skipping candidate-unchanged subtrees.
//! A subtree may be skipped only when every candidate it contains is already in
//! the current commit's ancestor blob set. Presence in another branch is insufficient.

use crate::git_metadata_graph::{ObjectIdx, RepositoryIndex};
use anyhow::{Result, bail};
use fixedbitset::FixedBitSet;
use gix::{objs::tree::EntryKind, prelude::*};
use parking_lot::Mutex;
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

const UNKNOWN: u32 = 0;
const CLEAN: u32 = 1;
const OVERFLOW: u32 = 2;
const MULTI: u32 = 1 << 31;
const LIMIT: usize = 4;
type Candidates = SmallVec<[u32; LIMIT]>;

#[derive(Default)]
struct Intern {
    ids: HashMap<Candidates, u32>,
    sets: Vec<Candidates>,
}

pub(crate) struct CandidateSummaries {
    trees: Vec<u32>,
    sets: Vec<Candidates>,
}

impl CandidateSummaries {
    pub(crate) fn build(
        index: &RepositoryIndex,
        repo: &gix::ThreadSafeRepository,
        deadline: Option<Instant>,
        path: &Path,
    ) -> Result<Self> {
        let states: Vec<_> = (0..index.num_trees()).map(|_| AtomicU32::new(UNKNOWN)).collect();
        let intern = Mutex::new(Intern::default());
        let workers = thread_local::ThreadLocal::new();
        (0..states.len()).into_par_iter().with_min_len(128).try_for_each(|i| {
            let worker = workers.get_or(|| RefCell::new((repo.to_thread_local(), Vec::new())));
            let mut worker = worker.borrow_mut();
            let (repo, buffer) = &mut *worker;
            summarize(index, ObjectIdx::new(i), repo, &states, &intern, buffer, 0, deadline, path)?;
            if buffer.capacity() > 8 * 1024 * 1024 {
                *buffer = Vec::new();
            }
            Ok::<_, anyhow::Error>(())
        })?;
        Ok(Self {
            trees: states.iter().map(|state| state.load(Ordering::Relaxed)).collect(),
            sets: intern.into_inner().sets,
        })
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

    pub(crate) fn covered(&self, tree: ObjectIdx, ancestors: &RoaringBitmap) -> bool {
        match self.trees[tree.as_usize()] {
            UNKNOWN | OVERFLOW => false,
            CLEAN => true,
            id if id & MULTI == 0 => ancestors.contains(id - 3),
            id => self.sets[(id & !MULTI) as usize].iter().all(|id| ancestors.contains(*id)),
        }
    }
}

fn merge(state: u32, out: &mut Candidates, intern: &Mutex<Intern>) -> bool {
    match state {
        UNKNOWN | OVERFLOW => return false,
        CLEAN => {}
        id if id & MULTI == 0 => out.push(id - 3),
        id => out.extend_from_slice(&intern.lock().sets[(id & !MULTI) as usize]),
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
    intern: &Mutex<Intern>,
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
    match repo.objects.find_tree_iter(index.get_tree_oid(tree).unwrap(), buffer) {
        Err(_) => overflow = true,
        Ok(entries) => {
            for entry in entries {
                if deadline.is_some_and(|d| Instant::now() > d) {
                    bail!("candidate summary preparation timed out for {}", path.display());
                }
                let Ok(entry) = entry else {
                    overflow = true;
                    break;
                };
                match entry.mode.kind() {
                    EntryKind::Blob | EntryKind::BlobExecutable => {
                        if let Some(id) = index.get_blob_index(entry.oid) {
                            let id = id.as_usize();
                            if id >= (MULTI - 3) as usize || !merge(id as u32 + 3, &mut ids, intern)
                            {
                                overflow = true;
                                break;
                            }
                        }
                    }
                    EntryKind::Tree => {
                        if let Some(id) = index.get_tree_index(entry.oid) {
                            children.push(id);
                        }
                    }
                    EntryKind::Link | EntryKind::Commit => {}
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
        let mut intern = intern.lock();
        if let Some(&id) = intern.ids.get(&ids) {
            id
        } else if intern.sets.len() >= MULTI as usize {
            OVERFLOW
        } else {
            let id = MULTI | intern.sets.len() as u32;
            intern.sets.push(ids.clone());
            intern.ids.insert(ids, id);
            id
        }
    };
    states[tree.as_usize()].store(result, Ordering::Relaxed);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_ancestor_coverage_allows_skipping() {
        let summaries = CandidateSummaries {
            trees: vec![CLEAN, OVERFLOW, 3, MULTI],
            sets: vec![smallvec::smallvec![0, 1]],
        };
        let mut seen = RoaringBitmap::new();
        assert!(summaries.covered(ObjectIdx::new(0), &seen));
        assert!(!summaries.covered(ObjectIdx::new(1), &seen));
        assert!(!summaries.covered(ObjectIdx::new(2), &seen));
        seen.insert(0);
        assert!(summaries.covered(ObjectIdx::new(2), &seen));
        assert!(!summaries.covered(ObjectIdx::new(3), &seen));
        seen.insert(1);
        assert!(summaries.covered(ObjectIdx::new(3), &seen));
        assert!(!summaries.covered(ObjectIdx::new(1), &seen));
    }

    #[test]
    fn real_tree_summaries_bound_unique_sets_and_retain_malformed_trees() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let git = git2::Repository::init_bare(temp.path())?;
        let blobs: Vec<_> = (0..5)
            .map(|i| git.blob(format!("candidate contents long enough number {i}").as_bytes()))
            .collect::<std::result::Result<_, _>>()?;
        let tree = |count: usize| -> Result<_> {
            let mut builder = git.treebuilder(None)?;
            for (i, oid) in blobs.iter().take(count).enumerate() {
                builder.insert(format!("file-{i}"), *oid, 0o100644)?;
            }
            Ok(builder.write()?)
        };
        let single = tree(1)?;
        let four = tree(4)?;
        let five = tree(5)?;
        let mut builder = git.treebuilder(None)?;
        for i in 0..8 {
            builder.insert(format!("alias-{i}"), single, 0o040000)?;
        }
        let aliases = builder.write()?;
        let malformed = git.odb()?.write(git2::ObjectType::Tree, b"not a valid tree entry")?;
        let repo = gix::open_opts(temp.path(), gix::open::Options::isolated())?.into_sync();
        let index = RepositoryIndex::new_with_deadline(&repo, None, temp.path())?;
        let summaries = CandidateSummaries::build(&index, &repo, None, temp.path())?;
        let oid = |id: git2::Oid| gix::ObjectId::from_hex(id.to_string().as_bytes());
        let tree_index = |id| index.get_tree_index(&oid(id).unwrap()).unwrap();
        let mut seen = RoaringBitmap::new();
        assert!(!summaries.covered(tree_index(single), &seen));
        seen.insert(index.get_blob_index(&oid(blobs[0])?).unwrap().as_usize() as u32);
        assert!(summaries.covered(tree_index(single), &seen));
        assert!(summaries.covered(tree_index(aliases), &seen));
        assert!(!summaries.covered(tree_index(four), &seen));
        for blob in blobs {
            seen.insert(index.get_blob_index(&oid(blob)?).unwrap().as_usize() as u32);
        }
        assert!(summaries.covered(tree_index(four), &seen));
        assert!(!summaries.covered(tree_index(five), &seen));
        assert!(!summaries.covered(tree_index(malformed), &seen));
        Ok(())
    }
}
