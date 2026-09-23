use std::{
    hash::BuildHasher,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Result, bail};
use bstr::ByteSlice;
use gix::{
    ObjectId, Repository,
    date::{Time, parse as parse_time},
    prelude::FindExt,
};
use tracing::{debug, debug_span};

use crate::{
    blob::{BlobAppearance, BlobAppearanceSet},
    git_commit_metadata::{CommitMetadata, intern_git_identity},
    git_metadata_graph::{GitMetadataGraph, RepositoryIndex},
};

/// Blobs smaller than this (in bytes) are skipped during enumeration.
/// No meaningful secret (API key, token, password assignment) fits in fewer
/// bytes, so filtering these avoids loading, hashing, and scanning overhead.
pub const MIN_SCANNABLE_BLOB_SIZE: u64 = 20;

// Convert "<seconds> <offset>" -- Time; fallback to the Unix-epoch on parse error
#[inline]
fn parse_sig_time(raw: &str) -> Time {
    parse_time(raw, None).unwrap_or_else(|_| Time::new(0, 0))
}

/// How blobs are provided to the scanning pipeline.
pub enum GitBlobSource {
    /// Blobs were pre-computed (metadata path, diff path).
    Precomputed(Vec<GitBlobMetadata>),
    /// Enumerate blobs lazily from the ODB during parallel iteration,
    /// overlapping enumeration with scanning.
    StreamFromOdb,
}

pub struct GitRepoResult {
    pub path: PathBuf,
    pub repository: Repository,
    pub blobs: GitBlobSource,
}

#[derive(Clone)]
pub struct GitBlobMetadata {
    pub blob_oid: ObjectId,
    pub first_seen: BlobAppearanceSet,
}

pub struct GitRepoWithMetadataEnumerator<'a> {
    path: &'a Path,
    repo: Repository,
    exclude_globset: Option<std::sync::Arc<globset::GlobSet>>,
}

impl<'a> GitRepoWithMetadataEnumerator<'a> {
    pub fn new(
        path: &'a Path,
        repo: Repository,
        exclude_globset: Option<std::sync::Arc<globset::GlobSet>>,
    ) -> Self {
        Self { path, repo, exclude_globset }
    }

    pub fn run(self) -> Result<GitRepoResult> {
        self.run_with_deadline(None)
    }

    pub fn run_with_deadline(self, deadline: Option<Instant>) -> Result<GitRepoResult> {
        let started = Instant::now();
        // let _span = debug_span!("enumerate_git_with_metadata", path = ?self.path).entered();
        check_deadline(deadline, "git repository metadata enumeration", self.path)?;
        let odb = &self.repo.objects;
        let object_index = RepositoryIndex::new_with_deadline(odb, deadline, self.path)?;

        debug!(
            "Indexed {} objects in {:.6}s; {} blobs; {} commits",
            object_index.num_objects(),
            started.elapsed().as_secs_f64(),
            object_index.num_blobs(),
            object_index.num_commits(),
        );

        let mut metadata_graph = GitMetadataGraph::with_capacity(object_index.num_commits());
        let mut scratch = Vec::with_capacity(4 * 1024 * 1024);

        // Build commit graph first; materialize committer metadata only for commits that
        // actually introduce blobs.
        for commit_oid in object_index.commits() {
            check_deadline(deadline, "git commit graph enumeration", self.path)?;
            let commit = match odb.find_commit(commit_oid, &mut scratch) {
                Ok(commit) => commit,
                Err(e) => {
                    debug!("Failed to find commit {commit_oid}: {e}");
                    continue;
                }
            };
            let tree_oid = commit.tree();
            let tree_idx = match object_index.get_tree_index(&tree_oid) {
                Some(idx) => idx,
                None => {
                    debug!("Failed to find tree {tree_oid} for commit {commit_oid}");
                    continue;
                }
            };
            let commit_idx = metadata_graph.get_commit_idx(*commit_oid, Some(tree_idx));

            for parent_oid in commit.parents() {
                let parent_idx = metadata_graph.get_commit_idx(parent_oid, None);
                metadata_graph.add_commit_edge(parent_idx, commit_idx);
            }
        }

        debug!("Built metadata graph in {:.6}s", started.elapsed().as_secs_f64());

        // Compute metadata once, then get all blob IDs (in pack-ascending order)
        let meta_result = metadata_graph.get_repo_metadata_with_deadline(
            &object_index,
            &self.repo,
            self.exclude_globset.as_deref(),
            deadline,
        );
        // Reuse the dense object index rather than building an appearances hash map
        // alongside a second final blob collection. Pack order remains unchanged.
        check_deadline(deadline, "git blob metadata assembly", self.path)?;
        let (all_blobs, blob_index) = object_index.into_blob_parts();
        let mut blobs: Vec<_> = all_blobs
            .into_iter()
            .map(|blob_oid| GitBlobMetadata { blob_oid, first_seen: Default::default() })
            .collect();
        check_deadline(deadline, "git blob metadata assembly", self.path)?;
        match meta_result {
            Err(e) => {
                debug!("Failed to compute reachable blobs; ignoring metadata: {e}");
            }
            Ok(metadata) => {
                for e in metadata {
                    check_deadline(deadline, "git commit metadata assembly", self.path)?;
                    if e.introduced_blobs.is_empty() {
                        continue;
                    }
                    let commit = match odb.find_commit(&e.commit_oid, &mut scratch) {
                        Ok(commit) => commit,
                        Err(err) => {
                            debug!("Failed to load commit metadata for {}: {err}", e.commit_oid);
                            continue;
                        }
                    };
                    let committer = match commit.committer() {
                        Ok(committer) => committer,
                        Err(err) => {
                            debug!(
                                "Failed to decode committer metadata for {}: {err}",
                                e.commit_oid
                            );
                            continue;
                        }
                    };
                    // Metadata traversal emits each commit once. Its appearances share
                    // this Arc directly, without a redundant per-commit cache.
                    let cm = Arc::new(CommitMetadata {
                        commit_id: e.commit_oid,
                        committer_name: intern_git_identity(
                            String::from_utf8_lossy(committer.name.as_ref()).as_ref(),
                        ),
                        committer_email: intern_git_identity(
                            String::from_utf8_lossy(committer.email.as_ref()).as_ref(),
                        ),
                        committer_timestamp: parse_sig_time(committer.time),
                    });
                    for (blob_oid, path) in e.introduced_blobs {
                        if let Some(idx) = blob_index
                            .find(gix::hashtable::hash::Builder.hash_one(blob_oid), |idx| {
                                blobs[idx.as_usize()].blob_oid == blob_oid
                            })
                        {
                            blobs[idx.as_usize()]
                                .first_seen
                                .push(BlobAppearance { commit_metadata: Arc::clone(&cm), path });
                        }
                    }
                }
                drop(blob_index);
                check_deadline(deadline, "git blob metadata assembly", self.path)?;
                blobs.retain_mut(|blob| {
                    // Preserve the existing treatment of unreferenced objects while
                    // removing blobs whose every known appearance is excluded.
                    if !blob.first_seen.is_empty() {
                        blob.first_seen.retain(|entry| match entry.path.to_path() {
                            Ok(p) => {
                                !self.exclude_globset.as_ref().is_some_and(|gs| gs.is_match(p))
                            }
                            Err(_) => true,
                        });
                        return !blob.first_seen.is_empty();
                    }
                    true
                });
                check_deadline(deadline, "git blob metadata assembly", self.path)?;
            }
        }

        Ok(GitRepoResult {
            repository: self.repo,
            path: self.path.to_owned(),
            blobs: GitBlobSource::Precomputed(blobs),
        })
    }
}

#[inline]
fn check_deadline(deadline: Option<Instant>, phase: &str, path: &Path) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() > deadline) {
        bail!("{phase} timed out for {}", path.display())
    }
    Ok(())
}

pub struct GitRepoEnumerator<'a> {
    path: &'a Path,
    repo: Repository,
}

impl<'a> GitRepoEnumerator<'a> {
    pub fn new(path: &'a Path, repo: Repository) -> Self {
        Self { path, repo }
    }

    pub fn run(self) -> Result<GitRepoResult> {
        let _span = debug_span!("enumerate_git", path = ?self.path).entered();
        Ok(GitRepoResult {
            repository: self.repo,
            path: self.path.to_owned(),
            blobs: GitBlobSource::StreamFromOdb,
        })
    }
}
