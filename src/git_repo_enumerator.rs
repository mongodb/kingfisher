use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Result, bail};
use bstr::ByteSlice;
use gix::{
    ObjectId, Repository,
    date::{Time, parse as parse_time},
    hashtable::HashMap,
    prelude::FindExt,
};
use smallvec::SmallVec;
use tracing::{debug, debug_span};

use crate::{
    blob::{BlobAppearance, BlobAppearanceSet},
    git_commit_metadata::CommitMetadata,
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
        let all_blobs = object_index.into_blobs();

        // Assemble final blob list, preserving pack-ascending order for I/O locality
        let blobs = match meta_result {
            Err(e) => {
                debug!("Failed to compute reachable blobs; ignoring metadata: {e}");
                let mut blobs = Vec::with_capacity(all_blobs.len());
                for blob_oid in all_blobs {
                    check_deadline(deadline, "git blob metadata assembly", self.path)?;
                    blobs.push(GitBlobMetadata { blob_oid, first_seen: Default::default() });
                }
                blobs
            }
            Ok(metadata) => {
                let mut commit_metadata: HashMap<ObjectId, Arc<CommitMetadata>> =
                    HashMap::with_capacity_and_hasher(0, Default::default());
                let mut blob_appearances: HashMap<ObjectId, SmallVec<_>> =
                    HashMap::with_capacity_and_hasher(all_blobs.len(), Default::default());

                for e in metadata {
                    check_deadline(deadline, "git commit metadata assembly", self.path)?;
                    if e.introduced_blobs.is_empty() {
                        continue;
                    }

                    let cm = if let Some(cm) = commit_metadata.get(&e.commit_oid) {
                        cm.clone()
                    } else {
                        let commit = match odb.find_commit(&e.commit_oid, &mut scratch) {
                            Ok(commit) => commit,
                            Err(err) => {
                                debug!(
                                    "Failed to load commit metadata for {}: {err}",
                                    e.commit_oid
                                );
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
                        let parsed = Arc::new(CommitMetadata {
                            commit_id: e.commit_oid,
                            committer_name: String::from_utf8_lossy(committer.name.as_ref())
                                .into_owned(),
                            committer_email: String::from_utf8_lossy(committer.email.as_ref())
                                .into_owned(),
                            committer_timestamp: parse_sig_time(committer.time),
                        });
                        commit_metadata.insert(e.commit_oid, Arc::clone(&parsed));
                        parsed
                    };
                    for (blob_oid, path) in e.introduced_blobs {
                        blob_appearances
                            .entry(blob_oid)
                            .or_default()
                            .push(BlobAppearance { commit_metadata: Arc::clone(&cm), path });
                    }
                }

                // Iterate in pack-ascending order (from RepositoryIndex) for I/O locality
                let mut blobs = Vec::with_capacity(all_blobs.len());
                for blob_oid in all_blobs {
                    check_deadline(deadline, "git blob metadata assembly", self.path)?;
                    let appearances = blob_appearances.remove(&blob_oid).unwrap_or_default();
                    if appearances.is_empty() {
                        blobs.push(GitBlobMetadata { blob_oid, first_seen: appearances });
                        continue;
                    }
                    let filtered = appearances
                        .into_iter()
                        .filter(|entry| match entry.path.to_path() {
                            Ok(p) => {
                                if let Some(gs) = &self.exclude_globset {
                                    let m = gs.is_match(p);
                                    if m {
                                        debug!("Skipping {} due to --exclude", p.display());
                                    }
                                    !m
                                } else {
                                    true
                                }
                            }
                            Err(_) => true,
                        })
                        .collect::<SmallVec<_>>();
                    if !filtered.is_empty() {
                        blobs.push(GitBlobMetadata { blob_oid, first_seen: filtered });
                    }
                }
                blobs
            }
        };

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
