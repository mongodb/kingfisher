use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result};
use bstr::ByteSlice;
use gix::{
    date::{parse as parse_time, Time},
    hashtable::HashMap,
    prelude::FindExt,
    ObjectId, Repository,
};
use smallvec::SmallVec;
use tracing::{debug, debug_span};

use crate::{
    blob::{BlobAppearance, BlobAppearanceSet},
    git_commit_metadata::CommitMetadata,
    git_metadata_graph::{GitMetadataGraph, RepositoryIndex},
};

// Macros unchanged:
macro_rules! unwrap_some_or_continue {
    ($arg:expr, $on_error:expr $(,)?) => {
        match $arg {
            Some(v) => v,
            None => {
                #[allow(clippy::redundant_closure_call)]
                $on_error();
                continue;
            }
        }
    };
}
pub(crate) use unwrap_some_or_continue;

macro_rules! unwrap_ok_or_continue {
    ($arg:expr, $on_error:expr $(,)?) => {
        match $arg {
            Ok(v) => v,
            Err(e) => {
                #[allow(clippy::redundant_closure_call)]
                $on_error(e);
                continue;
            }
        }
    };
}
pub(crate) use unwrap_ok_or_continue;

// Convert "<seconds> <offset>" -- Time; fallback to the Unix-epoch on parse error
fn parse_sig_time<T: AsRef<[u8]>>(raw: T) -> Time {
    match std::str::from_utf8(raw.as_ref()) {
        Ok(s) => parse_time(s, None).unwrap_or_else(|_| Time::new(0, 0)),
        Err(_) => Time::new(0, 0),
    }
}

pub struct GitRepoResult {
    pub path: PathBuf,
    pub repository: Repository,
    pub blobs: Vec<GitBlobMetadata>,
}

#[derive(Clone)]
pub struct GitBlobMetadata {
    pub blob_oid: ObjectId,
    pub first_seen: BlobAppearanceSet,
}

pub struct GitRepoWithMetadataEnumerator<'a> {
    path: &'a Path,
    repo: Repository,
}

impl<'a> GitRepoWithMetadataEnumerator<'a> {
    pub fn new(path: &'a Path, repo: Repository) -> Self {
        Self { path, repo }
    }

    pub fn run(self) -> Result<GitRepoResult> {
        let started = Instant::now();
        // let _span = debug_span!("enumerate_git_with_metadata", path = ?self.path).entered();
        let odb = &self.repo.objects;
        let object_index = RepositoryIndex::new(odb)?;

        debug!(
            "Indexed {} objects in {:.6}s; {} blobs; {} commits",
            object_index.num_objects(),
            started.elapsed().as_secs_f64(),
            object_index.num_blobs(),
            object_index.num_commits(),
        );

        let mut metadata_graph = GitMetadataGraph::with_capacity(object_index.num_commits());
        let mut scratch = Vec::with_capacity(4 * 1024 * 1024);
        let mut commit_metadata =
            HashMap::with_capacity_and_hasher(object_index.num_commits(), Default::default());

        // Collect commit metadata and build commit graph
        for commit_oid in object_index.commits() {
            let commit = unwrap_ok_or_continue!(odb.find_commit(commit_oid, &mut scratch), |e| {
                debug!("Failed to find commit {commit_oid}: {e}");
            });
            let tree_oid = commit.tree();
            let tree_idx = unwrap_some_or_continue!(object_index.get_tree_index(&tree_oid), || {
                debug!("Failed to find tree {tree_oid} for commit {commit_oid}");
            });
            let commit_idx = metadata_graph.get_commit_idx(*commit_oid, Some(tree_idx));

            for parent_oid in commit.parents() {
                let parent_idx = metadata_graph.get_commit_idx(parent_oid, None);
                metadata_graph.add_commit_edge(parent_idx, commit_idx);
            }

            let committer = &commit.committer;
            // let author = &commit.author;

            commit_metadata.insert(
                *commit_oid,
                Arc::new(CommitMetadata {
                    commit_id: *commit_oid,
                    committer_name: committer.name.to_owned(),
                    committer_email: committer.email.to_owned(),
                    committer_timestamp: parse_sig_time(committer.time),
                    // author_name: author.name.to_owned(),
                    // author_email: author.email.to_owned(),
                    // author_timestamp: parse_sig_time(author.time),
                }),
            );
        }

        debug!("Built metadata graph in {:.6}s", started.elapsed().as_secs_f64());

        // Compute metadata once, then get all blob IDs
        let meta_result = metadata_graph.get_repo_metadata(&object_index, &self.repo);
        let all_blobs = object_index.into_blobs();

        // Assemble final blob list
        let blobs = match meta_result {
            Err(e) => {
                debug!("Failed to compute reachable blobs; ignoring metadata: {e}");
                all_blobs
                    .into_iter()
                    .map(|blob_oid| GitBlobMetadata { blob_oid, first_seen: Default::default() })
                    .collect()
            }
            Ok(metadata) => {
                // Build map of blob -> appearances
                let mut blob_map: HashMap<_, SmallVec<_>> =
                    all_blobs.into_iter().map(|b| (b, SmallVec::new())).collect();

                for e in metadata {
                    let cm = unwrap_some_or_continue!(commit_metadata.get(&e.commit_oid), || {
                        debug!("Missing commit metadata for {}", e.commit_oid);
                    });
                    for (blob_oid, path) in e.introduced_blobs {
                        blob_map
                            .entry(blob_oid)
                            .or_default()
                            .push(BlobAppearance { commit_metadata: cm.clone(), path });
                    }
                }

                // Filter out empty or ignored paths
                blob_map
                    .into_iter()
                    .filter_map(|(blob_oid, appearances)| {
                        if appearances.is_empty() {
                            return Some(GitBlobMetadata { blob_oid, first_seen: appearances });
                        }
                        let filtered = appearances
                            .into_iter()
                            .filter(|entry| {
                                // Apply your actual ignore-logic here:
                                match entry.path.to_path() {
                                    Ok(_path) => true,
                                    Err(_) => true,
                                }
                            })
                            .collect::<SmallVec<_>>();
                        if filtered.is_empty() {
                            None
                        } else {
                            Some(GitBlobMetadata { blob_oid, first_seen: filtered })
                        }
                    })
                    .collect()
            }
        };

        Ok(GitRepoResult { repository: self.repo, path: self.path.to_owned(), blobs })
    }
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
        use gix::{object::Kind, odb::store::iter::Ordering, prelude::*};
        let _span = debug_span!("enumerate_git", path = ?self.path).entered();
        let odb = &self.repo.objects;
        let mut blobs = Vec::with_capacity(64 * 1024);

        for oid_result in odb
            .iter()
            .context("Failed to iterate object database")?
            .with_ordering(Ordering::PackAscendingOffsetThenLooseLexicographical)
        {
            let oid =
                unwrap_ok_or_continue!(oid_result, |e| debug!("Failed to read object id: {e}"));
            let hdr = unwrap_ok_or_continue!(odb.header(oid), |e| {
                debug!("Failed to read object header for {oid}: {e}")
            });

            if hdr.kind() == Kind::Blob {
                blobs.push(oid);
            }
        }

        let blobs = blobs
            .into_iter()
            .map(|blob_oid| GitBlobMetadata { blob_oid, first_seen: Default::default() })
            .collect();

        Ok(GitRepoResult { repository: self.repo, path: self.path.to_owned(), blobs })
    }
}
