use std::{
    hash::BuildHasher,
    num::NonZeroU64,
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
    git_candidates::{GitContentFilter, RetainedGitBlob},
    git_commit_metadata::{CommitMetadata, intern_git_identity},
    git_metadata_graph::{GitMetadataGraph, RepositoryIndex},
};

/// Blobs smaller than this (in bytes) are skipped during enumeration.
/// This fixed cutoff avoids work on tiny Git objects; it is not derived from
/// the selected rules and can exclude shorter custom-rule matches.
pub const MIN_SCANNABLE_BLOB_SIZE: u64 = 20;

// Small histories do not amortize an extra content pass. Keep their existing
// eager metadata path, including its memory and I/O behavior.
const CONTENT_PREPASS_MIN_BLOBS: usize = 1_000_000;
// Histories with wide directories can serialize gigabytes of tree traversal
// even with fewer blobs. The candidate prepass summarizes those trees in parallel.
const CONTENT_PREPASS_MIN_TREE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

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
    pub(crate) indexed_size: Option<NonZeroU64>,
    pub(crate) retained_data: Option<Arc<RetainedGitBlob>>,
    pub first_seen: BlobAppearanceSet,
}

pub struct GitRepoWithMetadataEnumerator<'a> {
    path: &'a Path,
    repo: Repository,
    exclude_globset: Option<std::sync::Arc<globset::GlobSet>>,
    content_filter: Option<&'a GitContentFilter<'a>>,
}

impl<'a> GitRepoWithMetadataEnumerator<'a> {
    pub fn new(
        path: &'a Path,
        repo: Repository,
        exclude_globset: Option<std::sync::Arc<globset::GlobSet>>,
    ) -> Self {
        Self { path, repo, exclude_globset, content_filter: None }
    }

    pub(crate) fn with_content_filter(mut self, filter: &'a GitContentFilter<'a>) -> Self {
        self.content_filter = Some(filter);
        self
    }

    pub fn run(self) -> Result<GitRepoResult> {
        self.run_with_deadline(None)
    }

    pub fn run_with_deadline(self, deadline: Option<Instant>) -> Result<GitRepoResult> {
        self.run_with_minimum_blobs(deadline, CONTENT_PREPASS_MIN_BLOBS)
    }

    fn run_with_minimum_blobs(
        self,
        deadline: Option<Instant>,
        minimum_blobs: usize,
    ) -> Result<GitRepoResult> {
        let started = Instant::now();
        check_deadline(deadline, "git repository metadata enumeration", self.path)?;
        let repo_sync = self.repo.clone().into_sync();
        let odb = &self.repo.objects;
        let mut object_index = RepositoryIndex::new_with_deadline(&repo_sync, deadline, self.path)?;

        debug!(
            "Indexed {} objects in {:.6}s; {} blobs; {} commits",
            object_index.num_objects(),
            started.elapsed().as_secs_f64(),
            object_index.num_blobs(),
            object_index.num_commits(),
        );

        let retained = if let Some(filter) = self.content_filter
            && (object_index.num_blobs() >= minimum_blobs
                || object_index.tree_bytes() >= CONTENT_PREPASS_MIN_TREE_BYTES)
        {
            let retained =
                object_index.retain_content_candidates(&repo_sync, filter, deadline, self.path)?;
            if object_index.num_blobs() == 0 {
                return Ok(GitRepoResult {
                    repository: self.repo,
                    path: self.path.to_owned(),
                    blobs: GitBlobSource::Precomputed(Vec::new()),
                });
            }
            object_index.prepare_candidate_trees(&repo_sync, deadline, self.path)?;
            retained
        } else {
            Vec::new()
        };

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

        object_index.compact_candidate_trees(&mut metadata_graph);

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
        let (all_blobs, blob_sizes, blob_index) = object_index.into_blob_parts();
        // Candidate compaction and cached bytes both preserve pack order.
        let mut retained = retained.into_iter().peekable();
        let mut blobs: Vec<_> = all_blobs
            .into_iter()
            .zip(blob_sizes)
            .map(|(blob_oid, size)| GitBlobMetadata {
                blob_oid,
                indexed_size: NonZeroU64::new(size),
                retained_data: retained.next_if(|(oid, _)| *oid == blob_oid).map(|(_, data)| data),
                first_seen: Default::default(),
            })
            .collect();
        debug_assert!(retained.next().is_none());
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
                    let author = commit.author().ok();
                    let cm = Arc::new(CommitMetadata {
                        commit_id: e.commit_oid,
                        author_name: author.as_ref().map(|author| {
                            intern_git_identity(
                                String::from_utf8_lossy(author.name.as_ref()).as_ref(),
                            )
                        }),
                        author_email: author.as_ref().map(|author| {
                            intern_git_identity(
                                String::from_utf8_lossy(author.email.as_ref()).as_ref(),
                            )
                        }),
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

#[cfg(test)]
mod tests {
    use crate::git_test_fixture as fixture;

    use std::collections::BTreeMap;

    use base64::{Engine, engine::general_purpose::STANDARD};
    use gix::ObjectId;
    use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern};
    use tempfile::tempdir;

    use super::*;
    use crate::{limits::ResourceLimits, scanner_pool::ScannerPool};

    fn commit(
        repo: &gix::Repository,
        entries: &[(&str, ObjectId)],
        parents: &[ObjectId],
        message: &str,
    ) -> Result<ObjectId> {
        let mut builder = repo.empty_tree().edit()?;
        for &(path, oid) in entries {
            let mode = if repo.find_object(oid)?.kind == gix::objs::Kind::Tree {
                0o040000
            } else {
                0o100644
            };
            fixture::insert(&mut builder, path, oid, mode)?;
        }
        let tree = builder.write()?.detach();
        let parents: Vec<_> = parents.iter().collect();
        let signature = fixture::signature("history tester", "history@example.com");
        fixture::commit(repo, None, &signature, &signature, message, &tree, &parents)
    }

    fn appearances(result: GitRepoResult) -> BTreeMap<String, serde_json::Value> {
        let GitBlobSource::Precomputed(blobs) = result.blobs else {
            panic!("expected metadata blobs")
        };
        blobs
            .into_iter()
            .map(|blob| {
                (blob.blob_oid.to_string(), serde_json::to_value(&blob.first_seen).unwrap())
            })
            .collect()
    }

    #[test]
    fn gix_fixture_preserves_commit_identities_dates_parents_and_refs() -> Result<()> {
        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let tree = repo.empty_tree().edit()?.write()?.detach();
        let author = gix::actor::Signature {
            time: gix::date::Time::new(1_700_000_000, -3600),
            ..fixture::signature("fixture author", "author@example.invalid")
        };
        let committer = gix::actor::Signature {
            time: gix::date::Time::new(1_700_003_600, 7200),
            ..fixture::signature("fixture committer", "committer@example.invalid")
        };
        let first = fixture::commit(&repo, None, &author, &committer, "first", &tree, &[])?;
        let second = fixture::commit(&repo, None, &author, &committer, "second", &tree, &[])?;
        fixture::set_head(&repo, "refs/heads/fixture")?;
        let merge = fixture::commit(
            &repo,
            Some("HEAD"),
            &author,
            &committer,
            "merge",
            &tree,
            &[&second, &first],
        )?;
        let object = repo.find_commit(merge)?;
        assert_eq!(object.author()?.to_owned()?, author);
        assert_eq!(object.committer()?.to_owned()?, committer);
        assert_eq!(object.tree_id()?.detach(), tree);
        assert_eq!(object.parent_ids().map(gix::Id::detach).collect::<Vec<_>>(), [second, first]);
        assert_eq!(repo.head_id()?.detach(), merge);
        assert_eq!(repo.head_name()?.unwrap().as_bstr(), "refs/heads/fixture");
        let tag = fixture::tag(&repo, "fixture", merge, &committer, "annotated fixture")?;
        assert_eq!(repo.find_tag(tag)?.target_id()?.detach(), merge);
        fixture::detach_head(&repo, first)?;
        assert_eq!(repo.head_id()?.detach(), first);
        assert!(repo.head_name()?.is_none());
        assert_eq!(repo.find_reference("refs/heads/fixture")?.id().detach(), merge);
        Ok(())
    }

    #[test]
    fn gix_fixture_preserves_index_staging_and_origin_replacement() -> Result<()> {
        let temp = tempdir()?;
        let repo = gix::init(temp.path())?;
        let path = Path::new("nested/fixture ü.txt");
        std::fs::create_dir_all(temp.path().join("nested"))?;
        std::fs::write(temp.path().join(path), b"first contents")?;
        let mut index = fixture::index(&repo)?;
        fixture::stage(&repo, &mut index, path)?;
        let first = fixture::write_tree(&repo, &index)?;
        index.write(Default::default())?;
        assert!(repo.index_path().is_file());
        assert_eq!(fixture::write_tree(&repo, &*fixture::index(&repo)?)?, first);
        std::fs::write(temp.path().join(path), b"second contents")?;
        fixture::stage(&repo, &mut index, path)?;
        assert_eq!(index.entries().len(), 1, "restaging replaces, rather than duplicates, a path");
        assert_ne!(fixture::write_tree(&repo, &index)?, first);
        assert_eq!(
            fixture::write_tree(&repo, &*fixture::index(&repo)?)?,
            first,
            "unstored changes do not alter the on-disk index"
        );
        fixture::unstage(&mut index, path)?;
        assert!(index.entries().is_empty());
        fixture::origin(&repo, "https://first.example.invalid/repo.git")?;
        fixture::origin(&repo, "https://second.example.invalid/repo.git")?;
        let reopened = gix::open(temp.path())?;
        assert_eq!(
            reopened.config_snapshot().string("remote.origin.url").unwrap().to_string(),
            "https://second.example.invalid/repo.git"
        );
        assert_eq!(
            reopened.config_snapshot().string("remote.origin.fetch").unwrap().to_string(),
            "+refs/heads/*:refs/remotes/origin/*"
        );
        Ok(())
    }

    fn content_filter() -> Result<GitContentFilter<'static>> {
        Ok(GitContentFilter::new(
            Arc::new(ScannerPool::new(Arc::new(BlockDatabase::new(vec![Pattern::new(
                b"candidate_secret_[a-z0-9]{16}".to_vec(),
                Flag::default(),
                Some(0),
            )])?))),
            1,
            true,
            true,
            ResourceLimits::default(),
        ))
    }

    #[test]
    fn content_prepass_respects_blob_size_limits_without_counting_skipped_bytes() -> Result<()> {
        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let secret = b"candidate_secret_0123456789abcdef";
        let small = repo.write_blob(secret).map(gix::Id::detach)?;
        let large = repo.write_blob(secret.repeat(10)).map(gix::Id::detach)?;
        let clean = repo.write_blob(vec![b'x'; secret.len() + 1]).map(gix::Id::detach)?;
        let head = commit(
            &repo,
            &[("small.txt", small), ("large.txt", large), ("clean.txt", clean)],
            &[],
            "size limit fixture",
        )?;
        fixture::reference(
            &repo,
            "refs/heads/main",
            head,
            gix::refs::transaction::PreviousValue::Any,
            "test",
        )?;
        fixture::set_head(&repo, "refs/heads/main")?;

        for limit in [Some(secret.len() as u64), None] {
            let filter = content_filter()?.with_max_blob_size(limit);
            let result = GitRepoWithMetadataEnumerator::new(
                temp.path(),
                gix::open_opts(temp.path(), gix::open::Options::isolated())?,
                None,
            )
            .with_content_filter(&filter)
            .run_with_minimum_blobs(None, 0)?;
            let GitBlobSource::Precomputed(blobs) = &result.blobs else {
                bail!("expected precomputed metadata");
            };
            for blob in blobs {
                assert_eq!(
                    blob.retained_data.as_ref().map(|blob| blob.len() as u64),
                    blob.indexed_size.map(std::num::NonZeroU64::get)
                );
            }
            let result = appearances(result);
            assert!(result.contains_key(&small.to_string()));
            assert_eq!(result.contains_key(&large.to_string()), limit.is_none());
            assert!(!result.contains_key(&clean.to_string()));
            assert_eq!(
                filter.clean_stats().bytes_scanned,
                if limit.is_none() { secret.len() as u64 + 1 } else { 0 }
            );
        }
        Ok(())
    }

    #[test]
    fn sparse_metadata_preserves_branch_introductions_duplicates_and_orphans() -> Result<()> {
        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let clean = repo
            .write_blob(b"ordinary source text without matching credentials")
            .map(gix::Id::detach)?;
        let secret = b"candidate_secret_0123456789abcdef";
        let candidate = repo.write_blob(secret).map(gix::Id::detach)?;
        let encoded = repo.write_blob(STANDARD.encode(secret).as_bytes()).map(gix::Id::detach)?;
        let unicode: Vec<_> = std::iter::once(0xfeff)
            .chain(std::str::from_utf8(secret)?.encode_utf16())
            .flat_map(u16::to_le_bytes)
            .collect();
        let unicode = repo.write_blob(&unicode).map(gix::Id::detach)?;
        let archive = repo
            .write_blob(b"PK\x03\x04 possible archive content long enough")
            .map(gix::Id::detach)?;
        let orphan =
            repo.write_blob(b"orphan candidate_secret_fedcba9876543210").map(gix::Id::detach)?;
        let root = commit(&repo, &[("clean.txt", clean)], &[], "root")?;
        let left = commit(
            &repo,
            &[("first.txt", candidate), ("duplicate.txt", candidate)],
            &[root],
            "left introduction",
        )?;
        let right = commit(&repo, &[("second.txt", candidate)], &[root], "right introduction")?;
        let merged = commit(
            &repo,
            &[
                ("merged.txt", candidate),
                ("encoded.txt", encoded),
                ("unicode.txt", unicode),
                ("archive.zip", archive),
            ],
            &[left, right],
            "merge",
        )?;
        fixture::reference(
            &repo,
            "refs/heads/main",
            merged,
            gix::refs::transaction::PreviousValue::Any,
            "test",
        )?;
        fixture::set_head(&repo, "refs/heads/main")?;

        let filter = content_filter()?;
        let open =
            || -> Result<_> { Ok(gix::open_opts(temp.path(), gix::open::Options::isolated())?) };
        let eager =
            appearances(GitRepoWithMetadataEnumerator::new(temp.path(), open()?, None).run()?);
        let sparse = appearances(
            GitRepoWithMetadataEnumerator::new(temp.path(), open()?, None)
                .with_content_filter(&filter)
                .run_with_minimum_blobs(None, 0)?,
        );
        assert!(!sparse.contains_key(&clean.to_string()));
        for oid in [candidate, encoded, unicode, archive, orphan] {
            assert_eq!(sparse.get(&oid.to_string()), eager.get(&oid.to_string()));
            assert!(sparse.contains_key(&oid.to_string()));
        }
        assert_eq!(sparse[&candidate.to_string()].as_array().unwrap().len(), 3);
        assert!(sparse[&orphan.to_string()].as_array().unwrap().is_empty());

        // Small histories must retain the eager path rather than paying for a prepass.
        let small = appearances(
            GitRepoWithMetadataEnumerator::new(temp.path(), open()?, None)
                .with_content_filter(&filter)
                .run()?,
        );
        assert_eq!(small, eager);

        // A content hit at an excluded path must not hide its later included introduction.
        let mut globs = globset::GlobSetBuilder::new();
        globs.add(globset::Glob::new("first.txt")?);
        globs.add(globset::Glob::new("duplicate.txt")?);
        let globs = Arc::new(globs.build()?);
        let eager = appearances(
            GitRepoWithMetadataEnumerator::new(temp.path(), open()?, Some(Arc::clone(&globs)))
                .run()?,
        );
        let sparse = appearances(
            GitRepoWithMetadataEnumerator::new(temp.path(), open()?, Some(globs))
                .with_content_filter(&filter)
                .run_with_minimum_blobs(None, 0)?,
        );
        assert_eq!(sparse[&candidate.to_string()], eager[&candidate.to_string()]);
        Ok(())
    }

    #[test]
    fn candidate_tree_pruning_preserves_shared_subtree_paths_and_clean_commit_ancestry()
    -> Result<()> {
        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let candidate =
            repo.write_blob(b"candidate_secret_0123456789abcdef").map(gix::Id::detach)?;
        let clean = repo
            .write_blob(b"ordinary source file with no possible matching token")
            .map(gix::Id::detach)?;
        let mut builder = repo.empty_tree().edit()?;
        fixture::insert(&mut builder, "secret.txt", candidate, 0o100644)?;
        let shared = builder.write()?.detach();
        let mut builder = repo.empty_tree().edit()?;
        fixture::insert(&mut builder, "clean.txt", clean, 0o100644)?;
        let clean_subtree = builder.write()?.detach();
        let first = commit(
            &repo,
            &[("alpha", shared), ("beta", shared), ("clean", clean_subtree)],
            &[],
            "shared candidate subtree",
        )?;
        // An irrelevant intervening snapshot must still transmit ancestor state.
        let middle = commit(&repo, &[("clean", clean_subtree)], &[first], "remove candidate")?;
        let last = commit(&repo, &[("reintroduced", shared)], &[middle], "reintroduce")?;
        fixture::reference(
            &repo,
            "refs/heads/main",
            last,
            gix::refs::transaction::PreviousValue::Any,
            "test",
        )?;
        fixture::set_head(&repo, "refs/heads/main")?;
        let open =
            || -> Result<_> { Ok(gix::open_opts(temp.path(), gix::open::Options::isolated())?) };
        for excluded in [None, Some("beta/**")] {
            let globs = excluded
                .map(|pattern| -> Result<_> {
                    let mut builder = globset::GlobSetBuilder::new();
                    builder.add(globset::Glob::new(pattern)?);
                    Ok(Arc::new(builder.build()?))
                })
                .transpose()?;
            let eager = appearances(
                GitRepoWithMetadataEnumerator::new(temp.path(), open()?, globs.clone()).run()?,
            );
            let filter = content_filter()?;
            let sparse = appearances(
                GitRepoWithMetadataEnumerator::new(temp.path(), open()?, globs)
                    .with_content_filter(&filter)
                    .run_with_minimum_blobs(None, 0)?,
            );
            assert_eq!(sparse[&candidate.to_string()], eager[&candidate.to_string()]);
            assert_eq!(sparse[&candidate.to_string()].as_array().unwrap().len(), 1);
            assert!(!sparse.contains_key(&clean.to_string()));
        }
        Ok(())
    }
}
