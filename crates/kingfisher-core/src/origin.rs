//! Provenance tracking for scanned content.
//!
//! This module provides types for tracking where content came from:
//! - [`FileOrigin`] - Content from a file path
//! - [`GitRepoOrigin`] - Content from a git repository
//! - [`ExtendedOrigin`] - Content from other sources (Jira, Confluence, etc.)
//! - [`OriginSet`] - A non-empty collection of origins

use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
};

use dashmap::DashMap;
use rustc_hash::FxHashSet;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize, ser::SerializeSeq};
use serde_json::json;
use smallvec::SmallVec;

use crate::git_commit_metadata::CommitMetadata;

// Cache for git remote URLs to avoid repeated lookups
static URL_CACHE: LazyLock<DashMap<PathBuf, Arc<str>>> = LazyLock::new(DashMap::default);

fn compute_url(repo_path: &Path) -> anyhow::Result<String> {
    let repo = gix::open(repo_path)?;
    let config = repo.config_snapshot();

    let url_bytes =
        config.string("remote.origin.url").ok_or_else(|| anyhow::anyhow!("No remote URL found"))?;

    use bstr::ByteSlice;
    if url_bytes.starts_with(b"http://") || url_bytes.starts_with(b"https://") {
        Ok(String::from_utf8_lossy(url_bytes.as_bytes()).into_owned())
    } else if url_bytes.starts_with(b"git@") {
        let url_str = String::from_utf8_lossy(url_bytes.as_bytes());
        if let Some(stripped) = url_str.strip_prefix("git@")
            && let Some((domain, path)) = stripped.split_once(':')
        {
            Ok(format!("https://{}/{}", domain, path))
        } else {
            Err(anyhow::anyhow!("Invalid SSH URL format"))
        }
    } else {
        Err(anyhow::anyhow!(
            "Unsupported remote URL format: {}",
            String::from_utf8_lossy(url_bytes.as_bytes())
        ))
    }
}

/// Gets the remote URL for a git repository, with caching.
pub fn get_repo_url(repo_path: &Path) -> anyhow::Result<Arc<str>> {
    // Fast path: cache hit
    if let Some(u) = URL_CACHE.get(repo_path) {
        return Ok(u.clone());
    }

    // Slow path: compute, intern, cache
    let url_arc: Arc<str> = compute_url(repo_path)?.into();
    URL_CACHE.insert(repo_path.to_path_buf(), url_arc.clone());
    Ok(url_arc)
}

/// The provenance of a scanned blob.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Origin {
    /// Content from a file on disk.
    File(FileOrigin),
    /// Content from a git repository.
    GitRepo(GitRepoOrigin),
    /// Content from an extended source (arbitrary JSON metadata).
    Extended(ExtendedOrigin),
}

impl Origin {
    /// Creates an `Origin` for a plain file.
    pub fn from_file(path: PathBuf) -> Self {
        Origin::File(FileOrigin::new(path))
    }

    /// Creates an `Origin` for a blob in a git repository without commit info.
    pub fn from_git_repo(repo_path: Arc<PathBuf>) -> Self {
        Origin::GitRepo(GitRepoOrigin { repo_path, first_commit: None })
    }

    /// Creates an `Origin` for a blob in a git repository with commit info.
    pub fn from_git_repo_with_first_commit(
        repo_path: Arc<PathBuf>,
        commit_metadata: Arc<CommitMetadata>,
        blob_path: String,
    ) -> Self {
        let first_commit = Some(CommitOrigin { commit_metadata, blob_path });
        Origin::GitRepo(GitRepoOrigin { repo_path, first_commit })
    }

    /// Creates an `Origin` from arbitrary JSON metadata.
    pub fn from_extended(value: serde_json::Value) -> Self {
        Origin::Extended(ExtendedOrigin(value))
    }

    /// Returns the path of the blob, if available.
    pub fn blob_path(&self) -> Option<&Path> {
        match self {
            Self::File(e) => Some(&e.path),
            Self::GitRepo(e) => e.first_commit.as_ref().map(|c| Path::new(&c.blob_path)),
            Self::Extended(e) => e.path(),
        }
    }

    /// Returns the full filesystem path to the content, if available.
    pub fn full_path(&self) -> Option<PathBuf> {
        match self {
            Self::File(e) => Some((*e.path).clone()),
            Self::GitRepo(e) => e.first_commit.as_ref().map(|c| e.repo_path.join(&c.blob_path)),
            Self::Extended(e) => e.path().map(PathBuf::from),
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::File(e) => write!(f, "file {}", e.path.display()),
            Origin::GitRepo(e) => match &e.first_commit {
                Some(md) => write!(
                    f,
                    "git repo {}: first seen in commit {} as {}",
                    e.repo_path.display(),
                    md.commit_metadata.commit_id,
                    &md.blob_path,
                ),
                None => write!(f, "git repo {}", e.repo_path.display()),
            },
            Origin::Extended(e) => write!(f, "extended {}", e),
        }
    }
}

/// Origin information for a file on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Hash)]
pub struct FileOrigin {
    /// The file path.
    pub path: Arc<PathBuf>,
}

impl FileOrigin {
    /// Creates a new `FileOrigin` from a path.
    pub fn new<P: Into<PathBuf>>(p: P) -> Self {
        Self { path: Arc::new(p.into()) }
    }
}

/// Origin information for a blob in a git repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Hash)]
pub struct GitRepoOrigin {
    /// Path to the repository on disk.
    pub repo_path: Arc<PathBuf>,
    /// Information about the first commit where this blob was seen.
    pub first_commit: Option<CommitOrigin>,
}

/// Information about where a blob was first seen in git history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Hash)]
pub struct CommitOrigin {
    /// Metadata about the commit.
    pub commit_metadata: Arc<CommitMetadata>,
    /// The path of the blob within the commit.
    pub blob_path: String,
}

/// An extended origin with arbitrary JSON metadata.
///
/// This is used for sources like Jira, Confluence, Slack, etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Hash)]
pub struct ExtendedOrigin(pub serde_json::Value);

impl std::fmt::Display for ExtendedOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl ExtendedOrigin {
    /// Returns the path from the extended origin, if available.
    pub fn path(&self) -> Option<&Path> {
        let p = self.0.get("path")?.as_str()?;
        Some(Path::new(p))
    }
}

/// A non-empty set of [`Origin`] entries.
///
/// This is used when a blob has been seen in multiple locations
/// (e.g., the same content in multiple files or commits).
#[derive(Debug, Clone)]
pub struct OriginSet {
    origin: Origin,
    more_provenance: SmallVec<[Origin; 1]>,
}

impl serde::Serialize for OriginSet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.len()))?;
        for p in self.iter() {
            seq.serialize_element(p)?;
        }
        seq.end()
    }
}

impl JsonSchema for OriginSet {
    fn schema_name() -> Cow<'static, str> {
        "OriginSet".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = <Vec<Origin>>::json_schema(generator);
        schema.insert("minItems".to_owned(), json!(1));
        schema.insert("description".to_owned(), json!("A non-empty set of `Origin` entries"));
        schema
    }
}

impl OriginSet {
    /// Creates a new `OriginSet` with a single origin.
    #[inline]
    pub fn single(origin: Origin) -> Self {
        Self { origin, more_provenance: SmallVec::new() }
    }

    /// Creates a new `OriginSet` from multiple origins.
    ///
    /// Filters out redundant less-specific origins.
    pub fn new(origin: Origin, more_origin: Vec<Origin>) -> Self {
        let mut git_repos_with_detailed: FxHashSet<Arc<PathBuf>> = FxHashSet::default();
        for p in std::iter::once(&origin).chain(&more_origin) {
            if let Origin::GitRepo(e) = p
                && e.first_commit.is_some()
            {
                git_repos_with_detailed.insert(e.repo_path.clone());
            }
        }
        let mut filtered = std::iter::once(origin).chain(more_origin).filter(|p| match p {
            Origin::GitRepo(e) => {
                e.first_commit.is_some() || !git_repos_with_detailed.contains(&e.repo_path)
            }
            Origin::File(_) => true,
            Origin::Extended(_) => true,
        });
        Self { origin: filtered.next().unwrap(), more_provenance: filtered.collect() }
    }

    /// Attempts to create an `OriginSet` from an iterator.
    ///
    /// Returns `None` if the iterator is empty.
    #[inline]
    pub fn try_from_iter<I>(it: I) -> Option<Self>
    where
        I: IntoIterator<Item = Origin>,
    {
        let mut it = it.into_iter();
        let provenance = it.next()?;
        let more_provenance = it.collect();
        Some(Self::new(provenance, more_provenance))
    }

    /// Returns the first origin in the set.
    #[inline]
    pub fn first(&self) -> &Origin {
        &self.origin
    }

    /// Returns the number of origins in the set.
    #[expect(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        1 + self.more_provenance.len()
    }

    /// Returns an iterator over all origins in the set.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Origin> {
        std::iter::once(&self.origin).chain(&self.more_provenance)
    }
}

impl IntoIterator for OriginSet {
    type IntoIter =
        std::iter::Chain<std::iter::Once<Origin>, <Vec<Origin> as IntoIterator>::IntoIter>;
    type Item = Origin;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(self.origin).chain(self.more_provenance.into_vec())
    }
}

impl From<Origin> for OriginSet {
    fn from(p: Origin) -> Self {
        Self::single(p)
    }
}
