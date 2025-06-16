use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, Result};
use bstr::{BString, ByteSlice};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use rustc_hash::FxHashSet;
use schemars::JsonSchema;
use serde::{ser::SerializeSeq, Deserialize, Serialize};
use smallvec::SmallVec;

use crate::{git_commit_metadata::CommitMetadata, serde_utils::BStringLossyUtf8};
static URL_CACHE: Lazy<DashMap<PathBuf, Arc<str>>> = Lazy::new(DashMap::default);

fn compute_url(repo_path: &Path) -> Result<String> {
    let repo = gix::open(repo_path)?;
    let config = repo.config_snapshot();

    let url_bytes =
        config.string("remote.origin.url").ok_or_else(|| anyhow!("No remote URL found"))?;

    if url_bytes.starts_with(b"http://") || url_bytes.starts_with(b"https://") {
        Ok(String::from_utf8_lossy(url_bytes.as_bytes()).into_owned())
    } else if url_bytes.starts_with(b"git@") {
        let url_str = String::from_utf8_lossy(url_bytes.as_bytes());
        if let Some(stripped) = url_str.strip_prefix("git@") {
            if let Some((domain, path)) = stripped.split_once(':') {
                Ok(format!("https://{}/{}", domain, path))
            } else {
                Err(anyhow!("Invalid SSH URL format"))
            }
        } else {
            Err(anyhow!("Invalid SSH URL format"))
        }
    } else {
        Err(anyhow!(
            "Unsupported remote URL format: {}",
            String::from_utf8_lossy(url_bytes.as_bytes())
        ))
    }
}

pub fn get_repo_url(repo_path: &Path) -> Result<Arc<str>> {
    // Fast path: cache hit
    if let Some(u) = URL_CACHE.get(repo_path) {
        return Ok(u.clone());
    }

    // Slow path: compute, intern, cache
    let url_arc: Arc<str> = compute_url(repo_path)?.into();
    URL_CACHE.insert(repo_path.to_path_buf(), url_arc.clone());
    Ok(url_arc)
}

impl FileOrigin {
    pub fn new<P: Into<PathBuf>>(p: P) -> Self {
        Self { path: Arc::new(p.into()) }
    }
}
// -------------------------------------------------------------------------------------------------
// Origin
// -------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[allow(clippy::large_enum_variant)]
pub enum Origin {
    File(FileOrigin),
    GitRepo(GitRepoOrigin),
    Extended(ExtendedOrigin),
}

impl Origin {
    /// Create an `Origin` entry for a plain file.
    pub fn from_file(path: PathBuf) -> Self {
        Origin::File(FileOrigin::new(path))
    }

    /// Create an `Origin` entry for a blob found within a Git repo's history,
    /// without any extra commit origin.
    ///
    /// See also `from_git_repo_with_first_commit`.
    pub fn from_git_repo(repo_path: Arc<PathBuf>) -> Self {
        Origin::GitRepo(GitRepoOrigin { repo_path, first_commit: None })
    }

    /// Create an `Origin` entry for a blob found within a Git repo's history,
    /// with commit origin.
    ///
    /// See also `from_git_repo`.
    pub fn from_git_repo_with_first_commit(
        repo_path: Arc<PathBuf>,
        commit_metadata: Arc<CommitMetadata>,
        blob_path: BString,
    ) -> Self {
        let first_commit = Some(CommitOrigin { commit_metadata, blob_path });
        Origin::GitRepo(GitRepoOrigin { repo_path, first_commit })
    }

    /// Create an `Origin` entry from an arbitrary JSON value.
    pub fn from_extended(value: serde_json::Value) -> Self {
        Origin::Extended(ExtendedOrigin(value))
    }

    /// Get the path for the blob from this `Origin` entry, if one is specified.
    pub fn blob_path(&self) -> Option<&Path> {
        use bstr::ByteSlice;
        match self {
            Self::File(e) => Some(&e.path),
            Self::GitRepo(e) => e.first_commit.as_ref().and_then(|c| c.blob_path.to_path().ok()),
            Self::Extended(e) => e.path(),
        }
    }

    pub fn full_path(&self) -> Option<PathBuf> {
        match self {
            Self::File(e) => Some((*e.path).clone()),
            Self::GitRepo(e) => e
                .first_commit
                .as_ref()
                .and_then(|c| c.blob_path.to_path().ok())
                .map(|p| e.repo_path.join(p)),
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
                    md.blob_path,
                ),
                None => write!(f, "git repo {}", e.repo_path.display()),
            },
            Origin::Extended(e) => write!(f, "extended {}", e),
        }
    }
}
// -------------------------------------------------------------------------------------------------
// FileOrigin
// -------------------------------------------------------------------------------------------------
/// Indicates that a blob was seen at a particular file path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Hash)]
pub struct FileOrigin {
    pub path: Arc<PathBuf>,
}
// -------------------------------------------------------------------------------------------------
// GitRepoOrigin
// -------------------------------------------------------------------------------------------------
/// Indicates that a blob was seen in a Git repo, optionally with particular
/// commit origin info
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Hash)]
pub struct GitRepoOrigin {
    pub repo_path: Arc<PathBuf>,
    pub first_commit: Option<CommitOrigin>,
}
// -------------------------------------------------------------------------------------------------
// CommitOrigin
// -------------------------------------------------------------------------------------------------
/// How was a particular Git commit encountered?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Hash)]
pub struct CommitOrigin {
    pub commit_metadata: Arc<CommitMetadata>,

    #[serde(with = "BStringLossyUtf8")]
    pub blob_path: BString,
}
// -------------------------------------------------------------------------------------------------
// ExtendedOrigin
// -------------------------------------------------------------------------------------------------
/// An extended origin entry.
///
/// This is an arbitrary JSON value.
/// If the value is an object containing certain fields, they will be
/// interpreted specially by Kingfisher:
///
/// - A `path` field containing a string
// - XXX A `url` string field that is a syntactically-valid URL
// - XXX A `time` string field
// - XXX A `display` string field
//
// - XXX A `parent_blob` string field with a hex-encoded blob ID that the associated blob was
//   derived from
// - XXX A `parent_transform` string field identifying the transform method used to derive the
//   associated blob
// - XXX A `parent_start_byte` integer field
// - XXX A `parent_end_byte` integer field
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Hash)]
pub struct ExtendedOrigin(pub serde_json::Value);
impl std::fmt::Display for ExtendedOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl ExtendedOrigin {
    pub fn path(&self) -> Option<&Path> {
        let p = self.0.get("path")?.as_str()?;
        Some(Path::new(p))
    }
}
/// A non-empty set of `Origin` entries.
#[derive(Debug, Clone)]
pub struct OriginSet {
    origin: Origin,
    more_provenance: SmallVec<[Origin; 1]>,
}
/// Serialize `OriginSet` as a flat sequence
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
    fn schema_name() -> String {
        "OriginSet".into()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let s = <Vec<Origin>>::json_schema(gen);
        let mut o = s.into_object();
        o.array().min_items = Some(1);
        let md = o.metadata();
        md.description = Some("A non-empty set of `Origin` entries".into());
        schemars::schema::Schema::Object(o)
    }
}
impl OriginSet {
    /// Create a new `OriginSet` from the given items, filtering out redundant
    /// less-specific `Origin` records.
    #[inline]
    pub fn single(origin: Origin) -> Self {
        Self { origin, more_provenance: SmallVec::new() }
    }

    pub fn new(origin: Origin, more_origin: Vec<Origin>) -> Self {
        let mut git_repos_with_detailed: FxHashSet<Arc<PathBuf>> = FxHashSet::default();
        for p in std::iter::once(&origin).chain(&more_origin) {
            if let Origin::GitRepo(e) = p {
                if e.first_commit.is_some() {
                    git_repos_with_detailed.insert(e.repo_path.clone());
                }
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

    #[inline]
    pub fn first(&self) -> &Origin {
        &self.origin
    }

    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        1 + self.more_provenance.len()
    }

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
        std::iter::once(self.origin)
            // turn the SmallVec into a Vec, then into_iter()
            .chain(self.more_provenance.into_vec().into_iter())
    }
}
impl From<Origin> for OriginSet {
    fn from(p: Origin) -> Self {
        Self::single(p)
    }
}
