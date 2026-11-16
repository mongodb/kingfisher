//! Filesystem enumeration and Git repository opening for application scans.

use std::path::{Path, PathBuf};

pub use crate::git_repo_enumerator::{
    GitBlobSource, GitRepoEnumerator, GitRepoResult, GitRepoWithMetadataEnumerator,
};
use anyhow::{Result, bail};
use crossbeam_channel::Sender;
pub use gix::{self, Repository, ThreadSafeRepository};
use gix::{open::Options, open_opts};
use globset::{Glob, GlobSet, GlobSetBuilder};
pub use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::{DirEntry, WalkBuilder, WalkState};
use tracing::debug;

use crate::{cli, limits};

const DEFAULT_GIX_PACK_CACHE_BYTES: usize = 96 * 1024 * 1024;
const MIN_GIX_PACK_CACHE_BYTES: usize = 16 * 1024 * 1024;
const TOTAL_GIX_PACK_CACHE_BUDGET_BYTES: usize = 256 * 1024 * 1024;

pub(crate) fn gix_pack_cache_bytes_for_threads(num_threads: usize) -> usize {
    (TOTAL_GIX_PACK_CACHE_BUDGET_BYTES / num_threads.max(1))
        .clamp(MIN_GIX_PACK_CACHE_BYTES, DEFAULT_GIX_PACK_CACHE_BYTES)
}

#[derive(Clone)]
pub struct GitDiffConfig {
    pub since_ref: Option<String>,
    pub branch_ref: String,
    pub branch_root: Option<String>,
    pub staged: bool,
}

pub enum FoundInput {
    File(FileResult),
    Directory(DirectoryResult),
    EnumeratorFile(EnumeratorFileResult),
}

pub struct FileResult {
    pub path: PathBuf,
    pub num_bytes: u64,
    pub extract_archives: bool,
    pub extraction_depth: Option<usize>,
    pub resources: limits::ResourceLimits,
}

pub struct EnumeratorFileResult {
    pub path: PathBuf,
}

pub struct DirectoryResult {
    pub path: PathBuf,
}

pub type Output = Sender<FoundInput>;

struct VisitorBuilder<'t> {
    max_file_size: Option<u64>,
    extract_archives: bool,
    extraction_depth: Option<usize>,
    resources: limits::ResourceLimits,
    output: &'t Output,
}

impl<'s, 't> ignore::ParallelVisitorBuilder<'s> for VisitorBuilder<'t>
where
    't: 's,
{
    fn build(&mut self) -> Box<dyn ignore::ParallelVisitor + 's> {
        Box::new(Visitor {
            max_file_size: self.max_file_size,
            extract_archives: self.extract_archives,
            extraction_depth: self.extraction_depth,
            resources: self.resources,
            output: self.output,
        })
    }
}

struct Visitor<'t> {
    max_file_size: Option<u64>,
    extract_archives: bool,
    extraction_depth: Option<usize>,
    resources: limits::ResourceLimits,
    output: &'t Output,
}

impl<'t> Visitor<'t> {
    #[inline]
    fn file_too_big(&self, size: u64) -> bool {
        match self.max_file_size {
            Some(max_size) => size > max_size,
            None => false,
        }
    }

    fn found_file(&self, r: FileResult) {
        let _ = self.output.send(FoundInput::File(r));
    }

    fn found_directory(&self, r: DirectoryResult) {
        let _ = self.output.send(FoundInput::Directory(r));
    }
}

impl<'t> ignore::ParallelVisitor for Visitor<'t> {
    fn visit(&mut self, result: Result<ignore::DirEntry, ignore::Error>) -> ignore::WalkState {
        let entry = match result {
            Ok(e) => e,
            Err(e) => {
                debug!("Skipping entry: {e}");
                return WalkState::Continue;
            }
        };

        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(md) => md,
            Err(e) => {
                debug!("Skipping {}: {e}", path.display());
                return WalkState::Continue;
            }
        };

        if metadata.is_file() {
            let num_bytes = metadata.len();
            if self.file_too_big(num_bytes) {
                debug!("Skipping {}: size {num_bytes} too big", path.display());
            } else {
                self.found_file(FileResult {
                    path: path.to_owned(),
                    num_bytes,
                    extract_archives: self.extract_archives,
                    extraction_depth: self.extraction_depth,
                    resources: self.resources,
                });
            }
        } else if metadata.is_dir() {
            self.found_directory(DirectoryResult { path: path.to_owned() });
        } else if metadata.is_symlink() {
            // Ignored; if follow_symlinks was set, we'd see the pointed-to entry instead.
        } else {
            debug!("Unhandled type for {}", path.display());
        }

        WalkState::Continue
    }
}

pub struct FilesystemEnumerator {
    walk_builder: WalkBuilder,
    gitignore_builder: GitignoreBuilder,
    max_file_size: Option<u64>,
    collect_git_metadata: bool,
    enumerate_git_history: bool,
    extract_archives: bool,
    extraction_depth: Option<usize>,
    resources: limits::ResourceLimits,
    no_dedup: bool,
    exclude_globset: Option<std::sync::Arc<GlobSet>>,
}

impl FilesystemEnumerator {
    pub const DEFAULT_ENUMERATE_GIT_HISTORY: bool = true;
    pub const DEFAULT_FOLLOW_LINKS: bool = false;
    pub const DEFAULT_MAX_FILESIZE: u64 = 100 * 1024 * 1024;

    pub fn new<T: AsRef<Path>>(inputs: &[T], args: &cli::commands::scan::ScanArgs) -> Result<Self> {
        if inputs.is_empty() {
            bail!("No inputs provided");
        }
        let mut builder = WalkBuilder::new(&inputs[0]);
        for input in &inputs[1..] {
            builder.add(input);
        }

        let max_file_size = args.content_filtering_args.max_file_size_bytes();
        builder.follow_links(Self::DEFAULT_FOLLOW_LINKS);
        builder.max_filesize(max_file_size);
        builder.standard_filters(false);

        Ok(Self {
            walk_builder: builder,
            gitignore_builder: GitignoreBuilder::new(""),
            max_file_size,
            collect_git_metadata: args.input_specifier_args.commit_metadata,
            enumerate_git_history: Self::DEFAULT_ENUMERATE_GIT_HISTORY,
            extract_archives: !args.content_filtering_args.no_extract_archives,
            extraction_depth: args.content_filtering_args.archive_depth(),
            resources: args.content_filtering_args.resource_limits(),
            no_dedup: args.no_dedup,
            exclude_globset: None,
        })
    }

    pub fn no_dedup(&mut self, no_dedup: bool) -> &mut Self {
        self.no_dedup = no_dedup;
        self
    }

    pub fn threads(&mut self, threads: usize) -> &mut Self {
        self.walk_builder.threads(threads);
        self
    }

    pub fn add_ignore<T: AsRef<Path>>(&mut self, path: T) -> Result<&mut Self> {
        let path = path.as_ref();
        if let Some(e) = self.gitignore_builder.add(path) {
            Err(e)?;
        }
        if let Some(e) = self.walk_builder.add_ignore(path) {
            Err(e)?;
        }
        Ok(self)
    }

    pub fn follow_links(&mut self, follow_links: bool) -> &mut Self {
        self.walk_builder.follow_links(follow_links);
        self
    }

    pub fn max_filesize(&mut self, max_filesize: Option<u64>) -> &mut Self {
        self.walk_builder.max_filesize(max_filesize);
        self.max_file_size = max_filesize;
        self
    }

    pub fn collect_git_metadata(&mut self, collect: bool) -> &mut Self {
        self.collect_git_metadata = collect;
        self
    }

    pub fn enumerate_git_history(&mut self, enumerate: bool) -> &mut Self {
        self.enumerate_git_history = enumerate;
        self
    }

    pub fn filter_entry<P>(&mut self, filter: P) -> &mut Self
    where
        P: Fn(&DirEntry) -> bool + Send + Sync + 'static,
    {
        self.walk_builder.filter_entry(filter);
        self
    }

    pub fn set_exclude_patterns(&mut self, patterns: &[String]) -> Result<&mut Self> {
        let Some(globset) = build_exclude_globset(patterns)? else {
            return Ok(self);
        };
        self.exclude_globset = Some(globset.clone());
        self.filter_entry(move |entry| {
            let path = entry.path();
            let matches = globset.is_match(path);
            if matches {
                debug!("Skipping {} due to --exclude", path.display());
            }
            !matches
        });
        Ok(self)
    }

    /// Prune repository subtrees from a grouped filesystem root while keeping
    /// the existing `--exclude` predicate active.
    pub fn set_repository_excludes(&mut self, repositories: Vec<PathBuf>) -> &mut Self {
        let exclude_globset = self.exclude_globset.clone();
        self.filter_entry(move |entry| {
            let path = entry.path();
            let excluded = exclude_globset.as_ref().is_some_and(|globset| globset.is_match(path))
                || repositories.iter().any(|repository| path.starts_with(repository));
            if excluded {
                debug!("Skipping {} during grouped filesystem scan", path.display());
            }
            !excluded
        });
        self
    }

    pub fn exclude_globset(&self) -> Option<std::sync::Arc<GlobSet>> {
        self.exclude_globset.clone()
    }

    pub fn gitignore(&self) -> Result<Gitignore> {
        Ok(self.gitignore_builder.build()?)
    }

    pub fn run(&self, output: Output) -> Result<()> {
        let mut visitor_builder = VisitorBuilder {
            max_file_size: self.max_file_size,
            extract_archives: self.extract_archives,
            extraction_depth: self.extraction_depth,
            resources: self.resources,
            output: &output,
        };
        self.walk_builder.build_parallel().visit(&mut visitor_builder);
        Ok(())
    }
}

/// Builds the `--exclude` match set shared by the filesystem walker and any
/// pre-scan traversal, so both skip exactly the same trees.
///
/// Returns `None` when no patterns are configured. Literal patterns (no glob
/// characters) also exclude a directory of that name anywhere in the tree, so
/// `--exclude=.git` skips the entire `.git` directory subtree no matter where
/// it appears.
pub(crate) fn build_exclude_globset(
    patterns: &[String],
) -> Result<Option<std::sync::Arc<globset::GlobSet>>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        builder.add(Glob::new(pat)?);
        if !pat.contains('*') && !pat.contains('?') && !pat.contains('[') {
            let base = pat.trim_end_matches('/');
            builder.add(Glob::new(&format!("**/{}", base))?);
            builder.add(Glob::new(&format!("**/{}/**", base))?);
        }
    }
    Ok(Some(std::sync::Arc::new(builder.build()?)))
}

/// Opens the given Git repository if it exists, returning None if not.
pub fn open_git_repo(path: &Path) -> Result<Option<Repository>> {
    open_git_repo_with_options(path, true)
}

/// Opens the given Git repository with explicit control over the
/// `open_path_as_is` option, returning None if not.
pub fn open_git_repo_with_options(
    path: &Path,
    open_path_as_is: bool,
) -> Result<Option<Repository>> {
    // gix creates one delta-base cache for every thread-local repository handle. Keep the
    // aggregate cache footprint bounded as scan parallelism grows instead of multiplying its
    // 96 MiB default by every Rayon worker.
    let pack_cache_bytes = gix_pack_cache_bytes_for_threads(rayon::current_num_threads());
    let pack_cache_override = format!("gitoxide.core.deltaBaseCacheLimit={pack_cache_bytes}");
    let opts = Options::isolated()
        .config_overrides([pack_cache_override])
        .open_path_as_is(open_path_as_is);
    match open_opts(path, opts) {
        // gix 0.90 wraps discovery failures in an outer NotFound classification.
        // A candidate's unreadable HEAD can carry PermissionDenied underneath;
        // this still means discovery did not identify a repository (as before
        // the upgrade). Do not apply that fallback to configuration/open errors
        // or to explicit corruption, even when they contain a NotFound cause.
        Err(err) if is_non_repository_discovery_error(&err) => Ok(None),
        Err(err) => Err(err.into()),
        Ok(repo) => Ok(Some(repo)),
    }
}

fn is_non_repository_discovery_error(error: &gix::Error) -> bool {
    error.classify().next().is_some_and(|class| class.class() == gix::error::Class::NotFound)
        && matches!(
            error.dominant_class(),
            Some(gix::error::Class::NotFound | gix::error::Class::PermissionDenied)
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn gix_pack_cache_uses_a_bounded_process_budget() {
        assert_eq!(gix_pack_cache_bytes_for_threads(1), DEFAULT_GIX_PACK_CACHE_BYTES);
        assert_eq!(gix_pack_cache_bytes_for_threads(4), 64 * 1024 * 1024);
        assert_eq!(gix_pack_cache_bytes_for_threads(16), MIN_GIX_PACK_CACHE_BYTES);
        assert_eq!(gix_pack_cache_bytes_for_threads(32), MIN_GIX_PACK_CACHE_BYTES);
        assert_eq!(gix_pack_cache_bytes_for_threads(128), MIN_GIX_PACK_CACHE_BYTES);
    }

    #[test]
    fn open_git_repo_returns_none_for_non_repositories() -> Result<()> {
        let temp = tempdir()?;

        assert!(open_git_repo(temp.path())?.is_none());
        assert!(open_git_repo(&temp.path().join("missing"))?.is_none());

        Ok(())
    }

    #[test]
    fn discovery_permission_errors_are_skipped_but_open_errors_are_not() {
        use gix::error::{ErrorExt, message};
        let denied =
            || gix::Error::from_error(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        // Reproduce gix's discovery wrapper without relying on filesystem modes
        // (which are ineffective for root and behave differently on Windows).
        let discovery = denied().and_raise(message("not a repository").not_found());
        assert!(is_non_repository_discovery_error(&discovery));
        assert!(!is_non_repository_discovery_error(&denied()));
        let corruption = gix::Error::from(message("corrupt repository").corrupted())
            .and_raise(message("not a repository").not_found());
        assert!(!is_non_repository_discovery_error(&corruption));
    }

    #[test]
    fn open_git_repo_skips_unreadable_head_candidates() -> Result<()> {
        let temp = tempdir()?;
        // A directory cannot be read as a loose HEAD reference on any platform.
        // Unlike chmod-based fixtures this remains effective when run as root.
        std::fs::create_dir(temp.path().join("HEAD"))?;
        for as_is in [true, false] {
            assert!(open_git_repo_with_options(temp.path(), as_is)?.is_none());
        }
        Ok(())
    }

    #[test]
    fn open_git_repo_preserves_configuration_errors() -> Result<()> {
        let temp = tempdir()?;
        let repo = gix::init(temp.path())?;
        let git_dir = repo.git_dir().to_path_buf();
        drop(repo);
        for config in ["[invalid\n", "[core]\n bare = false\n worktree =\n"] {
            std::fs::write(git_dir.join("config"), config)?;
            assert!(open_git_repo(&git_dir).is_err());
        }

        Ok(())
    }

    #[test]
    fn open_git_repo_accepts_worktree_root() -> Result<()> {
        let temp = tempdir()?;
        let repo_path = temp.path().join("repo");
        gix::init(&repo_path)?;

        assert!(open_git_repo(&repo_path.join(".git"))?.is_some());

        Ok(())
    }
}
