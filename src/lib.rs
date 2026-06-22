// Re-export library crates for easier access
pub use kingfisher_core;
pub use kingfisher_rules;
pub use kingfisher_scanner;

pub mod access_map;
pub mod alerts;
pub mod azure;
pub mod baseline;
pub mod binary;
pub mod bitbucket;
pub mod blob;
pub mod bstring_escape;
pub mod bstring_table;
pub mod cli;
pub mod confluence;
pub mod content_type;
pub mod decompress;
pub mod defaults;
pub mod direct_revoke;
pub mod direct_validate;
pub mod entropy;
pub mod finding_data;
pub mod findings_store;
pub mod gcs;
pub mod git_binary;
pub mod git_commit_metadata;
pub mod git_host;
pub mod git_metadata_graph;
mod git_repo_enumerator;
pub mod git_url;
pub mod gitea;
pub mod github;
pub mod gitlab;
pub mod grpc_validation;
pub mod huggingface;
pub mod inline_ignore;
pub mod jira;
pub mod liquid_filters;
pub mod location;
pub mod matcher;
pub mod origin;
pub mod parser;
pub mod postman;
pub mod provider_endpoints;
pub mod pyc;
pub mod reporter;
pub mod rule_loader;
pub mod rule_profiling;
pub mod rules;
pub mod rules_database;
pub mod s3;
pub mod safe_list;
pub mod scanner;
pub mod scanner_pool;
pub mod slack;
pub mod snippet;
pub mod sqlite;
pub mod teams;
pub(crate) mod template_vars;
pub mod toon;
pub mod update;
pub mod util;
pub mod validation;
pub mod validation_body;
pub mod validation_rate_limit;

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use crossbeam_channel::Sender;
pub use git_repo_enumerator::{
    GitBlobSource, GitRepoEnumerator, GitRepoResult, GitRepoWithMetadataEnumerator,
};
pub use gix::{self, Repository, ThreadSafeRepository};
use gix::{open::Options, open_opts};
use globset::{Glob, GlobSet, GlobSetBuilder};
pub use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::{DirEntry, WalkBuilder, WalkState};
use tokio::time::Duration;
use tracing::debug;

#[derive(Clone)]
pub struct GitDiffConfig {
    pub since_ref: Option<String>,
    pub branch_ref: String,
    pub branch_root: Option<String>,
    pub staged: bool,
}

struct EnumeratorConfig {
    enumerate_git_history: bool,
    collect_git_metadata: bool,
    repo_scan_timeout: Duration,
    exclude_globset: Option<std::sync::Arc<GlobSet>>,
    git_diff: Option<GitDiffConfig>,
    /// Whether archive blobs encountered during git scanning should be
    /// transparently extracted before pattern matching.
    extract_archives: bool,
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
    pub extraction_depth: usize,
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
    extraction_depth: usize,
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
            output: self.output,
        })
    }
}

struct Visitor<'t> {
    max_file_size: Option<u64>,
    extract_archives: bool,
    extraction_depth: usize,
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
    extraction_depth: usize,
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
            extraction_depth: args.content_filtering_args.extraction_depth as usize,
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
        if patterns.is_empty() {
            return Ok(self);
        }
        let mut builder = GlobSetBuilder::new();
        for pat in patterns {
            // Add the pattern itself
            builder.add(Glob::new(pat)?);

            // If the pattern doesn't contain any glob characters, also exclude
            // directories with this name anywhere in the tree. This lets
            // `--exclude=.git` skip the entire `.git` directory subtree no
            // matter where it appears in the path.
            if !pat.contains('*') && !pat.contains('?') && !pat.contains('[') {
                let base = pat.trim_end_matches('/');
                builder.add(Glob::new(&format!("**/{}", base))?);
                builder.add(Glob::new(&format!("**/{}/**", base))?);
            }
        }
        let globset = std::sync::Arc::new(builder.build()?);
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
            output: &output,
        };
        self.walk_builder.build_parallel().visit(&mut visitor_builder);
        Ok(())
    }
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
    let opts = Options::isolated().open_path_as_is(open_path_as_is);
    match open_opts(path, opts) {
        Err(gix::open::Error::NotARepository { .. }) => Ok(None),
        Err(err) => Err(err.into()),
        Ok(repo) => Ok(Some(repo)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Repository as Git2Repository;
    use tempfile::tempdir;

    #[test]
    fn open_git_repo_accepts_worktree_root() -> Result<()> {
        let temp = tempdir()?;
        let repo_path = temp.path().join("repo");
        Git2Repository::init(&repo_path)?;

        // assert!(open_git_repo(&repo_path)?.is_some());
        assert!(open_git_repo(&repo_path.join(".git"))?.is_some());

        Ok(())
    }
}
