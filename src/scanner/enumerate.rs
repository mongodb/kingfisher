use crate::limits::ResourceLimits;
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant as StdInstant, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bstr::{BString, ByteSlice};
use gix::{Repository as GixRepo, diff::tree::recorder::Change, object::tree::EntryKind};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::{
    iter::plumbing::Folder,
    prelude::{ParallelIterator, *},
};
use serde::{Deserialize, Deserializer};
use tracing::{debug, error};

use smallvec::smallvec;

use crate::{
    DirectoryResult, EnumeratorFileResult, FileResult, FilesystemEnumerator, FoundInput,
    GitDiffConfig, GitRepoEnumerator, GitRepoResult, GitRepoWithMetadataEnumerator,
    binary::is_binary,
    blob::{Blob, BlobAppearance, BlobId, BlobIdMap},
    cli::commands::{github::GitHistoryMode, scan},
    decompress::{
        CompressedContent, MAX_INMEM_ZIP_ARCHIVE_BYTES, ZIP_BASED_FORMATS,
        decompress_file_to_temp_with_limits, extract_zip_archive_in_memory_with_limits,
        looks_like_zip,
    },
    findings_store,
    git_commit_metadata::{CommitMetadata, intern_git_identity},
    git_repo_enumerator::{GitBlobMetadata, GitBlobSource, MIN_SCANNABLE_BLOB_SIZE},
    matcher::{Matcher, MatcherStats},
    open_git_repo_with_options,
    origin::{Origin, OriginSet},
    pyc::extract_pyc_strings_with_limits,
    rule_profiling::ConcurrentRuleProfiler,
    rules_database::RulesDatabase,
    scanner::{
        processing::BlobProcessor,
        storage::{create_datastore_channel, spawn_datastore_writer_thread},
        util::{is_compressed_content, is_compressed_file, is_pyc_file, is_sqlite_file},
    },
    scanner_pool::ScannerPool,
    sqlite::extract_sqlite_contents_with_limits,
};

type OwnedBlob = Blob<'static>;
type LoadedGitBlobs<'a> = Box<dyn Iterator<Item = (OriginSet, Blob<'a>)> + Send + 'a>;

struct EnumeratorConfig {
    enumerate_git_history: bool,
    collect_git_metadata: bool,
    repo_scan_timeout: Option<Duration>,
    exclude_globset: Option<Arc<globset::GlobSet>>,
    git_diff: Option<GitDiffConfig>,
    /// Start bounded history walks from all refs when no branch was explicitly selected.
    history_all_refs: bool,
    history_time_range: Option<(i64, i64)>,
    /// Whether archive blobs encountered during git scanning should be
    /// transparently extracted before pattern matching.
    extract_archives: bool,
    /// Maximum number of archive layers to extract while scanning git blobs.
    extraction_depth: Option<usize>,
    resources: ResourceLimits,
}

#[allow(clippy::too_many_arguments)]
pub fn enumerate_filesystem_inputs(
    args: &scan::ScanArgs,
    datastore: Arc<Mutex<findings_store::FindingsStore>>,
    input_roots: &[PathBuf],
    discovered_repos: &[PathBuf],
    progress_enabled: bool,
    rules_db: &RulesDatabase,
    enable_profiling: bool,
    shared_profiler: Arc<ConcurrentRuleProfiler>,
    matcher_stats: &Mutex<MatcherStats>,
) -> Result<bool> {
    let repo_scan_timeout = if args.content_filtering_args.no_limits || args.git_repo_timeout == 0 {
        None
    } else {
        Some(Duration::from_secs(args.git_repo_timeout))
    };

    let branch_root_enabled = args.input_specifier_args.branch_root
        || args.input_specifier_args.branch_root_commit.is_some();

    let wants_git_diff = args.input_specifier_args.staged
        || args.input_specifier_args.since_commit.is_some()
        || args.input_specifier_args.since_hours.is_some()
        || args.input_specifier_args.branch.is_some()
        || branch_root_enabled;

    let diff_config = if wants_git_diff {
        let branch_arg = args.input_specifier_args.branch.clone();
        let branch_root_commit = args.input_specifier_args.branch_root_commit.clone();
        let (branch_ref, branch_root) = if branch_root_enabled {
            if let Some(explicit_root) = branch_root_commit {
                (branch_arg.clone().unwrap_or_else(|| "HEAD".to_string()), Some(explicit_root))
            } else {
                ("HEAD".to_string(), branch_arg.clone())
            }
        } else {
            (branch_arg.clone().unwrap_or_else(|| "HEAD".to_string()), None)
        };

        Some(GitDiffConfig {
            since_ref: args.input_specifier_args.since_commit.clone(),
            branch_ref,
            branch_root,
            staged: args.input_specifier_args.staged,
        })
    } else {
        None
    };

    crate::scan_progress::phase(
        "Scanning files and Git history",
        0,
        crate::scan_progress::PhaseKind::Scan,
    );
    let progress = if progress_enabled {
        let style =
            ProgressStyle::with_template("{spinner} {msg} {total_bytes} [{elapsed_precise}]")
                .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner()
            .with_style(style)
            .with_message("Scanning files and git repository content...");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };
    let _input_enumerator = || -> Result<FilesystemEnumerator> {
        let mut ie = FilesystemEnumerator::new(input_roots, args)?;
        ie.threads(args.num_jobs);
        ie.max_filesize(args.content_filtering_args.max_file_size_bytes());
        if args.input_specifier_args.git_history == GitHistoryMode::None {
            ie.enumerate_git_history(false);
        }

        let collect_git_metadata = true;
        ie.collect_git_metadata(collect_git_metadata);
        Ok(ie)
    }()
    .context("Failed to initialize filesystem enumerator")?;

    let (enum_thread, input_recv, exclude_globset) = {
        let fs_enumerator = make_fs_enumerator(args, input_roots.to_vec(), discovered_repos)
            .context("Failed to initialize filesystem enumerator")?;
        let exclude_globset = fs_enumerator.as_ref().and_then(|ie| ie.exclude_globset());
        let channel_size = std::cmp::max(args.num_jobs * 128, 1024);

        let (input_send, input_recv) = crossbeam_channel::bounded(channel_size);
        let diff_config_for_thread = diff_config.clone();
        let roots_for_thread = input_roots.to_vec();
        let input_enumerator_thread = std::thread::Builder::new()
            .name("input_enumerator".to_string())
            .spawn(move || -> Result<_> {
                if diff_config_for_thread.is_some() {
                    for root in roots_for_thread {
                        input_send
                            .send(FoundInput::Directory(DirectoryResult { path: root }))
                            .context("Failed to queue repository for scanning")?;
                    }
                } else if let Some(fs_enumerator) = fs_enumerator {
                    fs_enumerator.run(input_send.clone())?;
                }
                Ok(())
            })
            .context("Failed to enumerate filesystem inputs")?;
        (input_enumerator_thread, input_recv, exclude_globset)
    };

    let enum_cfg = EnumeratorConfig {
        enumerate_git_history: match args.input_specifier_args.git_history {
            GitHistoryMode::Full => true,
            GitHistoryMode::None => false,
        },
        collect_git_metadata: args.input_specifier_args.commit_metadata,
        repo_scan_timeout,
        exclude_globset: exclude_globset.clone(),
        git_diff: diff_config.clone(),
        history_all_refs: (args.input_specifier_args.since_commit.is_some()
            || args.input_specifier_args.since_hours.is_some())
            && args.input_specifier_args.branch.is_none(),
        history_time_range: args.input_specifier_args.resolved_history_time_range(),
        extract_archives: !args.content_filtering_args.no_extract_archives,
        extraction_depth: args.content_filtering_args.archive_depth(),
        resources: args.content_filtering_args.resource_limits(),
    };
    let (send_ds, recv_ds) = create_datastore_channel(args.num_jobs);
    let datastore_writer_thread =
        spawn_datastore_writer_thread(datastore, recv_ds, !args.no_dedup)?;

    let t1 = Instant::now();
    let had_errors = Arc::new(AtomicBool::new(false));
    let num_blob_processors = Mutex::new(0u64);
    let seen_blobs = BlobIdMap::new();
    let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));

    let matcher = Matcher::new(
        rules_db,
        scanner_pool.clone(),
        &seen_blobs,
        Some(matcher_stats),
        enable_profiling,
        if enable_profiling { Some(shared_profiler) } else { None },
        &args.extra_ignore_comments,
        args.no_inline_ignore,
        !args.no_ignore_if_contains,
    )?
    .with_resource_limits(args.content_filtering_args.resource_limits());
    let blob_processor_init_time = Mutex::new(t1.elapsed());
    let make_blob_processor = || -> BlobProcessor {
        let t1 = Instant::now();
        *num_blob_processors.lock().unwrap() += 1;
        {
            let mut init_time = blob_processor_init_time.lock().unwrap();
            *init_time += t1.elapsed();
        }
        BlobProcessor { matcher }
    };
    let had_errors_for_enumeration = Arc::clone(&had_errors);
    let had_errors_for_processing = Arc::clone(&had_errors);
    let scan_res: Result<()> = input_recv
        .into_iter()
        .par_bridge()
        .filter_map(|input| match (&enum_cfg, input).into_blob_iter() {
            Err(e) => {
                had_errors_for_enumeration.store(true, Ordering::Relaxed);
                error!("Error enumerating input: {e:#}");
                None
            }
            Ok(blob_iter) => blob_iter,
        })
        .flatten()
        .try_for_each_init(
            || (make_blob_processor.clone()(), progress.clone()),
            move |(processor, progress), entry| {
                let (origin, blob) = match entry {
                    Err(e) => {
                        had_errors_for_processing.store(true, Ordering::Relaxed);
                        error!("Error loading input: {e:#}");
                        return Ok(());
                    }
                    Ok(entry) => entry,
                };
                // Check if this is an archive file. `blob_path()` covers both filesystem and git
                // origins, so archive/binary filtering stays consistent across input modes.
                // Byte sniffing also catches ZIP containers with no archive extension (e.g. a
                // Terraform `tf.plan`).
                let is_archive = origin
                    .first()
                    .blob_path()
                    .map(|path| is_compressed_content(path, blob.bytes()))
                    .unwrap_or(false);
                let is_binary = is_binary(blob.bytes());
                let should_skip = if is_archive {
                    // --no-extract-archives also suppresses raw containers at this stage.
                    args.content_filtering_args.no_extract_archives
                } else {
                    // Apply --no-binary to non-archive inputs.
                    is_binary && args.content_filtering_args.no_binary
                };
                if should_skip {
                    progress.suspend(|| {
                        let path = origin
                            .first()
                            .blob_path()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| blob.temp_id().to_string());
                        if is_archive {
                            debug!("Skipping archive: {path}");
                        } else {
                            debug!("Skipping binary blob: {path}");
                        }
                    });
                    return Ok(());
                }
                progress.inc(blob.len().try_into().unwrap());
                match processor.run(
                    origin,
                    blob,
                    args.no_dedup,
                    args.redact,
                    args.no_base64,
                    args.turbo,
                ) {
                    Ok(None) => {
                        // nothing to record
                    }
                    Ok(Some((origin_set, blob_metadata, vec_of_matches))) => {
                        let origin_set = Arc::new(origin_set);
                        let blob_metadata = Arc::new(blob_metadata);

                        for (_, single_match) in vec_of_matches {
                            // Send each match
                            send_ds.send((
                                origin_set.clone(),
                                blob_metadata.clone(),
                                single_match,
                            ))?;
                        }
                    }
                    Err(e) => {
                        had_errors_for_processing.store(true, Ordering::Relaxed);
                        debug!("Error scanning input: {e:#}");
                    }
                }
                Ok(())
            },
        );

    enum_thread.join().unwrap().context("Failed to enumerate inputs")?;
    let (..) = datastore_writer_thread
        .join()
        .unwrap()
        .context("Failed to save results to the datastore")?;
    scan_res.context("Failed to scan inputs")?;
    progress.finish();
    Ok(had_errors.load(Ordering::Relaxed))
}

/// Initialize a `FilesystemEnumerator` based on the command-line arguments and
/// datastore. Also initialize a `Gitignore` that is the same as that used by
/// the filesystem enumerator.
fn make_fs_enumerator(
    args: &scan::ScanArgs,
    input_roots: Vec<PathBuf>,
    discovered_repos: &[PathBuf],
) -> Result<Option<FilesystemEnumerator>> {
    if input_roots.is_empty() {
        Ok(None)
    } else {
        let mut ie = FilesystemEnumerator::new(&input_roots, args)?;
        ie.threads(args.num_jobs);
        ie.max_filesize(args.content_filtering_args.max_file_size_bytes());
        if args.input_specifier_args.git_history == GitHistoryMode::None {
            ie.enumerate_git_history(false);
        }

        // Pass no_dedup when enumerating git history
        ie.no_dedup(args.no_dedup);

        ie.set_exclude_patterns(&args.content_filtering_args.exclude)?;
        // Determine whether to collect git metadata or not
        let collect_git_metadata = false;
        ie.collect_git_metadata(collect_git_metadata);

        // A grouped directory root covers its subtree's non-repository
        // content; prune the repository subtrees discovered beneath it, which
        // are scanned through their own roots. Without this the grouped walk
        // would scan those repositories a second time.
        let grouped_root_excludes: Vec<PathBuf> = if args.input_specifier_args.scan_nested_repos {
            discovered_repos
                .iter()
                .filter(|repo| {
                    input_roots.iter().any(|root| repo.starts_with(root))
                        && !input_roots.contains(repo)
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        if !grouped_root_excludes.is_empty() {
            ie.set_repository_excludes(grouped_root_excludes);
        }

        Ok(Some(ie))
    }
}

/// Implements parallel iteration for either a single blob or a list of blobs.
struct FileResultIter<'a> {
    iter_kind: FileResultIterKind,
    _marker: PhantomData<&'a ()>,
}

impl<'a> ParallelIterator for FileResultIter<'a> {
    type Item = Result<(OriginSet, Blob<'a>)>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        match self.iter_kind {
            FileResultIterKind::Single(maybe_one) => {
                let mut folder = consumer.into_folder();
                if let Some(one) = maybe_one {
                    folder = folder.consume(Ok(one));
                }
                folder.complete()
            }
            FileResultIterKind::Archive(items) => {
                items.into_par_iter().map(Ok).drive_unindexed(consumer)
            }
        }
    }
}

/// Peek a file's leading bytes to detect a ZIP container whose name carries no
/// recognized archive extension (e.g. a Terraform `tf.plan`). Callers check the
/// cheap [`is_compressed_file`] extension test first; this reads at most four
/// bytes. A short read or I/O error is treated as "not an archive" so the
/// caller falls back to its normal read path.
fn file_header_looks_like_zip(path: &Path) -> bool {
    use std::io::Read;

    let mut header = [0u8; 4];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    // A file shorter than the signature cannot be a ZIP, so a partial read is
    // simply "not an archive".
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    looks_like_zip(&header)
}

impl ParallelBlobIterator for FileResult {
    type Iter<'a> = FileResultIter<'a>;

    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>> {
        let extraction_enabled = self.extract_archives;
        let max_extraction_depth = self.extraction_depth;
        let resources = self.resources;

        if extraction_enabled && is_sqlite_file(&self.path) {
            match extract_sqlite_contents_with_limits(&self.path, resources) {
                Ok(tables) if tables.is_empty() => {
                    debug!("No tables found in SQLite database: {}", self.path.display());
                    self.raw_blob_iter().map(Some)
                }
                Ok(tables) => {
                    let items = tables
                        .into_iter()
                        .map(|(logical_name, data)| {
                            let full_path = self.path.join(logical_name);
                            let origin = OriginSet::new(Origin::from_file(full_path), vec![]);
                            (origin, Blob::from_bytes(data))
                        })
                        .collect();
                    Ok(Some(FileResultIter {
                        iter_kind: FileResultIterKind::Archive(items),
                        _marker: PhantomData,
                    }))
                }
                Err(e) => {
                    debug!("Failed to extract SQLite database {}: {e:#}", self.path.display());
                    self.raw_blob_iter().map(Some)
                }
            }
        } else if extraction_enabled && is_pyc_file(&self.path) {
            match extract_pyc_strings_with_limits(&self.path, resources) {
                Ok(strings) if strings.is_empty() => {
                    debug!("No strings found in .pyc file: {}", self.path.display());
                    self.raw_blob_iter().map(Some)
                }
                Ok(strings) => {
                    let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
                    let blob = Blob::from_bytes(strings);
                    Ok(Some(FileResultIter {
                        iter_kind: FileResultIterKind::Single(Some((origin, blob))),
                        _marker: PhantomData,
                    }))
                }
                Err(e) => {
                    debug!("Failed to extract .pyc file {}: {e:#}", self.path.display());
                    self.raw_blob_iter().map(Some)
                }
            }
        } else if extraction_enabled
            && (is_compressed_file(&self.path) || file_header_looks_like_zip(&self.path))
        {
            match decompress_file_to_temp_with_limits(&self.path, resources) {
                Ok((content, _temp_dir)) => match content {
                    // Single-file decompression fully in memory.
                    CompressedContent::Raw(ref data) => {
                        let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
                        let blob = Blob::from_bytes(data.to_vec());
                        Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Single(Some((origin, blob))),
                            _marker: PhantomData,
                        }))
                    }

                    // Single-file decompression streamed to a file. We read it back into memory
                    // here.
                    CompressedContent::RawFile(path) => {
                        let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
                        let blob = Blob::from_file(&path)?;
                        Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Single(Some((origin, blob))),
                            _marker: PhantomData,
                        }))
                    }

                    // Multi‑file archive (in‑memory).
                    CompressedContent::Archive(files) => {
                        if max_extraction_depth == Some(0) {
                            debug!(
                                "Skipping nested archive (max depth reached): {}",
                                self.path.display()
                            );
                            return Ok(None);
                        }
                        let items = recursively_expand_archive_entries(
                            files,
                            max_extraction_depth.map(|depth| depth.saturating_sub(1)),
                            resources,
                        )?
                        .into_iter()
                        .map(|(filename, data)| {
                            let origin =
                                OriginSet::new(Origin::from_file(PathBuf::from(filename)), vec![]);
                            (origin, Blob::from_bytes(data))
                        })
                        .collect();
                        Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Archive(items),
                            _marker: PhantomData,
                        }))
                    }

                    // Multi‑file archive (files on disk).
                    CompressedContent::ArchiveFiles(entries) => {
                        if max_extraction_depth == Some(0) {
                            debug!(
                                "Skipping nested archive (max depth reached): {}",
                                self.path.display()
                            );
                            return Ok(None);
                        }
                        // Read each extracted file from disk and create a Blob. Archive entries
                        // that contain another archive are flattened before they reach the
                        // matcher; ordinary entries stay file-backed to avoid an extra copy.
                        let mut items = Vec::new();
                        for (filename, disk_path) in entries {
                            if max_extraction_depth.is_none_or(|depth| depth > 1)
                                && (is_compressed_file(Path::new(&filename))
                                    || file_header_looks_like_zip(&disk_path))
                                && let Ok(data) = std::fs::read(&disk_path)
                            {
                                let nested = recursively_expand_archive_entries(
                                    vec![(filename.clone(), data)],
                                    max_extraction_depth.map(|depth| depth - 1),
                                    resources,
                                )?;
                                // A successful nested extraction replaces the archive entry
                                // with its contents. Invalid or empty archives are returned as
                                // the original entry by the helper and remain scanable below.
                                if nested.len() != 1 || nested[0].0 != filename {
                                    for (logical, data) in nested {
                                        let origin = OriginSet::new(
                                            Origin::from_file(PathBuf::from(logical)),
                                            vec![],
                                        );
                                        items.push((origin, Blob::from_bytes(data)));
                                    }
                                    continue;
                                }
                            }
                            let blob = match Blob::from_file(&disk_path) {
                                Ok(b) => b,
                                Err(e) => {
                                    debug!(
                                        "Failed to mmap extracted file {}: {}",
                                        disk_path.display(),
                                        e
                                    );
                                    continue; // skip unreadable / unmappable file
                                }
                            };
                            let full_path = PathBuf::from(filename);
                            let nested_origin =
                                OriginSet::new(Origin::from_file(full_path), vec![]);

                            items.push((nested_origin, blob));
                        }
                        Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Archive(items),
                            _marker: PhantomData,
                        }))
                    }
                },
                Err(e) => {
                    debug!("Failed to decompress {}: {}", self.path.display(), e);
                    self.raw_blob_iter().map(Some)
                }
            }
        } else {
            // Not compressed or extraction disabled: read file as a single blob.
            let blob = Blob::from_file(&self.path)
                .with_context(|| format!("Failed to load blob from {}", self.path.display()))?;
            let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
            Ok(Some(FileResultIter {
                iter_kind: FileResultIterKind::Single(Some((origin, blob))),
                _marker: PhantomData,
            }))
        }
    }
}

impl FileResult {
    fn raw_blob_iter(&self) -> Result<FileResultIter<'static>> {
        let blob = Blob::from_file(&self.path)
            .with_context(|| format!("Failed to load blob from {}", self.path.display()))?;
        let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
        Ok(FileResultIter {
            iter_kind: FileResultIterKind::Single(Some((origin, blob))),
            _marker: PhantomData,
        })
    }
}

type OwnedArchiveEntry = (String, Vec<u8>);

// Bound the bytes retained while expanding one archive tree. The individual extractors enforce
// their own per-entry limits; this cap also covers the final fan-out from each archive layer.
const MAX_RECURSIVE_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

struct SharedArchive(Arc<Vec<u8>>);
impl AsRef<[u8]> for SharedArchive {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

type ArchiveEntries = Box<dyn Iterator<Item = OwnedArchiveEntry> + Send>;

fn lazy_expand_entries(
    entries: ArchiveEntries,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
) -> ArchiveEntries {
    expand_entries(entries, remaining_depth, resources, true)
}

fn expand_entries(
    entries: ArchiveEntries,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
    apply_budget: bool,
) -> ArchiveEntries {
    expand_entries_with(
        entries,
        remaining_depth,
        resources,
        apply_budget,
        move |logical, shared| {
            if looks_like_zip(&shared) && shared.len() <= MAX_INMEM_ZIP_ARCHIVE_BYTES {
                crate::decompress::zip_entries(
                    std::io::Cursor::new(SharedArchive(shared)),
                    logical.to_string(),
                    resources,
                )
                .map(|entries| Box::new(entries) as ArchiveEntries)
            } else {
                extract_archive_bytes(logical, &shared, resources).map(|entries| {
                    Box::new(entries.unwrap_or_default().into_iter()) as ArchiveEntries
                })
            }
        },
    )
}

fn expand_entries_with(
    entries: ArchiveEntries,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
    mut apply_budget: bool,
    mut extract: impl FnMut(&str, Arc<Vec<u8>>) -> Result<ArchiveEntries> + Send + 'static,
) -> ArchiveEntries {
    // Track only active ancestors: identical sibling archives must still be
    // scanned at each logical path. Cycles are not additional nesting depth.
    let mut ancestors = std::collections::HashSet::new();
    let mut stack = vec![(entries, remaining_depth, None)];
    let mut total = 0u64;
    Box::new(std::iter::from_fn(move || {
        while !apply_budget || !resources.reached(total, MAX_RECURSIVE_ARCHIVE_BYTES) {
            let (entries, depth, _) = stack.last_mut()?;
            let Some((logical, mut data)) = entries.next() else {
                if let Some((_, _, Some(hash))) = stack.pop() {
                    ancestors.remove(&hash);
                }
                continue;
            };
            let depth = *depth;
            if depth != Some(0) {
                let hash = blake3::hash(&data);
                if !ancestors.contains(&hash) {
                    let shared = Arc::new(data);
                    match extract(&logical, Arc::clone(&shared)) {
                        Ok(mut nested) => {
                            if let Some(first) = nested.next() {
                                apply_budget = true;
                                ancestors.insert(hash);
                                stack.push((
                                    Box::new(std::iter::once(first).chain(nested)),
                                    depth.map(|d| d - 1),
                                    Some(hash),
                                ));
                                continue;
                            }
                        }
                        Err(error) => debug!("Failed to expand archive {logical}: {error:#}"),
                    }
                    data = Arc::unwrap_or_clone(shared);
                } else {
                    debug!("Archive cycle at {logical}; scanning raw content without expanding");
                }
            }
            let remaining = MAX_RECURSIVE_ARCHIVE_BYTES.saturating_sub(total);
            if apply_budget {
                data.truncate(resources.cap(data.len() as u64, remaining) as usize);
            }
            total = total.saturating_add(data.len() as u64);
            return Some((logical, data));
        }
        None
    }))
}

fn lazy_expand_entry(
    logical: String,
    data: Vec<u8>,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
) -> ArchiveEntries {
    // Failed extraction preserves the entire raw input, as in bounded mode.
    expand_entries(Box::new(std::iter::once((logical, data))), remaining_depth, resources, false)
}

fn archive_staged_name(logical: &str) -> String {
    let entry = logical.rsplit_once('!').map_or(logical, |(_, entry)| entry);
    Path::new(entry)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .unwrap_or("archive")
        .to_string()
}

fn archive_staging_tempdir() -> std::io::Result<tempfile::TempDir> {
    let builder = tempfile::Builder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::PermissionsExt;
        let mut builder = builder;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
        builder
    };
    builder.tempdir()
}

/// Extract one archive layer from bytes, returning paths rooted at `logical`.
/// Decompression failures deliberately return `None` so callers can still scan the original entry
/// as raw content.
fn extract_archive_bytes(
    logical: &str,
    data: &[u8],
    resources: ResourceLimits,
) -> Result<Option<Vec<OwnedArchiveEntry>>> {
    let path = Path::new(logical);
    let is_zip_body = looks_like_zip(data);
    if !is_compressed_file(path) && !is_zip_body {
        return Ok(None);
    }

    let zip_based_ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .filter(|ext| ZIP_BASED_FORMATS.iter().any(|z| z == ext));

    // ZIP blobs are common in git repositories and are already resident in memory. Avoid a
    // staging round-trip unless the archive is too large for the bounded in-memory extractor.
    if zip_based_ext.is_some() || is_zip_body {
        if !is_zip_body {
            return Ok(None);
        }
        if data.len() <= MAX_INMEM_ZIP_ARCHIVE_BYTES {
            return match extract_zip_archive_in_memory_with_limits(data, logical, resources) {
                Ok(entries) if !entries.is_empty() => Ok(Some(entries)),
                Ok(_) => Ok(None),
                Err(e) => {
                    debug!(
                        "in-memory zip extract failed for {logical}: {e:#}; falling back to raw scan"
                    );
                    Ok(None)
                }
            };
        }
        debug!(
            "{logical} is {} bytes (> {} MB cap); falling back to disk streaming extractor",
            data.len(),
            MAX_INMEM_ZIP_ARCHIVE_BYTES / (1024 * 1024)
        );
    }

    let staging =
        archive_staging_tempdir().context("Failed to create staging tempdir for archive")?;
    let staged_path = staging.path().join(archive_staged_name(logical));
    std::fs::write(&staged_path, data)
        .with_context(|| format!("Failed to stage archive to {}", staged_path.display()))?;

    let (content, _temp_dir) = match decompress_file_to_temp_with_limits(&staged_path, resources) {
        Ok(content) => content,
        Err(e) => {
            debug!(
                "decompress_file_to_temp_with_limits({}, resources) failed: {e:#}",
                staged_path.display()
            );
            return Ok(None);
        }
    };

    let remap_logical = |extracted: String| match extracted.split_once('!') {
        Some((_, entry)) => format!("{logical}!{entry}"),
        None => format!("{logical}!{extracted}"),
    };

    let mut total = 0u64;
    let mut entries = Vec::new();

    match content {
        CompressedContent::Archive(files) => {
            for (entry_logical, bytes) in files {
                push_archive_bytes(
                    &mut entries,
                    &mut total,
                    remap_logical(entry_logical),
                    bytes,
                    resources,
                );
                if resources.reached(total, MAX_RECURSIVE_ARCHIVE_BYTES) {
                    break;
                }
            }
        }
        CompressedContent::ArchiveFiles(files) => {
            for (entry_logical, disk_path) in files {
                if resources.reached(total, MAX_RECURSIVE_ARCHIVE_BYTES) {
                    break;
                }
                let remaining = MAX_RECURSIVE_ARCHIVE_BYTES.saturating_sub(total);
                let entry_len = match std::fs::metadata(&disk_path) {
                    Ok(metadata) => metadata.len(),
                    Err(e) => {
                        debug!("Failed to stat extracted entry {}: {e}", disk_path.display());
                        continue;
                    }
                };
                let file = match std::fs::File::open(&disk_path) {
                    Ok(file) => file,
                    Err(e) => {
                        debug!("Failed to open extracted entry {}: {e}", disk_path.display());
                        continue;
                    }
                };
                let mut bytes = Vec::new();
                if let Err(e) =
                    resources.reader(file, entry_len.min(remaining)).read_to_end(&mut bytes)
                {
                    debug!("Failed to read extracted entry {}: {e}", disk_path.display());
                    continue;
                }
                push_archive_bytes(
                    &mut entries,
                    &mut total,
                    remap_logical(entry_logical),
                    bytes,
                    resources,
                );
            }
        }
        CompressedContent::Raw(mut bytes) => {
            if resources.exceeds(bytes.len() as u64, MAX_RECURSIVE_ARCHIVE_BYTES) {
                bytes.truncate(MAX_RECURSIVE_ARCHIVE_BYTES as usize);
            }
            push_archive_bytes(
                &mut entries,
                &mut total,
                format!("{logical}!content"),
                bytes,
                resources,
            );
        }
        CompressedContent::RawFile(path) => {
            let payload_len = match std::fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(e) => {
                    debug!("Failed to stat decompressed payload {}: {e}", path.display());
                    return Ok(None);
                }
            };
            let file = match std::fs::File::open(&path) {
                Ok(file) => file,
                Err(e) => {
                    debug!("Failed to open decompressed payload {}: {e}", path.display());
                    return Ok(None);
                }
            };
            let mut bytes = Vec::new();
            if let Err(e) = resources
                .reader(file, payload_len.min(MAX_RECURSIVE_ARCHIVE_BYTES))
                .read_to_end(&mut bytes)
            {
                debug!("Failed to read decompressed payload {}: {e}", path.display());
                return Ok(None);
            }
            push_archive_bytes(
                &mut entries,
                &mut total,
                format!("{logical}!content"),
                bytes,
                resources,
            );
        }
    }

    if entries.is_empty() { Ok(None) } else { Ok(Some(entries)) }
}

fn push_archive_bytes(
    entries: &mut Vec<OwnedArchiveEntry>,
    total: &mut u64,
    logical: String,
    mut bytes: Vec<u8>,
    resources: ResourceLimits,
) -> bool {
    let remaining = MAX_RECURSIVE_ARCHIVE_BYTES.saturating_sub(*total);
    if resources.reached(*total, MAX_RECURSIVE_ARCHIVE_BYTES) {
        return false;
    }
    if resources.exceeds(bytes.len() as u64, remaining) {
        bytes.truncate(remaining as usize);
    }
    *total += bytes.len() as u64;
    entries.push((logical, bytes));
    true
}

fn recursively_expand_archive_entries(
    entries: impl IntoIterator<Item = OwnedArchiveEntry>,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
) -> Result<Vec<OwnedArchiveEntry>> {
    let entries: Vec<_> = entries.into_iter().collect();
    Ok(lazy_expand_entries(Box::new(entries.into_iter()), remaining_depth, resources).collect())
}

fn archive_entry_suffix<'a>(entry_logical: &'a str, archive_path: &str) -> Option<&'a str> {
    entry_logical.strip_prefix(archive_path).filter(|suffix| suffix.starts_with('!')).or_else(
        || entry_logical.split_once('!').map(|(archive, _)| &entry_logical[archive.len()..]),
    )
}

struct GitRepoResultIter<'a> {
    inner: GitRepoResult,
    deadline: Option<std::time::Instant>,
    /// Extract recognized archive paths and content-sniffed ZIPs before scanning,
    /// subject to depth/resource limits. When false, scan the raw container bytes.
    extract_archives: bool,
    /// Maximum number of archive layers to extract from each git blob.
    extraction_depth: Option<usize>,
    resources: ResourceLimits,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl ParallelBlobIterator for GitRepoResult {
    type Iter<'a> = GitRepoResultIter<'a>;

    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>> {
        Ok(Some(GitRepoResultIter {
            inner: self,
            deadline: None,
            // Default to enabled; the dispatch site overrides from CLI args.
            extract_archives: true,
            extraction_depth: Some(1),
            resources: ResourceLimits::default(),
            _marker: std::marker::PhantomData,
        }))
    }
}

impl<'a> rayon::iter::ParallelIterator for GitRepoResultIter<'a> {
    type Item = Result<(OriginSet, Blob<'a>)>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        // ── shared state ──────────────────────────────────────────────
        let repo_sync = Arc::new(self.inner.repository.into_sync());
        let repo_path = Arc::new(self.inner.path.clone());
        let deadline = self.deadline;
        let flag = Arc::new(AtomicBool::new(false)); // first-timeout gate
        let extract_archives = self.extract_archives;
        let extraction_depth = self.extraction_depth;
        let resources = self.resources;
        // Loads one git blob and returns one *or more* `(OriginSet, Blob)`
        // tuples: a single tuple for normal blobs, multiple tuples for
        // archive blobs (zip/jar/apk/...) whose entries get unpacked into
        // synthetic per-entry blobs so pattern matchers can see the
        // contents. Entries are expanded lazily as the matcher consumes them.
        let load_blob = {
            let repo_path = Arc::clone(&repo_path);
            let flag = Arc::clone(&flag);

            move |repo: &mut GixRepo, md: GitBlobMetadata| -> Result<LoadedGitBlobs<'a>> {
                if deadline.is_some_and(|deadline| StdInstant::now() > deadline) {
                    if flag.swap(true, Ordering::Relaxed) {
                        bail!("__timeout_silenced__");
                    }
                    bail!("blob-read timeout (repo: {})", repo_path.display());
                }

                let blob_id = md.blob_oid;
                let mut raw = repo.find_object(blob_id)?.try_into_blob()?;
                let data = std::mem::take(&mut raw.data);

                // Try archive extraction if any first-seen path looks like
                // a known archive format, or the blob bytes are a ZIP under a
                // name with no archive extension (e.g. a committed `tfplan`).
                // Successful extraction replaces the raw container; invalid or empty
                // archives remain available for scanning as raw bytes.
                if extract_archives && extraction_depth != Some(0) {
                    // Prefer an appearance whose name is a recognized archive so
                    // report paths stay stable; fall back to the first appearance
                    // only when the bytes are a ZIP with no archive extension.
                    let archive_path: Option<String> = md
                        .first_seen
                        .iter()
                        .map(|e| String::from_utf8_lossy(&e.path).to_string())
                        .find(|p| is_compressed_file(Path::new(p)))
                        .or_else(|| {
                            if looks_like_zip(&data) {
                                md.first_seen
                                    .first()
                                    .map(|e| String::from_utf8_lossy(&e.path).to_string())
                            } else {
                                None
                            }
                        });

                    if let Some(archive_path) = archive_path {
                        let entries = lazy_expand_entry(
                            archive_path.clone(),
                            data,
                            extraction_depth,
                            resources,
                        );
                        let repo_path = Arc::clone(&repo_path);
                        return Ok(Box::new(entries.map(move |(entry_logical, entry_bytes)| {
                            // Invalid/empty archives keep the original blob identity and origins.
                            if entry_logical == archive_path {
                                let origin =
                                    OriginSet::try_from_iter(md.first_seen.iter().map(|e| {
                                        Origin::from_git_repo_with_first_commit(
                                            Arc::clone(&repo_path),
                                            Arc::clone(&e.commit_metadata),
                                            String::from_utf8_lossy(&e.path).to_string(),
                                        )
                                    }))
                                    .unwrap_or_else(|| {
                                        Origin::from_git_repo(Arc::clone(&repo_path)).into()
                                    });
                                return (origin, Blob::new(BlobId::from(&blob_id), entry_bytes));
                            }
                            let entry_suffix = archive_entry_suffix(&entry_logical, &archive_path);
                            let origin = OriginSet::try_from_iter(md.first_seen.iter().map(|e| {
                                let path = String::from_utf8_lossy(&e.path);
                                let logical = entry_suffix
                                    .map(|suffix| format!("{path}{suffix}"))
                                    .unwrap_or_else(|| entry_logical.clone());
                                Origin::from_git_repo_with_first_commit(
                                    Arc::clone(&repo_path),
                                    Arc::clone(&e.commit_metadata),
                                    logical,
                                )
                            }))
                            .unwrap_or_else(|| {
                                Origin::from_git_repo(Arc::clone(&repo_path)).into()
                            });
                            (origin, Blob::from_bytes(entry_bytes))
                        })));
                    }
                }

                let blob = Blob::new(BlobId::from(&blob_id), data);

                let origin = OriginSet::try_from_iter(md.first_seen.iter().map(|e| {
                    Origin::from_git_repo_with_first_commit(
                        Arc::clone(&repo_path),
                        Arc::clone(&e.commit_metadata),
                        String::from_utf8_lossy(&e.path).to_string(),
                    )
                }))
                .unwrap_or_else(|| Origin::from_git_repo(Arc::clone(&repo_path)).into());

                Ok(Box::new(std::iter::once((origin, blob))))
            }
        };

        // After flat-mapping, errors and successes both flow as
        // `Result<(OriginSet, Blob<'a>)>`. Filter out the silenced timeout
        // marker before handing items to the scan consumer.
        let timeout_filter = |res: &Result<(OriginSet, Blob<'a>)>| -> bool {
            !matches!(res, Err(e) if e.to_string() == "__timeout_silenced__")
        };

        // Convert a lazy blob iterator into a sequential iterator of `Result<T>`,
        // suitable for rayon's `flat_map_iter`. A failed load yields a single
        // `Err`; a successful load fans out into one item per extracted blob.
        // A closure is used (rather than a free function) so the produced
        // `Blob<'static>` items can coerce into the iterator's
        // `Blob<'a>` Item type — Blob is covariant in its lifetime, but a
        // free fn would lose that link.
        let fan_out = |res: Result<LoadedGitBlobs<'a>>|
         -> Box<dyn Iterator<Item = Result<(OriginSet, Blob<'a>)>> + Send + 'a> {
            match res {
                Ok(v) => Box::new(v.map(Ok)),
                Err(e) => Box::new(std::iter::once(Err(e))),
            }
        };

        match self.inner.blobs {
            GitBlobSource::Precomputed(blobs) => {
                let rs = Arc::clone(&repo_sync);
                blobs
                    .into_par_iter()
                    .with_min_len(1024)
                    .map_init(move || rs.to_thread_local(), load_blob)
                    .flat_map_iter(fan_out)
                    .filter(timeout_filter)
                    .drive_unindexed(consumer)
            }
            GitBlobSource::StreamFromOdb => {
                let (blob_tx, blob_rx) = crossbeam_channel::bounded(8192);
                let enum_repo_sync = Arc::clone(&repo_sync);
                let enum_repo_path = Arc::clone(&repo_path);
                let enum_flag = Arc::clone(&flag);

                std::thread::Builder::new()
                    .name("odb_enumerator".to_string())
                    .spawn(move || {
                        use gix::{
                            object::Kind, odb::store::iter::Ordering as OdbOrdering, prelude::*,
                        };
                        let repo = enum_repo_sync.to_thread_local();
                        let odb = &repo.objects;
                        let iter = match odb.iter() {
                            Ok(i) => i,
                            Err(_) => return,
                        };
                        for oid_result in iter
                            .with_ordering(OdbOrdering::PackAscendingOffsetThenLooseLexicographical)
                        {
                            if deadline.is_some_and(|deadline| StdInstant::now() > deadline) {
                                if !enum_flag.swap(true, Ordering::Relaxed) {
                                    debug!(
                                        "Git repo ODB enumeration at {} timed-out",
                                        enum_repo_path.display()
                                    );
                                }
                                break;
                            }
                            let oid = match oid_result {
                                Ok(oid) => oid,
                                Err(_) => continue,
                            };
                            let hdr = match odb.header(oid) {
                                Ok(hdr) => hdr,
                                Err(_) => continue,
                            };
                            if hdr.kind() == Kind::Blob && hdr.size() >= MIN_SCANNABLE_BLOB_SIZE {
                                let md = GitBlobMetadata {
                                    blob_oid: oid,
                                    first_seen: Default::default(),
                                };
                                if blob_tx.send(md).is_err() {
                                    break;
                                }
                            }
                        }
                    })
                    .expect("failed to spawn ODB enumerator thread");

                let rs = Arc::clone(&repo_sync);
                blob_rx
                    .into_iter()
                    .par_bridge()
                    .map_init(move || rs.to_thread_local(), load_blob)
                    .flat_map_iter(fan_out)
                    .filter(timeout_filter)
                    .drive_unindexed(consumer)
            }
        }
    }
}

struct EnumeratorFileIter<'a> {
    inner: EnumeratorFileResult,
    reader: std::io::BufReader<std::fs::File>,
    _marker: PhantomData<&'a ()>,
}

impl ParallelBlobIterator for EnumeratorFileResult {
    type Iter<'a> = EnumeratorFileIter<'a>;

    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>> {
        let file = std::fs::File::open(&self.path)?;
        let reader = std::io::BufReader::new(file);
        Ok(Some(EnumeratorFileIter { inner: self, reader, _marker: PhantomData }))
    }
}
#[allow(clippy::large_enum_variant)]
enum FoundInputIter<'a> {
    File(FileResultIter<'a>),
    GitRepo(GitRepoResultIter<'a>),
    EnumeratorFile(EnumeratorFileIter<'a>),
}

// Split JSONL sequentially, then deserialize and load each entry in parallel.

impl<'a> ParallelIterator for EnumeratorFileIter<'a> {
    type Item = Result<(OriginSet, Blob<'a>)>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        use std::io::BufRead;
        (1usize..)
            .zip(self.reader.lines())
            .filter_map(|(line_num, line)| line.map(|line| (line_num, line)).ok())
            .par_bridge()
            .map(|(line_num, line)| {
                let e: EnumeratorBlobResult = serde_json::from_str(&line).with_context(|| {
                    format!("Error in enumerator {}:{line_num}", self.inner.path.display())
                })?;
                let origin = OriginSet::new(Origin::from_extended(e.origin), Vec::new());
                let blob = Blob::from_bytes(e.content.as_bytes().to_owned());
                Ok((origin, blob))
            })
            .drive_unindexed(consumer)
    }
}

trait ParallelBlobIterator {
    /// The concrete parallel iterator returned by `into_blob_iter`.
    /// It is generic over the lifetime `'a` that the produced `Blob<'a>` carries.
    type Iter<'a>: ParallelIterator<Item = Result<(OriginSet, Blob<'a>)>> + 'a
    where
        Self: 'a;
    /// Convert the input into an *optional* parallel iterator of `(Origin, Blob)` tuples.
    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>>
    where
        Self: 'a;
}

impl<'a> ParallelIterator for FoundInputIter<'a> {
    type Item = Result<(OriginSet, Blob<'a>)>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        match self {
            FoundInputIter::File(i) => i.drive_unindexed(consumer),
            FoundInputIter::GitRepo(i) => i.drive_unindexed(consumer),
            FoundInputIter::EnumeratorFile(i) => i.drive_unindexed(consumer),
        }
    }
}
impl<'cfg> ParallelBlobIterator for (&'cfg EnumeratorConfig, FoundInput) {
    type Iter<'a>
        = FoundInputIter<'a>
    where
        Self: 'a;

    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>>
    where
        'cfg: 'a,
    {
        use std::time::Instant;

        let (cfg, input) = self;

        match input {
            // ───────────── regular file ─────────────
            FoundInput::File(i) => Ok(i.into_blob_iter()?.map(FoundInputIter::File)),

            // ───────────── directory (possible Git repo) ─────────────
            FoundInput::Directory(i) => {
                let path = &i.path;
                let open_path_as_is = cfg.git_diff.is_none();

                if open_path_as_is && !cfg.enumerate_git_history {
                    return Ok(None);
                }

                // Try to open a Git repository at that path
                let repository = match open_git_repo_with_options(path, open_path_as_is)? {
                    Some(r) => r,
                    None => return Ok(None),
                };

                debug!("Found Git repository at {}", path.display());
                let t_start = Instant::now();
                let collect_git_metadata = cfg.collect_git_metadata;
                let timeout = cfg.repo_scan_timeout;

                let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
                let git_result = if let Some(diff_cfg) = cfg.git_diff.clone() {
                    if cfg.enumerate_git_history
                        && !diff_cfg.staged
                        && diff_cfg.branch_root.is_none()
                    {
                        enumerate_git_branch_history(
                            path,
                            repository,
                            (!cfg.history_all_refs).then_some(diff_cfg.branch_ref.as_str()),
                            diff_cfg.since_ref.as_deref(),
                            cfg.history_time_range,
                            cfg.exclude_globset.clone(),
                            collect_git_metadata,
                            deadline,
                        )
                    } else {
                        enumerate_git_diff_repo(
                            path,
                            repository,
                            diff_cfg,
                            cfg.exclude_globset.clone(),
                            collect_git_metadata,
                            deadline,
                        )
                    }
                } else if collect_git_metadata {
                    GitRepoWithMetadataEnumerator::new(
                        path,
                        repository,
                        cfg.exclude_globset.clone(),
                    )
                    .run_with_deadline(deadline)
                } else {
                    GitRepoEnumerator::new(path, repository).run()
                };

                match git_result {
                    Err(e) => {
                        debug!("Failed to enumerate Git repo at {}: {e}", path.display());
                        Err(e)
                    }
                    Ok(repo_result) => {
                        debug!(
                            "Enumerated Git repo at {} in {:.2}s",
                            path.display(),
                            t_start.elapsed().as_secs_f64()
                        );

                        // Convert to a blob iterator, then patch deadline + extraction.
                        let extract_archives = cfg.extract_archives;
                        repo_result.into_blob_iter().map(|iter| {
                            iter.map(|mut gri| {
                                gri.deadline =
                                    timeout.and_then(|timeout| Instant::now().checked_add(timeout));
                                gri.resources = cfg.resources;
                                gri.extract_archives = extract_archives;
                                gri.extraction_depth = cfg.extraction_depth;
                                FoundInputIter::GitRepo(gri)
                            })
                        })
                    }
                }
            }

            // ───────────── pre-enumerated JSON file list ─────────────
            FoundInput::EnumeratorFile(i) => {
                Ok(i.into_blob_iter()?.map(FoundInputIter::EnumeratorFile))
            }
        }
    }
}

/// Collect each reachable commit once, treating shallow commits as roots only on
/// their own edges. The gix revision walker suppresses shallow parents globally,
/// which can hide ancestry still reachable through another tip or merge parent.
fn collect_git_history(
    repository: &gix::Repository,
    tips: impl IntoIterator<Item = gix::ObjectId>,
    excluded: &HashSet<gix::ObjectId>,
    path: &Path,
    deadline: Option<Instant>,
) -> Result<Vec<(gix::ObjectId, Option<gix::ObjectId>)>> {
    let mut commits = Vec::new();
    if let Some(shallow) = repository.shallow_commits()?.filter(|ids| !ids.is_empty()) {
        let mut pending: Vec<_> = tips.into_iter().collect();
        let mut seen = HashSet::new();
        while let Some(id) = pending.pop() {
            check_repo_deadline(deadline, path, "git shallow history traversal")?;
            if excluded.contains(&id) || !seen.insert(id) {
                continue;
            }
            let commit = repository.find_commit(id)?;
            let parents: Vec<_> = if shallow.binary_search(&id).is_ok() {
                Vec::new()
            } else {
                commit.parent_ids().map(|parent| parent.detach()).collect()
            };
            commits.push((id, parents.first().copied()));
            pending.extend(parents);
        }
    } else {
        for commit in repository.rev_walk(tips).selected(|id| !excluded.contains(id))? {
            check_repo_deadline(deadline, path, "git history traversal")?;
            let commit = commit?;
            commits.push((commit.id, commit.parent_ids.first().copied()));
        }
    }
    Ok(commits)
}

/// Scan commits reachable from the selected ref (or all refs and HEAD), including merge parents,
/// excluding the optional baseline and its ancestry.
/// Diffing each commit against its first parent avoids enumerating unchanged trees.
#[allow(clippy::too_many_arguments)]
fn enumerate_git_branch_history(
    path: &Path,
    mut repository: gix::Repository,
    branch_ref: Option<&str>,
    since_ref: Option<&str>,
    time_range: Option<(i64, i64)>,
    exclude_globset: Option<Arc<globset::GlobSet>>,
    collect_commit_metadata: bool,
    deadline: Option<Instant>,
) -> Result<GitRepoResult> {
    check_repo_deadline(deadline, path, "git branch history setup")?;
    let mut tips = Vec::new();
    if let Some(branch_ref) = branch_ref {
        let tip = resolve_diff_ref(&repository, path, branch_ref).with_context(|| {
            format!("Failed to resolve --branch '{branch_ref}' in repository {}", path.display())
        })?;
        tips.push(tip.object()?.peel_to_commit()?.id);
    } else {
        for reference in repository.references()?.all()? {
            check_repo_deadline(deadline, path, "git history ref collection")?;
            let mut reference = reference.map_err(anyhow::Error::from_boxed)?;
            let object = reference
                .peel_to_id()
                .with_context(|| {
                    format!(
                        "Failed to peel history ref {:?} in {}",
                        reference.name(),
                        path.display()
                    )
                })?
                .object()?;
            // Tags may point to trees or blobs, which have no commit history.
            if object.kind == gix::object::Kind::Commit {
                tips.push(object.id);
            }
        }
        check_repo_deadline(deadline, path, "git history HEAD collection")?;
        // HEAD can be detached, or unborn even when other refs have history.
        if let Some(head) = repository.head()?.try_into_peeled_id()? {
            tips.push(head.object()?.peel_to_commit()?.id);
        }
        tips.sort_unstable();
        tips.dedup();
    }
    // Exclude the baseline and all its ancestors, including shared merge ancestry.
    // Walk explicitly so every step observes the repository timeout; timestamps
    // cannot safely define a commit range (clocks may be skewed).
    let mut excluded = HashSet::new();
    if let Some(since_ref) = since_ref {
        let base = resolve_diff_ref(&repository, path, since_ref).with_context(|| {
            format!(
                "Failed to resolve --since-commit '{since_ref}' in repository {}",
                path.display()
            )
        })?;
        let base = base.object()?.peel_to_commit()?.id;
        excluded = collect_git_history(&repository, [base], &excluded, path, deadline)?
            .into_iter()
            .map(|(id, _)| id)
            .collect();
    }
    let commits = collect_git_history(&repository, tips, &excluded, path, deadline)?;
    let reachable: HashSet<_> = commits.iter().map(|(id, _)| *id).collect();
    let mut blobs: HashMap<gix::ObjectId, GitBlobMetadata> = HashMap::new();
    for (commit, parent) in commits {
        check_repo_deadline(deadline, path, "git branch history enumeration")?;
        // Filter after traversing: older descendants can have newer ancestors.
        // Keep all reachable parents above so older parent trees still bound diffs.
        if let Some((start, end)) = time_range {
            let timestamp = repository.find_commit(commit)?.time()?.seconds;
            if timestamp < start || timestamp > end {
                continue;
            }
        }
        let result = enumerate_git_diff_repo(
            path,
            repository,
            GitDiffConfig {
                // Shallow boundaries have no available parent tree: scan their full tree.
                since_ref: parent
                    .filter(|id| reachable.contains(id) || excluded.contains(id))
                    .map(|id| id.to_string()),
                branch_ref: commit.to_string(),
                branch_root: None,
                staged: false,
            },
            exclude_globset.clone(),
            collect_commit_metadata,
            deadline,
        )
        .with_context(|| {
            format!(
                "While enumerating commit {commit} in history of '{}'",
                branch_ref.unwrap_or("all refs and HEAD")
            )
        })?;
        repository = result.repository;
        let GitBlobSource::Precomputed(commit_blobs) = result.blobs else {
            unreachable!("git diff enumeration always precomputes blobs");
        };
        for blob in commit_blobs {
            check_repo_deadline(deadline, path, "git branch blob assembly")?;
            match blobs.entry(blob.blob_oid) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().first_seen.extend(blob.first_seen);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(blob);
                }
            }
        }
    }
    let mut blobs: Vec<_> = blobs.into_values().collect();
    // Hash iteration and revision-walk order must not determine enumeration order.
    for blob in &mut blobs {
        check_repo_deadline(deadline, path, "git branch blob ordering")?;
        blob.first_seen.sort_unstable_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then_with(|| a.commit_metadata.commit_id.cmp(&b.commit_metadata.commit_id))
        });
    }
    blobs.sort_unstable_by_key(|blob| blob.blob_oid);
    check_repo_deadline(deadline, path, "git branch blob ordering")?;
    Ok(GitRepoResult {
        repository,
        path: path.to_owned(),
        blobs: GitBlobSource::Precomputed(blobs),
    })
}

fn enumerate_git_diff_repo(
    path: &Path,
    repository: gix::Repository,
    diff_cfg: GitDiffConfig,
    exclude_globset: Option<Arc<globset::GlobSet>>,
    collect_commit_metadata: bool,
    deadline: Option<Instant>,
) -> Result<GitRepoResult> {
    check_repo_deadline(deadline, path, "git diff setup")?;
    let GitDiffConfig { since_ref, branch_ref, branch_root, staged } = diff_cfg;

    let (branch_ref, since_ref, branch_root) = if staged {
        if branch_root.is_some() {
            bail!("--staged cannot be combined with --branch-root options");
        }

        let base_ref = match since_ref {
            Some(explicit) => explicit,
            None => detect_staged_base_ref(path)?,
        };

        let parent_ref = resolve_optional_diff_ref(&repository, path, &branch_ref)
            .unwrap_or_else(|_| branch_ref.clone());
        let staged_commit = synthesize_staged_commit(path, parent_ref.as_str())?;

        (staged_commit, Some(base_ref), None)
    } else {
        (branch_ref, since_ref, branch_root)
    };

    let blobs = {
        check_repo_deadline(deadline, path, "git diff ref resolution")?;
        let head_id = resolve_diff_ref(&repository, path, &branch_ref).with_context(|| {
            format!("Failed to resolve --branch '{}' in repository {}", branch_ref, path.display())
        })?;

        check_repo_deadline(deadline, path, "git diff commit loading")?;
        let head_commit = head_id
            .object()
            .with_context(|| format!("Failed to load commit {} for diffing", head_id.to_hex()))?
            .try_into_commit()
            .with_context(|| format!("Referenced object {} is not a commit", head_id.to_hex()))?;

        let head_tree = head_commit
            .tree()
            .with_context(|| format!("Failed to read tree for commit {}", head_id.to_hex()))?;

        let mut base_tree = None;

        if let Some(ref since_ref_value) = since_ref {
            check_repo_deadline(deadline, path, "git diff base resolution")?;
            let base_id =
                resolve_diff_ref(&repository, path, since_ref_value).with_context(|| {
                    format!(
                        "Failed to resolve --since-commit '{}' in repository {}",
                        since_ref_value,
                        path.display()
                    )
                })?;

            let commit = base_id
                .object()
                .with_context(|| format!("Failed to load commit {} for diffing", base_id.to_hex()))?
                .try_into_commit()
                .with_context(|| {
                    format!("Referenced object {} is not a commit", base_id.to_hex())
                })?;
            let tree = commit
                .tree()
                .with_context(|| format!("Failed to read tree for commit {}", base_id.to_hex()))?;

            base_tree = Some(tree);
        } else if let Some(ref branch_root_value) = branch_root {
            check_repo_deadline(deadline, path, "git diff branch-root resolution")?;
            let root_id =
                resolve_diff_ref(&repository, path, branch_root_value).with_context(|| {
                    format!(
                        "Failed to resolve --branch-root '{}' in repository {}",
                        branch_root_value,
                        path.display()
                    )
                })?;

            let root_commit = root_id
                .object()
                .with_context(|| format!("Failed to load commit {} for diffing", root_id.to_hex()))?
                .try_into_commit()
                .with_context(|| {
                    format!("Referenced object {} is not a commit", root_id.to_hex())
                })?;

            let mut parent_ids = root_commit.parent_ids();
            if let Some(parent_id) = parent_ids.next() {
                let parent_commit = parent_id
                    .object()
                    .with_context(|| {
                        format!("Failed to load parent commit {} for diffing", parent_id.to_hex())
                    })?
                    .try_into_commit()
                    .with_context(|| {
                        format!("Referenced object {} is not a commit", parent_id.to_hex())
                    })?;
                let parent_tree = parent_commit.tree().with_context(|| {
                    format!("Failed to read tree for commit {}", parent_id.to_hex())
                })?;
                base_tree = Some(parent_tree);
            }
        }

        check_repo_deadline(deadline, path, "git diff computation")?;
        // Only tree entry IDs and paths are needed. The high-level diff helper builds
        // an index-backed attribute cache on every call (rebuilding HEAD's index in
        // bare clones) and performs unnecessary rename similarity checks. A rename
        // is equally useful here as a deletion plus an addition at its new path.
        let mut control = kingfisher_scanner::ScanControl::default();
        if let Some(deadline) = deadline {
            control = control.with_deadline(deadline);
        }
        let changes = kingfisher_scanner::__cli_internals::git_tree_changes(
            &repository,
            &head_tree,
            base_tree.as_ref(),
            &control,
        )
        .with_context(|| {
            if let Some(ref since_ref_value) = since_ref {
                format!("Failed to compute diff between '{}' and '{}'", since_ref_value, branch_ref)
            } else {
                format!("Failed to compute tree for '{}'", branch_ref)
            }
        })?;

        let commit_metadata = if collect_commit_metadata {
            let committer = head_commit
                .committer()
                .with_context(|| format!("Failed to read committer for {}", branch_ref))?
                .trim();
            let timestamp = committer.time().unwrap_or_else(|_| gix::date::Time::new(0, 0));
            let author = head_commit.author().ok();
            Arc::new(CommitMetadata {
                commit_id: head_commit.id,
                author_name: author
                    .as_ref()
                    .map(|author| intern_git_identity(author.name.to_str_lossy().as_ref())),
                author_email: author
                    .as_ref()
                    .map(|author| intern_git_identity(author.email.to_str_lossy().as_ref())),
                committer_name: intern_git_identity(committer.name.to_str_lossy().as_ref()),
                committer_email: intern_git_identity(committer.email.to_str_lossy().as_ref()),
                committer_timestamp: timestamp,
            })
        } else {
            Arc::new(CommitMetadata {
                commit_id: head_commit.id,
                author_name: None,
                author_email: None,
                committer_name: intern_git_identity(""),
                committer_email: intern_git_identity(""),
                committer_timestamp: gix::date::Time::new(0, 0),
            })
        };

        let mut blobs = Vec::new();
        for change in changes {
            check_repo_deadline(deadline, path, "git diff change enumeration")?;
            let (entry_mode, id, location) = match change {
                Change::Addition { entry_mode, oid, path, .. }
                | Change::Modification { entry_mode, oid, path, .. } => (entry_mode, oid, path),
                Change::Deletion { .. } => continue,
            };

            match entry_mode.kind() {
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {}
                _ => continue,
            }

            let relative_path_str = String::from_utf8_lossy(location.as_ref()).into_owned();
            let relative_path = Path::new(&relative_path_str);
            if let Some(gs) = &exclude_globset
                && (gs.is_match(relative_path) || gs.is_match(path.join(relative_path)))
            {
                debug!(
                    "Skipping {} due to --exclude while diffing {}",
                    relative_path.display(),
                    path.display()
                );
                continue;
            }

            let appearance =
                BlobAppearance { commit_metadata: Arc::clone(&commit_metadata), path: location };
            blobs.push(GitBlobMetadata { blob_oid: id, first_seen: smallvec![appearance] });
        }

        blobs
    };

    Ok(GitRepoResult {
        repository,
        path: path.to_owned(),
        blobs: GitBlobSource::Precomputed(blobs),
    })
}

fn check_repo_deadline(deadline: Option<Instant>, path: &Path, phase: &str) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() > deadline) {
        bail!("{phase} timed out for repo {}", path.display());
    }
    Ok(())
}

fn synthesize_staged_commit(path: &Path, parent_ref: &str) -> Result<String> {
    let parent_arg: Vec<&str> =
        if parent_ref.is_empty() { Vec::new() } else { vec!["-p", parent_ref] };

    let staged_tree =
        run_git_command(path, &["write-tree"], true)?.context("Failed to snapshot staged index")?;

    let mut args = vec!["commit-tree", &staged_tree, "-m", "kingfisher staged snapshot"];
    args.extend(parent_arg.iter().copied());

    run_git_command(path, &args, true)?.context("Failed to create staged snapshot commit")
}

fn detect_staged_base_ref(path: &Path) -> Result<String> {
    if let Some(head) = run_git_command(path, &["rev-parse", "--verify", "HEAD"], false)? {
        return Ok(head);
    }

    run_git_command(path, &["hash-object", "-t", "tree", "/dev/null"], true)?
        .context("Failed to resolve an empty tree when no base ref was available")
}

fn resolve_optional_diff_ref(
    repository: &gix::Repository,
    path: &Path,
    reference: &str,
) -> Result<String> {
    resolve_diff_ref(repository, path, reference).map(|id| id.to_hex().to_string())
}

fn run_git_command(path: &Path, args: &[&str], bubble_up_error: bool) -> Result<Option<String>> {
    let mut command = crate::git_binary::git_command();
    command.arg("-C").arg(path).args(args);
    let executable_hint = crate::git_binary::git_command_failure_hint(&command);
    let output = command.output().context(
        "Failed to execute Git; install Git on PATH or set KF_GIT_BINARY to its executable",
    )?;

    if !output.status.success() {
        if bubble_up_error {
            bail!(
                "Git command failed ({}): git -C {} {}{}",
                output.status,
                path.display(),
                args.join(" "),
                executable_hint
            );
        }
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() { Ok(None) } else { Ok(Some(stdout)) }
}

fn resolve_diff_ref<'repo>(
    repository: &'repo gix::Repository,
    path: &Path,
    reference: &str,
) -> Result<gix::Id<'repo>> {
    let mut candidates = reference_candidates(reference);
    if candidates.is_empty() {
        candidates.push(reference.to_string());
    }

    let mut last_err: Option<anyhow::Error> = None;
    for candidate in &candidates {
        match repository.rev_parse_single(candidate.as_bytes()) {
            Ok(id) => return Ok(id),
            Err(err) => last_err = Some(err.into()),
        }
    }

    let attempted = candidates.join(", ");
    let err = last_err.unwrap_or_else(|| {
        anyhow!("Reference resolution failed for '{}' without a more specific error", reference)
    });
    Err(err).with_context(|| {
        if attempted.is_empty() {
            format!("Failed to resolve reference '{}' in repository {}", reference, path.display())
        } else {
            format!(
                "Failed to resolve reference '{}' in repository {} (tried: {})",
                reference,
                path.display(),
                attempted
            )
        }
    })
}

pub(crate) fn reference_candidates(reference: &str) -> Vec<String> {
    fn push_unique(vec: &mut Vec<String>, candidate: String) {
        if !vec.iter().any(|existing| existing == &candidate) {
            vec.push(candidate);
        }
    }

    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    push_unique(&mut candidates, trimmed.to_string());

    if trimmed.eq_ignore_ascii_case("HEAD") {
        return candidates;
    }

    if trimmed.starts_with("refs/") {
        return candidates;
    }

    push_unique(&mut candidates, format!("refs/heads/{trimmed}"));
    push_unique(&mut candidates, format!("refs/tags/{trimmed}"));

    if let Some((remote, rest)) = trimmed.split_once('/') {
        if remote == "origin" {
            if !rest.is_empty() {
                push_unique(&mut candidates, format!("refs/remotes/{remote}/{rest}"));
            }
        } else if !rest.is_empty() {
            push_unique(&mut candidates, format!("refs/remotes/origin/{trimmed}"));
            push_unique(&mut candidates, format!("refs/remotes/{remote}/{rest}"));
        }
    } else {
        push_unique(&mut candidates, format!("origin/{trimmed}"));
        push_unique(&mut candidates, format!("refs/remotes/origin/{trimmed}"));
    }

    candidates
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};
    use std::{
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use super::{
        FileResult, GitBlobSource, GitDiffConfig, ParallelBlobIterator,
        enumerate_git_branch_history, enumerate_git_diff_repo, lazy_expand_entry,
        reference_candidates,
    };
    use anyhow::Result;
    use bstr::ByteSlice;
    use git2::{Repository as Git2Repository, Signature};
    use gix::{open::Options, open_opts};
    use rayon::iter::ParallelIterator;
    use rusqlite::Connection;
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    #[cfg(unix)]
    #[test]
    fn owned_archive_staging_excludes_group_and_other_access() -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let staging = super::archive_staging_tempdir()?;
        std::fs::write(staging.path().join("payload.tar"), b"synthetic archive")?;
        assert_eq!(staging.path().metadata()?.permissions().mode() & 0o077, 0);
        Ok(())
    }

    #[test]
    fn reference_candidates_for_plain_branch() {
        assert_eq!(
            reference_candidates("main"),
            vec![
                "main".to_string(),
                "refs/heads/main".to_string(),
                "refs/tags/main".to_string(),
                "origin/main".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]
        );
    }

    #[test]
    fn reference_candidates_for_remote_branch() {
        assert_eq!(
            reference_candidates("origin/feature"),
            vec![
                "origin/feature".to_string(),
                "refs/heads/origin/feature".to_string(),
                "refs/tags/origin/feature".to_string(),
                "refs/remotes/origin/feature".to_string(),
            ]
        );
    }

    #[test]
    fn reference_candidates_for_branch_with_path() {
        assert_eq!(
            reference_candidates("feature/foo"),
            vec![
                "feature/foo".to_string(),
                "refs/heads/feature/foo".to_string(),
                "refs/tags/feature/foo".to_string(),
                "refs/remotes/origin/feature/foo".to_string(),
                "refs/remotes/feature/foo".to_string(),
            ]
        );
    }

    #[test]
    fn reference_candidates_for_explicit_ref() {
        assert_eq!(reference_candidates("refs/heads/main"), vec!["refs/heads/main".to_string()]);
    }

    #[test]
    fn reference_candidates_for_head_symbol() {
        assert_eq!(reference_candidates("HEAD"), vec!["HEAD".to_string()]);
    }

    #[test]
    fn enumerate_git_diff_repo_branch_without_since_scans_head_tree() -> Result<()> {
        let temp = tempdir()?;
        let repo_path = temp.path().join("repo");
        let repo = Git2Repository::init(&repo_path)?;
        let signature = Signature::now("tester", "tester@exmple.com")?;

        let tracked_file = repo_path.join("secret.txt");
        fs::create_dir_all(tracked_file.parent().unwrap())?;
        fs::write(&tracked_file, b"super-secret")?;

        let mut index = repo.index()?;
        index.add_path(Path::new("secret.txt"))?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let commit_id = repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])?;
        let commit = repo.find_commit(commit_id)?;
        repo.branch("featurefake", &commit, true)?;

        let git_dir = repo_path.join(".git");
        let gix_repo = open_opts(&git_dir, Options::isolated().open_path_as_is(true))?;
        let result = enumerate_git_diff_repo(
            &repo_path,
            gix_repo,
            GitDiffConfig {
                since_ref: None,
                branch_ref: "featurefake".to_string(),
                branch_root: None,
                staged: false,
            },
            None,
            false,
            Some(Instant::now() + Duration::from_secs(60)),
        )?;

        let blobs = match result.blobs {
            GitBlobSource::Precomputed(b) => b,
            GitBlobSource::StreamFromOdb => panic!("expected Precomputed blobs from diff path"),
        };
        assert_eq!(blobs.len(), 1, "expected the full branch tree to be enumerated");
        let blob = &blobs[0];
        assert_eq!(blob.first_seen.len(), 1);
        let appearance_path = blob.first_seen[0].path.to_str_lossy();
        assert_eq!(appearance_path, "secret.txt");

        Ok(())
    }

    #[test]
    fn branch_history_deduplicates_reintroduced_blobs_and_preserves_appearances() -> Result<()> {
        let temp = tempdir()?;
        let repo = Git2Repository::init(temp.path())?;
        let signature = Signature::now("tester", "tester@example.com")?;
        let mut index = repo.index()?;
        for (path, content) in
            [("a.txt", "first historical secret"), ("b.txt", "second historical secret")]
        {
            fs::write(temp.path().join(path), content)?;
            index.add_path(Path::new(path))?;
        }
        let tree = repo.find_tree(index.write_tree()?)?;
        let root_id = repo.commit(None, &signature, &signature, "introduce", &tree, &[])?;
        let root = repo.find_commit(root_id)?;
        index.clear()?;
        let empty_tree = repo.find_tree(index.write_tree()?)?;
        let deleted_id =
            repo.commit(None, &signature, &signature, "delete", &empty_tree, &[&root])?;
        let deleted = repo.find_commit(deleted_id)?;
        let tip_id =
            repo.commit(Some("HEAD"), &signature, &signature, "restore", &tree, &[&deleted])?;

        let result = enumerate_git_branch_history(
            temp.path(),
            open_opts(repo.path(), Options::isolated().open_path_as_is(true))?,
            Some("HEAD"),
            None,
            None,
            None,
            true,
            Some(Instant::now() + Duration::from_secs(60)),
        )?;
        let GitBlobSource::Precomputed(blobs) = result.blobs else {
            panic!("expected precomputed history blobs");
        };
        assert_eq!(blobs.len(), 2, "each blob must be scanned only once");
        assert!(blobs[0].blob_oid < blobs[1].blob_oid, "blob order must be deterministic");
        let mut expected_commits = vec![root_id.to_string(), tip_id.to_string()];
        expected_commits.sort();
        for blob in blobs {
            let commits: Vec<_> = blob
                .first_seen
                .iter()
                .map(|appearance| appearance.commit_metadata.commit_id.to_string())
                .collect();
            assert_eq!(commits, expected_commits, "preserve both introductions in stable order");
            let path = blob.first_seen[0].path.to_str_lossy();
            assert!(path == "a.txt" || path == "b.txt");
            assert!(
                blob.first_seen.iter().all(|appearance| appearance.path.to_str_lossy() == path)
            );
        }
        Ok(())
    }

    #[test]
    fn timed_history_uses_committer_dates_without_pruning_older_descendants() -> Result<()> {
        let temp = tempdir()?;
        let repo = Git2Repository::init_bare(temp.path())?;
        let start = 1_700_000_000;
        let end = start + 3600;
        let signature =
            |seconds| Signature::new("tester", "tester@example.com", &git2::Time::new(seconds, 0));
        let old = signature(start - 1)?;
        let lower = signature(start)?;
        let upper = signature(end)?;
        let future = signature(end + 1)?;
        let mut builder = repo.treebuilder(None)?;
        let baseline_blob = repo.blob(b"unchanged old secret")?;
        builder.insert("baseline.txt", baseline_blob, 0o100644)?;
        let baseline_tree = repo.find_tree(builder.write()?)?;
        let root_id =
            repo.commit(None, &upper, &old, "old commit with recent author", &baseline_tree, &[])?;
        let root = repo.find_commit(root_id)?;
        let recent_blob = repo.blob(b"recent temporary secret")?;
        builder.insert("recent.txt", recent_blob, 0o100644)?;
        let recent_tree = repo.find_tree(builder.write()?)?;
        let recent_id = repo.commit(
            None,
            &old,
            &lower,
            "recent commit with old author",
            &recent_tree,
            &[&root],
        )?;
        let recent = repo.find_commit(recent_id)?;
        // An older child must not prune its newer ancestor; it removes the secret.
        repo.commit(
            Some("refs/heads/main"),
            &upper,
            &old,
            "older child",
            &baseline_tree,
            &[&recent],
        )?;
        repo.set_head("refs/heads/main")?;
        let mut builder = repo.treebuilder(Some(&baseline_tree))?;
        let remote_blob = repo.blob(b"remote secret at upper bound")?;
        builder.insert("remote.txt", remote_blob, 0o100644)?;
        let remote_tree = repo.find_tree(builder.write()?)?;
        let remote_id =
            repo.commit(None, &old, &upper, "at upper bound", &remote_tree, &[&root])?;
        let remote = repo.find_commit(remote_id)?;
        builder.insert("future.txt", repo.blob(b"future secret outside window")?, 0o100644)?;
        let future_tree = repo.find_tree(builder.write()?)?;
        repo.commit(
            Some("refs/remotes/origin/feature"),
            &upper,
            &future,
            "future child",
            &future_tree,
            &[&remote],
        )?;

        for metadata in [true, false] {
            for branch in [None, Some("main")] {
                let result = enumerate_git_branch_history(
                    temp.path(),
                    open_opts(repo.path(), Options::isolated().open_path_as_is(true))?,
                    branch,
                    None,
                    Some((start, end)),
                    None,
                    metadata,
                    Some(Instant::now() + Duration::from_secs(60)),
                )?;
                let GitBlobSource::Precomputed(blobs) = result.blobs else {
                    panic!("expected blobs");
                };
                let mut actual: Vec<_> =
                    blobs.iter().map(|blob| blob.blob_oid.to_string()).collect();
                let mut expected = vec![recent_blob.to_string()];
                if branch.is_none() {
                    expected.push(remote_blob.to_string());
                }
                actual.sort();
                expected.sort();
                assert_eq!(
                    actual, expected,
                    "old unchanged content and future commits must be excluded"
                );
                if metadata {
                    assert!(blobs.iter().flat_map(|blob| &blob.first_seen).all(|appearance| {
                        let id = appearance.commit_metadata.commit_id.to_string();
                        id == recent_id.to_string() || id == remote_id.to_string()
                    }));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn all_ref_history_preserves_unique_appearances_and_shallow_tips() -> Result<()> {
        let temp = tempdir()?;
        let repo = Git2Repository::init_bare(temp.path())?;
        let sig = Signature::now("tester", "tester@example.com")?;
        let empty_tree = repo.find_tree(repo.treebuilder(None)?.write()?)?;
        let base_id = repo.commit(Some("refs/heads/main"), &sig, &sig, "base", &empty_tree, &[])?;
        let base = repo.find_commit(base_id)?;
        let mut builder = repo.treebuilder(None)?;
        let shared_blob = repo.blob(b"shared historical secret")?;
        builder.insert("shared.txt", shared_blob, 0o100644)?;
        let shared_tree = repo.find_tree(builder.write()?)?;
        let shared_id = repo.commit(None, &sig, &sig, "shared", &shared_tree, &[&base])?;
        let shared = repo.find_commit(shared_id)?;
        let mut expected = vec![shared_id.to_string()];
        for (name, reference) in [
            ("local", Some("refs/heads/feature")),
            ("remote", Some("refs/remotes/origin/feature")),
            ("tag", None),
            ("detached", None),
        ] {
            let mut builder = repo.treebuilder(Some(&shared_tree))?;
            builder.insert(name, repo.blob(format!("secret for {name}").as_bytes())?, 0o100644)?;
            let tree = repo.find_tree(builder.write()?)?;
            let id = repo.commit(reference, &sig, &sig, name, &tree, &[&shared])?;
            expected.push(id.to_string());
            match name {
                "tag" => {
                    repo.tag("release", repo.find_commit(id)?.as_object(), &sig, "release", false)?;
                }
                "detached" => repo.set_head_detached(id)?,
                _ => {}
            }
        }
        // Symbolic/duplicate tips must not repeat appearances. Non-commit tags are harmless.
        repo.reference_symbolic(
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/feature",
            true,
            "test",
        )?;
        repo.tag("tree", empty_tree.as_object(), &sig, "tree tag", false)?;
        repo.reference("refs/tags/blob", shared_blob, true, "blob tag")?;
        // A separate shallow tip inherits a blob from its unavailable parent.
        let shallow_id = repo.commit(
            Some("refs/heads/shallow"),
            &sig,
            &sig,
            "shallow",
            &shared_tree,
            &[&shared],
        )?;
        fs::write(repo.path().join("shallow"), format!("{shallow_id}\n"))?;
        expected.push(shallow_id.to_string());
        expected.sort();

        // Unborn HEAD must not prevent scanning the remaining refs either.
        for unborn in [false, true] {
            if unborn {
                repo.set_head("refs/heads/unborn")?;
            }
            let result = enumerate_git_branch_history(
                temp.path(),
                open_opts(repo.path(), Options::isolated().open_path_as_is(true))?,
                None,
                Some(&base_id.to_string()),
                None,
                None,
                true,
                Some(Instant::now() + Duration::from_secs(60)),
            )?;
            let GitBlobSource::Precomputed(blobs) = result.blobs else {
                panic!("expected blobs");
            };
            assert_eq!(blobs.len(), if unborn { 4 } else { 5 });
            let shared_blob = blobs
                .iter()
                .find(|blob| blob.blob_oid.as_slice() == shared_blob.as_bytes())
                .unwrap();
            let mut appearances: Vec<_> = shared_blob
                .first_seen
                .iter()
                .map(|a| a.commit_metadata.commit_id.to_string())
                .collect();
            appearances.sort();
            let mut expected_shared = vec![shared_id.to_string(), shallow_id.to_string()];
            expected_shared.sort();
            assert_eq!(appearances, expected_shared, "shared ancestry must be visited once");
            let mut actual: Vec<_> = blobs
                .iter()
                .flat_map(|b| b.first_seen.iter().map(|a| a.commit_metadata.commit_id.to_string()))
                .collect();
            actual.sort();
            actual.dedup();
            if unborn {
                assert_eq!(actual.len(), expected.len() - 1);
            } else {
                assert_eq!(actual, expected);
            }
        }
        Ok(())
    }

    #[test]
    fn bare_branch_scan_ignores_index_and_preserves_changed_paths() -> Result<()> {
        let temp = tempdir()?;
        let repo = Git2Repository::init_bare(temp.path())?;
        let signature = Signature::now("tester", "tester@example.com")?;
        let shared = repo.blob(b"secret moved and copied without changing content")?;
        let old = repo.blob(b"old secret in modified file")?;
        let new = repo.blob(b"new secret in modified file")?;
        let deleted = repo.blob(b"deleted historical secret")?;
        let excluded = repo.blob(b"excluded secret")?;
        let mut nested = repo.treebuilder(None)?;
        nested.insert("secret.txt", shared, 0o100644)?;
        let nested = nested.write()?;
        let mut builder = repo.treebuilder(None)?;
        builder.insert("old-dir", nested, 0o040000)?;
        builder.insert("modified.txt", old, 0o100644)?;
        builder.insert("deleted.txt", deleted, 0o100644)?;
        let root_tree = repo.find_tree(builder.write()?)?;
        let root_id = repo.commit(None, &signature, &signature, "root", &root_tree, &[])?;
        let root = repo.find_commit(root_id)?;
        builder.remove("old-dir")?;
        builder.remove("deleted.txt")?;
        builder.insert("new-dir", nested, 0o040000)?;
        builder.insert("copy.txt", shared, 0o100644)?;
        builder.insert("modified.txt", new, 0o100644)?;
        builder.insert("excluded.txt", excluded, 0o100644)?;
        let tip_tree = repo.find_tree(builder.write()?)?;
        let tip_id =
            repo.commit(Some("HEAD"), &signature, &signature, "tip", &tip_tree, &[&root])?;
        // User diff preferences must not trigger similarity checks or index loading.
        repo.config()?.set_str("diff.renames", "copies")?;
        let mut excludes = globset::GlobSetBuilder::new();
        excludes.add(globset::Glob::new("excluded.txt")?);
        let excludes = std::sync::Arc::new(excludes.build()?);

        for corrupt_index in [false, true] {
            let index_path = repo.path().join("index");
            if corrupt_index {
                fs::write(&index_path, b"deliberately invalid index")?;
            } else {
                assert!(!index_path.exists());
            }
            let open = || {
                open_opts(repo.path(), Options::isolated().open_path_as_is(true))
                    .map_err(anyhow::Error::from)
            };
            let result = enumerate_git_diff_repo(
                temp.path(),
                open()?,
                GitDiffConfig {
                    since_ref: Some(root_id.to_string()),
                    branch_ref: tip_id.to_string(),
                    branch_root: None,
                    staged: false,
                },
                Some(excludes.clone()),
                true,
                Some(Instant::now() + Duration::from_secs(60)),
            )?;
            let GitBlobSource::Precomputed(blobs) = result.blobs else {
                panic!("expected precomputed diff blobs");
            };
            let mut paths: Vec<_> = blobs
                .iter()
                .map(|blob| blob.first_seen[0].path.to_str_lossy().into_owned())
                .collect();
            paths.sort();
            assert_eq!(paths, ["copy.txt", "modified.txt", "new-dir/secret.txt"]);
            assert!(blobs.iter().all(|blob| blob.blob_oid.as_slice() != old.as_bytes()));

            let result = enumerate_git_branch_history(
                temp.path(),
                open()?,
                Some("HEAD"),
                None,
                None,
                Some(excludes.clone()),
                true,
                Some(Instant::now() + Duration::from_secs(60)),
            )?;
            let GitBlobSource::Precomputed(blobs) = result.blobs else {
                panic!("expected precomputed history blobs");
            };
            assert_eq!(blobs.len(), 4, "include modified and deleted historical blobs");
            let shared_blob =
                blobs.iter().find(|blob| blob.blob_oid.as_slice() == shared.as_bytes()).unwrap();
            let paths: Vec<_> = shared_blob
                .first_seen
                .iter()
                .map(|appearance| appearance.path.to_str_lossy().into_owned())
                .collect();
            assert_eq!(paths, ["copy.txt", "new-dir/secret.txt", "old-dir/secret.txt"]);
            if corrupt_index {
                assert_eq!(fs::read(index_path)?, b"deliberately invalid index");
            } else {
                assert!(!index_path.exists(), "scanning must not create an index");
            }
        }
        Ok(())
    }

    #[test]
    fn branch_history_scans_annotated_tag_at_shallow_boundary() -> Result<()> {
        let temp = tempdir()?;
        let repo = Git2Repository::init(temp.path())?;
        let signature = Signature::now("tester", "tester@example.com")?;
        fs::write(temp.path().join("secret.txt"), "a secret inherited from missing history")?;
        let mut index = repo.index()?;
        index.add_path(Path::new("secret.txt"))?;
        let tree = repo.find_tree(index.write_tree()?)?;
        let root_id = repo.commit(None, &signature, &signature, "root", &tree, &[])?;
        let root = repo.find_commit(root_id)?;
        let tip_id = repo.commit(Some("HEAD"), &signature, &signature, "tip", &tree, &[&root])?;
        let tip = repo.find_commit(tip_id)?;
        repo.tag("release", tip.as_object(), &signature, "annotated tag", false)?;
        fs::write(repo.path().join("shallow"), format!("{tip_id}\n"))?;

        let result = enumerate_git_branch_history(
            temp.path(),
            open_opts(repo.path(), Options::isolated().open_path_as_is(true))?,
            Some("release"),
            None,
            None,
            None,
            true,
            Some(Instant::now() + Duration::from_secs(60)),
        )?;
        let GitBlobSource::Precomputed(blobs) = result.blobs else {
            panic!("expected precomputed history blobs");
        };
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].first_seen.len(), 1);
        assert_eq!(
            blobs[0].first_seen[0].commit_metadata.commit_id.to_string(),
            tip_id.to_string()
        );
        assert_eq!(blobs[0].first_seen[0].path.to_str_lossy(), "secret.txt");
        Ok(())
    }

    #[test]
    fn archive_entry_suffix_preserves_entry_component() {
        assert_eq!(
            super::archive_entry_suffix("dir/archive.zip!nested/secret.txt", "dir/archive.zip"),
            Some("!nested/secret.txt")
        );
        assert_eq!(
            super::archive_entry_suffix("archive.zip!nested/secret.txt", "other/archive.zip"),
            Some("!nested/secret.txt")
        );
    }

    #[test]
    fn archive_cycles_stop_but_identical_siblings_are_expanded() {
        for unlimited in [false, true] {
            let entries = vec![("first".into(), vec![1]), ("second".into(), vec![1])];
            let mut extractions = 0;
            let expanded: Vec<_> = super::expand_entries_with(
                Box::new(entries.into_iter()),
                None,
                crate::limits::ResourceLimits { unlimited },
                false,
                move |logical, data| {
                    extractions += 1;
                    assert!(extractions <= 4, "archive cycle was expanded again");
                    // A -> B -> A models a cycle without relying on a specific
                    // archive codec's ability to encode a quine.
                    let next = if data[0] == 1 { 2 } else { 1 };
                    Ok(Box::new(std::iter::once((format!("{logical}!child"), vec![next]))))
                },
            )
            .take(3)
            .collect();
            assert_eq!(
                expanded,
                vec![("first!child!child".into(), vec![1]), ("second!child!child".into(), vec![1]),]
            );
        }
    }

    #[test]
    fn lazy_archive_fallback_preserves_unreadable_and_empty_inputs() -> Result<()> {
        let empty_zip = ZipWriter::new(std::io::Cursor::new(Vec::new())).finish()?.into_inner();
        for bytes in [
            b"PK\x03\x04broken archive with raw content".to_vec(),
            b"plain content".to_vec(),
            empty_zip,
        ] {
            let entries = lazy_expand_entry(
                "fixture.zip".into(),
                bytes.clone(),
                Some(2),
                crate::limits::ResourceLimits::default(),
            )
            .collect::<Vec<_>>();
            assert_eq!(entries, vec![("fixture.zip".into(), bytes)]);
        }
        Ok(())
    }

    #[test]
    fn git_blob_archive_extraction_preserves_repo_relative_paths() -> Result<()> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);
            zip.start_file("nested/secret.txt", options)?;
            zip.write_all(b"token=not-a-real-secret")?;
            zip.finish()?;
        }

        let entries = lazy_expand_entry(
            "dir/payload.zip".into(),
            cursor.into_inner(),
            Some(1),
            crate::limits::ResourceLimits::default(),
        )
        .collect::<Vec<_>>();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "dir/payload.zip!nested/secret.txt");
        assert_eq!(entries[0].1, b"token=not-a-real-secret");
        Ok(())
    }

    #[test]
    fn git_blob_nested_archive_extraction_respects_depth() -> Result<()> {
        let mut inner_cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut inner_cursor);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);
            zip.start_file("nested/secret.txt", options)?;
            zip.write_all(b"nested archive content")?;
            zip.finish()?;
        }
        let inner_bytes = inner_cursor.into_inner();

        let mut outer_cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut outer_cursor);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);
            zip.start_file("inner.zip", options)?;
            zip.write_all(&inner_bytes)?;
            zip.finish()?;
        }
        let outer_bytes = outer_cursor.into_inner();

        let shallow = lazy_expand_entry(
            "dir/outer.zip".into(),
            outer_bytes.clone(),
            Some(1),
            crate::limits::ResourceLimits::default(),
        )
        .collect::<Vec<_>>();
        assert_eq!(shallow.len(), 1);
        assert_eq!(shallow[0].0, "dir/outer.zip!inner.zip");
        assert_eq!(shallow[0].1, inner_bytes);

        let deep = lazy_expand_entry(
            "dir/outer.zip".into(),
            outer_bytes,
            Some(2),
            crate::limits::ResourceLimits::default(),
        )
        .collect::<Vec<_>>();
        assert_eq!(deep.len(), 1);
        assert_eq!(deep[0].0, "dir/outer.zip!inner.zip!nested/secret.txt");
        assert_eq!(deep[0].1, b"nested archive content");

        Ok(())
    }

    fn collect_file_bytes(file: FileResult) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        let iter = file.into_blob_iter()?.expect("file result should yield a blob");
        iter.collect::<Vec<_>>()
            .into_iter()
            .map(|item| {
                let (origin, blob) = item?;
                let path = origin
                    .first()
                    .full_path()
                    .expect("file origin should preserve the filesystem path");
                Ok((path, blob.bytes().to_vec()))
            })
            .collect()
    }

    #[test]
    fn sqlite_extension_falls_back_to_raw_bytes_when_extraction_fails() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("not-a-database.db");
        let expected = b"ghp_not_really_sqlite_but_should_still_scan".to_vec();
        fs::write(&path, &expected)?;

        let blobs = collect_file_bytes(FileResult {
            path: path.clone(),
            num_bytes: expected.len() as u64,
            extract_archives: true,
            extraction_depth: Some(2),
            resources: crate::limits::ResourceLimits::default(),
        })?;

        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].0, path);
        assert_eq!(blobs[0].1, expected);
        Ok(())
    }

    #[test]
    fn nested_archive_entries_are_extracted_to_configured_depth() -> Result<()> {
        let dir = tempdir()?;
        let outer_path = dir.path().join("outer.zip");

        let mut inner_cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut inner_cursor);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);
            zip.start_file("nested/secret.txt", options)?;
            zip.write_all(b"nested archive content")?;
            zip.finish()?;
        }
        let inner_bytes = inner_cursor.into_inner();

        {
            let file = fs::File::create(&outer_path)?;
            let mut zip = ZipWriter::new(file);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);
            zip.start_file("inner.zip", options)?;
            zip.write_all(&inner_bytes)?;
            zip.finish()?;
        }

        let shallow = collect_file_bytes(FileResult {
            path: outer_path.clone(),
            num_bytes: fs::metadata(&outer_path)?.len(),
            extract_archives: true,
            extraction_depth: Some(1),
            resources: crate::limits::ResourceLimits::default(),
        })?;
        assert_eq!(shallow.len(), 1);
        assert_eq!(shallow[0].0, PathBuf::from(format!("{}!inner.zip", outer_path.display())));
        assert_eq!(shallow[0].1, inner_bytes);

        let deep = collect_file_bytes(FileResult {
            path: outer_path.clone(),
            num_bytes: fs::metadata(&outer_path)?.len(),
            extract_archives: true,
            extraction_depth: Some(2),
            resources: crate::limits::ResourceLimits::default(),
        })?;
        assert_eq!(deep.len(), 1);
        assert_eq!(
            deep[0].0,
            PathBuf::from(format!("{}!inner.zip!nested/secret.txt", outer_path.display()))
        );
        assert_eq!(deep[0].1, b"nested archive content");

        Ok(())
    }

    #[test]
    fn compressed_archives_fall_back_to_raw_bytes_when_extraction_fails() -> Result<()> {
        let dir = tempdir()?;

        for (name, expected) in [
            ("broken.zip", b"not-a-real-zip".to_vec()),
            ("broken.asar", b"not-a-real-asar".to_vec()),
        ] {
            let path = dir.path().join(name);
            fs::write(&path, &expected)?;

            let blobs = collect_file_bytes(FileResult {
                path: path.clone(),
                num_bytes: expected.len() as u64,
                extract_archives: true,
                extraction_depth: Some(2),
                resources: crate::limits::ResourceLimits::default(),
            })?;

            assert_eq!(blobs.len(), 1, "{} should fall back to raw bytes", name);
            assert_eq!(blobs[0].0, path);
            assert_eq!(blobs[0].1, expected);
        }

        Ok(())
    }

    #[test]
    fn pyc_without_extractable_strings_falls_back_to_raw_bytes() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("empty.pyc");
        let mut expected = vec![0x55, 0x0D, b'\r', b'\n'];
        expected.extend_from_slice(&[0; 12]);
        fs::write(&path, &expected)?;

        let blobs = collect_file_bytes(FileResult {
            path: path.clone(),
            num_bytes: expected.len() as u64,
            extract_archives: true,
            extraction_depth: Some(2),
            resources: crate::limits::ResourceLimits::default(),
        })?;

        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].0, path);
        assert_eq!(blobs[0].1, expected);
        Ok(())
    }

    #[test]
    fn sqlite_with_no_user_tables_falls_back_to_raw_bytes() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("empty.db");
        Connection::open(&path)?;
        let expected = fs::read(&path)?;

        let blobs = collect_file_bytes(FileResult {
            path: path.clone(),
            num_bytes: expected.len() as u64,
            extract_archives: true,
            extraction_depth: Some(2),
            resources: crate::limits::ResourceLimits::default(),
        })?;

        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].0, path);
        assert_eq!(blobs[0].1, expected);
        Ok(())
    }
}

/// A simple enum describing how we yield file content:
/// - Single: one `(origin, blob)`
/// - Archive: multiple `(origin, blob)` items from a decompressed archive
enum FileResultIterKind {
    Single(Option<(OriginSet, OwnedBlob)>),
    Archive(Vec<(OriginSet, OwnedBlob)>),
}

#[derive(Deserialize)]
pub enum Content {
    #[serde(rename = "content_base64")]
    Base64(#[serde(deserialize_with = "deserialize_b64_bstring")] BString),

    #[serde(rename = "content")]
    Utf8(String),
}

impl Content {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Content::Base64(s) => s.as_slice(),
            Content::Utf8(s) => s.as_bytes(),
        }
    }
}

fn deserialize_b64_bstring<'de, D>(deserializer: D) -> Result<BString, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = STANDARD.decode(&encoded).map_err(serde::de::Error::custom)?;
    Ok(decoded.into())
}

// -------------------------------------------------------------------------------------------------
/// An entry deserialized from an extensible enumerator
#[derive(serde::Deserialize)]
struct EnumeratorBlobResult {
    #[serde(flatten)]
    pub content: Content,

    pub origin: serde_json::Value,
}
