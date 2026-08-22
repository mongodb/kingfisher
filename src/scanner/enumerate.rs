use std::{
    io::Read,
    marker::PhantomData,
    path::Path,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant as StdInstant, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bstr::{BString, ByteSlice};
use gix::{Repository as GixRepo, object::tree::EntryKind, object::tree::diff::ChangeDetached};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::{
    iter::plumbing::Folder,
    prelude::{ParallelIterator, *},
};
use serde::{Deserialize, Deserializer};
use tracing::{debug, error};

use smallvec::smallvec;

use crate::{
    DirectoryResult, EnumeratorConfig, EnumeratorFileResult, FileResult, FilesystemEnumerator,
    FoundInput, GitDiffConfig, GitRepoEnumerator, GitRepoResult, GitRepoWithMetadataEnumerator,
    PathBuf,
    binary::is_binary,
    blob::{Blob, BlobAppearance, BlobId, BlobIdMap},
    cli::commands::{github::GitHistoryMode, scan},
    decompress::{
        CompressedContent, MAX_INMEM_ZIP_ARCHIVE_BYTES, ZIP_BASED_FORMATS, decompress_file_to_temp,
        extract_zip_archive_in_memory, looks_like_zip,
    },
    findings_store,
    git_commit_metadata::{CommitMetadata, intern_git_identity},
    git_repo_enumerator::{GitBlobMetadata, GitBlobSource, MIN_SCANNABLE_BLOB_SIZE},
    matcher::{Matcher, MatcherStats},
    open_git_repo_with_options,
    origin::{Origin, OriginSet},
    pyc::extract_pyc_strings,
    rule_profiling::ConcurrentRuleProfiler,
    rules_database::RulesDatabase,
    scanner::{
        processing::BlobProcessor,
        runner::{create_datastore_channel, spawn_datastore_writer_thread},
        util::{is_compressed_content, is_compressed_file, is_pyc_file, is_sqlite_file},
    },
    scanner_pool::ScannerPool,
    sqlite::extract_sqlite_contents,
};

type OwnedBlob = Blob<'static>;

#[allow(clippy::too_many_arguments)]
pub fn enumerate_filesystem_inputs(
    args: &scan::ScanArgs,
    datastore: Arc<Mutex<findings_store::FindingsStore>>,
    input_roots: &[PathBuf],
    progress_enabled: bool,
    rules_db: &RulesDatabase,
    enable_profiling: bool,
    shared_profiler: Arc<ConcurrentRuleProfiler>,
    matcher_stats: &Mutex<MatcherStats>,
) -> Result<()> {
    let repo_scan_timeout = Duration::from_secs(args.git_repo_timeout);

    let branch_root_enabled = args.input_specifier_args.branch_root
        || args.input_specifier_args.branch_root_commit.is_some();

    let wants_git_diff = args.input_specifier_args.staged
        || args.input_specifier_args.since_commit.is_some()
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
        let fs_enumerator = make_fs_enumerator(args, input_roots.to_vec())
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
        extract_archives: !args.content_filtering_args.no_extract_archives,
        extraction_depth: args.content_filtering_args.extraction_depth as usize,
    };
    let (send_ds, recv_ds) = create_datastore_channel(args.num_jobs);
    let datastore_writer_thread =
        spawn_datastore_writer_thread(datastore, recv_ds, !args.no_dedup)?;

    let t1 = Instant::now();
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
    )?;
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
    let scan_res: Result<()> = input_recv
        .into_iter()
        .par_bridge()
        .filter_map(|input| match (&enum_cfg, input).into_blob_iter() {
            Err(e) => {
                debug!("Error enumerating input: {e:#}");
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
                    // For archives: skip only if --no_extract_archives is true
                    args.content_filtering_args.no_extract_archives
                } else {
                    // For non-archives: skip if it's binary and --no_binary is true
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
    Ok(())
}

/// Initialize a `FilesystemEnumerator` based on the command-line arguments and
/// datastore. Also initialize a `Gitignore` that is the same as that used by
/// the filesystem enumerator.
fn make_fs_enumerator(
    args: &scan::ScanArgs,
    input_roots: Vec<PathBuf>,
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
        Ok(Some(ie))
    }
}

// Rest of the file remains the same...
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

        if extraction_enabled && is_sqlite_file(&self.path) {
            match extract_sqlite_contents(&self.path) {
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
            match extract_pyc_strings(&self.path) {
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
            match decompress_file_to_temp(&self.path) {
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
                        if max_extraction_depth == 0 {
                            debug!(
                                "Skipping nested archive (max depth reached): {}",
                                self.path.display()
                            );
                            return Ok(None);
                        }
                        let items = recursively_expand_archive_entries(
                            files,
                            max_extraction_depth.saturating_sub(1),
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
                        if max_extraction_depth == 0 {
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
                            if max_extraction_depth > 1
                                && (is_compressed_file(Path::new(&filename))
                                    || file_header_looks_like_zip(&disk_path))
                                && let Ok(data) = std::fs::read(&disk_path)
                            {
                                let nested = recursively_expand_archive_entries(
                                    vec![(filename.clone(), data)],
                                    max_extraction_depth - 1,
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

fn archive_staged_name(logical: &str) -> String {
    let entry = logical.rsplit_once('!').map_or(logical, |(_, entry)| entry);
    Path::new(entry)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .unwrap_or("archive")
        .to_string()
}

/// Extract one archive layer from bytes, returning paths rooted at `logical`.
/// Decompression failures deliberately return `None` so callers can still scan the original entry
/// as raw content.
fn extract_archive_bytes(logical: &str, data: &[u8]) -> Result<Option<Vec<OwnedArchiveEntry>>> {
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
            return match extract_zip_archive_in_memory(data, logical) {
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

    let staging = tempfile::tempdir().context("Failed to create staging tempdir for archive")?;
    let staged_path = staging.path().join(archive_staged_name(logical));
    std::fs::write(&staged_path, data)
        .with_context(|| format!("Failed to stage archive to {}", staged_path.display()))?;

    let (content, _temp_dir) = match decompress_file_to_temp(&staged_path) {
        Ok(content) => content,
        Err(e) => {
            debug!("decompress_file_to_temp({}) failed: {e:#}", staged_path.display());
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
                push_archive_bytes(&mut entries, &mut total, remap_logical(entry_logical), bytes);
                if total >= MAX_RECURSIVE_ARCHIVE_BYTES {
                    break;
                }
            }
        }
        CompressedContent::ArchiveFiles(files) => {
            for (entry_logical, disk_path) in files {
                if total >= MAX_RECURSIVE_ARCHIVE_BYTES {
                    break;
                }
                let remaining = MAX_RECURSIVE_ARCHIVE_BYTES - total;
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
                let mut bytes = Vec::with_capacity(entry_len.min(remaining) as usize);
                if let Err(e) = file.take(entry_len.min(remaining)).read_to_end(&mut bytes) {
                    debug!("Failed to read extracted entry {}: {e}", disk_path.display());
                    continue;
                }
                push_archive_bytes(&mut entries, &mut total, remap_logical(entry_logical), bytes);
            }
        }
        CompressedContent::Raw(mut bytes) => {
            if bytes.len() as u64 > MAX_RECURSIVE_ARCHIVE_BYTES {
                bytes.truncate(MAX_RECURSIVE_ARCHIVE_BYTES as usize);
            }
            push_archive_bytes(&mut entries, &mut total, format!("{logical}!content"), bytes);
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
            let mut bytes =
                Vec::with_capacity(payload_len.min(MAX_RECURSIVE_ARCHIVE_BYTES) as usize);
            if let Err(e) =
                file.take(payload_len.min(MAX_RECURSIVE_ARCHIVE_BYTES)).read_to_end(&mut bytes)
            {
                debug!("Failed to read decompressed payload {}: {e}", path.display());
                return Ok(None);
            }
            push_archive_bytes(&mut entries, &mut total, format!("{logical}!content"), bytes);
        }
    }

    if entries.is_empty() { Ok(None) } else { Ok(Some(entries)) }
}

fn push_archive_bytes(
    entries: &mut Vec<OwnedArchiveEntry>,
    total: &mut u64,
    logical: String,
    mut bytes: Vec<u8>,
) -> bool {
    let remaining = MAX_RECURSIVE_ARCHIVE_BYTES.saturating_sub(*total);
    if remaining == 0 {
        return false;
    }
    if bytes.len() as u64 > remaining {
        bytes.truncate(remaining as usize);
    }
    *total += bytes.len() as u64;
    entries.push((logical, bytes));
    true
}

fn recursively_expand_archive_entry(
    logical: String,
    data: Vec<u8>,
    remaining_depth: usize,
) -> Result<Vec<OwnedArchiveEntry>> {
    if remaining_depth == 0 {
        return Ok(vec![(logical, data)]);
    }

    let Some(entries) = extract_archive_bytes(&logical, &data)? else {
        return Ok(vec![(logical, data)]);
    };

    let mut expanded = Vec::new();
    let mut total = 0;
    for (entry_logical, entry_data) in entries {
        let nested = recursively_expand_archive_entry(
            entry_logical,
            entry_data,
            remaining_depth.saturating_sub(1),
        )?;
        for (nested_logical, nested_data) in nested {
            if !push_archive_bytes(&mut expanded, &mut total, nested_logical, nested_data) {
                break;
            }
        }
        if total >= MAX_RECURSIVE_ARCHIVE_BYTES {
            break;
        }
    }
    Ok(expanded)
}

fn recursively_expand_archive_entries(
    entries: impl IntoIterator<Item = OwnedArchiveEntry>,
    remaining_depth: usize,
) -> Result<Vec<OwnedArchiveEntry>> {
    let mut expanded = Vec::new();
    let mut total = 0;
    for (logical, data) in entries {
        let nested = recursively_expand_archive_entry(logical, data, remaining_depth)?;
        for (nested_logical, nested_data) in nested {
            if !push_archive_bytes(&mut expanded, &mut total, nested_logical, nested_data) {
                return Ok(expanded);
            }
        }
    }
    Ok(expanded)
}

fn recursively_extract_archive_entries(
    archive_label: &str,
    data: &[u8],
    extraction_depth: usize,
) -> Result<Option<Vec<OwnedArchiveEntry>>> {
    if extraction_depth == 0 {
        return Ok(None);
    }
    let Some(entries) = extract_archive_bytes(archive_label, data)? else {
        return Ok(None);
    };

    let expanded = recursively_expand_archive_entries(entries, extraction_depth.saturating_sub(1))?;
    if expanded.is_empty() { Ok(None) } else { Ok(Some(expanded)) }
}

fn archive_entry_suffix<'a>(entry_logical: &'a str, archive_path: &str) -> Option<&'a str> {
    entry_logical.strip_prefix(archive_path).filter(|suffix| suffix.starts_with('!')).or_else(
        || entry_logical.split_once('!').map(|(archive, _)| &entry_logical[archive.len()..]),
    )
}

// A marker so the struct itself carries the lifetime.
struct GitRepoResultIter<'a> {
    inner: GitRepoResult,
    deadline: std::time::Instant,
    /// When true, blobs whose in-tree path matches a known archive format
    /// (zip/jar/apk/tar/gz/...) are extracted before scanning, so secrets
    /// inside the archive can be matched. When false, archive blobs are
    /// scanned as raw compressed bytes (legacy behavior).
    extract_archives: bool,
    /// Maximum number of archive layers to extract from each git blob.
    extraction_depth: usize,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl ParallelBlobIterator for GitRepoResult {
    type Iter<'a> = GitRepoResultIter<'a>;

    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>> {
        // placeholder 1 h deadline; will be overwritten immediately
        const PLACEHOLDER: Duration = Duration::from_secs(3600);

        Ok(Some(GitRepoResultIter {
            inner: self,
            deadline: Instant::now() + PLACEHOLDER,
            // Default to enabled; the dispatch site overrides from CLI args.
            extract_archives: true,
            extraction_depth: 1,
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

        // Loads one git blob and returns one *or more* `(OriginSet, Blob)`
        // tuples: a single tuple for normal blobs, multiple tuples for
        // archive blobs (zip/jar/apk/...) whose entries get unpacked into
        // synthetic per-entry blobs so pattern matchers can see the
        // contents. See `recursively_extract_archive_entries` below.
        let load_blob = {
            let repo_path = Arc::clone(&repo_path);
            let flag = Arc::clone(&flag);

            move |repo: &mut GixRepo, md: GitBlobMetadata| -> Result<Vec<(OriginSet, Blob<'a>)>> {
                if StdInstant::now() > deadline {
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
                // We don't need to keep the raw archive bytes around — its
                // compressed contents won't produce useful matches anyway.
                if extract_archives && extraction_depth > 0 {
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
                        match recursively_extract_archive_entries(
                            &archive_path,
                            data.as_slice(),
                            extraction_depth,
                        ) {
                            Ok(Some(entries)) => {
                                let mut out = Vec::with_capacity(entries.len());
                                for (entry_logical, entry_bytes) in entries {
                                    let entry_suffix =
                                        archive_entry_suffix(&entry_logical, &archive_path);
                                    let origin =
                                        OriginSet::try_from_iter(md.first_seen.iter().map(|e| {
                                            let repo_relative_path =
                                                String::from_utf8_lossy(&e.path).to_string();
                                            let per_appearance_logical = entry_suffix
                                                .map(|suffix| {
                                                    format!("{repo_relative_path}{suffix}")
                                                })
                                                .unwrap_or_else(|| entry_logical.clone());
                                            Origin::from_git_repo_with_first_commit(
                                                Arc::clone(&repo_path),
                                                Arc::clone(&e.commit_metadata),
                                                per_appearance_logical,
                                            )
                                        }))
                                        .unwrap_or_else(
                                            || Origin::from_git_repo(Arc::clone(&repo_path)).into(),
                                        );
                                    out.push((origin, Blob::from_bytes(entry_bytes)));
                                }
                                return Ok(out);
                            }
                            Ok(None) => { /* not an archive we can crack — fall through */ }
                            Err(e) => {
                                debug!(
                                    "Failed to extract git archive blob {} ({}): {e:#}",
                                    blob_id, archive_path
                                );
                                // fall through and scan raw bytes
                            }
                        }
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

                Ok(vec![(origin, blob)])
            }
        };

        // After flat-mapping, errors and successes both flow as
        // `Result<(OriginSet, Blob<'a>)>`. Filter out the silenced timeout
        // marker before handing items to the scan consumer.
        let timeout_filter = |res: &Result<(OriginSet, Blob<'a>)>| -> bool {
            !matches!(res, Err(e) if e.to_string() == "__timeout_silenced__")
        };

        // Convert `Result<Vec<T>>` into a sequential iterator of `Result<T>`,
        // suitable for rayon's `flat_map_iter`. A failed load yields a single
        // `Err`; a successful load fans out into one item per extracted blob.
        // A closure is used (rather than a free function) so the produced
        // `Blob<'static>` items can coerce into the iterator's
        // `Blob<'a>` Item type — Blob is covariant in its lifetime, but a
        // free fn would lose that link.
        let fan_out = |res: Result<Vec<(OriginSet, Blob<'a>)>>|
         -> Box<dyn Iterator<Item = Result<(OriginSet, Blob<'a>)>> + Send + 'a> {
            match res {
                Ok(v) => Box::new(v.into_iter().map(Ok)),
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
                            if StdInstant::now() > deadline {
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

// Enumerator file parallelism approach:
//
// - Split into lines sequentially
// - Parallelize JSON deserialization (JSON is an expensive serialization format, but easy to sling
//   around, hence used here -- another format like Arrow or msgpack would be much more efficient)

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
                // let origin = Origin::from_extended(e.origin).into();
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

                let deadline = Instant::now() + timeout;
                let git_result = if let Some(diff_cfg) = cfg.git_diff.clone() {
                    enumerate_git_diff_repo(
                        path,
                        repository,
                        diff_cfg,
                        cfg.exclude_globset.clone(),
                        collect_git_metadata,
                        deadline,
                    )
                } else if collect_git_metadata {
                    GitRepoWithMetadataEnumerator::new(
                        path,
                        repository,
                        cfg.exclude_globset.clone(),
                    )
                    .run_with_deadline(Some(deadline))
                } else {
                    GitRepoEnumerator::new(path, repository).run()
                };

                match git_result {
                    Err(e) => {
                        debug!("Failed to enumerate Git repo at {}: {e}", path.display());
                        Ok(None)
                    }
                    Ok(repo_result) => {
                        debug!(
                            "Enumerated Git repo at {} in {:.2}s",
                            path.display(),
                            t_start.elapsed().as_secs_f64()
                        );

                        // Convert to a blob iterator, then patch deadline + extraction.
                        let extract_archives = cfg.extract_archives;
                        repo_result
                            .into_blob_iter() // Option<GitRepoResultIter>
                            .map(|iter| {
                                iter.map(|mut gri| {
                                    gri.deadline = Instant::now() + timeout;
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

fn enumerate_git_diff_repo(
    path: &Path,
    repository: gix::Repository,
    diff_cfg: GitDiffConfig,
    exclude_globset: Option<std::sync::Arc<globset::GlobSet>>,
    collect_commit_metadata: bool,
    deadline: Instant,
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
        let changes = repository
            .diff_tree_to_tree(base_tree.as_ref(), Some(&head_tree), None)
            .with_context(|| {
                if let Some(ref since_ref_value) = since_ref {
                    format!(
                        "Failed to compute diff between '{}' and '{}'",
                        since_ref_value, branch_ref
                    )
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
            Arc::new(CommitMetadata {
                commit_id: head_commit.id,
                committer_name: intern_git_identity(committer.name.to_str_lossy().as_ref()),
                committer_email: intern_git_identity(committer.email.to_str_lossy().as_ref()),
                committer_timestamp: timestamp,
            })
        } else {
            Arc::new(CommitMetadata {
                commit_id: head_commit.id,
                committer_name: intern_git_identity(""),
                committer_email: intern_git_identity(""),
                committer_timestamp: gix::date::Time::new(0, 0),
            })
        };

        let mut blobs = Vec::new();
        for change in changes {
            check_repo_deadline(deadline, path, "git diff change enumeration")?;
            let (entry_mode, id, location) = match change {
                ChangeDetached::Addition { entry_mode, id, location, .. } => {
                    (entry_mode, id, location)
                }
                ChangeDetached::Modification { entry_mode, id, location, .. } => {
                    (entry_mode, id, location)
                }
                ChangeDetached::Rewrite { entry_mode, id, location, .. } => {
                    (entry_mode, id, location)
                }
                ChangeDetached::Deletion { .. } => continue,
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

fn check_repo_deadline(deadline: Instant, path: &Path, phase: &str) -> Result<()> {
    if Instant::now() > deadline {
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
    let output = Command::new("git").arg("-C").arg(path).args(args).output()?;

    if !output.status.success() {
        if bubble_up_error {
            bail!(
                "Git command failed ({}): git -C {} {}",
                output.status,
                path.display(),
                args.join(" ")
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

fn reference_candidates(reference: &str) -> Vec<String> {
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
        FileResult, GitBlobSource, GitDiffConfig, ParallelBlobIterator, enumerate_git_diff_repo,
        recursively_extract_archive_entries, reference_candidates,
    };
    use anyhow::Result;
    use bstr::ByteSlice;
    use git2::{Repository as Git2Repository, Signature};
    use gix::{open::Options, open_opts};
    use rayon::iter::ParallelIterator;
    use rusqlite::Connection;
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

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
            Instant::now() + Duration::from_secs(60),
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

        let entries =
            recursively_extract_archive_entries("dir/payload.zip", &cursor.into_inner(), 1)?
                .expect("zip blob should extract");

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

        let shallow = recursively_extract_archive_entries("dir/outer.zip", &outer_bytes, 1)?
            .expect("outer ZIP should extract");
        assert_eq!(shallow.len(), 1);
        assert_eq!(shallow[0].0, "dir/outer.zip!inner.zip");
        assert_eq!(shallow[0].1, inner_bytes);

        let deep = recursively_extract_archive_entries("dir/outer.zip", &outer_bytes, 2)?
            .expect("nested ZIP should extract");
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
            extraction_depth: 2,
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
            extraction_depth: 1,
        })?;
        assert_eq!(shallow.len(), 1);
        assert_eq!(shallow[0].0, PathBuf::from(format!("{}!inner.zip", outer_path.display())));
        assert_eq!(shallow[0].1, inner_bytes);

        let deep = collect_file_bytes(FileResult {
            path: outer_path.clone(),
            num_bytes: fs::metadata(&outer_path)?.len(),
            extract_archives: true,
            extraction_depth: 2,
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
                extraction_depth: 2,
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
            extraction_depth: 2,
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
            extraction_depth: 2,
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
