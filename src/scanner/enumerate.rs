use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant as StdInstant, Instant},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use bstr::BString;
use gix::Repository as GixRepo;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::{
    iter::plumbing::Folder,
    prelude::{ParallelIterator, *},
};
use serde::{Deserialize, Deserializer};
use tracing::{debug, error};

use crate::{
    binary::is_binary,
    blob::{Blob, BlobId, BlobIdMap},
    cli::commands::{github::GitHistoryMode, scan},
    decompress::{decompress_file_to_temp, CompressedContent},
    findings_store,
    guesser::Guesser,
    matcher::{Matcher, MatcherStats},
    open_git_repo,
    origin::{Origin, OriginSet},
    rule_profiling::ConcurrentRuleProfiler,
    rules_database::RulesDatabase,
    scanner::{
        processing::BlobProcessor,
        runner::{create_datastore_channel, spawn_datastore_writer_thread},
        util::is_compressed_file,
    },
    scanner_pool::ScannerPool,
    EnumeratorConfig, EnumeratorFileResult, FileResult, FilesystemEnumerator, FoundInput,
    GitRepoEnumerator, GitRepoResult, GitRepoWithMetadataEnumerator, PathBuf,
};

type OwnedBlob = Blob<'static>;

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
        let mut ie = FilesystemEnumerator::new(input_roots, &args)?;
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

    let (enum_thread, input_recv) = {
        let fs_enumerator = make_fs_enumerator(args, input_roots.into())
            .context("Failed to initialize filesystem enumerator")?;
        let channel_size = std::cmp::max(args.num_jobs * 128, 1024);

        let (input_send, input_recv) = crossbeam_channel::bounded(channel_size);
        let input_enumerator_thread = std::thread::Builder::new()
            .name("input_enumerator".to_string())
            .spawn(move || -> Result<_> {
                if let Some(fs_enumerator) = fs_enumerator {
                    fs_enumerator.run(input_send.clone())?;
                }
                Ok(())
            })
            .context("Failed to enumerate filesystem inputs")?;
        (input_enumerator_thread, input_recv)
    };

    let enum_cfg = EnumeratorConfig {
        enumerate_git_history: match args.input_specifier_args.git_history {
            GitHistoryMode::Full => true,
            GitHistoryMode::None => false,
        },
        collect_git_metadata: args.input_specifier_args.commit_metadata,
        repo_scan_timeout,
    };
    let (send_ds, recv_ds) = create_datastore_channel(args.num_jobs);
    let datastore_writer_thread =
        spawn_datastore_writer_thread(datastore, recv_ds, !args.no_dedup)?;

    let t1 = Instant::now();
    let num_blob_processors = Mutex::new(0u64);
    let seen_blobs = BlobIdMap::new();
    let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vsdb.clone())));

    let matcher = Matcher::new(
        &rules_db,
        scanner_pool.clone(),
        &seen_blobs,
        Some(&matcher_stats),
        enable_profiling,
        Some(shared_profiler),
    )?;
    let blob_processor_init_time = Mutex::new(t1.elapsed());
    let make_blob_processor = || -> BlobProcessor {
        let t1 = Instant::now();
        *num_blob_processors.lock().unwrap() += 1;
        let guesser = Guesser::new().expect("should be able to create filetype guesser");
        {
            let mut init_time = blob_processor_init_time.lock().unwrap();
            *init_time += t1.elapsed();
        }
        BlobProcessor { matcher, guesser }
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
                // Check if this is an archive file
                let is_archive = if let Origin::File(file_origin) = &origin.first() {
                    is_compressed_file(&file_origin.path)
                } else {
                    false
                };
                let is_binary = is_binary(&blob.bytes());
                let should_skip = if is_archive {
                    // For archives: skip only if --no_extract_archives is true
                    args.content_filtering_args.no_extract_archives
                } else {
                    // For non-archives: skip if it's binary and --no_binary is true
                    is_binary && args.content_filtering_args.no_binary
                };
                if should_skip {
                    progress.suspend(|| {
                        if is_archive {
                            debug!("Skipping archive: {}", blob.id);
                        } else {
                            debug!("Skipping binary blob: {}", blob.id);
                        }
                    });
                    return Ok(());
                }
                progress.inc(blob.len().try_into().unwrap());
                match processor.run(origin, blob, args.no_dedup) {
                    Ok(None) => {
                        // nothing to record
                    }
                    Ok(Some((origin_set, blob_metadata, vec_of_matches))) => {
                        for (_, single_match) in vec_of_matches {
                            // Send each match
                            send_ds.send((
                                Arc::new(origin_set.clone()),
                                Arc::new(blob_metadata.clone()),
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
        let mut ie = FilesystemEnumerator::new(&input_roots, &args)?;
        ie.threads(args.num_jobs);
        ie.max_filesize(args.content_filtering_args.max_file_size_bytes());
        if args.input_specifier_args.git_history == GitHistoryMode::None {
            ie.enumerate_git_history(false);
        }

        // Pass no_dedup when enumerating git history
        ie.no_dedup(args.no_dedup);

        // Load any specified ignore files
        for ignore_path in args.content_filtering_args.ignore.iter() {
            debug!("Using ignore rules from {}", ignore_path.display());
            ie.add_ignore(ignore_path).with_context(|| {
                format!("Failed to load ignore rules from {}", ignore_path.display())
            })?;
        }
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

impl ParallelBlobIterator for FileResult {
    type Iter<'a> = FileResultIter<'a>;

    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>> {
        let extraction_enabled = self.extract_archives;
        let max_extraction_depth = self.extraction_depth;

        if extraction_enabled && is_compressed_file(&self.path) {
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
                    CompressedContent::Archive(ref files) => {
                        if max_extraction_depth == 0 {
                            debug!(
                                "Skipping nested archive (max depth reached): {}",
                                self.path.display()
                            );
                            return Ok(None);
                        }
                        let items = files
                            .iter()
                            .map(|(filename, data)| {
                                let full_path = PathBuf::from(filename);
                                let nested_origin =
                                    OriginSet::new(Origin::from_file(full_path), vec![]);
                                // Construct a FileResult for deeper extraction if needed (not used
                                // directly here)
                                let _ = FileResult {
                                    path: self.path.join(filename),
                                    num_bytes: data.len() as u64,
                                    extract_archives: self.extract_archives,
                                    extraction_depth: max_extraction_depth - 1,
                                };
                                (nested_origin, Blob::from_bytes(data.to_vec()))
                            })
                            .collect();
                        Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Archive(items),
                            _marker: PhantomData,
                        }))
                    }

                    // Multi‑file archive (files on disk).
                    CompressedContent::ArchiveFiles(ref entries) => {
                        if max_extraction_depth == 0 {
                            debug!(
                                "Skipping nested archive (max depth reached): {}",
                                self.path.display()
                            );
                            return Ok(None);
                        }
                        // Read each extracted file from disk and create a Blob.
                        let mut items = Vec::new();
                        for (filename, disk_path) in entries {
                            let blob = match Blob::from_file(disk_path) {
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

                            // Construct a FileResult for deeper extraction if needed (not used
                            // directly here)
                            let _ = FileResult {
                                path: self.path.join(filename),
                                num_bytes: blob.len() as u64,
                                extract_archives: self.extract_archives,
                                extraction_depth: max_extraction_depth - 1,
                            };
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
                    Ok(None) // Skip on decompression failure
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

// A marker so the struct itself carries the lifetime.
struct GitRepoResultIter<'a> {
    inner: GitRepoResult,
    deadline: std::time::Instant,
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
        let repo_sync = self.inner.repository.into_sync();
        let repo_path = Arc::new(self.inner.path.clone());
        let deadline = self.deadline;
        let flag = Arc::new(AtomicBool::new(false)); // first-timeout gate

        self.inner
            .blobs
            .into_par_iter()
            .with_min_len(1024)
            .map_init(|| repo_sync.to_thread_local(), {
                let repo_path = Arc::clone(&repo_path);
                let flag = Arc::clone(&flag);

                move |repo: &mut GixRepo, md| -> Result<(OriginSet, Blob)> {
                    // ── 10-minute guard ──────────────────────────
                    if StdInstant::now() > deadline {
                        if flag.swap(true, Ordering::Relaxed) {
                            bail!("__timeout_silenced__");
                        }
                        bail!("blob-read timeout (repo: {})", repo_path.display());
                    }

                    // ── load blob ────────────────────────────────
                    let blob_id = md.blob_oid;
                    let mut raw = repo.find_object(blob_id)?.try_into_blob()?;
                    let blob = Blob::new(BlobId::from(&blob_id), std::mem::take(&mut raw.data));

                    // ── build Origin — CLONE Arc & PathBuf ──────
                    let origin = OriginSet::try_from_iter(md.first_seen.iter().map(|e| {
                        Origin::from_git_repo_with_first_commit(
                            Arc::clone(&repo_path),
                            Arc::clone(&e.commit_metadata), // ← clone Arc
                            e.path.clone(),                 // ← clone path
                        )
                    }))
                    .unwrap_or_else(|| Origin::from_git_repo(Arc::clone(&repo_path)).into());

                    Ok((origin, blob))
                }
            })
            .filter(|res| {
                !matches!(res,
                    Err(e) if e.to_string() == "__timeout_silenced__"
                )
            })
            .drive_unindexed(consumer)
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

                if !cfg.enumerate_git_history {
                    return Ok(None);
                }

                // Try to open a Git repository at that path
                let repository = match open_git_repo(path)? {
                    Some(r) => r,
                    None => return Ok(None),
                };

                debug!("Found Git repository at {}", path.display());
                let t_start = Instant::now();
                let collect_git_metadata = cfg.collect_git_metadata;
                let timeout = cfg.repo_scan_timeout;

                // Spawn an enumerator thread so we can time-out cleanly
                let path_clone = path.to_path_buf();
                let (tx, rx) = std::sync::mpsc::channel();
                let handle = std::thread::spawn(move || {
                    let res = if collect_git_metadata {
                        GitRepoWithMetadataEnumerator::new(&path_clone, repository).run()
                    } else {
                        GitRepoEnumerator::new(&path_clone, repository).run()
                    };
                    let _ = tx.send(res);
                });

                // Wait for enumeration, polling every 100 ms
                let git_result = loop {
                    if t_start.elapsed() > timeout {
                        debug!(
                            "Git repo enumeration at {} timed-out after {:.1}s (> {} s)",
                            path.display(),
                            t_start.elapsed().as_secs_f64(),
                            timeout.as_secs()
                        );
                        // Abandon the worker thread and skip this repo
                        return Ok(None);
                    }

                    match rx.try_recv() {
                        Ok(res) => break res,
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            debug!("Enumerator thread disconnected for {}", path.display());
                            return Ok(None);
                        }
                    }
                };

                let _ = handle.join(); // avoid leak

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

                        // Convert to a blob iterator, then patch the deadline
                        repo_result
                            .into_blob_iter() // Option<GitRepoResultIter>
                            .map(|iter| {
                                iter.map(|mut gri| {
                                    gri.deadline = Instant::now() + timeout;
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
