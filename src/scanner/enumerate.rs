use crate::limits::ResourceLimits;
use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{Cursor, ErrorKind, Read, Seek},
    marker::PhantomData,
    path::{Component, Path, PathBuf},
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
use kingfisher_scanner::archive::{
    ScanArchive, ScanArchiveData, ScanArchiveMember,
    scan_tar::{scan_tar, scan_tar_bytes},
    scan_zip::scan_zip,
};
use kingfisher_scanner::extraction::pdf::{
    extract_pdf_text_from_bytes_with_budget, extract_pdf_text_from_bytes_with_control,
    extract_pdf_text_from_bytes_with_limits, extract_pdf_text_with_limits, has_pdf_magic,
};
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
    git_candidates::{GitContentFilter, RetainedGitBlob},
    git_commit_metadata::{CommitMetadata, intern_git_identity},
    git_repo_enumerator::{GitBlobMetadata, GitBlobSource, MIN_SCANNABLE_BLOB_SIZE},
    input::scan_repo_from_sync,
    matcher::{Match, Matcher, MatcherStats, NativeScan},
    open_git_repo_with_options,
    origin::{Origin, OriginSet},
    pyc::extract_pyc_strings_with_limits,
    rule_profiling::ConcurrentRuleProfiler,
    rules_database::RulesDatabase,
    scanner::{
        processing::{BlobProcessor, ProcessedBlob},
        storage::{create_datastore_channel, spawn_datastore_writer_thread},
        util::{is_compressed_content, is_compressed_file, is_pyc_file, is_sqlite_file},
    },
    scanner_pool::ScannerPool,
    sqlite::extract_sqlite_contents_with_limits,
};

// The optional selection path preserves archive-member or PDF-container selection.
// Literal `!` characters in ordinary source paths are never archive delimiters.
type LoadedBlob<'a> = (OriginSet, Blob<'a>, Option<String>, LoadedBlobContext);
type LoadedGitBlobs<'a> = Box<dyn Iterator<Item = LoadedBlob<'a>> + Send + 'a>;

// Keep a PDF's representations in one scan job. Raw matches establish the
// canonical location before extracted pages can report the same occurrence.
#[derive(Debug, Default)]
struct LoadedBlobContext {
    pages: Vec<(String, Vec<u8>)>,
    control: kingfisher_scanner::ScanControl,
    // Share the repository's once-only timeout diagnostic with in-flight pages.
    timeout_reported: Option<Arc<AtomicBool>>,
    // The Git prepass scanned the exact bytes of this raw blob without a native hit.
    native_negative: bool,
}

fn check_pdf_control(
    control: &kingfisher_scanner::ScanControl,
    timeout_reported: Option<&AtomicBool>,
) -> Result<()> {
    control.check().map_err(|error| {
        if timeout_reported.is_some_and(|flag| flag.swap(true, Ordering::Relaxed)) {
            anyhow!("__timeout_silenced__")
        } else {
            error.into()
        }
    })
}

fn pdf_page_origin(origin: &OriginSet, name: &str) -> OriginSet {
    OriginSet::try_from_iter(origin.iter().map(|source| match source {
        Origin::File(file) => {
            Origin::from_file(PathBuf::from(format!("{}!{name}", file.path.display())))
        }
        Origin::GitRepo(repo) => match &repo.first_commit {
            Some(commit) => Origin::from_git_repo_with_first_commit(
                Arc::clone(&repo.repo_path),
                Arc::clone(&commit.commit_metadata),
                format!("{}!{name}", commit.blob_path),
            ),
            None => source.clone(),
        },
        Origin::Extended(_) => source.clone(),
    }))
    .expect("a PDF retains its container origins")
}

fn pdf_match_key(finding: &Match) -> [u8; 32] {
    super::processing::pdf_match_key(
        finding.rule.id(),
        &finding.groups,
        &finding.dependent_captures,
        &finding.ambiguous_dependencies,
        &finding.dependency_candidates,
    )
}

fn keep_pdf_match(raw_matches: &mut HashMap<[u8; 32], usize>, key: [u8; 32]) -> bool {
    if let Some(count) = raw_matches.get_mut(&key)
        && *count > 0
    {
        *count -= 1;
        false
    } else {
        true
    }
}

// Canonical Windows inputs use verbatim prefixes, while current_dir and walker
// paths can use ordinary DOS/UNC prefixes for the same location. Compare those
// prefix components equivalently without resolving symlinks or changing origins.
fn strip_selection_prefix<'a>(path: &'a Path, prefix: &Path) -> Option<&'a Path> {
    #[cfg(windows)]
    use std::path::{Component, Prefix};

    let mut components = path.components();
    for expected in prefix.components() {
        let actual = components.next()?;
        #[cfg(not(windows))]
        let matches = actual == expected;
        #[cfg(windows)]
        let matches = match (actual, expected) {
            (Component::Prefix(actual), Component::Prefix(expected)) => {
                match (actual.kind(), expected.kind()) {
                    (
                        Prefix::Disk(a) | Prefix::VerbatimDisk(a),
                        Prefix::Disk(b) | Prefix::VerbatimDisk(b),
                    ) => a == b,
                    (
                        Prefix::UNC(a_server, a_share) | Prefix::VerbatimUNC(a_server, a_share),
                        Prefix::UNC(b_server, b_share) | Prefix::VerbatimUNC(b_server, b_share),
                    ) => a_server == b_server && a_share == b_share,
                    _ => actual == expected,
                }
            }
            _ => actual == expected,
        };
        if !matches {
            return None;
        }
    }
    Some(components.as_path())
}

fn matches_selected_file(
    selection: &crate::path_selection::PathSelection,
    path: &Path,
    roots: &[PathBuf],
    base: &Path,
) -> bool {
    let absolute = if path.is_absolute() { path.to_owned() } else { base.join(path) };
    let relative = roots
        .iter()
        .filter_map(|root| {
            strip_selection_prefix(&absolute, root)
                .map(|relative| (root.components().count(), relative))
        })
        .max_by_key(|(depth, _)| *depth)
        .map(|(_, relative)| relative)
        .unwrap_or_else(|| strip_selection_prefix(&absolute, base).unwrap_or(path));
    selection.matches(&relative.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
}

struct EnumeratorConfig<'a> {
    path_selection: crate::path_selection::PathSelection,
    selection_roots: Vec<PathBuf>,
    selection_base: PathBuf,
    #[cfg(windows)]
    explicit_paths: HashSet<&'a Path>,
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
    /// Maximum size of a filesystem file or Git blob, from `--max-file-size`.
    max_blob_size: Option<u64>,
    git_content_filter: Option<GitContentFilter<'a>>,
}

#[allow(clippy::too_many_arguments)]
pub fn enumerate_filesystem_inputs(
    args: &scan::ScanArgs,
    datastore: Arc<Mutex<findings_store::FindingsStore>>,
    input_roots: &[PathBuf],
    discovered_repos: &[PathBuf],
    _progress_enabled: bool,
    rules_db: &RulesDatabase,
    enable_profiling: bool,
    shared_profiler: Arc<ConcurrentRuleProfiler>,
    matcher_stats: &Mutex<MatcherStats>,
    pre_commit_files: Option<&[PathBuf]>,
) -> Result<bool> {
    let repo_scan_timeout = args.repository_timeout();
    let selection_base = if args.content_filtering_args.path_selection.is_empty() {
        PathBuf::new()
    } else {
        std::env::current_dir()
            .context("Cannot resolve the working directory for path selection")?
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

    let _scanning_progress = crate::scan_progress::scanning();
    if input_roots.is_empty() {
        return Err(
            anyhow!("No inputs provided").context("Failed to initialize filesystem enumerator")
        );
    }

    let max_blob_size = args.content_filtering_args.max_file_size_bytes();
    let extract_archives = !args.content_filtering_args.no_extract_archives;
    let extraction_depth = args.content_filtering_args.archive_depth();
    let resources = args.content_filtering_args.resource_limits();
    let (enum_thread, input_recv, exclude_globset) = {
        let pre_commit_selection = pre_commit_files.map(|files| {
            let limits = SelectedFileLimits {
                max_file_size: max_blob_size,
                extract_archives,
                extraction_depth,
                resources,
            };
            (files.to_vec(), limits)
        });
        let (fs_enumerator, exclude_globset) = if pre_commit_selection.is_some() {
            (None, crate::build_exclude_globset(&args.content_filtering_args.exclude)?)
        } else {
            let fs_enumerator = make_fs_enumerator(args, input_roots.to_vec(), discovered_repos)
                .context("Failed to initialize filesystem enumerator")?;
            let exclude_globset = fs_enumerator.as_ref().and_then(|ie| ie.exclude_globset());
            (fs_enumerator, exclude_globset)
        };
        let excludes_for_thread = exclude_globset.clone();
        let channel_size = std::cmp::max(args.num_jobs * 128, 1024);

        let (input_send, input_recv) = crossbeam_channel::bounded(channel_size);
        let diff_config_for_thread = diff_config.clone();
        let roots_for_thread = input_roots.to_vec();
        let input_enumerator_thread = std::thread::Builder::new()
            .name("input_enumerator".to_string())
            .spawn(move || -> Result<_> {
                if let Some((files, limits)) = pre_commit_selection {
                    let root = roots_for_thread.first().context("Missing pre-commit scan root")?;
                    enumerate_pre_commit_files(
                        root,
                        &files,
                        excludes_for_thread.as_deref(),
                        limits,
                        &input_send,
                    )?;
                } else if diff_config_for_thread.is_some() {
                    for root in roots_for_thread {
                        input_send
                            .send(FoundInput::Directory(DirectoryResult { path: root }))
                            .context("Failed to queue repository for scanning")?;
                    }
                } else if let Some(fs_enumerator) = fs_enumerator {
                    fs_enumerator.run_with_deferred_file_size(input_send)?;
                }
                Ok(())
            })
            .context("Failed to enumerate filesystem inputs")?;
        (input_enumerator_thread, input_recv, exclude_globset)
    };

    let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
    // Path-only rules can match content negatives. A narrow path selection is
    // also cheaper with eager metadata because it can skip out-of-scope reads.
    let can_prefilter =
        args.content_filtering_args.path_selection.is_empty() && !rules_db.has_path_only_rules();
    let git_content_filter = can_prefilter.then(|| {
        let filter = GitContentFilter::new(
            Arc::clone(&scanner_pool),
            rules_db.num_rules(),
            !args.no_base64,
            extract_archives,
            args.content_filtering_args.resource_limits(),
        )
        .with_archive_depth(extraction_depth)
        .with_max_blob_size(max_blob_size);
        if (0..rules_db.num_rules()).any(|index| rules_db.uses_vectorscan_prefilter(index)) {
            filter.with_chunked_prefilters(|| rules_db.chunked_prefilter_scanners())
        } else {
            filter
        }
    });
    let enum_cfg = EnumeratorConfig {
        path_selection: args.content_filtering_args.path_selection.clone(),
        selection_roots: input_roots
            .iter()
            .chain(discovered_repos)
            .map(|path| if path.is_absolute() { path.clone() } else { selection_base.join(path) })
            // Explicit file inputs are selected by their cwd-relative path, not just their leaf.
            .filter(|path| !path.is_file())
            .collect(),
        selection_base,
        #[cfg(windows)]
        explicit_paths: if pre_commit_files.is_none() {
            input_roots.iter().map(PathBuf::as_path).collect()
        } else {
            HashSet::new()
        },
        enumerate_git_history: match args.input_specifier_args.git_history {
            GitHistoryMode::Full => true,
            GitHistoryMode::None => false,
        },
        collect_git_metadata: args.input_specifier_args.commit_metadata
            || !args.content_filtering_args.path_selection.is_empty(),
        repo_scan_timeout,
        exclude_globset: exclude_globset.clone(),
        git_diff: diff_config.clone(),
        history_all_refs: (args.input_specifier_args.since_commit.is_some()
            || args.input_specifier_args.since_hours.is_some())
            && args.input_specifier_args.branch.is_none(),
        history_time_range: args.input_specifier_args.resolved_history_time_range(),
        extract_archives,
        extraction_depth,
        resources,
        max_blob_size,
        git_content_filter,
    };
    let (send_ds, recv_ds) = create_datastore_channel(args.num_jobs);
    let datastore_writer_thread =
        spawn_datastore_writer_thread(datastore, recv_ds, !args.no_dedup)?;

    let t1 = Instant::now();
    let had_errors = Arc::new(AtomicBool::new(false));
    let num_blob_processors = Mutex::new(0u64);
    let seen_blobs = BlobIdMap::new();

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
    let selection_roots = enum_cfg.selection_roots.clone();
    let selection_base = enum_cfg.selection_base.clone();
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
            || make_blob_processor.clone()(),
            move |processor, entry| {
                let (origin, blob, archive_member, context) = match entry {
                    Err(e) => {
                        had_errors_for_processing.store(true, Ordering::Relaxed);
                        error!("Error loading input: {e:#}");
                        return Ok(());
                    }
                    Ok(entry) => entry,
                };
                let LoadedBlobContext { pages, control, timeout_reported, native_negative } =
                    context;
                let is_pdf = !pages.is_empty();
                let page_origin = is_pdf.then(|| origin.clone());
                let page_selection = if is_pdf {
                    archive_member.clone().or_else(|| {
                        let source = origin.first();
                        let path = source.blob_path()?;
                        let path = if matches!(source, Origin::File(_)) {
                            std::path::absolute(path).ok()?
                        } else {
                            path.to_path_buf()
                        };
                        Some(path.to_string_lossy().into_owned())
                    })
                } else {
                    None
                };
                let pages = pages.into_iter().map(|(name, bytes)| {
                    (
                        false,
                        pdf_page_origin(page_origin.as_ref().unwrap(), &name),
                        Blob::from_bytes(bytes),
                        page_selection.clone(),
                    )
                });
                let mut raw_matches = HashMap::<[u8; 32], usize>::new();
                // Progress counts occurrences, including duplicate pages, independently
                // of storage suppression. Duplicate blobs must never consume the latter.
                let mut raw_observations = HashMap::<[u8; 32], usize>::new();
                for (is_raw, mut origin, blob, archive_member) in
                    std::iter::once((true, origin, blob, archive_member)).chain(pages)
                {
                    if let Err(error) = check_pdf_control(&control, timeout_reported.as_deref()) {
                        had_errors_for_processing.store(true, Ordering::Relaxed);
                        if error.to_string() != "__timeout_silenced__" {
                            error!("Error loading PDF content: {error:#}");
                        }
                        break;
                    }
                    if !args.content_filtering_args.path_selection.is_empty() {
                        let selection = &args.content_filtering_args.path_selection;
                        let selected = origin
                            .iter()
                            .filter(|source| {
                                if let Some(member) = &archive_member {
                                    if Path::new(member).is_absolute()
                                        && matches!(source, Origin::File(_))
                                    {
                                        return matches_selected_file(
                                            selection,
                                            Path::new(member),
                                            &selection_roots,
                                            &selection_base,
                                        );
                                    }
                                    return selection.matches(member);
                                }
                                match source {
                                    Origin::File(file) => matches_selected_file(
                                        selection,
                                        &file.path,
                                        &selection_roots,
                                        &selection_base,
                                    ),
                                    _ => selection.matches(
                                        &source
                                            .blob_path()
                                            .map(|path| path.to_string_lossy())
                                            .unwrap_or_default(),
                                    ),
                                }
                            })
                            .cloned();
                        let Some(selected) = OriginSet::try_from_iter(selected) else { continue };
                        origin = selected;
                    }
                    let filters = &args.content_filtering_args;
                    if filters.no_extract_archives || filters.no_binary {
                        // Recognize archives by extension or ZIP magic across input modes.
                        // Only non-archive inputs are subject to --no-binary.
                        let path = origin.first().blob_path();
                        let is_archive =
                            path.is_some_and(|path| is_compressed_content(path, blob.bytes()));
                        let skip_kind = if is_archive {
                            filters.no_extract_archives.then_some("archive")
                        } else if filters.no_binary && is_binary(blob.bytes()) {
                            Some("binary blob")
                        } else {
                            None
                        };
                        if let Some(kind) = skip_kind {
                            let path = path
                                .map(|path| path.display().to_string())
                                .unwrap_or_else(|| blob.temp_id().to_string());
                            debug!("Skipping {kind}: {path}");
                            continue;
                        }
                    }
                    match processor.run_with_native_prepass(
                        origin,
                        blob,
                        // Raw PDF matches are also needed for representation-level
                        // suppression when an identical blob was scanned elsewhere.
                        args.no_dedup || is_pdf && is_raw,
                        args.redact,
                        args.no_base64,
                        args.turbo,
                        if native_negative && is_raw {
                            NativeScan::PrepassNegative
                        } else {
                            NativeScan::Required
                        },
                    ) {
                        Ok(None) => {
                            // nothing to record
                        }
                        Ok(Some(ProcessedBlob {
                            message: (origin_set, blob_metadata, mut vec_of_matches),
                            duplicate,
                            duplicate_observations,
                        })) => {
                            if duplicate {
                                crate::scan_progress::found(
                                    duplicate_observations.into_iter().filter_map(
                                        |(visible, key)| {
                                            (!is_pdf
                                                || !visible
                                                || keep_pdf_match(&mut raw_observations, key))
                                            .then_some(visible)
                                        },
                                    ),
                                    origin_set.len() as u64,
                                );
                                continue;
                            }
                            // Count progress before storage suppression, with its own PDF
                            // counts so duplicate pages cannot affect report contents.
                            if crate::scan_progress::enabled() {
                                crate::scan_progress::found(
                                    vec_of_matches.iter().filter_map(|(_, finding)| {
                                        (!is_pdf
                                            || is_raw
                                            || !finding.visible
                                            || keep_pdf_match(
                                                &mut raw_observations,
                                                pdf_match_key(finding),
                                            ))
                                        .then_some(finding.visible)
                                    }),
                                    origin_set.len() as u64,
                                );
                            }
                            if is_pdf {
                                if is_raw {
                                    for (_, finding) in &vec_of_matches {
                                        if finding.visible {
                                            *raw_matches
                                                .entry(pdf_match_key(finding))
                                                .or_default() += 1;
                                        }
                                    }
                                    if crate::scan_progress::enabled() {
                                        raw_observations.clone_from(&raw_matches);
                                    }
                                } else {
                                    vec_of_matches.retain(|(_, finding)| {
                                        !finding.visible
                                            || keep_pdf_match(
                                                &mut raw_matches,
                                                pdf_match_key(finding),
                                            )
                                    });
                                }
                            }
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
    // Clear negatives were scanned by the content prepass instead of the matcher.
    // Include them in coverage statistics without counting retained candidates twice.
    if let Some(filter) = &enum_cfg.git_content_filter {
        matcher_stats.lock().unwrap().update(&filter.clean_stats());
    }
    let had_errors = had_errors.load(Ordering::Relaxed);
    if had_errors && pre_commit_files.is_some() {
        bail!("Could not scan all files selected by pre-commit");
    }
    Ok(had_errors)
}

/// Content limits shared by every file a pre-commit runner selects.
#[derive(Clone, Copy)]
struct SelectedFileLimits {
    max_file_size: Option<u64>,
    extract_archives: bool,
    extraction_depth: Option<usize>,
    resources: ResourceLimits,
}

fn enumerate_pre_commit_files(
    root: &Path,
    files: &[PathBuf],
    excludes: Option<&globset::GlobSet>,
    limits: SelectedFileLimits,
    output: &crate::input::Output,
) -> Result<()> {
    let SelectedFileLimits { max_file_size, extract_archives, extraction_depth, resources } =
        limits;
    inspect_pre_commit_files(root, files, excludes, |relative, metadata| {
        if max_file_size.is_some_and(|max| metadata.len() > max) {
            debug!("Skipping {} due to --max-file-size", root.join(relative).display());
            return Ok(());
        }
        output.send(FoundInput::File(FileResult {
            // The runner invokes us from the root. Use its relative path for
            // rule expressions and findings, as Git scans do.
            path: relative.to_owned(),
            num_bytes: metadata.len(),
            extract_archives,
            extraction_depth,
            resources,
        }))?;
        Ok(())
    })
}

pub(super) fn inspect_pre_commit_files(
    root: &Path,
    files: &[PathBuf],
    excludes: Option<&globset::GlobSet>,
    mut visit: impl FnMut(&Path, std::fs::Metadata) -> Result<()>,
) -> Result<()> {
    let canonical_root = root.canonicalize().context("Failed to resolve pre-commit scan root")?;
    for relative in files {
        let path = root.join(relative);
        if excludes.is_some_and(|gs| {
            relative
                .ancestors()
                .take_while(|ancestor| !ancestor.as_os_str().is_empty())
                .any(|ancestor| gs.is_match(ancestor) || gs.is_match(root.join(ancestor)))
        }) {
            debug!("Skipping {} due to --exclude", path.display());
            continue;
        }
        let metadata = path
            .symlink_metadata()
            .with_context(|| format!("Failed to inspect pre-commit file {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            // Git records a symlink as its target path, and a selected target is scanned on its
            // own. Following the link could also read content outside the repository.
            debug!("Skipping symlink {} selected by pre-commit", path.display());
            continue;
        }
        if !metadata.is_file() {
            bail!("Pre-commit file must be a regular file: {}", path.display());
        }
        let canonical_path = path
            .canonicalize()
            .with_context(|| format!("Failed to resolve pre-commit file {}", path.display()))?;
        if !canonical_path.starts_with(&canonical_root) {
            bail!("Pre-commit file is outside the working directory: {}", path.display());
        }
        visit(relative, metadata)?;
    }
    Ok(())
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
    type Item = Result<LoadedBlob<'a>>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        match self.iter_kind {
            FileResultIterKind::Single(maybe_one) => {
                let mut folder = consumer.into_folder();
                if let Some((origin, blob)) = maybe_one {
                    folder = folder.consume(Ok((origin, blob, None, LoadedBlobContext::default())));
                }
                folder.complete()
            }
            FileResultIterKind::Archive(items) => {
                items.into_par_iter().map(Ok).drive_unindexed(consumer)
            }
            // Extraction advances one member at a time. Rayon hands each ready
            // blob to a worker without queuing more extracted members.
            FileResultIterKind::Stream(items) => items
                .par_bridge()
                .map(|item| -> Result<LoadedBlob<'a>> { Ok(item) })
                .drive_unindexed(consumer),
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

fn file_looks_like_pdf(path: &Path) -> bool {
    let mut header = [0u8; 5];
    std::fs::File::open(path).and_then(|mut file| file.read_exact(&mut header)).is_ok()
        && has_pdf_magic(&header)
}

fn read_prefix<'a>(reader: &mut impl Read, header: &'a mut [u8; 5]) -> &'a [u8] {
    let mut len = 0;
    while len < header.len() {
        match reader.read(&mut header[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    &header[..len]
}

const SMALL_FILE_BUFFER_LIMIT: u64 = 16 * 1024;

fn read_small_file(file: &mut (impl Read + Seek), size: usize) -> std::io::Result<Option<Vec<u8>>> {
    // Request one extra byte so an observed growth can go through the general
    // loader while the buffer stays bounded, even when a read stops at the
    // reported size before EOF.
    let mut bytes = vec![0; size + 1];
    let mut filled = 0;
    while filled < bytes.len() {
        match file.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if filled > size {
        file.rewind()?;
        return Ok(None);
    }
    bytes.truncate(filled);
    Ok(Some(bytes))
}

enum FileOpenMode {
    NoFollow,
    #[cfg(windows)]
    ExplicitWindowsPath,
}

fn open_scan_file(path: &Path, mode: FileOpenMode) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    match mode {
        FileOpenMode::NoFollow => {
            // A queued regular file could have been replaced before we opened it.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
        }
        #[cfg(windows)]
        FileOpenMode::ExplicitWindowsPath => {} // Direct inputs have always used the target.
    }
    options.open(path)
}

impl FileResult {
    fn into_blob_iter<'a>(
        self,
        max_file_size: Option<u64>,
        selected: bool,
        mode: FileOpenMode,
    ) -> Result<Option<FileResultIter<'a>>> {
        let extraction_enabled = self.extract_archives;
        let max_extraction_depth = self.extraction_depth;
        let resources = self.resources;

        if !selected && !extraction_enabled {
            return Ok(None);
        }
        let archive_by_extension = !selected && is_compressed_file(&self.path);
        let load_error = || format!("Failed to load blob from {}", self.path.display());
        let mut file = match open_scan_file(&self.path, mode) {
            Err(_) if !selected && !archive_by_extension => return Ok(None),
            result => result.with_context(load_error)?,
        };
        let metadata = file.metadata().with_context(load_error)?;
        let mut file_size = metadata.len();
        if !metadata.is_file() || max_file_size.is_some_and(|max| file_size > max) {
            debug!(
                "Skipping {}: not a regular file or size {file_size} too big",
                self.path.display()
            );
            return Ok(None);
        }

        // A path outside the selection only needs a short ZIP probe unless its
        // extension already opts it into archive processing.
        let mut buffered = if (selected || archive_by_extension)
            && (1..=SMALL_FILE_BUFFER_LIMIT).contains(&file_size)
        {
            let buffered =
                read_small_file(&mut file, file_size as usize).with_context(load_error)?;
            if buffered.is_none() {
                file_size = file.metadata().with_context(load_error)?.len();
                if max_file_size.is_some_and(|max| file_size > max) {
                    return Ok(None);
                }
            }
            buffered
        } else {
            None
        };

        // Check magic on raw bytes before Blob normalizes text encodings.
        let mut header = [0; 5];
        let prefix = if !extraction_enabled {
            &[]
        } else if let Some(bytes) = &buffered {
            let len = bytes.len().min(header.len());
            header[..len].copy_from_slice(&bytes[..len]);
            &header[..len]
        } else {
            read_prefix(&mut file, &mut header)
        };
        if !selected && !archive_by_extension && !looks_like_zip(prefix) {
            return Ok(None);
        }

        if extraction_enabled && is_sqlite_file(&self.path) {
            return match extract_sqlite_contents_with_limits(&self.path, resources) {
                Ok(tables) if tables.is_empty() => {
                    debug!("No tables found in SQLite database: {}", self.path.display());
                    self.raw_blob_iter(file, prefix, file_size, buffered).map(Some)
                }
                Ok(tables) => {
                    let items = tables
                        .into_iter()
                        .map(|(logical_name, data)| {
                            let full_path = self.path.join(logical_name);
                            let origin = OriginSet::new(Origin::from_file(full_path), vec![]);
                            (origin, Blob::from_bytes(data), None, LoadedBlobContext::default())
                        })
                        .collect();
                    Ok(Some(FileResultIter {
                        iter_kind: FileResultIterKind::Archive(items),
                        _marker: PhantomData,
                    }))
                }
                Err(e) => {
                    debug!("Failed to extract SQLite database {}: {e:#}", self.path.display());
                    self.raw_blob_iter(file, prefix, file_size, buffered).map(Some)
                }
            };
        }
        if extraction_enabled && is_pyc_file(&self.path) {
            return match extract_pyc_strings_with_limits(&self.path, resources) {
                Ok(strings) if strings.is_empty() => {
                    debug!("No strings found in .pyc file: {}", self.path.display());
                    self.raw_blob_iter(file, prefix, file_size, buffered).map(Some)
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
                    self.raw_blob_iter(file, prefix, file_size, buffered).map(Some)
                }
            };
        }

        if has_pdf_magic(prefix) {
            let pages = match &buffered {
                Some(bytes) => extract_pdf_text_from_bytes_with_limits(bytes, resources),
                None => extract_pdf_text_with_limits(&self.path, resources),
            };
            match pages {
                Ok(pages) if !pages.is_empty() => {
                    // Page text augments raw coverage; metadata, links and
                    // attachments need not appear in the extracted text.
                    let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
                    let items = vec![(
                        origin,
                        self.raw_blob(file, prefix, file_size, buffered)?,
                        None,
                        LoadedBlobContext { pages, ..Default::default() },
                    )];
                    return Ok(Some(FileResultIter {
                        iter_kind: FileResultIterKind::Archive(items),
                        _marker: PhantomData,
                    }));
                }
                Ok(_) => {}
                Err(_) => {
                    debug!(path = %self.path.display(), "PDF text extraction failed or exceeded limits; scanning raw bytes");
                }
            }
        } else if extraction_enabled
            && (archive_by_extension || is_compressed_file(&self.path) || looks_like_zip(prefix))
        {
            match stream_file_archive(
                &mut file,
                &self.path,
                prefix,
                file_size,
                resources,
                &mut buffered,
            ) {
                Ok(Some((archive, shared_budget))) => {
                    return match archive {
                        ScanArchive::Original => {
                            if buffered.is_none() {
                                file.rewind()?;
                            }
                            self.raw_blob_iter(file, &[], file_size, buffered).map(Some)
                        }
                        ScanArchive::Raw(data) => {
                            Ok(Some(self.single_blob_iter(scan_archive_blob(data)?)))
                        }
                        ScanArchive::Members(entries) => {
                            if max_extraction_depth == Some(0) {
                                return Ok(None);
                            }
                            Ok(Some(FileResultIter {
                                iter_kind: FileResultIterKind::Stream(streamed_archive_blobs(
                                    entries,
                                    max_extraction_depth.map(|depth| depth - 1),
                                    resources,
                                    self.path.to_string_lossy().into_owned(),
                                    shared_budget,
                                )),
                                _marker: PhantomData,
                            }))
                        }
                    };
                }
                Ok(None) => {}
                Err(e) => debug!("Streaming archive {} failed: {e:#}", self.path.display()),
            }
            match decompress_file_to_temp_with_limits(&self.path, resources) {
                Ok((content, _temp_dir)) => match content {
                    // Single-file decompression fully in memory.
                    CompressedContent::Raw(ref data) => {
                        let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
                        let blob = Blob::from_bytes(data.to_vec());
                        return Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Single(Some((origin, blob))),
                            _marker: PhantomData,
                        }));
                    }

                    // Single-file decompression streamed to a file. We read it back into memory
                    // here.
                    CompressedContent::RawFile(path) => {
                        let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
                        let blob = Blob::from_file(&path)?;
                        return Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Single(Some((origin, blob))),
                            _marker: PhantomData,
                        }));
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
                            Some(self.path.to_string_lossy().into_owned()),
                        )?
                        .into_iter()
                        .map(|(filename, data, member, pages)| {
                            let origin =
                                OriginSet::new(Origin::from_file(PathBuf::from(filename)), vec![]);
                            (origin, Blob::from_bytes(data), member, pages)
                        })
                        .collect();
                        return Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Archive(items),
                            _marker: PhantomData,
                        }));
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
                            if (file_looks_like_pdf(&disk_path)
                                || max_extraction_depth.is_none_or(|depth| depth > 1)
                                    && (is_compressed_file(Path::new(&filename))
                                        || file_header_looks_like_zip(&disk_path)))
                                && let Ok(data) = std::fs::read(&disk_path)
                            {
                                let nested = recursively_expand_archive_entries(
                                    vec![(filename.clone(), data)],
                                    max_extraction_depth.map(|depth| depth - 1),
                                    resources,
                                    Some(self.path.to_string_lossy().into_owned()),
                                )?;
                                // A successful nested extraction replaces the archive entry
                                // with its contents. Invalid or empty archives are returned as
                                // the original entry by the helper and remain scanable below.
                                if nested.len() != 1
                                    || nested[0].0 != filename
                                    || !nested[0].3.pages.is_empty()
                                {
                                    for (logical, data, member, pages) in nested {
                                        let origin = OriginSet::new(
                                            Origin::from_file(PathBuf::from(logical)),
                                            vec![],
                                        );
                                        items.push((origin, Blob::from_bytes(data), member, pages));
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
                            let member = member_path(&filename, &self.path.to_string_lossy());
                            let full_path = PathBuf::from(filename);
                            let nested_origin =
                                OriginSet::new(Origin::from_file(full_path), vec![]);

                            items.push((nested_origin, blob, member, LoadedBlobContext::default()));
                        }
                        return Ok(Some(FileResultIter {
                            iter_kind: FileResultIterKind::Archive(items),
                            _marker: PhantomData,
                        }));
                    }
                },
                Err(e) => {
                    debug!("Failed to decompress {}: {}", self.path.display(), e);
                }
            }
        }
        self.raw_blob_iter(file, prefix, file_size, buffered).map(Some)
    }
}

impl FileResult {
    fn raw_blob_iter(
        &self,
        file: File,
        prefix: &[u8],
        file_size: u64,
        buffered: Option<Vec<u8>>,
    ) -> Result<FileResultIter<'static>> {
        Ok(self.single_blob_iter(self.raw_blob(file, prefix, file_size, buffered)?))
    }

    fn raw_blob(
        &self,
        file: File,
        prefix: &[u8],
        file_size: u64,
        buffered: Option<Vec<u8>>,
    ) -> Result<Blob<'static>> {
        if let Some(bytes) = buffered {
            return Ok(Blob::from_bytes(bytes));
        }
        Blob::from_open_file_with_size(file, prefix, file_size)
            .with_context(|| format!("Failed to load blob from {}", self.path.display()))
    }

    fn single_blob_iter(&self, blob: Blob<'static>) -> FileResultIter<'static> {
        let origin = OriginSet::new(Origin::from_file(self.path.clone()), vec![]);
        FileResultIter {
            iter_kind: FileResultIterKind::Single(Some((origin, blob))),
            _marker: PhantomData,
        }
    }
}

type OwnedArchiveEntry = (String, Vec<u8>);

fn stream_file_archive(
    file: &mut File,
    path: &Path,
    prefix: &[u8],
    file_size: u64,
    resources: ResourceLimits,
    buffered: &mut Option<Vec<u8>>,
) -> Result<Option<(ScanArchive, bool)>> {
    if file_size == 0
        || path.components().enumerate().any(|(index, part)| {
            matches!(part, Component::ParentDir)
                || index > 0 && matches!(part, Component::Prefix(_))
        })
    {
        return Ok(None);
    }
    let extension = path.extension().and_then(|ext| ext.to_str()).map(str::to_ascii_lowercase);
    let extension = extension.as_deref().unwrap_or_default();
    let named_zip = ZIP_BASED_FORMATS.contains(&extension);
    // Keep the legacy extension dispatch when a recognized non-ZIP format
    // happens to have ZIP signature bytes.
    let magic_zip = looks_like_zip(prefix)
        && !matches!(
            extension,
            "tar"
                | "gz"
                | "gzip"
                | "tgz"
                | "bz2"
                | "bzip2"
                | "xz"
                | "zlib"
                | "asar"
                | "hwp"
                | "egg"
        );
    if named_zip || magic_zip {
        let small_sniffed_zip = !named_zip && file_size <= MAX_INMEM_ZIP_ARCHIVE_BYTES as u64;
        let archive = if let Some(bytes) = buffered.take() {
            let bytes = Arc::new(bytes);
            let reader = Cursor::new(SharedArchive(Arc::clone(&bytes)));
            let archive = scan_zip(reader, path, file_size, !named_zip, resources);
            if !matches!(&archive, Ok(ScanArchive::Members(_))) {
                *buffered = Some(Arc::unwrap_or_clone(bytes));
            }
            archive
        } else {
            scan_zip(file.try_clone()?, path, file_size, !named_zip, resources)
        };
        return archive.map(|archive| Some((archive, small_sniffed_zip)));
    }
    scan_tar(file, path, resources).map(|archive| archive.map(|archive| (archive, false)))
}

fn scan_archive_blob(data: ScanArchiveData) -> Result<Blob<'static>> {
    match data {
        ScanArchiveData::Bytes(bytes) => Ok(Blob::from_bytes(bytes)),
        ScanArchiveData::File(file) => Ok(Blob::from_open_file(file, &[])?),
        ScanArchiveData::Mapped(mapped) => Ok(Blob::from_memory_map(mapped)),
    }
}

fn scan_archive_bytes(data: ScanArchiveData) -> std::io::Result<Vec<u8>> {
    match data {
        ScanArchiveData::Bytes(bytes) => Ok(bytes),
        ScanArchiveData::Mapped(mapped) => Ok(mapped.to_vec()),
        ScanArchiveData::File(mut file) => {
            file.rewind()?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(bytes)
        }
    }
}

type StreamedArchiveBlobs = Box<dyn Iterator<Item = LoadedBlob<'static>> + Send>;

fn streamed_archive_blobs(
    entries: Box<dyn Iterator<Item = ScanArchiveMember> + Send>,
    depth: Option<usize>,
    resources: ResourceLimits,
    parent: String,
    shared_budget: bool,
) -> StreamedArchiveBlobs {
    let load = |(name, bytes, member, pages): ExpandedArchiveEntry| {
        let origin = OriginSet::new(Origin::from_file(PathBuf::from(name)), vec![]);
        (origin, Blob::from_bytes(bytes), member, pages)
    };
    if shared_budget {
        let entries = entries.filter_map(|entry| match scan_archive_bytes(entry.data) {
            Ok(bytes) => Some((entry.name, bytes)),
            Err(e) => {
                debug!("Failed to load archive member {}: {e}", entry.name);
                None
            }
        });
        return Box::new(
            lazy_expand_entries(Box::new(entries), depth, resources, Some(parent)).map(load),
        );
    }

    Box::new(entries.flat_map(
        move |ScanArchiveMember { name, mut data }| -> StreamedArchiveBlobs {
            let mut header = [0; 5];
            let prefix = match &mut data {
                ScanArchiveData::Bytes(bytes) => read_prefix(&mut bytes.as_slice(), &mut header),
                ScanArchiveData::Mapped(mapped) => read_prefix(&mut &mapped[..], &mut header),
                ScanArchiveData::File(file) => read_prefix(file, &mut header),
            };
            if has_pdf_magic(prefix)
                || depth != Some(0)
                    && (is_compressed_file(Path::new(&name)) || looks_like_zip(prefix))
            {
                match scan_archive_bytes(data) {
                    Ok(bytes) => {
                        return Box::new(
                            lazy_expand_entries(
                                Box::new(std::iter::once((name, bytes))),
                                depth,
                                resources,
                                Some(parent.clone()),
                            )
                            .map(load),
                        );
                    }
                    Err(e) => {
                        debug!("Failed to load archive member {name}: {e}");
                        return Box::new(std::iter::empty());
                    }
                }
            }
            let blob = match data {
                ScanArchiveData::Bytes(bytes) => Ok(Blob::from_bytes(bytes)),
                ScanArchiveData::File(file) => Blob::from_open_file(file, prefix),
                ScanArchiveData::Mapped(mapped) => Ok(Blob::from_memory_map(mapped)),
            };
            match blob {
                Ok(blob) => {
                    let member = member_path(&name, &parent);
                    let origin = OriginSet::new(Origin::from_file(PathBuf::from(name)), vec![]);
                    Box::new(std::iter::once((origin, blob, member, LoadedBlobContext::default())))
                }
                Err(e) => {
                    debug!("Failed to load archive member {name}: {e}");
                    Box::new(std::iter::empty())
                }
            }
        },
    ))
}

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
type ProvenancedArchiveEntry = (String, Vec<u8>, Option<String>);
type ProvenancedArchiveEntries = Box<dyn Iterator<Item = ProvenancedArchiveEntry> + Send>;
type ExpandedArchiveEntry = (String, Vec<u8>, Option<String>, LoadedBlobContext);
type ExpandedArchiveEntries = Box<dyn Iterator<Item = ExpandedArchiveEntry> + Send>;

fn member_path(logical: &str, parent: &str) -> Option<String> {
    logical
        .strip_prefix(parent)?
        .strip_prefix('!')
        .map(|member| member.trim_start_matches('/').to_owned())
}

fn lazy_expand_entries(
    entries: ArchiveEntries,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
    parent: Option<String>,
) -> ExpandedArchiveEntries {
    expand_entries(entries, remaining_depth, resources, true, parent, Default::default())
}

fn expand_entries(
    entries: ArchiveEntries,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
    apply_budget: bool,
    parent: Option<String>,
    control: kingfisher_scanner::ScanControl,
) -> ExpandedArchiveEntries {
    expand_entries_with_pdf_budget(
        entries,
        remaining_depth,
        resources,
        apply_budget,
        parent,
        control,
        MAX_RECURSIVE_ARCHIVE_BYTES as usize,
    )
}

// The explicit PDF budget also lets regression tests exercise the >half-budget
// boundary through a real archive without allocating a 129 MiB fixture.
fn expand_entries_with_pdf_budget(
    entries: ArchiveEntries,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
    apply_budget: bool,
    parent: Option<String>,
    control: kingfisher_scanner::ScanControl,
    pdf_budget: usize,
) -> ExpandedArchiveEntries {
    let entries = expand_entries_with(
        entries,
        remaining_depth,
        resources,
        apply_budget,
        parent,
        move |logical, shared| {
            if looks_like_zip(&shared) && shared.len() <= MAX_INMEM_ZIP_ARCHIVE_BYTES {
                crate::decompress::zip_entries(
                    std::io::Cursor::new(SharedArchive(shared)),
                    logical.to_string(),
                    resources,
                )
                .map(|entries| Box::new(entries) as ArchiveEntries)
            } else {
                extract_archive_bytes(logical, &shared, resources)
            }
        },
    );
    // PDF is a leaf content transform, not another archive level. Extract it
    // even when the surrounding archive has reached its configured depth.
    let mut total = 0usize;
    Box::new(entries.map_while(move |(logical, mut data, member)| {
        let remaining = pdf_budget.saturating_sub(total);
        let archive_entry = apply_budget || member.is_some();
        // Include extracted page text in the same archive-tree budget as later
        // siblings. A failed, unexpanded Git input still keeps its raw bytes.
        if archive_entry {
            if resources.reached(total as u64, pdf_budget as u64) {
                return None;
            }
            if resources.exceeds(data.len() as u64, remaining as u64) {
                data.truncate(remaining);
            }
        }
        if has_pdf_magic(&data) {
            let extracted = if archive_entry {
                extract_archive_pdf_pages(&data, remaining, resources, &control)
            } else if resources.unlimited {
                extract_pdf_text_from_bytes_with_control(&data, resources, &control)
            } else {
                // A standalone Git PDF is not an archive tree. As for a file
                // on disk, its input and page-output caps are independent.
                extract_pdf_text_from_bytes_with_budget(&data, pdf_budget, &control)
            };
            match extracted {
                Ok(pages) if !pages.is_empty() => {
                    total = total.saturating_add(data.len());
                    for (_, bytes) in &pages {
                        total = total.saturating_add(bytes.len());
                    }
                    return Some((
                        logical,
                        data,
                        member,
                        LoadedBlobContext { pages, control: control.clone(), ..Default::default() },
                    ));
                }
                Ok(_) => {}
                // The Git iterator boundary propagates aborts; do not misreport
                // an expired repository deadline as a malformed PDF.
                Err(error) if error.is::<kingfisher_scanner::ScanAborted>() => {}
                Err(_) => debug!(path = %logical, "PDF text extraction failed or exceeded limits; scanning raw bytes"),
            }
        }
        total = total.saturating_add(data.len());
        Some((logical, data, member, LoadedBlobContext::default()))
    }))
}

fn extract_archive_pdf_pages(
    data: &[u8],
    remaining: usize,
    resources: ResourceLimits,
    control: &kingfisher_scanner::ScanControl,
) -> Result<Vec<(String, Vec<u8>)>> {
    if resources.unlimited {
        return extract_pdf_text_from_bytes_with_control(data, resources, control);
    }
    // The extractor checks its input and decoded-work caps separately. Do not
    // subtract the input before passing that cap, which halves the input limit.
    let pages = extract_pdf_text_from_bytes_with_budget(data, remaining, control)?;
    let mut output_remaining = remaining.saturating_sub(data.len());
    for (_, bytes) in &pages {
        if bytes.len() > output_remaining {
            return Err(kingfisher_scanner::extraction::ExtractionLimitExceeded::Bytes.into());
        }
        output_remaining -= bytes.len();
    }
    Ok(pages)
}

fn expand_entries_with(
    entries: ArchiveEntries,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
    mut apply_budget: bool,
    parent: Option<String>,
    mut extract: impl FnMut(&str, Arc<Vec<u8>>) -> Result<ArchiveEntries> + Send + 'static,
) -> ProvenancedArchiveEntries {
    // Track only active ancestors: identical sibling archives must still be
    // scanned at each logical path. Cycles are not additional nesting depth.
    let mut ancestors = std::collections::HashSet::new();
    let mut stack = vec![(entries, remaining_depth, None, parent)];
    let mut total = 0u64;
    Box::new(std::iter::from_fn(move || {
        while !apply_budget || !resources.reached(total, MAX_RECURSIVE_ARCHIVE_BYTES) {
            let (entries, depth, _, parent) = stack.last_mut()?;
            let Some((logical, mut data)) = entries.next() else {
                if let Some((_, _, Some(hash), _)) = stack.pop() {
                    ancestors.remove(&hash);
                }
                continue;
            };
            let depth = *depth;
            let member = parent.as_deref().and_then(|parent| member_path(&logical, parent));
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
                                    Some(logical),
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
            return Some((logical, data, member));
        }
        None
    }))
}

fn lazy_expand_entry(
    logical: String,
    data: Vec<u8>,
    remaining_depth: Option<usize>,
    resources: ResourceLimits,
    control: kingfisher_scanner::ScanControl,
) -> ExpandedArchiveEntries {
    // Failed extraction preserves the entire raw input, as in bounded mode.
    expand_entries(
        Box::new(std::iter::once((logical, data))),
        remaining_depth,
        resources,
        false,
        None,
        control,
    )
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

fn remap_archive_member(logical: &str, extracted: String) -> String {
    match extracted.split_once('!') {
        Some((_, entry)) => format!("{logical}!{entry}"),
        None => format!("{logical}!{extracted}"),
    }
}

/// Extract one archive layer from bytes, returning paths rooted at `logical`.
/// An empty iterator lets the caller scan the original entry as raw content.
fn extract_archive_bytes(
    logical: &str,
    data: &[u8],
    resources: ResourceLimits,
) -> Result<ArchiveEntries> {
    let path = Path::new(logical);
    let is_zip_body = looks_like_zip(data);
    if !is_compressed_file(path) && !is_zip_body {
        return Ok(Box::new(std::iter::empty()));
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
            return Ok(Box::new(std::iter::empty()));
        }
        if data.len() <= MAX_INMEM_ZIP_ARCHIVE_BYTES {
            return match extract_zip_archive_in_memory_with_limits(data, logical, resources) {
                Ok(entries) => Ok(Box::new(entries.into_iter())),
                Err(e) => {
                    debug!(
                        "in-memory zip extract failed for {logical}: {e:#}; falling back to raw scan"
                    );
                    Ok(Box::new(std::iter::empty()))
                }
            };
        }
        debug!(
            "{logical} is {} bytes (> {} MB cap); falling back to disk streaming extractor",
            data.len(),
            MAX_INMEM_ZIP_ARCHIVE_BYTES / (1024 * 1024)
        );
    }

    let staged_name = archive_staged_name(logical);
    if !is_zip_body {
        match scan_tar_bytes(data, Path::new(&staged_name), resources) {
            Ok(Some(ScanArchive::Members(mut members))) => {
                let logical = logical.to_owned();
                let mut total = 0u64;
                return Ok(Box::new(std::iter::from_fn(move || {
                    while !resources.reached(total, MAX_RECURSIVE_ARCHIVE_BYTES) {
                        let member = members.next()?;
                        match scan_archive_bytes(member.data) {
                            Ok(mut bytes) => {
                                let remaining = MAX_RECURSIVE_ARCHIVE_BYTES.saturating_sub(total);
                                bytes.truncate(resources.cap(bytes.len() as u64, remaining) as usize);
                                total = total.saturating_add(bytes.len() as u64);
                                return Some((remap_archive_member(&logical, member.name), bytes));
                            }
                            Err(error) => debug!(
                                "Failed to read extracted TAR member {}: {error}",
                                member.name
                            ),
                        }
                    }
                    None
                })));
            }
            // The staged path preserves the decoded raw payload and its
            // !content label when the TAR is malformed or incomplete.
            Ok(_) => {}
            Err(error) => debug!("Failed to extract resident TAR {logical}: {error:#}"),
        }
    }

    let entries = extract_staged_archive_bytes(logical, &staged_name, data, resources)?;
    Ok(Box::new(entries.into_iter()))
}

fn extract_staged_archive_bytes(
    logical: &str,
    staged_name: &str,
    data: &[u8],
    resources: ResourceLimits,
) -> Result<Vec<OwnedArchiveEntry>> {
    let staging =
        archive_staging_tempdir().context("Failed to create staging tempdir for archive")?;
    let staged_path = staging.path().join(staged_name);
    std::fs::write(&staged_path, data)
        .with_context(|| format!("Failed to stage archive to {}", staged_path.display()))?;

    let (content, _temp_dir) = match decompress_file_to_temp_with_limits(&staged_path, resources) {
        Ok(content) => content,
        Err(e) => {
            debug!(
                "decompress_file_to_temp_with_limits({}, resources) failed: {e:#}",
                staged_path.display()
            );
            return Ok(Vec::new());
        }
    };

    let mut total = 0u64;
    let mut entries = Vec::new();

    match content {
        CompressedContent::Archive(files) => {
            for (entry_logical, bytes) in files {
                push_archive_bytes(
                    &mut entries,
                    &mut total,
                    remap_archive_member(logical, entry_logical),
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
                    remap_archive_member(logical, entry_logical),
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
                    return Ok(Vec::new());
                }
            };
            let file = match std::fs::File::open(&path) {
                Ok(file) => file,
                Err(e) => {
                    debug!("Failed to open decompressed payload {}: {e}", path.display());
                    return Ok(Vec::new());
                }
            };
            let mut bytes = Vec::new();
            if let Err(e) = resources
                .reader(file, payload_len.min(MAX_RECURSIVE_ARCHIVE_BYTES))
                .read_to_end(&mut bytes)
            {
                debug!("Failed to read decompressed payload {}: {e}", path.display());
                return Ok(Vec::new());
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

    Ok(entries)
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
    parent: Option<String>,
) -> Result<Vec<ExpandedArchiveEntry>> {
    let entries: Vec<_> = entries.into_iter().collect();
    Ok(lazy_expand_entries(Box::new(entries.into_iter()), remaining_depth, resources, parent)
        .collect())
}

fn archive_entry_suffix<'a>(entry_logical: &'a str, archive_path: &str) -> Option<&'a str> {
    entry_logical.strip_prefix(archive_path).filter(|suffix| suffix.starts_with('!')).or_else(
        || entry_logical.split_once('!').map(|(archive, _)| &entry_logical[archive.len()..]),
    )
}

struct GitRepoResultIter<'a> {
    path_selection: crate::path_selection::PathSelection,
    inner: GitRepoResult,
    deadline: Option<std::time::Instant>,
    /// Extract recognized archive paths and content-sniffed ZIPs before scanning,
    /// subject to depth/resource limits. When false, scan the raw container bytes.
    extract_archives: bool,
    /// Maximum number of archive layers to extract from each git blob.
    extraction_depth: Option<usize>,
    resources: ResourceLimits,
    /// Skip git blobs larger than this many bytes, as `--max-file-size` does for files.
    max_blob_size: Option<u64>,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl GitRepoResult {
    fn into_blob_iter<'a>(
        self,
        cfg: &EnumeratorConfig<'_>,
        deadline: Option<Instant>,
    ) -> GitRepoResultIter<'a> {
        GitRepoResultIter {
            path_selection: cfg.path_selection.clone(),
            inner: self,
            deadline,
            extract_archives: cfg.extract_archives,
            extraction_depth: cfg.extraction_depth,
            resources: cfg.resources,
            max_blob_size: cfg.max_blob_size,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a> rayon::iter::ParallelIterator for GitRepoResultIter<'a> {
    type Item = Result<LoadedBlob<'a>>;

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
        let path_selection = self.path_selection;
        let max_blob_size = self.max_blob_size;
        // A Rayon job is not a worker: map_init repeatedly recreates handles and
        // discards their delta-base caches. Reuse one bounded handle per worker.
        let repositories = thread_local::ThreadLocal::new();
        // Loads one git blob and returns one *or more* `(OriginSet, Blob)`
        // tuples: a single tuple for normal blobs, multiple tuples for
        // archive blobs (zip/jar/apk/...) whose entries get unpacked into
        // synthetic per-entry blobs so pattern matchers can see the
        // contents. Entries are expanded lazily as the matcher consumes them.
        let load_blob = {
            let repo_path = Arc::clone(&repo_path);
            let flag = Arc::clone(&flag);

            move |repo: &GixRepo, mut md: GitBlobMetadata| -> Result<LoadedGitBlobs<'a>> {
                if !path_selection.is_empty() {
                    let had_paths = !md.first_seen.is_empty();
                    md.first_seen.retain(|appearance| {
                        path_selection.matches(&appearance.path.to_str_lossy())
                            || (extract_archives
                                && is_compressed_file(Path::new(
                                    appearance.path.to_str_lossy().as_ref(),
                                )))
                    });
                    if md.first_seen.is_empty() && (had_paths || !path_selection.matches("")) {
                        if !had_paths {
                            debug!(blob = %md.blob_oid, repo = %repo_path.display(),
                                "Skipping Git blob without path metadata because its path or extension cannot be selected");
                        }
                        return Ok(Box::new(std::iter::empty()));
                    }
                }
                if deadline.is_some_and(|deadline| StdInstant::now() > deadline) {
                    if flag.swap(true, Ordering::Relaxed) {
                        bail!("__timeout_silenced__");
                    }
                    bail!("blob-read timeout (repo: {})", repo_path.display());
                }

                let blob_id = md.blob_oid;
                // Check the indexed size, or read the header if it wasn't indexed,
                // to skip oversized blobs without inflating them.
                if let Some(limit) = max_blob_size {
                    let size = match md.indexed_size {
                        Some(size) => size.get(),
                        None => repo.find_header(blob_id)?.size(),
                    };
                    if size > limit {
                        debug!(blob = %blob_id, size, limit, repo = %repo_path.display(),
                            "Skipping Git blob larger than the maximum file size");
                        return Ok(Box::new(std::iter::empty()));
                    }
                }
                let (data, native_negative) =
                    match md.retained_data.take().and_then(RetainedGitBlob::into_data) {
                        Some(data) => data,
                        None => {
                            let mut raw = repo.find_object(blob_id)?.try_into_blob()?;
                            (std::mem::take(&mut raw.data), false)
                        }
                    };
                let is_pdf = has_pdf_magic(&data);

                // Try PDF text or archive extraction if any first-seen path looks like
                // a known archive format, or the blob bytes are a ZIP under a
                // name with no archive extension (e.g. a committed `tfplan`).
                // Successful extraction replaces the raw container; invalid or empty
                // archives remain available for scanning as raw bytes.
                if extract_archives && (extraction_depth != Some(0) || is_pdf) {
                    // Prefer an appearance whose name is a recognized archive so
                    // report paths stay stable; fall back to the first appearance
                    // only when the bytes are a ZIP with no archive extension.
                    let archive_path = md
                        .first_seen
                        .iter()
                        .map(|e| String::from_utf8_lossy(&e.path))
                        .find(|p| is_pdf || is_compressed_file(Path::new(p.as_ref())))
                        .or_else(|| {
                            if looks_like_zip(&data) {
                                md.first_seen.first().map(|e| String::from_utf8_lossy(&e.path))
                            } else {
                                None
                            }
                        });

                    if let Some(archive_path) = archive_path {
                        let archive_path = archive_path.into_owned();
                        let entries = lazy_expand_entry(
                            archive_path.clone(),
                            data,
                            extraction_depth,
                            resources,
                            deadline.map_or_else(
                                kingfisher_scanner::ScanControl::default,
                                |deadline| {
                                    kingfisher_scanner::ScanControl::default()
                                        .with_deadline(deadline)
                                },
                            ),
                        );
                        let repo_path = Arc::clone(&repo_path);
                        let timeout_reported = Arc::clone(&flag);
                        return Ok(Box::new(entries.map(
                            move |(entry_logical, entry_bytes, member, mut pages)| {
                                pages.timeout_reported = Some(Arc::clone(&timeout_reported));
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
                                        .unwrap_or_else(
                                            || Origin::from_git_repo(Arc::clone(&repo_path)).into(),
                                        );
                                    return (
                                        origin,
                                        Blob::new(BlobId::from(&blob_id), entry_bytes),
                                        None,
                                        pages,
                                    );
                                }
                                let entry_suffix =
                                    archive_entry_suffix(&entry_logical, &archive_path);
                                let origin =
                                    OriginSet::try_from_iter(md.first_seen.iter().map(|e| {
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
                                let selection_path =
                                    member.or_else(|| is_pdf.then(|| archive_path.clone()));
                                (origin, Blob::from_bytes(entry_bytes), selection_path, pages)
                            },
                        )));
                    }
                }

                let raw_buffer = (data.as_ptr(), data.len());
                let blob = Blob::new(BlobId::from(&blob_id), data);
                // Unicode normalization replaces the original buffer. The prepass proof
                // is only valid for the bytes it actually scanned.
                let native_negative =
                    native_negative && (blob.bytes().as_ptr(), blob.len()) == raw_buffer;
                let context = LoadedBlobContext { native_negative, ..Default::default() };

                let origin = OriginSet::try_from_iter(md.first_seen.iter().map(|e| {
                    Origin::from_git_repo_with_first_commit(
                        Arc::clone(&repo_path),
                        Arc::clone(&e.commit_metadata),
                        String::from_utf8_lossy(&e.path).to_string(),
                    )
                }))
                .unwrap_or_else(|| Origin::from_git_repo(Arc::clone(&repo_path)).into());

                Ok(Box::new(std::iter::once((origin, blob, None, context))))
            }
        };

        // After flat-mapping, errors and successes both flow as
        // `Result<LoadedBlob<'a>>`. Filter out the silenced timeout
        // marker before handing items to the scan consumer.
        let timeout_filter = |res: &Result<LoadedBlob<'a>>| -> bool {
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
         -> Box<dyn Iterator<Item = Result<LoadedBlob<'a>>> + Send + 'a> {
            match res {
                Ok(v) => {
                    let repo_path = Arc::clone(&repo_path);
                    let flag = Arc::clone(&flag);
                    Box::new(v.map(move |blob| {
                        if let Err(error) = check_repo_deadline(deadline, &repo_path, "git content extraction") {
                            if flag.swap(true, Ordering::Relaxed) {
                                bail!("__timeout_silenced__");
                            }
                            return Err(error);
                        }
                        Ok(blob)
                    }))
                }
                Err(e) => Box::new(std::iter::once(Err(e))),
            }
        };

        match self.inner.blobs {
            GitBlobSource::Precomputed(blobs) => {
                let rs = Arc::clone(&repo_sync);
                // Give small histories enough splits to use the scan pool. Cap the
                // minimum at 1024 to keep large scans close to pack order.
                let jobs = rayon::current_num_threads();
                let min_len = (blobs.len() / jobs.saturating_mul(4)).clamp(64, 1024);
                blobs
                    .into_par_iter()
                    .with_min_len(min_len)
                    .map(|md| load_blob(repositories.get_or(|| scan_repo_from_sync(&rs)), md))
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
                            let size = hdr.size();
                            if hdr.kind() == Kind::Blob && size >= MIN_SCANNABLE_BLOB_SIZE {
                                let md = GitBlobMetadata {
                                    blob_oid: oid,
                                    indexed_size: std::num::NonZeroU64::new(size),
                                    retained_data: None,
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
                    .map(|md| load_blob(repositories.get_or(|| scan_repo_from_sync(&rs)), md))
                    .flat_map_iter(fan_out)
                    .filter(timeout_filter)
                    .drive_unindexed(consumer)
            }
        }
    }
}

struct EnumeratorFileIter<'a> {
    path_selection: crate::path_selection::PathSelection,
    inner: EnumeratorFileResult,
    reader: std::io::BufReader<std::fs::File>,
    _marker: PhantomData<&'a ()>,
}

impl ParallelBlobIterator for EnumeratorFileResult {
    type Iter<'a> = EnumeratorFileIter<'a>;

    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>> {
        let file = std::fs::File::open(&self.path)?;
        let reader = std::io::BufReader::new(file);
        Ok(Some(EnumeratorFileIter {
            path_selection: Default::default(),
            inner: self,
            reader,
            _marker: PhantomData,
        }))
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
    type Item = Result<LoadedBlob<'a>>;

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
                Ok((origin, blob, None, LoadedBlobContext::default()))
            })
            .filter(|entry| match entry {
                Err(_) => true,
                Ok((origin, _, _, _)) => {
                    self.path_selection.is_empty()
                        || self.path_selection.matches(
                            &origin
                                .first()
                                .blob_path()
                                .map(|path| path.to_string_lossy())
                                .unwrap_or_default(),
                        )
                }
            })
            .drive_unindexed(consumer)
    }
}

trait ParallelBlobIterator {
    /// The concrete parallel iterator returned by `into_blob_iter`.
    /// It is generic over the lifetime `'a` that the produced `Blob<'a>` carries.
    type Iter<'a>: ParallelIterator<Item = Result<LoadedBlob<'a>>> + 'a
    where
        Self: 'a;
    /// Convert the input into an *optional* parallel iterator of `(Origin, Blob)` tuples.
    fn into_blob_iter<'a>(self) -> Result<Option<Self::Iter<'a>>>
    where
        Self: 'a;
}

impl<'a> ParallelIterator for FoundInputIter<'a> {
    type Item = Result<LoadedBlob<'a>>;

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
impl<'cfg> ParallelBlobIterator for (&'cfg EnumeratorConfig<'_>, FoundInput) {
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
            FoundInput::File(i) => {
                let selected = cfg.path_selection.is_empty()
                    || matches_selected_file(
                        &cfg.path_selection,
                        &i.path,
                        &cfg.selection_roots,
                        &cfg.selection_base,
                    );
                let mode = FileOpenMode::NoFollow;
                #[cfg(windows)]
                let mode = if cfg.explicit_paths.contains(i.path.as_path()) {
                    FileOpenMode::ExplicitWindowsPath
                } else {
                    mode
                };
                Ok(i.into_blob_iter(cfg.max_blob_size, selected, mode)?.map(FoundInputIter::File))
            }

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
                    let enumerator = GitRepoWithMetadataEnumerator::new(
                        path,
                        repository,
                        cfg.exclude_globset.clone(),
                    );
                    let enumerator = if let Some(filter) = &cfg.git_content_filter {
                        enumerator.with_content_filter(filter)
                    } else {
                        enumerator
                    };
                    enumerator.run_with_deadline(deadline)
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

                        Ok(Some(FoundInputIter::GitRepo(repo_result.into_blob_iter(cfg, deadline))))
                    }
                }
            }

            // ───────────── pre-enumerated JSON file list ─────────────
            FoundInput::EnumeratorFile(i) => Ok(i.into_blob_iter()?.map(|mut iter| {
                iter.path_selection = cfg.path_selection.clone();
                FoundInputIter::EnumeratorFile(iter)
            })),
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
            let mut reference = reference?;
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
            Some(explicit) => Some(explicit),
            None => detect_staged_base_ref(&repository)?,
        };
        let parent = if branch_ref == "HEAD" && repository.head()?.is_unborn() {
            None
        } else {
            Some(resolve_diff_ref(&repository, path, &branch_ref)?.object()?.peel_to_commit()?.id)
        };
        let staged_commit = synthesize_staged_commit(&repository, path, parent, deadline)?;

        (staged_commit, base_ref, None)
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
            blobs.push(GitBlobMetadata {
                blob_oid: id,
                indexed_size: None,
                retained_data: None,
                first_seen: smallvec![appearance],
            });
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

fn synthesize_staged_commit(
    repository: &gix::Repository,
    path: &Path,
    parent: Option<gix::ObjectId>,
    deadline: Option<Instant>,
) -> Result<String> {
    check_repo_deadline(deadline, path, "staged index loading")?;
    // Like `git -C <path> write-tree`, honor an alternate index without changing
    // the process environment or falling back to HEAD when the index is absent.
    let index_path = std::env::var_os("GIT_INDEX_FILE")
        .map(|index| path.join(index))
        .unwrap_or_else(|| repository.index_path());
    let index = gix::index::File::at_or_default(
        index_path,
        repository.object_hash(),
        false,
        Default::default(),
    )
    .context("Failed to read staged index")?;
    index.verify_entries().context("Invalid staged index entries")?;

    // Plumbing editing preserves Git's byte paths, including index-only names
    // that cannot be checked out on this platform. No worktree data or filters
    // are used: the index already holds the canonical staged blob objects.
    let mut tree = repository.empty_tree().edit()?.detach();
    for entry in index.entries() {
        check_repo_deadline(deadline, path, "staged index snapshot")?;
        if entry.flags.stage() != gix::index::entry::Stage::Unconflicted {
            bail!("Cannot snapshot staged index with unmerged entries");
        }
        let mode = entry.mode.to_tree_entry_mode().context("Invalid mode in staged index")?;
        let entry_path = entry.path(&index);
        if !mode.is_commit() && !repository.has_object(entry.id) {
            bail!("Missing object {} for staged index entry {:?}", entry.id, entry_path);
        }
        // Sparse-index directories use a trailing slash, but tree paths do not.
        let entry_path = entry_path.strip_suffix(b"/").unwrap_or(entry_path);
        tree.upsert(
            entry_path.split(|byte| *byte == b'/').map(|component| component.as_bstr()),
            mode.kind(),
            entry.id,
        )
        .context("Failed to construct staged tree")?;
    }
    let staged_tree = tree.write(|tree| -> Result<gix::ObjectId> {
        check_repo_deadline(deadline, path, "staged tree writing")?;
        Ok(repository.write_object(tree)?.detach())
    })?;

    // Read the same user/config/environment identity as commit-tree, without
    // enabling gix's optional Git-installation-config executable discovery.
    // A scanner also works on machines without a configured commit identity.
    let identity_repo =
        gix::open_opts(repository.git_dir(), gix::open::Options::default().open_path_as_is(true))
            .context("Failed to read staged snapshot identity")?;
    let fallback = || gix::actor::Signature {
        name: "Kingfisher".into(),
        email: "kingfisher@localhost".into(),
        time: gix::date::Time::now_local_or_utc(),
    };
    let author = identity_repo
        .author()
        .transpose()?
        .map(|signature| signature.to_owned())
        .transpose()?
        .unwrap_or_else(fallback);
    let committer = identity_repo
        .committer()
        .transpose()?
        .map(|signature| signature.to_owned())
        .transpose()?
        .unwrap_or_else(fallback);
    let commit = gix::objs::Commit {
        tree: staged_tree,
        parents: parent.into_iter().collect(),
        author,
        committer,
        encoding: None,
        message: "kingfisher staged snapshot\n".into(),
        extra_headers: Default::default(),
    };
    check_repo_deadline(deadline, path, "staged commit writing")?;
    Ok(repository.write_object(&commit)?.to_string())
}

fn detect_staged_base_ref(repository: &gix::Repository) -> Result<Option<String>> {
    let head = repository.head().context("Failed to read HEAD for staged scan")?;
    // An unborn HEAD has neither a diff base nor a synthetic-commit parent.
    // The existing diff pipeline compares it with the repository's empty tree.
    Ok(head.id().map(|id| id.to_string()))
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
    use crate::git_test_fixture as fixture;

    use std::{fs, io::Write};
    use std::{
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use super::{
        FileResult, GitBlobSource, GitDiffConfig, enumerate_git_branch_history,
        enumerate_git_diff_repo, lazy_expand_entry, reference_candidates,
    };
    use anyhow::Result;
    use bstr::ByteSlice;
    use gix::{open::Options, open_opts};
    use rayon::iter::ParallelIterator;
    use rusqlite::Connection;
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    #[test]
    fn selected_file_paths_preserve_bangs_and_explicit_file_directories() {
        let base = std::env::current_dir().unwrap();
        let selection = crate::path_selection::PathSelection {
            include_prefixes: vec!["configs/".into()],
            ..Default::default()
        };
        for path in [Path::new("configs/key.env"), Path::new("configs/key!literal.env")] {
            assert!(super::matches_selected_file(&selection, path, &[], &base));
            assert!(super::matches_selected_file(&selection, &base.join(path), &[], &base));
        }
        assert!(!super::matches_selected_file(
            &selection,
            Path::new("outside!configs/key.env"),
            &[],
            &base
        ));
        let literal = crate::path_selection::PathSelection {
            include_prefixes: vec!["configs/key!".into()],
            ..Default::default()
        };
        assert!(super::matches_selected_file(
            &literal,
            Path::new("configs/key!literal.env"),
            &[],
            &base
        ));
    }

    #[cfg(windows)]
    #[test]
    fn selected_file_paths_accept_mixed_windows_prefixes() {
        let selection = crate::path_selection::PathSelection {
            include_prefixes: vec!["configs/".into()],
            exclude_prefixes: vec!["configs/generated/".into()],
            ..Default::default()
        };
        for (ordinary, verbatim) in [
            (Path::new(r"C:\work"), Path::new(r"\\?\C:\work")),
            (Path::new(r"\\server\share\work"), Path::new(r"\\?\UNC\server\share\work")),
        ] {
            for base in [ordinary, verbatim] {
                for root in [ordinary, verbatim] {
                    for path_root in [ordinary, verbatim] {
                        assert_eq!(
                            super::strip_selection_prefix(path_root, base),
                            Some(Path::new(""))
                        );
                        for roots in [Vec::new(), vec![root.to_path_buf()]] {
                            for (relative, expected) in [
                                ("configs/key.env", true),
                                ("configs/key!literal.env", true),
                                ("configs/秘密.env", true),
                                ("configs/generated/key.env", false),
                                ("outside/key.env", false),
                            ] {
                                let path = path_root.join(relative);
                                assert_eq!(
                                    super::matches_selected_file(&selection, &path, &roots, base),
                                    expected,
                                    "path={path:?}, roots={roots:?}, base={base:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
        // Prefix equivalence must not blur drive, share, or directory boundaries.
        for (path, prefix) in [
            (r"\\?\D:\work\configs\key.env", r"C:\work"),
            (r"\\?\UNC\server\other\work\configs\key.env", r"\\server\share\work"),
            (r"\\?\UNC\other\share\work\configs\key.env", r"\\server\share\work"),
            (r"\\?\C:\work-other\configs\key.env", r"C:\work"),
        ] {
            assert!(super::strip_selection_prefix(Path::new(path), Path::new(prefix)).is_none());
        }
    }

    #[test]
    fn archive_member_selection_uses_extraction_boundaries_not_literal_bangs() -> Result<()> {
        let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file("configs/key!literal.env", SimpleFileOptions::default())?;
        zip.write_all(b"archive member content")?;
        let bytes = zip.finish()?.into_inner();
        let entries: Vec<_> = lazy_expand_entry(
            "archive!literal.zip".into(),
            bytes,
            Some(2),
            crate::limits::ResourceLimits::default(),
            Default::default(),
        )
        .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "archive!literal.zip!configs/key!literal.env");
        assert_eq!(entries[0].2.as_deref(), Some("configs/key!literal.env"));
        Ok(())
    }

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

    fn staged_index(
        repo: &gix::Repository,
        entries: &[(&[u8], gix::ObjectId, gix::index::entry::Mode, gix::index::entry::Flags)],
    ) -> Result<()> {
        let mut index = gix::index::File::from_state(
            gix::index::State::new(repo.object_hash()),
            repo.index_path(),
        );
        for (path, id, mode, flags) in entries {
            index.dangerously_push_entry(Default::default(), *id, *flags, *mode, path.as_bstr());
        }
        index.sort_entries();
        index.write(Default::default())?;
        Ok(())
    }

    fn staged_diff(
        repo: &gix::Repository,
        since_ref: Option<String>,
        exclude: Option<globset::GlobSet>,
    ) -> Result<crate::GitRepoResult> {
        enumerate_git_diff_repo(
            repo.workdir().unwrap(),
            open_opts(repo.git_dir(), Options::isolated().open_path_as_is(true))?,
            GitDiffConfig { since_ref, branch_ref: "HEAD".into(), branch_root: None, staged: true },
            exclude.map(std::sync::Arc::new),
            true,
            Some(Instant::now() + Duration::from_secs(60)),
        )
    }

    #[test]
    fn staged_diff_reads_index_changes_and_preserves_raw_paths() -> Result<()> {
        use gix::index::entry::{Flags, Mode};

        let temp = tempdir()?;
        let repo = gix::init(temp.path())?;
        fixture::config(&repo, "user.name", "tester")?;
        fixture::config(&repo, "user.email", "tester@example.com")?;
        let signature = fixture::signature("tester", "tester@example.com");
        let original = repo.write_blob(b"original staged content")?.detach();
        let modified = repo.write_blob(b"modified staged content")?.detach();
        let binary = repo.write_blob(b"\0binary staged content\xff\r\n")?.detach();
        let link = repo.write_blob(b"relative-target")?.detach();
        let mut tree = repo.empty_tree().edit()?;
        for name in ["modified.txt", "deleted.txt", "old-name.txt", "unchanged.txt"] {
            fixture::insert(&mut tree, name, original, 0o100644)?;
        }
        let tree = tree.write()?.detach();
        let head =
            fixture::commit(&repo, Some("HEAD"), &signature, &signature, "base", &tree, &[])?;
        // Index-only names need not be representable by the host filesystem.
        let unusual = b"nested/-spaces \t\n\"!\xff.bin";
        staged_index(
            &repo,
            &[
                (b"modified.txt", modified, Mode::FILE_EXECUTABLE, Flags::empty()),
                (b"renamed.txt", original, Mode::FILE, Flags::empty()),
                (b"unchanged.txt", original, Mode::FILE, Flags::empty()),
                (unusual, binary, Mode::FILE, Flags::empty()),
                (b"link", link, Mode::SYMLINK, Flags::empty()),
                (b"submodule", head, Mode::COMMIT, Flags::empty()),
                (b"intent.txt", repo.write_blob(b"")?.detach(), Mode::FILE, Flags::INTENT_TO_ADD),
            ],
        )?;
        // A modified or absent worktree must never replace the indexed object data.
        fs::write(temp.path().join("modified.txt"), b"unstaged worktree content")?;
        fs::write(temp.path().join("unchanged.txt"), b"unstaged changes only")?;
        let before = repo.open_index()?;
        let result = staged_diff(&repo, None, None)?;
        let GitBlobSource::Precomputed(blobs) = result.blobs else {
            panic!("expected staged blobs")
        };
        let mut actual = std::collections::BTreeMap::new();
        for blob in &blobs {
            let path = blob.first_seen[0].path.clone();
            let id = gix::ObjectId::from_bytes_or_panic(blob.blob_oid.as_slice());
            actual.insert(path, result.repository.find_object(id)?.data.clone());
            let metadata = &blob.first_seen[0].commit_metadata;
            assert_eq!(metadata.author_name.as_deref(), Some("tester"));
            assert_eq!(metadata.committer_email.as_ref(), "tester@example.com");
            let commit = result.repository.find_commit(metadata.commit_id)?;
            assert_eq!(commit.parent_ids().next().unwrap().detach(), head);
            assert_eq!(commit.message_raw()?.as_bytes(), b"kingfisher staged snapshot\n");
        }
        assert_eq!(
            actual,
            std::collections::BTreeMap::from([
                (bstr::BString::from("modified.txt"), b"modified staged content".to_vec()),
                (bstr::BString::from("renamed.txt"), b"original staged content".to_vec()),
                (
                    bstr::BString::from(unusual.as_slice()),
                    b"\0binary staged content\xff\r\n".to_vec()
                ),
                (bstr::BString::from("link"), b"relative-target".to_vec()),
                (bstr::BString::from("intent.txt"), Vec::new()),
            ])
        );
        assert_eq!(repo.head_id()?.detach(), head, "staged scan must not advance HEAD");
        // write-tree may add a cache-tree extension, but it must not change entries.
        let after = repo.open_index()?;
        assert_eq!(before.entries().len(), after.entries().len());
        for (before_entry, after_entry) in before.entries().iter().zip(after.entries()) {
            assert_eq!(before_entry.path(&before), after_entry.path(&after));
            assert_eq!(before_entry.id, after_entry.id);
            assert_eq!(before_entry.mode, after_entry.mode);
            assert_eq!(before_entry.flags, after_entry.flags);
        }
        let mut exclusions = globset::GlobSetBuilder::new();
        exclusions.add(globset::Glob::new("nested/**")?);
        exclusions.add(globset::Glob::new("renamed.txt")?);
        let filtered = staged_diff(&repo, None, Some(exclusions.build()?))?;
        let GitBlobSource::Precomputed(blobs) = filtered.blobs else {
            panic!("expected staged blobs")
        };
        assert_eq!(blobs.len(), 3);
        assert!(blobs.iter().all(|blob| {
            ["modified.txt", "link", "intent.txt"]
                .contains(&blob.first_seen[0].path.to_str_lossy().as_ref())
        }));
        Ok(())
    }

    #[test]
    fn staged_diff_explicit_base_and_unmerged_index() -> Result<()> {
        use gix::index::entry::{Flags, Mode, Stage};

        let temp = tempdir()?;
        let repo = gix::init(temp.path())?;
        let signature = fixture::signature("tester", "tester@example.com");
        let empty = repo.empty_tree().edit()?.write()?.detach();
        let root =
            fixture::commit(&repo, Some("HEAD"), &signature, &signature, "root", &empty, &[])?;
        let blob = repo.write_blob(b"already committed content")?.detach();
        let mut tree = repo.empty_tree().edit()?;
        fixture::insert(&mut tree, "committed.txt", blob, 0o100644)?;
        let tree = tree.write()?.detach();
        let head =
            fixture::commit(&repo, Some("HEAD"), &signature, &signature, "head", &tree, &[&root])?;
        staged_index(&repo, &[(b"committed.txt", blob, Mode::FILE, Flags::empty())])?;
        let default = staged_diff(&repo, None, None)?;
        let GitBlobSource::Precomputed(blobs) = default.blobs else {
            panic!("expected staged blobs")
        };
        assert!(blobs.is_empty(), "unchanged index is empty relative to HEAD");
        let explicit = staged_diff(&repo, Some(root.to_string()), None)?;
        let GitBlobSource::Precomputed(blobs) = explicit.blobs else {
            panic!("expected staged blobs")
        };
        assert_eq!(blobs.len(), 1, "--since-commit remains the staged comparison base");
        staged_index(
            &repo,
            &[(b"conflicted.txt", blob, Mode::FILE, Flags::from_stage(Stage::Ours))],
        )?;
        let index_before = fs::read(repo.index_path())?;
        let mut exclude_all = globset::GlobSetBuilder::new();
        exclude_all.add(globset::Glob::new("**")?);
        assert!(
            staged_diff(&repo, None, Some(exclude_all.build()?)).is_err(),
            "an unmerged index must fail even if paths are excluded"
        );
        assert_eq!(fs::read(repo.index_path())?, index_before);
        assert_eq!(repo.head_id()?.detach(), head);
        Ok(())
    }

    #[test]
    fn staged_diff_unborn_sparse_index_and_missing_objects() -> Result<()> {
        use gix::index::entry::{Flags, Mode};

        let temp = tempdir()?;
        let repo = gix::init(temp.path())?;
        let empty = staged_diff(&repo, None, None)?;
        let GitBlobSource::Precomputed(blobs) = empty.blobs else {
            panic!("expected staged blobs")
        };
        assert!(blobs.is_empty());
        assert!(!repo.index_path().exists());
        assert!(repo.head()?.is_unborn());

        let blob = repo.write_blob(b"sparse staged content")?.detach();
        let mut subtree = repo.empty_tree().edit()?;
        fixture::insert(&mut subtree, "secret.txt", blob, 0o100644)?;
        let subtree = subtree.write()?.detach();
        staged_index(&repo, &[(b"sparse/", subtree, Mode::DIR, Flags::SKIP_WORKTREE)])?;
        // Reopening recognizes the sparse mode; writing adds its required sdir extension.
        let mut sparse = repo.open_index()?;
        assert!(sparse.is_sparse());
        sparse.write(Default::default())?;
        let before = fs::read(repo.index_path())?;
        let result = staged_diff(&repo, None, None)?;
        let GitBlobSource::Precomputed(blobs) = result.blobs else {
            panic!("expected staged blobs")
        };
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].first_seen[0].path.as_bytes(), b"sparse/secret.txt");
        let commit =
            result.repository.find_commit(blobs[0].first_seen[0].commit_metadata.commit_id)?;
        assert_eq!(commit.parent_ids().count(), 0);
        assert_eq!(fs::read(repo.index_path())?, before);
        assert!(repo.head()?.is_unborn());
        assert!(staged_diff(&repo, Some("not-a-reference".into()), None).is_err());

        let missing = gix::ObjectId::from_hex(b"1111111111111111111111111111111111111111")?;
        staged_index(&repo, &[(b"missing.txt", missing, Mode::FILE, Flags::empty())])?;
        assert!(staged_diff(&repo, None, None).is_err(), "missing staged objects must fail");
        Ok(())
    }

    #[test]
    fn staged_diff_reads_split_index_without_modifying_either_file() -> Result<()> {
        use gix::index::entry::{Flags, Mode};

        let temp = tempdir()?;
        let repo = gix::init(temp.path())?;
        let blob = repo.write_blob(b"shared staged content")?.detach();
        staged_index(&repo, &[(b"shared.txt", blob, Mode::FILE, Flags::empty())])?;
        let shared = repo.open_index()?;
        let checksum = shared.checksum().unwrap();
        let shared_path = repo.git_dir().join(format!("sharedindex.{checksum}"));
        let shared_bytes = fs::read(repo.index_path())?;
        fs::write(&shared_path, &shared_bytes)?;

        // An empty split index links all shared entries, with empty delete and
        // replace EWAH bitmaps (bit length, one zero word, and RLW position).
        let mut link = checksum.as_slice().to_vec();
        for _ in 0..2 {
            link.extend_from_slice(&0u32.to_be_bytes());
            link.extend_from_slice(&1u32.to_be_bytes());
            link.extend_from_slice(&0u64.to_be_bytes());
            link.extend_from_slice(&0u32.to_be_bytes());
        }
        let mut split = b"DIRC".to_vec();
        split.extend_from_slice(&2u32.to_be_bytes());
        split.extend_from_slice(&0u32.to_be_bytes());
        split.extend_from_slice(b"link");
        split.extend_from_slice(&(link.len() as u32).to_be_bytes());
        split.extend_from_slice(&link);
        let mut hash = gix::hash::hasher(repo.object_hash());
        hash.update(&split);
        split.extend_from_slice(hash.try_finalize()?.as_slice());
        fs::write(repo.index_path(), &split)?;
        let result = staged_diff(&repo, None, None)?;
        let GitBlobSource::Precomputed(blobs) = result.blobs else {
            panic!("expected staged blobs")
        };
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].first_seen[0].path.as_bytes(), b"shared.txt");
        assert_eq!(fs::read(repo.index_path())?, split);
        assert_eq!(fs::read(shared_path)?, shared_bytes);
        Ok(())
    }

    #[test]
    fn repository_deadlines_apply_to_history_and_snapshot_with_unlimited_content() -> Result<()> {
        use crate::cli::{CommandLineArgs, commands::scan::ScanOperation, global::Command};
        use clap::Parser;

        let temp = tempdir()?;
        let repo = gix::init(temp.path())?;
        fs::write(temp.path().join("secret.txt"), "fixture-secret")?;
        let mut index = fixture::index(&repo)?;
        fixture::stage(&repo, &mut index, Path::new("secret.txt"))?;
        let tree = fixture::write_tree(&repo, &index)?;
        let signature = fixture::signature("tester", "tester@example.com");
        fixture::commit(&repo, Some("HEAD"), &signature, &signature, "fixture", &tree, &[])?;

        for content in [false, true] {
            for timeouts in [false, true] {
                let mut options = vec!["kingfisher", "scan", ".", "--git-repo-timeout=1"];
                if content {
                    options.push("--no-limits");
                }
                if timeouts {
                    options.push("--no-timeouts");
                }
                let Command::Scan(command) = CommandLineArgs::try_parse_from(options)?.command
                else {
                    panic!()
                };
                let ScanOperation::Scan(args) = command.into_operation()? else { panic!() };
                // Exercise an elapsed budget without relying on repository size or CPU speed.
                let deadline =
                    args.repository_timeout().map(|_| Instant::now() - Duration::from_secs(1));
                let open = || -> Result<gix::Repository> {
                    Ok(open_opts(repo.git_dir(), Options::isolated().open_path_as_is(true))?)
                };
                let history = enumerate_git_branch_history(
                    temp.path(),
                    open()?,
                    Some("HEAD"),
                    None,
                    None,
                    None,
                    true,
                    deadline,
                );
                let snapshot = enumerate_git_diff_repo(
                    temp.path(),
                    open()?,
                    GitDiffConfig {
                        since_ref: None,
                        branch_ref: "HEAD".into(),
                        branch_root: None,
                        staged: false,
                    },
                    None,
                    false,
                    deadline,
                );
                for result in [history, snapshot] {
                    if timeouts {
                        let GitBlobSource::Precomputed(blobs) = result?.blobs else {
                            panic!("expected fixture blob")
                        };
                        assert_eq!(blobs.len(), 1);
                        assert_eq!(blobs[0].first_seen[0].path.to_str_lossy(), "secret.txt");
                    } else {
                        let error = result
                            .err()
                            .expect("an expired repository budget must stop enumeration");
                        assert!(error.to_string().contains("timed out"), "{error}");
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn enumerate_git_diff_repo_branch_without_since_scans_head_tree() -> Result<()> {
        let temp = tempdir()?;
        let repo_path = temp.path().join("repo");
        let repo = gix::init(&repo_path)?;
        let signature = fixture::signature("tester", "tester@exmple.com");

        let tracked_file = repo_path.join("secret.txt");
        fs::create_dir_all(tracked_file.parent().unwrap())?;
        fs::write(&tracked_file, b"super-secret")?;

        let mut index = fixture::index(&repo)?;
        fixture::stage(&repo, &mut index, Path::new("secret.txt"))?;
        let tree_id = fixture::write_tree(&repo, &index)?;
        let tree = tree_id;
        let commit_id =
            fixture::commit(&repo, Some("HEAD"), &signature, &signature, "initial", &tree, &[])?;
        let commit = commit_id;
        fixture::reference(
            &repo,
            &format!("refs/heads/{}", "featurefake"),
            commit,
            gix::refs::transaction::PreviousValue::Any,
            "branch",
        )?;

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
        let repo = gix::init(temp.path())?;
        let signature = fixture::signature("tester", "tester@example.com");
        let mut index = fixture::index(&repo)?;
        for (path, content) in
            [("a.txt", "first historical secret"), ("b.txt", "second historical secret")]
        {
            fs::write(temp.path().join(path), content)?;
            fixture::stage(&repo, &mut index, Path::new(path))?;
        }
        let tree = fixture::write_tree(&repo, &index)?;
        let root_id =
            fixture::commit(&repo, None, &signature, &signature, "introduce", &tree, &[])?;
        let root = root_id;
        index.remove_entries(|_, _, _| true);
        let empty_tree = fixture::write_tree(&repo, &index)?;
        let deleted_id =
            fixture::commit(&repo, None, &signature, &signature, "delete", &empty_tree, &[&root])?;
        let deleted = deleted_id;
        let tip_id = fixture::commit(
            &repo,
            Some("HEAD"),
            &signature,
            &signature,
            "restore",
            &tree,
            &[&deleted],
        )?;

        let result = enumerate_git_branch_history(
            temp.path(),
            open_opts(repo.git_dir(), Options::isolated().open_path_as_is(true))?,
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
        let repo = gix::init_bare(temp.path())?;
        let start = 1_700_000_000;
        let end = start + 3600;
        let signature = |seconds| gix::actor::Signature {
            time: gix::date::Time::new(seconds, 0),
            ..fixture::signature("tester", "tester@example.com")
        };
        let old = signature(start - 1);
        let lower = signature(start);
        let upper = signature(end);
        let future = signature(end + 1);
        let mut builder = repo.empty_tree().edit()?;
        let baseline_blob = repo.write_blob(b"unchanged old secret").map(gix::Id::detach)?;
        fixture::insert(&mut builder, "baseline.txt", baseline_blob, 0o100644)?;
        let baseline_tree = builder.write()?.detach();
        let root_id = fixture::commit(
            &repo,
            None,
            &upper,
            &old,
            "old commit with recent author",
            &baseline_tree,
            &[],
        )?;
        let root = root_id;
        let recent_blob = repo.write_blob(b"recent temporary secret").map(gix::Id::detach)?;
        fixture::insert(&mut builder, "recent.txt", recent_blob, 0o100644)?;
        let recent_tree = builder.write()?.detach();
        let recent_id = fixture::commit(
            &repo,
            None,
            &old,
            &lower,
            "recent commit with old author",
            &recent_tree,
            &[&root],
        )?;
        let recent = recent_id;
        // An older child must not prune its newer ancestor; it removes the secret.
        fixture::commit(
            &repo,
            Some("refs/heads/main"),
            &upper,
            &old,
            "older child",
            &baseline_tree,
            &[&recent],
        )?;
        fixture::set_head(&repo, "refs/heads/main")?;
        let mut builder = repo.edit_tree(baseline_tree)?;
        let remote_blob = repo.write_blob(b"remote secret at upper bound").map(gix::Id::detach)?;
        fixture::insert(&mut builder, "remote.txt", remote_blob, 0o100644)?;
        let remote_tree = builder.write()?.detach();
        let remote_id =
            fixture::commit(&repo, None, &old, &upper, "at upper bound", &remote_tree, &[&root])?;
        let remote = remote_id;
        fixture::insert(
            &mut builder,
            "future.txt",
            repo.write_blob(b"future secret outside window").map(gix::Id::detach)?,
            0o100644,
        )?;
        let future_tree = builder.write()?.detach();
        fixture::commit(
            &repo,
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
                    open_opts(repo.git_dir(), Options::isolated().open_path_as_is(true))?,
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
                        let id = appearance.commit_metadata.commit_id;
                        id == recent_id || id == remote_id
                    }));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn all_ref_history_preserves_unique_appearances_and_shallow_tips() -> Result<()> {
        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let sig = fixture::signature("tester", "tester@example.com");
        let empty_tree = repo.empty_tree().edit()?.write()?.detach();
        let base_id =
            fixture::commit(&repo, Some("refs/heads/main"), &sig, &sig, "base", &empty_tree, &[])?;
        let base = base_id;
        let mut builder = repo.empty_tree().edit()?;
        let shared_blob = repo.write_blob(b"shared historical secret").map(gix::Id::detach)?;
        fixture::insert(&mut builder, "shared.txt", shared_blob, 0o100644)?;
        let shared_tree = builder.write()?.detach();
        let shared_id = fixture::commit(&repo, None, &sig, &sig, "shared", &shared_tree, &[&base])?;
        let shared = shared_id;
        let mut expected = vec![shared_id.to_string()];
        for (name, reference) in [
            ("local", Some("refs/heads/feature")),
            ("remote", Some("refs/remotes/origin/feature")),
            ("tag", None),
            ("detached", None),
        ] {
            let mut builder = repo.edit_tree(shared_tree)?;
            fixture::insert(
                &mut builder,
                name,
                repo.write_blob(format!("secret for {name}").as_bytes()).map(gix::Id::detach)?,
                0o100644,
            )?;
            let tree = builder.write()?.detach();
            let id = fixture::commit(&repo, reference, &sig, &sig, name, &tree, &[&shared])?;
            expected.push(id.to_string());
            match name {
                "tag" => {
                    fixture::tag(&repo, "release", id, &sig, "release")?;
                }
                "detached" => fixture::detach_head(&repo, id)?,
                _ => {}
            }
        }
        // Symbolic/duplicate tips must not repeat appearances. Non-commit tags are harmless.
        fixture::reference(
            &repo,
            "refs/remotes/origin/HEAD",
            gix::refs::Target::Symbolic("refs/remotes/origin/feature".try_into()?),
            gix::refs::transaction::PreviousValue::Any,
            "test",
        )?;
        fixture::tag(&repo, "tree", empty_tree, &sig, "tree tag")?;
        fixture::reference(
            &repo,
            "refs/tags/blob",
            shared_blob,
            gix::refs::transaction::PreviousValue::Any,
            "blob tag",
        )?;
        // A separate shallow tip inherits a blob from its unavailable parent.
        let shallow_id = fixture::commit(
            &repo,
            Some("refs/heads/shallow"),
            &sig,
            &sig,
            "shallow",
            &shared_tree,
            &[&shared],
        )?;
        fs::write(repo.git_dir().join("shallow"), format!("{shallow_id}\n"))?;
        expected.push(shallow_id.to_string());
        expected.sort();

        // Unborn HEAD must not prevent scanning the remaining refs either.
        for unborn in [false, true] {
            if unborn {
                fixture::set_head(&repo, "refs/heads/unborn")?;
            }
            let result = enumerate_git_branch_history(
                temp.path(),
                open_opts(repo.git_dir(), Options::isolated().open_path_as_is(true))?,
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
        let repo = gix::init_bare(temp.path())?;
        let signature = fixture::signature("tester", "tester@example.com");
        let shared = repo
            .write_blob(b"secret moved and copied without changing content")
            .map(gix::Id::detach)?;
        let old = repo.write_blob(b"old secret in modified file").map(gix::Id::detach)?;
        let new = repo.write_blob(b"new secret in modified file").map(gix::Id::detach)?;
        let deleted = repo.write_blob(b"deleted historical secret").map(gix::Id::detach)?;
        let excluded = repo.write_blob(b"excluded secret").map(gix::Id::detach)?;
        let mut nested = repo.empty_tree().edit()?;
        fixture::insert(&mut nested, "secret.txt", shared, 0o100644)?;
        let nested = nested.write()?.detach();
        let mut builder = repo.empty_tree().edit()?;
        fixture::insert(&mut builder, "old-dir", nested, 0o040000)?;
        fixture::insert(&mut builder, "modified.txt", old, 0o100644)?;
        fixture::insert(&mut builder, "deleted.txt", deleted, 0o100644)?;
        let root_tree = builder.write()?.detach();
        let root_id =
            fixture::commit(&repo, None, &signature, &signature, "root", &root_tree, &[])?;
        let root = root_id;
        builder.remove("old-dir")?;
        builder.remove("deleted.txt")?;
        fixture::insert(&mut builder, "new-dir", nested, 0o040000)?;
        fixture::insert(&mut builder, "copy.txt", shared, 0o100644)?;
        fixture::insert(&mut builder, "modified.txt", new, 0o100644)?;
        fixture::insert(&mut builder, "excluded.txt", excluded, 0o100644)?;
        let tip_tree = builder.write()?.detach();
        let tip_id = fixture::commit(
            &repo,
            Some("HEAD"),
            &signature,
            &signature,
            "tip",
            &tip_tree,
            &[&root],
        )?;
        // User diff preferences must not trigger similarity checks or index loading.
        fixture::config(&repo, "diff.renames", "copies")?;
        let mut excludes = globset::GlobSetBuilder::new();
        excludes.add(globset::Glob::new("excluded.txt")?);
        let excludes = std::sync::Arc::new(excludes.build()?);

        for corrupt_index in [false, true] {
            let index_path = repo.git_dir().join("index");
            if corrupt_index {
                fs::write(&index_path, b"deliberately invalid index")?;
            } else {
                assert!(!index_path.exists());
            }
            let open = || {
                open_opts(repo.git_dir(), Options::isolated().open_path_as_is(true))
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
        let repo = gix::init(temp.path())?;
        let signature = fixture::signature("tester", "tester@example.com");
        fs::write(temp.path().join("secret.txt"), "a secret inherited from missing history")?;
        let mut index = fixture::index(&repo)?;
        fixture::stage(&repo, &mut index, Path::new("secret.txt"))?;
        let tree = fixture::write_tree(&repo, &index)?;
        let root_id = fixture::commit(&repo, None, &signature, &signature, "root", &tree, &[])?;
        let root = root_id;
        let tip_id =
            fixture::commit(&repo, Some("HEAD"), &signature, &signature, "tip", &tree, &[&root])?;
        let tip = tip_id;
        fixture::tag(&repo, "release", tip, &signature, "annotated tag")?;
        fs::write(repo.git_dir().join("shallow"), format!("{tip_id}\n"))?;

        let result = enumerate_git_branch_history(
            temp.path(),
            open_opts(repo.git_dir(), Options::isolated().open_path_as_is(true))?,
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
                None,
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
                vec![
                    ("first!child!child".into(), vec![1], Some("child".into())),
                    ("second!child!child".into(), vec![1], Some("child".into())),
                ]
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
                Default::default(),
            )
            .map(|(logical, bytes, member, pages)| {
                assert!(pages.pages.is_empty());
                (logical, bytes, member)
            })
            .collect::<Vec<_>>();
            assert_eq!(entries, vec![("fixture.zip".into(), bytes, None)]);
        }
        Ok(())
    }

    #[test]
    fn git_pdf_expansion_uses_the_repository_control() -> Result<()> {
        use kingfisher_scanner::ScanControl;
        let hex: String =
            include_str!("../../crates/kingfisher-scanner/src/extraction/testdata/pages.pdf.hex")
                .split_whitespace()
                .collect();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect();
        let deadline = Instant::now();
        let control = ScanControl::default().with_deadline(deadline);
        for unlimited in [false, true] {
            let entries: Vec<_> = lazy_expand_entry(
                "fixture.pdf".into(),
                bytes.clone(),
                Some(1),
                crate::limits::ResourceLimits { unlimited },
                control.clone(),
            )
            .map(|(logical, bytes, member, pages)| {
                assert!(pages.pages.is_empty());
                (logical, bytes, member)
            })
            .collect();
            // The intermediate iterator preserves raw data; the Git fan-out boundary
            // checks its deadline and returns an error rather than scanning this data.
            assert_eq!(entries, vec![("fixture.pdf".into(), bytes.clone(), None)]);
        }
        assert!(
            super::check_repo_deadline(Some(deadline), Path::new("repo"), "git content extraction")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn archive_pdf_input_is_not_charged_twice_against_the_byte_limit() -> Result<()> {
        let hex: String =
            include_str!("../../crates/kingfisher-scanner/src/extraction/testdata/pages.pdf.hex")
                .split_whitespace()
                .collect();
        let bytes = hex::decode(hex)?;
        let control = kingfisher_scanner::ScanControl::default();
        let resources = crate::limits::ResourceLimits::default();
        let expected = super::extract_pdf_text_from_bytes_with_budget(&bytes, 4096, &control)?;
        let output_size: usize = expected.iter().map(|(_, text)| text.len()).sum();
        let budget = bytes.len() + output_size;
        assert!(bytes.len() > budget / 2);
        assert_eq!(
            super::extract_archive_pdf_pages(&bytes, budget, resources, &control)?,
            expected
        );
        assert!(
            super::extract_archive_pdf_pages(&bytes, budget - 1, resources, &control)
                .unwrap_err()
                .is::<kingfisher_scanner::extraction::ExtractionLimitExceeded>()
        );
        Ok(())
    }

    #[test]
    fn archive_pdf_expansion_keeps_members_larger_than_half_the_tree_budget() -> Result<()> {
        let hex: String =
            include_str!("../../crates/kingfisher-scanner/src/extraction/testdata/pages.pdf.hex")
                .split_whitespace()
                .collect();
        let bytes = hex::decode(hex)?;
        let control = kingfisher_scanner::ScanControl::default();
        let expected = super::extract_pdf_text_from_bytes_with_budget(&bytes, 4096, &control)?;
        let output_size: usize = expected.iter().map(|(_, text)| text.len()).sum();
        let budget = bytes.len() + output_size;
        assert!(bytes.len() > budget / 2);
        let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file("document.pdf", SimpleFileOptions::default())?;
        zip.write_all(&bytes)?;
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        tar.append_data(&mut header, "document.pdf", bytes.as_slice())?;
        // Exercise archive enumeration with the 128/256 MiB PDF budget
        // boundary scaled down to a tiny fixture.
        for (label, archive) in
            [("outer.zip", zip.finish()?.into_inner()), ("outer.tar", tar.into_inner()?)]
        {
            let mut entries = super::expand_entries_with_pdf_budget(
                Box::new(std::iter::once((label.into(), archive))),
                Some(1),
                crate::limits::ResourceLimits::default(),
                false,
                None,
                control.clone(),
                budget,
            );
            let (logical, raw, member, pages) = entries.next().unwrap();
            assert_eq!(logical, format!("{label}!document.pdf"));
            assert_eq!(member.as_deref(), Some("document.pdf"));
            assert_eq!(raw, bytes);
            assert_eq!(pages.pages, expected);
            assert!(entries.next().is_none());
        }
        Ok(())
    }

    #[test]
    fn standalone_git_pdf_has_independent_input_and_output_budgets() -> Result<()> {
        let hex: String =
            include_str!("../../crates/kingfisher-scanner/src/extraction/testdata/pages.pdf.hex")
                .split_whitespace()
                .collect();
        let bytes = hex::decode(hex)?;
        let control = kingfisher_scanner::ScanControl::default();
        let budget = bytes.len();
        let expected = super::extract_pdf_text_from_bytes_with_budget(&bytes, budget, &control)?;
        let mut entries = super::expand_entries_with_pdf_budget(
            Box::new(std::iter::once(("document.pdf".into(), bytes))),
            Some(1),
            crate::limits::ResourceLimits::default(),
            false,
            None,
            control,
            budget,
        );
        let (_, _, member, pages) = entries.next().unwrap();
        assert_eq!(member, None);
        assert_eq!(pages.pages, expected);
        assert!(entries.next().is_none());
        Ok(())
    }

    #[test]
    fn concurrent_pdf_deadlines_claim_only_one_repository_diagnostic() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        let control = kingfisher_scanner::ScanControl::default().with_deadline(Instant::now());
        use rayon::prelude::*;
        let errors: Vec<_> = (0..16)
            .into_par_iter()
            .map(|_| super::check_pdf_control(&control, Some(&flag)).unwrap_err())
            .collect();
        assert_eq!(
            errors.iter().filter(|error| error.is::<kingfisher_scanner::ScanAborted>()).count(),
            1
        );
        assert_eq!(
            errors.iter().filter(|error| error.to_string() == "__timeout_silenced__").count(),
            15
        );
    }

    #[test]
    fn git_blob_loader_reuses_retained_bytes_when_object_is_unavailable() -> Result<()> {
        use std::sync::Arc;

        use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern};

        let temp = tempdir()?;
        let repo = gix::init_bare(temp.path())?;
        let bytes = b"c3ludGhldGljIHJldGFpbmVkIEdpdCBjb250ZW50";
        let id = super::BlobId::compute_from_bytes(bytes);
        let oid = gix::ObjectId::from(id);
        assert!(repo.find_object(oid).is_err());

        let database = BlockDatabase::new(vec![Pattern::new(
            b"synthetic retained".to_vec(),
            Flag::default(),
            Some(0),
        )])?;
        let filter = super::GitContentFilter::new(
            Arc::new(super::ScannerPool::new(Arc::new(database))),
            1,
            true,
            false,
            Default::default(),
        );
        let blobs = GitBlobSource::Precomputed(vec![super::GitBlobMetadata {
            blob_oid: oid,
            indexed_size: std::num::NonZeroU64::new(bytes.len() as u64),
            retained_data: filter.retain_blob(bytes),
            first_seen: Default::default(),
        }]);
        let iter = super::GitRepoResultIter {
            inner: super::GitRepoResult { path: temp.path().to_owned(), repository: repo, blobs },
            path_selection: Default::default(),
            deadline: None,
            extract_archives: false,
            extraction_depth: None,
            resources: Default::default(),
            max_blob_size: Some(bytes.len() as u64),
            _marker: std::marker::PhantomData,
        };
        let loaded: Vec<_> = iter.collect::<Result<_>>()?;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1.bytes(), bytes);
        assert_eq!(loaded[0].1.id(), id);
        assert!(loaded[0].3.native_negative);
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
            Default::default(),
        )
        .collect::<Vec<_>>();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "dir/payload.zip!nested/secret.txt");
        assert_eq!(entries[0].1, b"token=not-a-real-secret");
        assert_eq!(entries[0].2.as_deref(), Some("nested/secret.txt"));
        Ok(())
    }

    #[test]
    fn resident_tar_matches_staged_members_and_fallbacks() -> Result<()> {
        use flate2::{Compression, write::GzEncoder};

        fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(bytes)?;
            Ok(encoder.finish()?)
        }

        let mut archive = tar::Builder::new(Vec::new());
        for bytes in [b"first".as_slice(), b"second".as_slice()] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            archive.append_data(&mut header, "nested/entry!literal.txt", bytes)?;
        }
        let archive = archive.into_inner()?;
        let mut invalid_path_archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let invalid_path = b"file-with-directory-separator/";
        header.as_old_mut().name[..invalid_path.len()].copy_from_slice(invalid_path);
        header.set_mode(0o644);
        header.set_size(1);
        header.set_cksum();
        invalid_path_archive.append(&header, b"x".as_slice())?;
        let invalid_path_archive = invalid_path_archive.into_inner()?;
        let resources = crate::limits::ResourceLimits::default();
        for (case, data) in [
            ("duplicates", archive.as_slice()),
            ("truncated first member", &archive[..513]),
            ("truncated second member", &archive[..1537]),
            ("invalid header", b"incomplete TAR header".as_slice()),
            ("invalid file path", invalid_path_archive.as_slice()),
            ("empty archive", &[0; 1024]),
        ] {
            let compressed = gzip(data)?;
            for (logical, data) in [
                ("outer.zip!nested/input.tar", data),
                ("outer.zip!nested/input.tar.gz", compressed.as_slice()),
            ] {
                let actual: Vec<_> =
                    super::extract_archive_bytes(logical, data, resources)?.collect();
                let expected = super::extract_staged_archive_bytes(
                    logical,
                    &super::archive_staged_name(logical),
                    data,
                    resources,
                )?;
                assert_eq!(actual, expected, "{case} in {logical}");
                if case == "duplicates" {
                    assert_eq!(actual.len(), 2);
                    for (entry, contents) in actual.iter().zip([b"first".as_slice(), b"second"]) {
                        assert_eq!(entry.0, format!("{logical}!nested/entry!literal.txt"));
                        assert_eq!(entry.1, contents);
                    }
                }
            }
        }

        let mut corrupt = gzip(&archive)?;
        let checksum = corrupt.len() - 8;
        corrupt[checksum] ^= 1;
        let entries: Vec<_> = lazy_expand_entry(
            "input.tgz".into(),
            corrupt.clone(),
            Some(2),
            resources,
            Default::default(),
        )
        .map(|(path, bytes, member, _)| (path, bytes, member))
        .collect();
        assert_eq!(entries, [("input.tgz".into(), corrupt, None)]);
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
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(inner_bytes.len() as u64);
        tar.append_data(&mut header, "inner.zip", inner_bytes.as_slice())?;
        for (label, archive) in
            [("dir/outer.zip", outer_cursor.into_inner()), ("dir/outer.tar", tar.into_inner()?)]
        {
            let shallow = lazy_expand_entry(
                label.into(),
                archive.clone(),
                Some(1),
                crate::limits::ResourceLimits::default(),
                Default::default(),
            )
            .collect::<Vec<_>>();
            assert_eq!(shallow.len(), 1);
            assert_eq!(shallow[0].0, format!("{label}!inner.zip"));
            assert_eq!(shallow[0].1, inner_bytes);

            let deep = lazy_expand_entry(
                label.into(),
                archive,
                Some(2),
                crate::limits::ResourceLimits::default(),
                Default::default(),
            )
            .collect::<Vec<_>>();
            assert_eq!(deep.len(), 1);
            assert_eq!(deep[0].0, format!("{label}!inner.zip!nested/secret.txt"));
            assert_eq!(deep[0].1, b"nested archive content");
            assert_eq!(deep[0].2.as_deref(), Some("nested/secret.txt"));
        }

        Ok(())
    }

    fn collect_file_bytes(file: FileResult) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>> {
        let iter = file
            .into_blob_iter(None, true, super::FileOpenMode::NoFollow)?
            .expect("file result should yield a blob");
        iter.collect::<Vec<_>>()
            .into_iter()
            .map(|item| {
                let (origin, blob, _, _) = item?;
                let path = origin
                    .first()
                    .full_path()
                    .expect("file origin should preserve the filesystem path");
                Ok((path, blob.bytes().to_vec()))
            })
            .collect()
    }

    #[test]
    fn raw_file_scan_preserves_the_probed_prefix() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("ordinary.txt");
        for data in [&b""[..], b"a", b"abcd", b"abcde", b"prefix followed by content"] {
            fs::write(&path, data)?;
            let blobs = collect_file_bytes(FileResult {
                path: path.clone(),
                num_bytes: data.len() as u64,
                extract_archives: true,
                extraction_depth: Some(2),
                resources: crate::limits::ResourceLimits::default(),
            })?;
            assert_eq!(blobs, [(path.clone(), data.to_vec())]);
        }
        Ok(())
    }

    #[test]
    fn buffered_utf16_file_keeps_the_original_blob_id() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("document.txt");
        let bytes = [0xff, 0xfe, b'a', 0, b'b', 0, b'c', 0];
        fs::write(&path, bytes)?;
        let file = FileResult {
            path,
            num_bytes: 0,
            extract_archives: true,
            extraction_depth: Some(2),
            resources: crate::limits::ResourceLimits::default(),
        };
        let iter =
            file.into_blob_iter(None, true, super::FileOpenMode::NoFollow)?.expect("buffered file");
        let loaded = iter.collect::<Vec<_>>();
        let (_, blob, _, _) = loaded[0].as_ref().unwrap();
        assert_eq!(blob.bytes(), b"abc");
        assert_eq!(blob.id(), super::BlobId::new(&bytes));
        Ok(())
    }

    #[test]
    fn buffered_read_rewinds_when_the_file_grows_past_its_reported_size() -> Result<()> {
        use std::io::{self, Cursor, Read, Seek, SeekFrom};

        struct ShortReads(Cursor<&'static [u8]>);

        impl Read for ShortReads {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let len = buffer.len().min(2);
                self.0.read(&mut buffer[..len])
            }
        }

        impl Seek for ShortReads {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.0.seek(pos)
            }
        }

        let mut reader = ShortReads(Cursor::new(b"grown"));
        assert!(super::read_small_file(&mut reader, 4)?.is_none());
        assert_eq!(reader.stream_position()?, 0);
        Ok(())
    }

    #[test]
    fn file_scan_checks_opened_size_before_extracting_zip_by_magic() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("payload");
        let mut zip = ZipWriter::new(fs::File::create(&path)?);
        zip.start_file("selected.txt", SimpleFileOptions::default())?;
        zip.write_all(b"archive member")?;
        let length = zip.finish()?.metadata()?.len();
        let queued = || FileResult {
            path: path.clone(),
            num_bytes: 0,
            extract_archives: true,
            extraction_depth: Some(2),
            resources: crate::limits::ResourceLimits::default(),
        };

        for selected in [false, true] {
            assert!(
                queued()
                    .into_blob_iter(Some(length - 1), selected, super::FileOpenMode::NoFollow)?
                    .is_none()
            );
            let blobs = queued()
                .into_blob_iter(Some(length), selected, super::FileOpenMode::NoFollow)?
                .expect("ZIP by magic");
            let blobs = blobs.collect::<Vec<_>>();
            assert_eq!(blobs.len(), 1);
            assert_eq!(blobs[0].as_ref().unwrap().1.bytes(), b"archive member");
        }
        Ok(())
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

/// Single files need no archive-member selection metadata; archive entries carry
/// paths established during extraction. Keep the ordinary path allocation-free.
enum FileResultIterKind {
    Single(Option<(OriginSet, Blob<'static>)>),
    Archive(Vec<LoadedBlob<'static>>),
    Stream(StreamedArchiveBlobs),
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
