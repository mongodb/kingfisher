//! Filesystem enumeration compatibility before inherited helper replacement.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::Parser;

use super::{FileResult, FilesystemEnumerator, FoundInput};
use crate::cli;

fn args(root: &Path, extra: &[&str]) -> cli::commands::scan::ScanArgs {
    let mut arguments =
        vec![OsString::from("kingfisher"), OsString::from("scan"), root.as_os_str().to_owned()];
    arguments.extend(extra.iter().map(OsString::from));
    let parsed = cli::global::CommandLineArgs::try_parse_from(arguments).unwrap();
    let cli::global::Command::Scan(command) = parsed.command else { panic!("expected scan") };
    let cli::commands::scan::ScanOperation::Scan(args) = command.into_operation().unwrap() else {
        panic!("expected scan operation")
    };
    args
}

fn collect(
    enumerator: &FilesystemEnumerator,
) -> (BTreeMap<PathBuf, FileResult>, BTreeSet<PathBuf>) {
    let (send, receive) = crossbeam_channel::unbounded();
    enumerator.run(send).unwrap();
    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    for input in receive.try_iter() {
        match input {
            FoundInput::File(file) => {
                assert!(files.insert(file.path.clone(), file).is_none());
            }
            FoundInput::Directory(directory) => {
                directories.insert(directory.path);
            }
            FoundInput::EnumeratorFile(_) => {
                panic!("filesystem walk must not invent JSONL inputs")
            }
        }
    }
    (files, directories)
}

#[test]
fn an_empty_root_list_retains_its_error() {
    let temp = tempfile::tempdir().unwrap();
    let error = FilesystemEnumerator::new::<PathBuf>(&[], &args(temp.path(), &[]))
        .err()
        .expect("an empty root list must fail");
    assert_eq!(error.to_string(), "No inputs provided");
}

#[test]
fn recursive_walk_preserves_sizes_hidden_files_and_archive_resource_settings() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("nested")).unwrap();
    let files = [temp.path().join(".hidden"), temp.path().join("nested").join("binary.bin")];
    std::fs::write(&files[0], b"abc").unwrap();
    std::fs::write(&files[1], [0, 0xff, 1, 2]).unwrap();
    let args = args(temp.path(), &["--no-extract-archives", "--no-limits"]);
    let mut enumerator = FilesystemEnumerator::new(&[temp.path()], &args).unwrap();
    enumerator.threads(2);
    let (found, directories) = collect(&enumerator);
    assert_eq!(found.len(), 2);
    assert!(directories.contains(temp.path()));
    assert!(directories.contains(&temp.path().join("nested")));
    for (index, size) in [3, 4].into_iter().enumerate() {
        let file = &found[&files[index]];
        assert_eq!(file.num_bytes, size);
        assert!(!file.extract_archives);
        assert_eq!(file.extraction_depth, args.content_filtering_args.archive_depth());
        assert_eq!(file.resources, args.content_filtering_args.resource_limits());
        assert!(file.resources.unlimited);
    }
}

#[test]
fn file_size_limits_apply_to_direct_roots_and_directory_entries_inclusively() {
    let temp = tempfile::tempdir().unwrap();
    let exact = temp.path().join("exact.bin");
    let over = temp.path().join("over.bin");
    std::fs::write(&exact, b"1234").unwrap();
    std::fs::write(&over, b"12345").unwrap();
    let args = args(temp.path(), &[]);
    for roots in [vec![temp.path().to_owned()], vec![exact.clone(), over.clone()]] {
        let mut enumerator = FilesystemEnumerator::new(&roots, &args).unwrap();
        enumerator.threads(2).max_filesize(Some(4));
        let (files, _) = collect(&enumerator);
        assert!(files.contains_key(&exact));
        assert!(!files.contains_key(&over));
        enumerator.max_filesize(None);
        let (files, _) = collect(&enumerator);
        assert!(files.contains_key(&exact) && files.contains_key(&over));
        enumerator.max_filesize(Some(0));
        assert!(collect(&enumerator).0.is_empty());
    }
}

#[test]
fn explicit_ignore_rules_and_exported_gitignore_agree_for_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("inputs");
    std::fs::create_dir(&root).unwrap();
    let keep = root.join("keep.txt");
    let ignored = root.join("drop.tmp");
    std::fs::write(&keep, b"keep").unwrap();
    std::fs::write(&ignored, b"drop").unwrap();
    let ignore = temp.path().join("ignore.txt");
    std::fs::write(&ignore, "*.tmp\n").unwrap();
    let mut enumerator = FilesystemEnumerator::new(&[&root], &args(&root, &[])).unwrap();
    enumerator.threads(2).add_ignore(&ignore).unwrap();
    let (files, _) = collect(&enumerator);
    assert!(files.contains_key(&keep));
    assert!(!files.contains_key(&ignored));
    let propagated = enumerator.gitignore().unwrap();
    assert!(propagated.matched(&ignored, false).is_ignore());
    assert!(!propagated.matched(&keep, false).is_ignore());
}

#[test]
fn repository_pruning_keeps_explicit_exclusions_active() {
    let temp = tempfile::tempdir().unwrap();
    for name in ["keep", "excluded", "repository"] {
        std::fs::create_dir(temp.path().join(name)).unwrap();
        std::fs::write(temp.path().join(name).join("secret.env"), b"fixture").unwrap();
    }
    let mut enumerator =
        FilesystemEnumerator::new(&[temp.path()], &args(temp.path(), &[])).unwrap();
    enumerator.threads(2).set_exclude_patterns(&["excluded".into()]).unwrap();
    enumerator.set_repository_excludes(vec![temp.path().join("repository")]);
    let (files, directories) = collect(&enumerator);
    assert_eq!(
        files.keys().cloned().collect::<Vec<_>>(),
        [temp.path().join("keep").join("secret.env")]
    );
    assert!(!directories.contains(&temp.path().join("excluded")));
    assert!(!directories.contains(&temp.path().join("repository")));
}

#[test]
fn custom_filter_prunes_a_subtree_and_multiple_roots_are_all_visited() {
    let temp = tempfile::tempdir().unwrap();
    let roots = [temp.path().join("first"), temp.path().join("second")];
    for root in &roots {
        std::fs::create_dir_all(root.join("prune")).unwrap();
        std::fs::write(root.join("keep.env"), b"keep").unwrap();
        std::fs::write(root.join("prune").join("drop.env"), b"drop").unwrap();
    }
    let mut enumerator = FilesystemEnumerator::new(&roots, &args(&roots[0], &[])).unwrap();
    enumerator.threads(2).filter_entry(|entry| entry.file_name() != "prune");
    let (files, _) = collect(&enumerator);
    assert_eq!(files.len(), 2);
    for root in &roots {
        assert!(files.contains_key(&root.join("keep.env")));
    }
}

#[test]
fn a_closed_receiver_does_not_panic_or_make_the_walk_fail() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("data.txt"), "data").unwrap();
    let mut enumerator =
        FilesystemEnumerator::new(&[temp.path()], &args(temp.path(), &[])).unwrap();
    enumerator.threads(2);
    let (send, receive) = crossbeam_channel::unbounded();
    drop(receive);
    enumerator.run(send).unwrap();
}

#[cfg(unix)]
#[test]
fn unicode_paths_and_symlink_policy_are_preserved() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let path = root.join("路径.txt");
    std::fs::write(&path, b"bytes").unwrap();
    let external = temp.path().join("external.txt");
    std::fs::write(&external, "target").unwrap();
    let link = root.join("linked.txt");
    symlink(&external, &link).unwrap();
    let mut enumerator = FilesystemEnumerator::new(&[&root], &args(&root, &[])).unwrap();
    enumerator.threads(2);
    let (files, _) = collect(&enumerator);
    assert!(files.contains_key(&path));
    assert!(!files.contains_key(&link));
    enumerator.follow_links(true);
    let (files, _) = collect(&enumerator);
    assert!(files.contains_key(&path));
    assert!(files.contains_key(&link));
}

// APFS requires valid UTF-8 filenames; Linux filesystems also allow these raw bytes.
#[cfg(target_os = "linux")]
#[test]
fn arbitrary_filename_bytes_are_preserved() {
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join(OsString::from_vec(vec![b'n', 0xff]));
    std::fs::write(&path, b"bytes").unwrap();
    let mut enumerator =
        FilesystemEnumerator::new(&[temp.path()], &args(temp.path(), &[])).unwrap();
    enumerator.threads(2);
    let (files, _) = collect(&enumerator);
    assert_eq!(files.keys().cloned().collect::<Vec<_>>(), [path]);
}

// This test adapter invokes the original private visitor boundary. If that private
// adapter is replaced, only this delegation changes; the assertions below remain.
fn invoke_entry_for_contract(
    result: Result<ignore::DirEntry, ignore::Error>,
    output: &super::Output,
) -> ignore::WalkState {
    let mut visitor = super::Visitor {
        max_file_size: None,
        extract_archives: true,
        extraction_depth: Some(7),
        resources: crate::limits::ResourceLimits { unlimited: false },
        output,
    };
    ignore::ParallelVisitor::visit(&mut visitor, result)
}

#[test]
fn a_walker_error_continues_without_emitting_an_input() {
    let (send, receive) = crossbeam_channel::unbounded();
    let error = ignore::Error::Io(std::io::Error::other("synthetic walker failure"));
    assert_eq!(invoke_entry_for_contract(Err(error), &send), ignore::WalkState::Continue);
    assert!(matches!(receive.try_recv(), Err(crossbeam_channel::TryRecvError::Empty)));
}

#[test]
fn archive_extraction_and_finite_resource_limits_are_forwarded_to_files() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.bin");
    std::fs::write(&path, b"synthetic input").unwrap();
    let args = args(temp.path(), &["--extraction-depth", "7"]);
    assert!(!args.content_filtering_args.no_extract_archives);
    assert!(!args.content_filtering_args.no_limits);
    let mut enumerator = FilesystemEnumerator::new(&[temp.path()], &args).unwrap();
    enumerator.threads(2);
    let (found, _) = collect(&enumerator);
    assert_eq!(found.len(), 1);
    let file = &found[&path];
    assert!(file.extract_archives);
    assert_eq!(file.extraction_depth, Some(7));
    assert_eq!(file.resources, crate::limits::ResourceLimits { unlimited: false });
    assert_eq!(file.resources, args.content_filtering_args.resource_limits());
}
