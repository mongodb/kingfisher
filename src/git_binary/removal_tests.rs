//! Offline Git clone/update compatibility before inherited helper replacement.

use std::ffi::OsStr;

use super::{CloneMode, Git, GitError};
use crate::git_url::GitUrl;

fn commit(source: &git2::Repository, contents: &[u8], parent: Option<git2::Oid>) -> git2::Oid {
    let signature = git2::Signature::now("fixture", "fixture@example.invalid").unwrap();
    let blob = source.blob(contents).unwrap();
    let mut builder = source.treebuilder(None).unwrap();
    builder.insert("secret.txt", blob, 0o100644).unwrap();
    let tree = source.find_tree(builder.write().unwrap()).unwrap();
    let parent = parent.map(|id| source.find_commit(id).unwrap());
    source
        .commit(
            Some("refs/heads/main"),
            &signature,
            &signature,
            "fixture",
            &tree,
            &parent.iter().collect::<Vec<_>>(),
        )
        .unwrap()
}

fn local_source(temp: &tempfile::TempDir) -> (git2::Repository, GitUrl, Git, git2::Oid) {
    let source_path = temp.path().join("source with spaces");
    let source = git2::Repository::init_bare(&source_path).unwrap();
    let root = commit(&source, b"original contents", None);
    source.set_head("refs/heads/main").unwrap();
    let url: GitUrl = "https://example.invalid/acme/repo.git".parse().unwrap();
    let absolute = std::path::absolute(&source_path).unwrap();
    let local_path = absolute.to_string_lossy();
    // Git for Windows/MSYS2 accepts an absolute local path, without a file:// URL.
    #[cfg(windows)]
    let local_path = local_path.replace('\\', "/");
    let mut git = Git::default();
    git.credentials.extend(["-c".into(), format!("url.{local_path}.insteadOf={url}")]);
    (source, url, git, root)
}

#[test]
fn fresh_clone_modes_and_updates_work_with_local_rewrites_and_spaced_paths() {
    let temp = tempfile::tempdir().unwrap();
    let (source, url, git, root) = local_source(&temp);
    let destinations = [
        (CloneMode::Bare, temp.path().join("bare cache")),
        (CloneMode::Mirror, temp.path().join("mirror cache")),
        (CloneMode::Checkout, temp.path().join("checkout cache")),
    ];
    for (mode, destination) in &destinations {
        git.create_fresh_clone(&url, destination, *mode).unwrap();
        let clone = git2::Repository::open(destination).unwrap();
        assert_eq!(clone.head().unwrap().target(), Some(root));
        assert_eq!(clone.is_bare(), !matches!(mode, CloneMode::Checkout));
        if matches!(mode, CloneMode::Checkout) {
            assert_eq!(
                std::fs::read(destination.join("secret.txt")).unwrap(),
                b"original contents"
            );
        }
    }
    let next = commit(&source, b"updated contents", Some(root));
    for (_, destination) in &destinations {
        git.update_clone(&url, destination).unwrap();
        let clone = git2::Repository::open(destination).unwrap();
        assert!(clone.find_commit(next).is_ok());
    }
}

#[test]
fn clone_failure_retains_exit_status_and_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let (_source, url, git, _) = local_source(&temp);
    let destination = temp.path().join("occupied destination");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("keep.txt"), "caller-owned data").unwrap();
    let error = git.create_fresh_clone(&url, &destination, CloneMode::Bare).unwrap_err();
    let GitError::GitError { status, stderr, .. } = error else { panic!("wrong failure") };
    assert!(!status.success());
    assert!(!stderr.is_empty());
    assert_eq!(std::fs::read(destination.join("keep.txt")).unwrap(), b"caller-owned data");
}

#[test]
fn command_environment_preserves_noninteractive_isolation_and_tls_opt_in() {
    for ignore_certs in [false, true] {
        let command = Git::new(ignore_certs).git();
        let env: std::collections::HashMap<_, _> = command.get_envs().collect();
        for (key, value) in [
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
        ] {
            assert_eq!(env.get(OsStr::new(key)), Some(&Some(OsStr::new(value))));
        }
        assert_eq!(
            env.get(OsStr::new("GIT_SSL_NO_VERIFY")),
            ignore_certs.then_some(&Some(OsStr::new("1"))),
        );
    }
}

#[test]
fn fresh_clone_modes_install_exact_ordered_fetch_refspecs() {
    let temp = tempfile::tempdir().unwrap();
    let (_source, url, git, _) = local_source(&temp);
    for (mode, directory, expected) in [
        (CloneMode::Bare, "bare refspec cache", vec!["+refs/*:refs/remotes/origin/*"]),
        (
            CloneMode::Mirror,
            "mirror refspec cache",
            vec!["+refs/*:refs/remotes/origin/*", "+refs/*:refs/*"],
        ),
        (
            CloneMode::Checkout,
            "checkout refspec cache",
            vec!["+refs/*:refs/remotes/origin/*", "+refs/heads/*:refs/remotes/origin/*"],
        ),
    ] {
        let destination = temp.path().join(directory);
        git.create_fresh_clone(&url, &destination, mode).unwrap();
        let clone = git2::Repository::open(&destination).unwrap();
        // Read only the file installed by clone, without libgit2's global config layers.
        let config = git2::Config::open(&clone.path().join("config")).unwrap();
        let mut entries = config.multivar("remote.origin.fetch", None).unwrap();
        let mut installed = Vec::new();
        while let Some(entry) = entries.next() {
            installed.push(entry.unwrap().value().unwrap().to_owned());
        }
        let expected: Vec<String> = expected.into_iter().map(str::to_owned).collect();
        assert_eq!(installed, expected, "clone mode {mode:?}");
    }
}

#[test]
fn updates_move_and_prune_remote_refs_without_overwriting_checkout_or_bare_heads() {
    let temp = tempfile::tempdir().unwrap();
    let (source, url, git, root) = local_source(&temp);
    for name in ["refs/heads/to-prune", "refs/notes/to-prune"] {
        source.reference(name, root, false, "fixture").unwrap();
    }
    let destinations = [
        (CloneMode::Bare, temp.path().join("bare prune cache")),
        (CloneMode::Mirror, temp.path().join("mirror prune cache")),
        (CloneMode::Checkout, temp.path().join("checkout prune cache")),
    ];
    for (mode, destination) in &destinations {
        git.create_fresh_clone(&url, destination, *mode).unwrap();
        let clone = git2::Repository::open(destination).unwrap();
        for name in ["refs/remotes/origin/heads/to-prune", "refs/remotes/origin/notes/to-prune"] {
            assert_eq!(clone.find_reference(name).unwrap().target(), Some(root));
        }
    }
    let next = commit(&source, b"updated contents", Some(root));
    for name in ["refs/heads/to-prune", "refs/notes/to-prune"] {
        source.find_reference(name).unwrap().delete().unwrap();
    }
    for name in ["refs/heads/added", "refs/notes/added"] {
        source.reference(name, next, false, "fixture").unwrap();
    }
    for (mode, destination) in &destinations {
        git.update_clone(&url, destination).unwrap();
        let clone = git2::Repository::open(destination).unwrap();
        for name in [
            "refs/remotes/origin/heads/main",
            "refs/remotes/origin/heads/added",
            "refs/remotes/origin/notes/added",
        ] {
            assert_eq!(
                clone.find_reference(name).unwrap().target(),
                Some(next),
                "{mode:?}: {name}"
            );
        }
        for name in ["refs/remotes/origin/heads/to-prune", "refs/remotes/origin/notes/to-prune"] {
            assert_eq!(clone.find_reference(name).err().unwrap().code(), git2::ErrorCode::NotFound);
        }
        match mode {
            CloneMode::Mirror => {
                assert_eq!(clone.find_reference("refs/heads/main").unwrap().target(), Some(next));
                assert_eq!(clone.find_reference("refs/heads/added").unwrap().target(), Some(next));
                assert_eq!(
                    clone.find_reference("refs/heads/to-prune").err().unwrap().code(),
                    git2::ErrorCode::NotFound
                );
            }
            CloneMode::Bare => {
                assert_eq!(clone.find_reference("refs/heads/main").unwrap().target(), Some(root));
                assert_eq!(
                    clone.find_reference("refs/heads/to-prune").unwrap().target(),
                    Some(root)
                );
            }
            CloneMode::Checkout => {
                assert_eq!(clone.find_reference("refs/heads/main").unwrap().target(), Some(root));
                assert_eq!(
                    clone.find_reference("refs/remotes/origin/main").unwrap().target(),
                    Some(next)
                );
                assert_eq!(
                    clone.find_reference("refs/remotes/origin/to-prune").err().unwrap().code(),
                    git2::ErrorCode::NotFound
                );
                assert_eq!(
                    std::fs::read(destination.join("secret.txt")).unwrap(),
                    b"original contents"
                );
            }
        }
    }
}
