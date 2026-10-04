// Avoid "installer" in the test binary name: Windows may otherwise require elevation.
#![cfg(not(windows))]

use assert_cmd::Command;
use assert_cmd::assert::OutputAssertExt;
use predicates::str::contains;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use tempfile::TempDir;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn copy_scripts(dest: &Path) {
    let scripts_dir = dest.join("scripts");
    fs::create_dir_all(&scripts_dir).unwrap();

    let src = project_root().join("scripts").join("install-kingfisher-pre-commit.sh");
    let dst = scripts_dir.join("install-kingfisher-pre-commit.sh");
    fs::copy(src, dst).unwrap();
}

fn bash_path() -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("bash")];

    if cfg!(windows) {
        candidates.push(PathBuf::from(r"C:\\Program Files\\Git\\bin\\bash.exe"));
        candidates.push(PathBuf::from(r"C:\\Program Files (x86)\\Git\\bin\\bash.exe"));
    }

    candidates.into_iter().find(|candidate| {
        StdCommand::new(candidate)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    })
}

fn init_repo() -> (TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().to_path_buf();

    copy_scripts(&repo);

    Command::new("git").arg("init").current_dir(&repo).assert().success();

    let hooks_path = repo.join(".git/hooks");
    fs::create_dir_all(&hooks_path).unwrap();

    (dir, repo.clone(), hooks_path)
}

fn install(repo: &Path, hooks_path: &Path) {
    let Some(bash) = bash_path() else {
        eprintln!("skipping install: no bash found");
        return;
    };

    Command::new(bash)
        .arg(repo.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--hooks-path")
        .arg(hooks_path)
        .current_dir(repo)
        .assert()
        .success()
        .stdout(contains("Kingfisher pre-commit hook installed"));
}

//
// =====================================================
// REPO-MODE TESTS
// =====================================================
//
#[test]
fn installs_wrapper_without_existing_hook() {
    let (_tmp, repo, hooks_path) = init_repo();

    install(&repo, &hooks_path);

    let pre_commit = hooks_path.join("pre-commit");
    let kf_wrapper = hooks_path.join("kingfisher-pre-commit");
    let legacy = hooks_path.join("pre-commit.legacy.kingfisher");

    let wrapper = fs::read_to_string(&pre_commit).unwrap();
    let kf_script = fs::read_to_string(&kf_wrapper).unwrap();

    assert!(wrapper.contains("# Kingfisher pre-commit wrapper"));
    assert!(wrapper.contains("kingfisher-pre-commit"));
    assert!(kf_script.contains("kingfisher scan . --staged --quiet --no-update-check"));
    assert!(!legacy.exists());
}

#[test]
fn preserves_existing_hook_and_runs_it_first() {
    let (_tmp, repo, hooks_path) = init_repo();

    let log = repo.join("hook.log");
    let legacy = hooks_path.join("pre-commit");
    fs::write(&legacy, format!("#!/usr/bin/env bash\necho legacy >> {}\n", log.display())).unwrap();
    StdCommand::new("chmod").args(["+x", legacy.to_str().unwrap()]).assert().success();

    let bin_dir = repo.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let fake_kingfisher = bin_dir.join("kingfisher");
    fs::write(
        &fake_kingfisher,
        format!("#!/usr/bin/env bash\necho \"kingfisher $*\" >> {}\n", log.display()),
    )
    .unwrap();
    StdCommand::new("chmod").args(["+x", fake_kingfisher.to_str().unwrap()]).assert().success();

    install(&repo, &hooks_path);

    // Execute wrapper
    let wrapper = hooks_path.join("pre-commit");
    StdCommand::new(wrapper)
        .current_dir(&repo)
        .env("PATH", format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap()))
        .assert()
        .success();

    let log_contents = fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = log_contents.lines().collect();
    assert_eq!(lines[0], "legacy");
    assert!(lines[1].contains("kingfisher scan . --staged --quiet --no-update-check"));

    assert!(hooks_path.join("pre-commit.legacy.kingfisher").exists());
}

#[test]
fn uninstall_restores_original_hook() {
    let (_tmp, repo, hooks_path) = init_repo();

    let legacy = hooks_path.join("pre-commit");
    fs::write(&legacy, "#!/usr/bin/env bash\necho legacy\n").unwrap();
    StdCommand::new("chmod").args(["+x", legacy.to_str().unwrap()]).assert().success();

    install(&repo, &hooks_path);

    Command::new("bash")
        .arg(repo.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--uninstall")
        .arg("--hooks-path")
        .arg(&hooks_path)
        .current_dir(&repo)
        .assert()
        .success();

    let restored = hooks_path.join("pre-commit");
    let restored_content = fs::read_to_string(&restored).unwrap();
    assert!(restored_content.contains("legacy"));
    assert!(!restored_content.contains("Kingfisher pre-commit wrapper"));
    assert!(!hooks_path.join("kingfisher-pre-commit").exists());
    assert!(!hooks_path.join("pre-commit.legacy.kingfisher").exists());
}

#[test]
fn uninstall_removes_wrapper_when_no_previous_hook() {
    let (_tmp, repo, hooks_path) = init_repo();

    install(&repo, &hooks_path);

    Command::new("bash")
        .arg(repo.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--uninstall")
        .arg("--hooks-path")
        .arg(&hooks_path)
        .current_dir(&repo)
        .assert()
        .success();

    assert!(!hooks_path.join("pre-commit").exists());
    assert!(!hooks_path.join("kingfisher-pre-commit").exists());
    assert!(!hooks_path.join("pre-commit.legacy.kingfisher").exists());
}

#[test]
fn pre_commit_framework_invokes_kingfisher() {
    // Skip this test if `pre-commit` is not available (e.g., in some CI images).
    if StdCommand::new("pre-commit").arg("--version").output().is_err() {
        eprintln!(
            "skipping pre_commit_framework_invokes_kingfisher: `pre-commit` not found in PATH"
        );
        return;
    }

    let (_tmp, repo, _hooks_path) = init_repo();

    let log = repo.join("hook.log");
    let bin_dir = repo.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    // Fake kingfisher binary that just logs its argv to hook.log
    let fake_kingfisher = bin_dir.join("kingfisher");
    fs::write(&fake_kingfisher, format!("#!/usr/bin/env bash\necho \"$@\" > {}\n", log.display()))
        .unwrap();
    StdCommand::new("chmod").args(["+x", fake_kingfisher.to_str().unwrap()]).assert().success();

    // Local pre-commit config that uses `kingfisher` as the entry
    fs::write(
        repo.join(".pre-commit-config.yaml"),
        r#"repos:
- repo: local
  hooks:
    - id: kingfisher-local
      name: kingfisher (local binary)
      entry: kingfisher
      language: system
      args: ["scan", ".", "--staged", "--quiet", "--redact", "--only-valid", "--no-update-check"]
      pass_filenames: false
      always_run: true
"#,
    )
    .unwrap();

    // Something for pre-commit to see as a tracked file
    fs::write(repo.join("README.md"), "demo").unwrap();

    // Run pre-commit directly, with our fake kingfisher at the front of PATH
    Command::new("pre-commit")
        .args(["run", "--all-files"])
        .current_dir(&repo)
        .env("PATH", format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap()))
        .assert()
        .success()
        .stdout(contains("kingfisher (local binary)"));

    let log_contents = fs::read_to_string(&log).unwrap();
    assert!(log_contents.contains("scan"));
    assert!(log_contents.contains("--staged"));
    assert!(log_contents.contains("--quiet"));
    assert!(log_contents.contains("--redact"));
}

#[test]
fn installer_hook_executes_kingfisher_command() {
    let (_tmp, repo, hooks_path) = init_repo();

    fs::write(repo.join("canary.txt"), "secret").unwrap();
    StdCommand::new("git").args(["add", "canary.txt"]).current_dir(&repo).assert().success();

    let log = repo.join("hook.log");
    let bin_dir = repo.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let fake_kingfisher = bin_dir.join("kingfisher");
    fs::write(
        &fake_kingfisher,
        format!("#!/usr/bin/env bash\necho \"kingfisher $@\" >> {}\n", log.display()),
    )
    .unwrap();
    StdCommand::new("chmod").args(["+x", fake_kingfisher.to_str().unwrap()]).assert().success();

    install(&repo, &hooks_path);

    let wrapper = hooks_path.join("pre-commit");
    StdCommand::new(wrapper)
        .current_dir(&repo)
        .env("PATH", format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap()))
        .assert()
        .success();

    let log_contents = fs::read_to_string(&log).unwrap();
    assert!(log_contents.contains("kingfisher scan . --staged --quiet --no-update-check"));
}

//
// =====================================================
// "GLOBAL" SEMANTICS TESTS USING --hooks-path
// (deterministic, no real global config)
// =====================================================
//

fn init_fake_global() -> (TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let fake_global_hooks = root.join("fake-global-hooks");
    fs::create_dir_all(&fake_global_hooks).unwrap();

    copy_scripts(&root);

    (tmp, root, fake_global_hooks)
}

#[test]
fn global_semantics_installs_wrapper_and_inner_hook() {
    let (_tmp, root, hooks) = init_fake_global();

    let Some(bash) = bash_path() else {
        eprintln!("skipping global_semantics_installs_wrapper_and_inner_hook: no bash found");
        return;
    };

    Command::new(bash)
        .arg(root.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--hooks-path")
        .arg(&hooks)
        .assert()
        .success();

    assert!(hooks.join("pre-commit").exists());
    assert!(hooks.join("kingfisher-pre-commit").exists());
}

#[test]
fn global_semantics_preserves_existing_hook_and_backup() {
    let (_tmp, root, hooks) = init_fake_global();

    let legacy = hooks.join("pre-commit");
    fs::write(&legacy, "#!/usr/bin/env bash\necho global-legacy\n").unwrap();
    StdCommand::new("chmod").args(["+x", legacy.to_str().unwrap()]).assert().success();

    let Some(bash) = bash_path() else {
        eprintln!("skipping global_semantics_preserves_existing_hook_and_backup: no bash found");
        return;
    };

    Command::new(bash)
        .arg(root.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--hooks-path")
        .arg(&hooks)
        .assert()
        .success();

    assert!(hooks.join("pre-commit").exists());
    assert!(hooks.join("pre-commit.legacy.kingfisher").exists());
}

#[test]
fn global_semantics_uninstall_restores_or_removes() {
    let (_tmp, root, hooks) = init_fake_global();

    // case 1: with existing legacy
    let legacy = hooks.join("pre-commit");
    fs::write(&legacy, "#!/usr/bin/env bash\necho global-legacy\n").unwrap();
    StdCommand::new("chmod").args(["+x", legacy.to_str().unwrap()]).assert().success();

    let Some(bash) = bash_path() else {
        eprintln!("skipping global_semantics_uninstall_restores_or_removes: no bash found");
        return;
    };

    Command::new(&bash)
        .arg(root.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--hooks-path")
        .arg(&hooks)
        .assert()
        .success();

    Command::new(&bash)
        .arg(root.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--uninstall")
        .arg("--hooks-path")
        .arg(&hooks)
        .assert()
        .success();

    // After uninstall with legacy, pre-commit should exist and contain legacy content
    let restored = fs::read_to_string(hooks.join("pre-commit")).unwrap();
    assert!(restored.contains("global-legacy"));

    // case 2: no existing legacy, fresh install then uninstall
    let (_tmp2, root2, hooks2) = init_fake_global();
    Command::new(&bash)
        .arg(root2.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--hooks-path")
        .arg(&hooks2)
        .assert()
        .success();

    Command::new(&bash)
        .arg(root2.join("scripts/install-kingfisher-pre-commit.sh"))
        .arg("--uninstall")
        .arg("--hooks-path")
        .arg(&hooks2)
        .assert()
        .success();

    assert!(!hooks2.join("pre-commit").exists());
    assert!(!hooks2.join("kingfisher-pre-commit").exists());
    assert!(!hooks2.join("pre-commit.legacy.kingfisher").exists());
}
