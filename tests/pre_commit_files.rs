use std::{
    env, fs,
    path::Path,
    process::{Command, Output},
    time::Duration,
};

use predicates::{prelude::PredicateBooleanExt, str::contains};
use tempfile::tempdir;

const KINGFISHER: &str = env!("CARGO_BIN_EXE_kingfisher");
// Synthetic credential used to exercise the bundled GitHub detector offline.
const LEAK: &str = "github_token = \"ghp_p7R3k9Mx2N5q8W4b6C1d0F9h3J7s5V2x8L4z\"\n";
const SCAN_OPTIONS: &[&str] = &["--no-validate", "--redact", "--no-update-check", "--format=toon"];

fn git(repo: &Path, args: &[&str]) -> Output {
    let output = Command::new("git").current_dir(repo).args(args).output().expect("git should run");
    assert!(output.status.success(), "{args:?}: {}", String::from_utf8_lossy(&output.stderr));
    output
}

fn init_git(repo: &Path) {
    fs::create_dir_all(repo).unwrap();
    git(repo, &["init", "--quiet", "--template="]);
    git(repo, &["config", "user.name", "Kingfisher Test"]);
    git(repo, &["config", "user.email", "kingfisher@example.invalid"]);
    git(repo, &["config", "commit.gpgsign", "false"]);
    git(repo, &["config", "core.autocrlf", "false"]);
    git(repo, &["config", "core.hooksPath", ".git/no-hooks"]);
}

fn commit(repo: &Path) {
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "--quiet", "-m", "Add test fixtures"]);
}

fn file_scan(repo: &Path) -> assert_cmd::Command {
    let mut command = assert_cmd::Command::new(KINGFISHER);
    command
        .current_dir(repo)
        .args(["scan", "--pre-commit-files", "--quiet"])
        .args(SCAN_OPTIONS)
        .timeout(Duration::from_secs(60));
    command
}

#[test]
fn selected_files_are_literal_and_require_a_boundary() {
    let repo = tempdir().unwrap();
    init_git(repo.path());
    let selected = ["with space.txt", "--help", "github", "-"];
    for path in selected {
        fs::write(repo.path().join(path), LEAK).unwrap();
    }
    fs::write(repo.path().join("unselected.txt"), LEAK).unwrap();

    let output = file_scan(repo.path())
        .args(["--no-dedup", ""])
        .args(selected)
        .assert()
        .code(200)
        .stdout(contains("findings[4|]").and(contains("unselected.txt").not()))
        .get_output()
        .stdout
        .clone();
    let report = String::from_utf8(output).unwrap();
    for path in &selected[..3] {
        assert!(report.contains(path), "missing finding in {path:?}: {report}");
    }
    // Scan '-' on its own to distinguish the file from the standard input placeholder.
    file_scan(repo.path()).args(["", "-"]).assert().code(200);

    file_scan(repo.path()).arg("with space.txt").assert().failure();
    file_scan(repo.path()).arg("").assert().success();
    fs::create_dir(repo.path().join("directory")).unwrap();
    for mode in [None, Some("--preview")] {
        for (path, message) in
            [("directory", "regular file"), ("missing.txt", "Failed to inspect pre-commit file")]
        {
            file_scan(repo.path())
                .args(mode)
                .args(["", path])
                .assert()
                .failure()
                .stderr(contains(message));
        }
    }
}

#[test]
fn selected_files_respect_existing_exclusions() {
    let repo = tempdir().unwrap();
    init_git(repo.path());
    fs::create_dir(repo.path().join("excluded")).unwrap();
    fs::write(repo.path().join("excluded").join("excluded-child.txt"), LEAK).unwrap();
    fs::create_dir_all(repo.path().join("nested/build/sub")).unwrap();
    fs::write(repo.path().join("nested/build/sub/wildcard-child.txt"), LEAK).unwrap();
    fs::write(repo.path().join("also-excluded.txt"), LEAK).unwrap();
    fs::write(repo.path().join("selected.txt"), LEAK).unwrap();
    fs::write(repo.path().join("kingfisher.yml"), "filters:\n  exclude: [also-excluded.txt]\n")
        .unwrap();

    file_scan(repo.path())
        .args([
            "--config=kingfisher.yml",
            "--exclude=excluded",
            "--exclude=**/build",
            "--no-dedup",
            "",
            "excluded/excluded-child.txt",
            "also-excluded.txt",
            "nested/build/sub/wildcard-child.txt",
            "selected.txt",
        ])
        .assert()
        .code(200)
        .stdout(
            contains("selected.txt")
                .and(contains("excluded-child.txt").not())
                .and(contains("wildcard-child.txt").not())
                .and(contains("also-excluded.txt").not()),
        );
}

#[test]
fn selected_files_reject_explicit_history_and_nested_repository_scans() {
    let repo = tempdir().unwrap();
    init_git(repo.path());
    fs::write(repo.path().join("leak.txt"), LEAK).unwrap();

    for option in ["--git-history=full", "--scan-nested-repos", "--manage-baseline"] {
        for mode in [None, Some("--preview")] {
            file_scan(repo.path())
                .args(mode)
                .args([option, "", "leak.txt"])
                .assert()
                .failure()
                .stderr(contains(option.split('=').next().unwrap()));
        }
    }
    file_scan(repo.path()).args(["--git-history=none", "", "leak.txt"]).assert().code(200);
}

#[test]
fn selected_files_keep_repository_relative_paths_for_rules() {
    let repo = tempdir().unwrap();
    init_git(repo.path());
    fs::create_dir(repo.path().join("nested")).unwrap();
    fs::write(repo.path().join("nested/key.txt"), "acme_A1b2C3d4E5f6G7h8").unwrap();
    fs::write(
        repo.path().join("rules.yml"),
        "rules:\n  - id: acme.hook-path\n    name: Hook path fixture\n    pattern: '(acme_[A-Za-z0-9]{16})'\n    path: '^nested/key[.]txt$'\n    min_entropy: 0\n    confidence: high\n",
    )
    .unwrap();
    file_scan(repo.path())
        .args(["--rules-path=rules.yml", "--load-builtins=false", "", "nested/key.txt"])
        .assert()
        .code(200);
}

#[test]
fn selected_files_reuse_staged_repository_baselines() {
    let repo = tempdir().unwrap();
    init_git(repo.path());
    git(
        repo.path(),
        &["remote", "add", "origin", "https://example.invalid/org/kingfisher-fixture.git"],
    );
    fs::create_dir(repo.path().join("nested")).unwrap();
    fs::write(repo.path().join("nested").join("known.txt"), LEAK).unwrap();
    fs::write(repo.path().join(".gitattributes"), "*.txt text eol=crlf\n").unwrap();
    let crlf_path = repo.path().join("nested").join("known-crlf.txt");
    let crlf_leak = LEAK.replace('\n', "\r\n");
    let crlf_fixture = format!("first line\r\nsecond line\r\n{crlf_leak}");
    fs::write(&crlf_path, &crlf_fixture).unwrap();
    git(repo.path(), &["add", ".gitattributes", "nested/known.txt", "nested/known-crlf.txt"]);
    assert!(!git(repo.path(), &["show", ":nested/known-crlf.txt"]).stdout.contains(&b'\r'));
    let baseline = repo.path().join("baseline.yml");

    assert_cmd::Command::new(KINGFISHER)
        .current_dir(repo.path())
        .args(["scan", ".", "--staged", "--manage-baseline", "--baseline-file"])
        .arg(&baseline)
        .args(SCAN_OPTIONS)
        .timeout(Duration::from_secs(60))
        .assert()
        .code(200);
    let original = fs::read_to_string(&baseline).unwrap();
    assert!(original.contains("git://example.invalid/org/kingfisher-fixture"));
    commit(repo.path());

    file_scan(repo.path())
        .arg("--baseline-file")
        .arg(&baseline)
        .args(["--no-dedup", "", "nested/known.txt", "nested/known-crlf.txt"])
        .assert()
        .success();
    fs::write(&crlf_path, format!("{crlf_fixture}{crlf_leak}")).unwrap();
    file_scan(repo.path())
        .arg("--baseline-file")
        .arg(&baseline)
        .args(["--no-dedup", "", "nested/known-crlf.txt"])
        .assert()
        .code(200)
        .stdout(contains("findings[1|]"));
    file_scan(repo.path())
        .args(["--manage-baseline", "--baseline-file"])
        .arg(&baseline)
        .args(["", "nested/known.txt"])
        .assert()
        .failure();
    assert_eq!(original, fs::read_to_string(&baseline).unwrap());
}

#[test]
fn framework_hooks_scan_the_runner_selection() {
    let runners: Vec<_> = ["pre-commit", "prek"]
        .into_iter()
        .filter(|runner| {
            Command::new(runner)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        })
        .collect();
    if runners.is_empty() {
        eprintln!("Skipping hook runner integration: neither pre-commit nor prek is installed");
        return;
    }

    let fixture = tempdir().unwrap();
    let hooks_repo = fixture.path().join("hooks");
    init_git(&hooks_repo);
    let source = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::copy(source.join(".pre-commit-hooks.yaml"), hooks_repo.join(".pre-commit-hooks.yaml"))
        .unwrap();
    commit(&hooks_repo);
    let revision = git(&hooks_repo, &["rev-parse", "HEAD"]);
    let revision = std::str::from_utf8(&revision.stdout).unwrap().trim();
    // Pre-commit passes this local path to Git, including with MSYS2 Git on Windows.
    let hook_url = serde_json::to_string(&hooks_repo.to_str().unwrap().replace('\\', "/")).unwrap();
    let binary_dir = Path::new(KINGFISHER).parent().unwrap().to_owned();
    let path = env::join_paths(
        std::iter::once(binary_dir).chain(env::split_paths(&env::var_os("PATH").unwrap())),
    )
    .unwrap();

    for runner in runners {
        let repo = fixture.path().join(runner);
        init_git(&repo);
        fs::write(
            repo.join(".pre-commit-config.yaml"),
            format!(
                r#"repos:
  - repo: {hook_url}
    rev: {revision}
    hooks:
      - id: kingfisher
      - id: kingfisher-files
        exclude: '^excluded\.txt$'
        args: [--no-validate, --redact, --format=toon, --no-dedup, '']
"#
            ),
        )
        .unwrap();
        fs::write(repo.join("selected credential.txt"), LEAK).unwrap();
        // The runner selects tracked files even when a Git ignore rule matches.
        fs::write(repo.join(".gitignore"), "selected credential.txt\n").unwrap();
        git(&repo, &["add", "-f", "--", "selected credential.txt"]);
        fs::write(repo.join("excluded.txt"), LEAK).unwrap();
        fs::write(repo.join("benign.txt"), "no finding\n").unwrap();
        fs::write(repo.join("partially staged.txt"), "before\n").unwrap();
        commit(&repo);

        let hook = |id: &str, args: &[&str]| {
            let mut command = assert_cmd::Command::new(runner);
            command
                .args(["run", id])
                .args(args)
                .current_dir(&repo)
                .env("PATH", &path)
                .env("PRE_COMMIT_HOME", fixture.path().join("pre-commit-cache"))
                .env("PREK_HOME", fixture.path().join("prek-cache"))
                .timeout(Duration::from_secs(60));
            command.assert()
        };

        hook("kingfisher-files", &["--all-files"])
            .failure()
            .stdout(contains("selected credential.txt").and(contains("excluded.txt").not()));
        hook("kingfisher", &["--all-files"]).success();
        hook("kingfisher-files", &["--files", "excluded.txt", "benign.txt"]).success();
        hook("kingfisher-files", &["--files", "selected credential.txt"])
            .failure()
            .stdout(contains("selected credential.txt"));

        fs::write(repo.join("partially staged.txt"), "staged without finding\n").unwrap();
        git(&repo, &["add", "partially staged.txt"]);
        fs::write(repo.join("partially staged.txt"), LEAK).unwrap();
        hook("kingfisher-files", &[]).success();
        assert_eq!(fs::read_to_string(repo.join("partially staged.txt")).unwrap(), LEAK);

        git(&repo, &["add", "partially staged.txt"]);
        fs::write(repo.join("partially staged.txt"), "unstaged without finding\n").unwrap();
        hook("kingfisher-files", &[]).failure().stdout(contains("partially staged.txt"));
        assert_eq!(
            fs::read_to_string(repo.join("partially staged.txt")).unwrap(),
            "unstaged without finding\n"
        );
    }
}

#[test]
fn empty_option_values_do_not_end_the_hook_args() {
    let repo = tempdir().unwrap();
    init_git(repo.path());
    fs::write(repo.path().join("leak.txt"), LEAK).unwrap();

    // Only the last empty argument separates hook args from runner filenames.
    file_scan(repo.path())
        .args(["--user-agent-suffix", "", "", "leak.txt"])
        .assert()
        .code(200)
        .stdout(contains("leak.txt"));
}

#[test]
fn misplaced_file_mode_flag_reports_its_required_position() {
    let repo = tempdir().unwrap();
    init_git(repo.path());
    assert_cmd::Command::new(KINGFISHER)
        .current_dir(repo.path())
        .args(["scan", "--quiet", "--pre-commit-files", ""])
        .timeout(Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(contains("must immediately follow `scan`"));
}

#[cfg(unix)]
#[test]
fn selected_symlinks_are_skipped_without_failing_the_hook() {
    let repo = tempdir().unwrap();
    let outside = tempdir().unwrap();
    init_git(repo.path());
    fs::write(outside.path().join("target.txt"), LEAK).unwrap();
    std::os::unix::fs::symlink(outside.path().join("target.txt"), repo.path().join("link.txt"))
        .unwrap();
    fs::write(repo.path().join("leak.txt"), LEAK).unwrap();

    file_scan(repo.path())
        .args(["", "link.txt", "leak.txt"])
        .assert()
        .code(200)
        .stdout(contains("findings[1|]").and(contains("link.txt").not()));
}

#[test]
fn absolute_selection_matches_the_resolved_working_directory() {
    let repo = tempdir().unwrap();
    init_git(repo.path());
    fs::write(repo.path().join("leak.txt"), LEAK).unwrap();

    // Temp paths can differ from the process cwd by a symlink (macOS /var -> /private/var).
    file_scan(repo.path())
        .arg("")
        .arg(repo.path().join("leak.txt"))
        .assert()
        .code(200)
        .stdout(contains("leak.txt"));
}
