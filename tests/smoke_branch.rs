//
// Integration tests that exercise `kingfisher scan` against Git branches and commit
// references using locally constructed repositories. These ensure that the
// branch-focused flags behave as expected when scanning a repo without
// validation, including the ability to resume from a specific commit.

use std::fs;
use std::path::Path;

use anyhow::Result;
use assert_cmd::Command;
use git2::{BranchType, Repository, Signature, build::CheckoutBuilder};
use predicates::{prelude::PredicateBooleanExt, str::contains};
use tempfile::{TempDir, tempdir};

const GITHUB_TOKEN_VALUE: &str = "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";
const AWS_ACCESS_KEY_VALUE: &str = "AKIAX24QKKOLDJMZ5Y2T";
const GCP_API_KEY_VALUE: &str = "AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM";
const SLACK_TOKEN_VALUE: &str = "xoxb-123465789012-0987654321123-AbDcEfGhIjKlMnOpQrStUvWx";
const STRIPE_SECRET_VALUE: &str = "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";

const GITHUB_TOKEN_LINE: &str = "GITHUB_TOKEN = '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'";
const GCP_API_KEY_LINE: &str = "GCP_API_KEY = 'AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM'";
const SLACK_TOKEN_LINE: &str =
    "SLACK_BOT_TOKEN = 'xoxb-123465789012-0987654321123-AbDcEfGhIjKlMnOpQrStUvWx'";
const STRIPE_SECRET_LINE: &str = concat!(
    "STRIPE_SECRET_KEY = '",
    "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",
    "'",
);

#[test]
fn staged_scan_uses_git_executable_override() -> Result<()> {
    let temp = tempdir()?;
    let repo_dir = temp.path().join("repository with spaces");
    let repo = Repository::init(&repo_dir)?;
    repo.config()?.set_str("user.name", "Kingfisher Test")?;
    repo.config()?.set_str("user.email", "kingfisher@example.invalid")?;
    let signature = Signature::now("Kingfisher Test", "kingfisher@example.invalid")?;
    let empty_tree = repo.find_tree(repo.treebuilder(None)?.write()?)?;
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &empty_tree, &[])?;
    fs::write(repo_dir.join("secret.txt"), GITHUB_TOKEN_LINE)?;
    {
        let mut index = repo.index()?;
        index.add_path(Path::new("secret.txt"))?;
        index.write()?;
    }
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&repo_dir)
        .args(["--staged", "--no-validate", "--no-update-check", "--format", "toon"])
        .assert()
        .code(200)
        .stdout(contains(GITHUB_TOKEN_VALUE));

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&repo_dir)
        .args(["--staged", "--no-validate", "--no-update-check", "--format", "toon"])
        .env("KF_GIT_BINARY", temp.path().join("missing git.exe"))
        .assert()
        .stderr(contains("KF_GIT_BINARY"));
    Ok(())
}

#[test]
fn scan_by_commit_and_branch_diff() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let repo_dir = dir.path().join("repo");
    let repo = Repository::init(&repo_dir)?;
    let signature = Signature::now("tester", "tester@exmple.com")?;

    // Commit an initial config file packed with known test secrets. We'll scan
    // this commit directly via `--branch <commit-hash>` in the first assertion.
    let config_path = repo_dir.join("config.py");
    let config_contents = r"# test configuration with multiple secrets
GITHUB_TOKEN = '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'
GCP_API_KEY = 'AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM'
GOOGLE_API_KEY = 'AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM'
";
    fs::create_dir_all(config_path.parent().unwrap())?;
    fs::write(&config_path, config_contents)?;

    let mut index = repo.index()?;
    index.add_path(Path::new("config.py"))?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let initial_commit_id =
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])?;
    let initial_commit = repo.find_commit(initial_commit_id)?;
    let initial_commit_hex = initial_commit_id.to_string();

    // Create a "main" branch pointing at the initial commit to mirror the
    // documented example, but keep the default branch checkout untouched. Some
    // Git installations already default to `main`, so only create the branch
    // if it does not exist yet.
    if repo.find_branch("main", BranchType::Local).is_err() {
        repo.branch("main", &initial_commit, false)?;
    }

    // Create a feature branch that introduces a new secret file. The diff based
    // scan later on should report only this file when paired with --since-commit.
    repo.branch("feature-1", &initial_commit, true)?;
    repo.set_head("refs/heads/feature-1")?;
    repo.checkout_head(Some(CheckoutBuilder::new().force()))?;

    let canary_path = repo_dir.join("canary-token");
    let canary_contents = r"[default]
aws_access_key_id = AKIAX24QKKOLDJMZ5Y2T
aws_secret_access_key = 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
";
    fs::write(&canary_path, canary_contents)?;

    let mut index = repo.index()?;
    index.add_path(Path::new("config.py"))?;
    index.add_path(Path::new("canary-token"))?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let parent_commit = repo.head()?.peel_to_commit()?;
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "add canary token",
        &tree,
        &[&parent_commit],
    )?;

    // ── scan the repository by commit hash ───────────────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--branch",
            initial_commit_hex.as_str(),
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            contains("GITHUB-PAT")
                .and(contains("config.py"))
                .and(contains(initial_commit_hex.as_str())),
        );

    // ── scan only the diff between feature-1 and the merge base ─────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--branch",
            "feature-1",
            "--since-commit",
            initial_commit_hex.as_str(),
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            contains("canary-token")
                .and(contains("AWS-ACCESS-TOKEN"))
                .and(contains(AWS_ACCESS_KEY_VALUE)),
        )
        .stdout(contains("config.py").not());

    Ok(())
}

/// Create a repository with five commits appending synthetic secrets to one file.
/// Return the repository directory and commit IDs from oldest to newest.
fn setup_linear_repo_with_secrets() -> Result<(TempDir, std::path::PathBuf, Vec<git2::Oid>)> {
    let dir = tempdir()?;
    let repo_dir = dir.path().join("repo");
    let repo = Repository::init(&repo_dir)?;
    let sig = Signature::now("tester", "tester@exmple.com")?;

    let secrets_path = repo_dir.join("secrets.txt");

    // Commit #1 — GitHub
    fs::write(&secrets_path, GITHUB_TOKEN_LINE)?;
    let mut index = repo.index()?;
    index.add_path(Path::new("secrets.txt"))?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let mut commits = Vec::new();
    let c1 = repo.commit(Some("HEAD"), &sig, &sig, "Add GitHub token", &tree, &[])?;
    commits.push(c1);
    let mut parent_commit = repo.find_commit(c1)?;
    let mut contents = String::from(GITHUB_TOKEN_LINE);

    // Append one provider-specific secret per commit.
    let additions = [
        ("Add GCP API key", GCP_API_KEY_LINE),
        ("Add Slack bot token", SLACK_TOKEN_LINE),
        ("Add Stripe API key", STRIPE_SECRET_LINE),
    ];

    for (message, line) in additions {
        contents.push('\n');
        contents.push_str(line);
        fs::write(&secrets_path, &contents)?;

        let mut index = repo.index()?;
        index.add_path(Path::new("secrets.txt"))?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let oid = repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &[&parent_commit])?;
        commits.push(oid);
        parent_commit = repo.find_commit(oid)?;
    }

    // Create a named branch to mirror long-lived branch workflows.
    repo.branch("long-lived", &parent_commit, true)?;

    Ok((dir, repo_dir, commits))
}

#[test]
fn scan_specific_commit_reports_only_that_commit() -> Result<()> {
    let (_temp_dir, repo_dir, commits) = setup_linear_repo_with_secrets()?;
    let c1_hex = commits[0].to_string(); // first commit (GitHub only)

    // Scan exactly the initial commit via --branch <commit>
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--branch",
            c1_hex.as_str(),
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            // Must contain the first token, but none of the later secrets.
            contains("GITHUB-PAT")
                .and(contains(GITHUB_TOKEN_VALUE))
                .and(contains(GCP_API_KEY_VALUE).not())
                .and(contains(SLACK_TOKEN_VALUE).not())
                .and(contains(STRIPE_SECRET_VALUE).not()),
        );

    Ok(())
}

#[test]
fn scan_with_branch_root_includes_descendants() -> Result<()> {
    let (_temp_dir, repo_dir, commits) = setup_linear_repo_with_secrets()?;
    let c1_hex = commits[0].to_string(); // start from first commit

    // Using --branch-root should include the selected commit and remaining history up to HEAD
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--branch",
            c1_hex.as_str(),
            "--branch-root",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            contains("GITHUB-PAT")
                .and(contains(GITHUB_TOKEN_VALUE))
                .and(contains(GCP_API_KEY_VALUE))
                .and(contains(SLACK_TOKEN_VALUE))
                .and(contains(STRIPE_SECRET_VALUE)),
        );

    Ok(())
}

#[test]
fn scan_branch_tip_with_branch_root_commit() -> Result<()> {
    let (_temp_dir, repo_dir, commits) = setup_linear_repo_with_secrets()?;
    let root_commit_hex = commits[0].to_string();
    let latest_commit_hex = commits.last().expect("expected at least one commit").to_string();

    // Passing --branch-root-commit should implicitly enable inclusive scanning even
    // without the legacy --branch-root flag when targeting a named branch tip.
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--branch",
            "long-lived",
            "--branch-root-commit",
            root_commit_hex.as_str(),
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            contains("GITHUB-PAT")
                .and(contains(GITHUB_TOKEN_VALUE))
                .and(contains(GCP_API_KEY_VALUE))
                .and(contains(SLACK_TOKEN_VALUE))
                .and(contains(STRIPE_SECRET_VALUE))
                .and(contains(latest_commit_hex.as_str())),
        );

    Ok(())
}

#[test]
fn scan_branch_history_finds_deleted_secrets_only_in_reachable_commits() -> Result<()> {
    let dir = tempdir()?;
    let repo_dir = dir.path().join("repo");
    let repo = Repository::init(&repo_dir)?;
    let sig = Signature::now("tester", "tester@example.com")?;
    let mut index = repo.index()?;
    index.clear()?;
    let empty_tree = repo.find_tree(index.write_tree()?)?;
    let root_id = repo.commit(Some("HEAD"), &sig, &sig, "root", &empty_tree, &[])?;
    let root = repo.find_commit(root_id)?;

    // The checked-out branch stays clean. The selected branch introduces a secret,
    // then removes the file entirely.
    fs::write(repo_dir.join("deleted.txt"), GITHUB_TOKEN_LINE)?;
    index.add_path(Path::new("deleted.txt"))?;
    let secret_tree = repo.find_tree(index.write_tree()?)?;
    let secret_id = repo.commit(None, &sig, &sig, "secret", &secret_tree, &[&root])?;
    let secret = repo.find_commit(secret_id)?;
    let removed_id = repo.commit(None, &sig, &sig, "remove secret", &empty_tree, &[&secret])?;
    let removed = repo.find_commit(removed_id)?;

    // A merged side branch also deletes its secret before the merge. Traversing
    // only first parents would miss it.
    fs::write(repo_dir.join("deleted.txt"), GCP_API_KEY_LINE)?;
    index.add_path(Path::new("deleted.txt"))?;
    let side_tree = repo.find_tree(index.write_tree()?)?;
    let side_id = repo.commit(None, &sig, &sig, "side secret", &side_tree, &[&root])?;
    let side = repo.find_commit(side_id)?;
    let side_removed_id = repo.commit(None, &sig, &sig, "remove side", &empty_tree, &[&side])?;
    let side_removed = repo.find_commit(side_removed_id)?;
    let merge_id = repo.commit(
        Some("refs/heads/selected"),
        &sig,
        &sig,
        "merge",
        &empty_tree,
        &[&removed, &side_removed],
    )?;

    // Neither an unrelated branch nor the working tree belongs to this scan.
    fs::write(repo_dir.join("deleted.txt"), SLACK_TOKEN_LINE)?;
    index.add_path(Path::new("deleted.txt"))?;
    let unrelated_tree = repo.find_tree(index.write_tree()?)?;
    repo.commit(Some("refs/heads/unrelated"), &sig, &sig, "unrelated", &unrelated_tree, &[&root])?;

    let bare_dir = dir.path().join("bare.git");
    git2::build::RepoBuilder::new().bare(true).clone(repo_dir.to_str().unwrap(), &bare_dir)?;
    for path in [&repo_dir, &bare_dir] {
        for extra_args in [
            vec![],
            vec!["--git-history", "full"],
            vec!["--commit-metadata=false"],
            vec!["--since-commit", "HEAD"],
            vec!["--since-commit", "HEAD", "--git-history", "full"],
            vec!["--since-commit", "HEAD", "--commit-metadata=false"],
        ] {
            let range = extra_args.contains(&"--since-commit");
            let assertion = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
                .args([
                    "scan",
                    path.to_str().unwrap(),
                    "--branch",
                    "selected",
                    "--format",
                    "toon",
                    "--no-validate",
                    "--no-update-check",
                ])
                .args(extra_args)
                .assert()
                .code(200)
                .stdout(
                    contains(GITHUB_TOKEN_VALUE)
                        .and(contains(GCP_API_KEY_VALUE))
                        .and(contains(if range { "commit_range" } else { "branch_history" })),
                )
                .stdout(contains(SLACK_TOKEN_VALUE).not());
            let output = std::str::from_utf8(&assertion.get_output().stdout)?;
            let report: serde_json::Value = toon_format::decode_default(output)?;
            // Six reachable commits, excluding the unrelated branch's extra commit.
            if !range {
                assert_eq!(
                    report["audit"]["repositories"][0]["git"]["fetched_commit_count"], 6,
                    "{}",
                    report["audit"]
                );
            }
        }
        // Snapshot mode and explicit diff mode still scan the clean tip only.
        for extra_args in [
            vec!["--git-history", "none"],
            vec!["--since-commit", "selected"],
            vec!["--since-commit", "HEAD", "--git-history", "none"],
            vec!["--exclude", "deleted.txt"],
        ] {
            Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
                .args([
                    "scan",
                    path.to_str().unwrap(),
                    "--branch",
                    "selected",
                    "--format",
                    "toon",
                    "--no-validate",
                    "--no-update-check",
                ])
                .args(extra_args)
                .assert()
                .success()
                .stdout(contains(GITHUB_TOKEN_VALUE).not().and(contains(GCP_API_KEY_VALUE).not()));
        }
    }

    // Commit refs obey the same history scope and retain the introducing commit.
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--branch",
            &merge_id.to_string(),
            "--format",
            "toon",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(contains(secret_id.to_string()).and(contains(side_id.to_string())));
    Ok(())
}

#[test]
fn scan_preserves_original_author_separately_from_committer() -> Result<()> {
    let dir = tempdir()?;
    let repo_dir = dir.path().join("repository with spaces");
    let repo = Repository::init(&repo_dir)?;
    let author = Signature::now("Original Author", "author@example.invalid")?;
    let committer = Signature::now("Commit Bot", "bot@example.invalid")?;
    fs::write(repo_dir.join("config.py"), GITHUB_TOKEN_LINE)?;
    let mut index = repo.index()?;
    index.add_path(Path::new("config.py"))?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let commit_id = repo.commit(Some("HEAD"), &author, &committer, "fixture", &tree, &[])?;
    let commit_id = commit_id.to_string();

    // Retain both the working-tree and historical occurrences so the test inspects
    // Git provenance regardless of which copy parallel scanning encounters first.
    for selection in [["--git-history", "full"], ["--branch", commit_id.as_str()]] {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                "--format",
                "json",
                "--no-validate",
                "--no-dedup",
                "--no-update-check",
                "--rule",
                "github",
            ])
            .args(selection)
            .arg("--")
            .arg(&repo_dir)
            .output()?;
        assert_eq!(output.status.code(), Some(200), "{}", String::from_utf8_lossy(&output.stderr));
        let documents = serde_json::Deserializer::from_slice(&output.stdout)
            .into_iter::<serde_json::Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let commits: Vec<_> = documents
            .iter()
            .flat_map(|document| {
                document["findings"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_else(|| std::slice::from_ref(document))
            })
            .map(|record| &record["finding"]["git_metadata"]["commit"])
            .filter(|commit| commit.is_object())
            .collect();
        assert!(!commits.is_empty(), "missing Git provenance for {selection:?}");
        for commit in commits {
            assert_eq!(commit["author"]["name"], "Original Author");
            assert_eq!(commit["author"]["email"], "author@example.invalid");
            assert_eq!(commit["committer"]["name"], "Commit Bot");
            assert_eq!(commit["id"], commit_id);
            assert!(commit["date"].as_str().is_some_and(|date| !date.is_empty()));
        }
    }
    Ok(())
}

#[test]
fn remote_branch_scans_use_narrow_caches_separate_from_full_clones() -> Result<()> {
    let (temp, repo_dir, commits) = setup_linear_repo_with_secrets()?;
    let cache = temp.path().join("clones");
    let url = "https://example.invalid/branch-scan.git";
    // Keep an ordinary drive path: Git for Windows rejects canonicalized
    // verbatim paths (`//?/C:/...`) when used as a clone URL rewrite.
    let local = std::path::absolute(&repo_dir)?.to_string_lossy().replace('\\', "/");
    let run = |flags: &[&str]| {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        command
            .args([
                "scan",
                url,
                "--no-update-check",
                "--no-validate",
                "--format",
                "toon",
                "--rule",
                "github",
            ])
            .arg("--git-clone-dir")
            .arg(&cache)
            .args(flags)
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", format!("url.{local}.insteadOf"))
            .env("GIT_CONFIG_VALUE_0", url)
            .assert()
            .code(200)
            .stdout(contains(GITHUB_TOKEN_VALUE));
    };
    // Create and reuse a single-branch clone across full-history and snapshot scans,
    // even when mirror cloning is otherwise requested.
    for flags in [
        vec!["--branch", "long-lived", "--git-clone", "mirror"],
        vec!["--branch", "refs/heads/long-lived", "--git-clone", "bare"],
        vec!["--branch", "long-lived", "--git-history", "none"],
    ] {
        run(&flags);
    }
    let selected: Vec<_> =
        fs::read_dir(cache.join(".branch-clones"))?.collect::<std::io::Result<_>>()?;
    assert_eq!(selected.len(), 1, "equivalent selectors should reuse one narrow cache");
    {
        let clone = Repository::open_bare(selected[0].path())?;
        let branches: Vec<_> =
            clone.branches(Some(BranchType::Local))?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(branches.len(), 1);
        assert_eq!(clone.head()?.target(), commits.last().copied());
        for commit in &commits {
            assert!(clone.find_commit(*commit).is_ok());
        }
    }
    // A subsequent unrestricted scan must get its own complete clone.
    run(&[]);
    let full = Repository::open_bare(cache.join(url.replace(['/', ':'], "_")))?;
    assert!(full.branches(Some(BranchType::Local))?.count() >= 2);
    Ok(())
}

#[test]
fn since_commit_excludes_baseline_ancestry_and_keeps_intermediate_changes() -> Result<()> {
    let temp = tempdir()?;
    let repo = Repository::init_bare(temp.path())?;
    let sig = Signature::now("tester", "tester@example.com")?;
    let mut builder = repo.treebuilder(None)?;
    builder.insert("baseline.txt", repo.blob(GCP_API_KEY_LINE.as_bytes())?, 0o100644)?;
    let baseline_tree = repo.find_tree(builder.write()?)?;
    let root_id = repo.commit(None, &sig, &sig, "root", &baseline_tree, &[])?;
    let root = repo.find_commit(root_id)?;
    // The baseline diverges from HEAD, so excluding only the baseline commit
    // (instead of its ancestry) would report the unchanged GCP secret.
    repo.commit(Some("refs/heads/baseline"), &sig, &sig, "baseline", &baseline_tree, &[&root])?;
    builder.insert("temporary.txt", repo.blob(GITHUB_TOKEN_LINE.as_bytes())?, 0o100644)?;
    let secret_tree = repo.find_tree(builder.write()?)?;
    let secret_id = repo.commit(None, &sig, &sig, "add secret", &secret_tree, &[&root])?;
    let secret = repo.find_commit(secret_id)?;
    repo.commit(
        Some("refs/heads/selected"),
        &sig,
        &sig,
        "remove secret",
        &baseline_tree,
        &[&secret],
    )?;
    repo.set_head("refs/heads/selected")?;
    repo.tag(
        "baseline-tag",
        repo.find_reference("refs/heads/baseline")?.peel_to_commit()?.as_object(),
        &sig,
        "baseline",
        false,
    )?;

    for baseline in ["baseline", "baseline-tag", &root_id.to_string()] {
        for flags in [vec![], vec!["--git-history", "full"], vec!["--commit-metadata=false"]] {
            Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
                .arg("scan")
                .arg(temp.path())
                .args([
                    "--since-commit",
                    baseline,
                    "--no-validate",
                    "--no-update-check",
                    "--format",
                    "toon",
                ])
                .args(flags)
                .assert()
                .code(200)
                .stdout(contains(GITHUB_TOKEN_VALUE).and(contains(GCP_API_KEY_VALUE).not()));
        }
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(temp.path())
            .args([
                "--since-commit",
                baseline,
                "--git-history",
                "none",
                "--no-validate",
                "--no-update-check",
                "--format",
                "toon",
            ])
            .assert()
            .success()
            .stdout(contains(GITHUB_TOKEN_VALUE).not().and(contains(GCP_API_KEY_VALUE).not()));
    }
    Ok(())
}

#[test]
fn since_commit_without_branch_scans_all_refs() -> Result<()> {
    let temp = tempdir()?;
    let repo = Repository::init_bare(temp.path())?;
    let sig = Signature::now("tester", "tester@example.com")?;
    let mut builder = repo.treebuilder(None)?;
    builder.insert("baseline.txt", repo.blob(GCP_API_KEY_LINE.as_bytes())?, 0o100644)?;
    let baseline_tree = repo.find_tree(builder.write()?)?;
    let baseline_id =
        repo.commit(Some("refs/heads/main"), &sig, &sig, "baseline", &baseline_tree, &[])?;
    let baseline = repo.find_commit(baseline_id)?;
    repo.set_head("refs/heads/main")?;
    builder.insert("secret.txt", repo.blob(GITHUB_TOKEN_LINE.as_bytes())?, 0o100644)?;
    let secret_tree = repo.find_tree(builder.write()?)?;
    let secret_id = repo.commit(None, &sig, &sig, "add secret", &secret_tree, &[&baseline])?;
    let secret = repo.find_commit(secret_id)?;
    // No local branch reaches this history, and the secret is gone at its tip.
    repo.commit(
        Some("refs/remotes/origin/feature"),
        &sig,
        &sig,
        "remove secret",
        &baseline_tree,
        &[&secret],
    )?;

    for flags in [vec![], vec!["--git-history", "full"], vec!["--commit-metadata=false"]] {
        let assertion = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(temp.path())
            .args([
                "--since-commit",
                "HEAD",
                "--no-validate",
                "--no-update-check",
                "--format",
                "toon",
            ])
            .args(flags)
            .assert()
            .code(200)
            .stdout(contains(GITHUB_TOKEN_VALUE).and(contains(GCP_API_KEY_VALUE).not()));
        let report: serde_json::Value =
            toon_format::decode_default(std::str::from_utf8(&assertion.get_output().stdout)?)?;
        let audit = &report["audit"]["repositories"][0]["git"];
        assert_eq!(audit["scope"], "commit_range");
        assert_eq!(audit["tip_ref"], "(all refs and HEAD)");
        assert!(audit["tip_sha"].is_null());
    }
    for flags in [vec!["--branch", "HEAD"], vec!["--branch", "main"], vec!["--git-history", "none"]]
    {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(temp.path())
            .args([
                "--since-commit",
                "HEAD",
                "--no-validate",
                "--no-update-check",
                "--format",
                "toon",
            ])
            .args(flags)
            .assert()
            .success()
            .stdout(contains(GITHUB_TOKEN_VALUE).not().and(contains(GCP_API_KEY_VALUE).not()));
    }
    Ok(())
}

#[test]
fn since_hours_scans_remote_history_with_one_window_for_all_repositories() -> Result<()> {
    let temp = tempdir()?;
    let now = chrono::Utc::now().timestamp();
    let old = Signature::new("tester", "tester@example.com", &git2::Time::new(now - 172800, 0))?;
    let recent = Signature::new("tester", "tester@example.com", &git2::Time::new(now - 3600, 0))?;
    let paths = [temp.path().join("first.git"), temp.path().join("second.git")];
    for path in &paths {
        let repo = Repository::init_bare(path)?;
        let mut builder = repo.treebuilder(None)?;
        builder.insert("baseline.txt", repo.blob(GCP_API_KEY_LINE.as_bytes())?, 0o100644)?;
        let baseline_tree = repo.find_tree(builder.write()?)?;
        let baseline_id =
            repo.commit(Some("refs/heads/main"), &recent, &old, "old", &baseline_tree, &[])?;
        let baseline = repo.find_commit(baseline_id)?;
        repo.set_head("refs/heads/main")?;
        builder.insert("temporary.txt", repo.blob(GITHUB_TOKEN_LINE.as_bytes())?, 0o100644)?;
        let secret_tree = repo.find_tree(builder.write()?)?;
        let secret_id = repo.commit(None, &old, &recent, "recent", &secret_tree, &[&baseline])?;
        let secret = repo.find_commit(secret_id)?;
        repo.commit(
            Some("refs/remotes/origin/feature"),
            &recent,
            &old,
            "older child",
            &baseline_tree,
            &[&secret],
        )?;
    }
    let report_path = temp.path().join("report.json");
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .args(&paths)
        .args([
            "--since-hours",
            "24",
            "--git-history",
            "full",
            "--no-validate",
            "--no-update-check",
            "--format",
            "json",
            "--output",
        ])
        .arg(&report_path)
        .assert()
        .code(200);
    let output = fs::read_to_string(report_path)?;
    assert!(output.contains(GITHUB_TOKEN_VALUE));
    assert!(!output.contains(GCP_API_KEY_VALUE));
    let report: serde_json::Value = serde_json::from_str(&output)?;
    let repositories = report["audit"]["repositories"].as_array().unwrap();
    assert_eq!(repositories.len(), 2);
    let first = &repositories[0]["git"];
    for repository in repositories {
        let git = &repository["git"];
        assert_eq!(git["scope"], "commit_time_range");
        assert_eq!(git["tip_ref"], "(all refs and HEAD)");
        assert_eq!(git["since_timestamp"], first["since_timestamp"]);
        assert_eq!(git["until_timestamp"], first["until_timestamp"]);
        let end = git["until_timestamp"].as_i64().unwrap();
        assert_eq!(end - git["since_timestamp"].as_i64().unwrap(), 24 * 3600);
        assert!(end >= now && end <= chrono::Utc::now().timestamp());
    }
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&paths[0])
        .args([
            "--since-hours",
            "24",
            "--branch",
            "main",
            "--no-validate",
            "--no-update-check",
            "--format",
            "toon",
        ])
        .assert()
        .success()
        .stdout(contains(GITHUB_TOKEN_VALUE).not().and(contains(GCP_API_KEY_VALUE).not()));
    Ok(())
}

#[test]
fn since_hours_rejects_invalid_values_and_conflicting_scopes() -> Result<()> {
    let temp = tempdir()?;
    for value in ["0", "-1", "1.5", "NaN", "4294967296"] {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(temp.path())
            .arg(format!("--since-hours={value}"))
            .arg("--no-update-check")
            .assert()
            .failure()
            .stderr(contains("--since-hours"));
    }
    for flags in [
        vec!["--since-commit", "HEAD"],
        vec!["--staged"],
        vec!["--branch-root", "--branch", "main"],
        vec!["--branch-root-commit", "HEAD"],
        vec!["--git-history", "none"],
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(temp.path())
            .args(["--since-hours", "24", "--no-validate", "--no-update-check"])
            .args(flags)
            .assert()
            .failure()
            .stderr(contains("--since-hours"));
    }
    Ok(())
}
