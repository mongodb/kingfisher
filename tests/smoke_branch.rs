// tests/smoke_branch.rs
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

///
///
///
///
///
/// Create a repo with a single file `secrets.txt` and five commits that append
/// lines in order, exactly like the provided shell script. Returns the repo dir
/// and the vector of commit IDs (oldest → newest).
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

    // Remaining commits mirror the shell script example.
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
