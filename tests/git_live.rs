//! Opt-in, read-only provider checks. Credentials are captured in memory from gh,
//! never printed, placed in URLs, or written to repository configuration.
use std::{path::PathBuf, process::Command};

use anyhow::{Context, Result, ensure};
use kingfisher::{
    git_binary::{CloneMode, Git, ProviderHosts},
    git_url::GitUrl,
};

fn isolated(name: &str, body: impl FnOnce() -> Result<()>) -> Result<()> {
    if std::env::var_os("KF_GIT_LIVE_CHILD").is_some() {
        return body();
    }
    let output = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", name, "--nocapture"])
        .env("KF_GIT_LIVE_CHILD", "1")
        .output()?;
    ensure!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn gh(args: &[&str]) -> Result<Vec<u8>> {
    let output =
        Command::new("gh").args(args).output().context("gh must be installed and authenticated")?;
    ensure!(output.status.success(), "gh credential/metadata request failed ({})", output.status);
    Ok(output.stdout)
}

fn private_repository() -> Result<(String, String)> {
    let token = String::from_utf8(gh(&["auth", "token", "--hostname", "github.com"])?)?;
    let token = token.trim().to_owned();
    ensure!(!token.is_empty(), "gh returned no credential");
    let repos: serde_json::Value = serde_json::from_slice(&gh(&[
        "api",
        "--hostname",
        "github.com",
        "user/repos?visibility=private&affiliation=owner&per_page=100&sort=pushed",
    ])?)?;
    let repo = repos
        .as_array()
        .context("Expected repository metadata")?
        .iter()
        .filter(|repo| repo["private"].as_bool() == Some(true))
        .filter(|repo| repo["size"].as_u64().is_some_and(|size| size > 0 && size <= 10_240))
        .min_by_key(|repo| repo["size"].as_u64().unwrap_or(u64::MAX))
        .context(
            "No small, nonempty private repository is accessible for the opt-in clone check",
        )?;
    Ok((repo["full_name"].as_str().context("Missing repository name")?.to_owned(), token))
}

#[test]
#[ignore = "requires gh authentication and read access to a small private GitHub repository"]
fn authenticated_private_https_clone_without_git() -> Result<()> {
    isolated("authenticated_private_https_clone_without_git", || {
        let (name, token) = private_repository()?;
        let url: GitUrl =
            format!("https://github.com/{name}.git").parse().map_err(anyhow::Error::msg)?;
        let temp = tempfile::tempdir()?;
        temp_env::with_vars(
            [
                ("PATH", Some("")),
                ("KF_GIT_BINARY", Some("kingfisher-no-git-must-be-needed")),
                ("KF_GIT_CLONE_TIMEOUT_SECS", Some("90")),
                ("KF_GIT_UPDATE_TIMEOUT_SECS", Some("90")),
                ("GIT_CONFIG_COUNT", None),
                ("GIT_CONFIG_PARAMETERS", None),
            ],
            || -> Result<()> {
                let hosts = ProviderHosts::saas_defaults();
                // A private repository must not accidentally pass as anonymous/public.
                ensure!(
                    Git::with_provider_hosts_and_github_token(false, &hosts, None)
                        .create_fresh_clone(&url, &temp.path().join("anonymous"), CloneMode::Bare)
                        .is_err(),
                    "Private clone unexpectedly worked without credentials"
                );
                let git =
                    Git::with_provider_hosts_and_github_token(false, &hosts, Some(token.clone()));
                for (directory, mode) in [
                    ("bare", CloneMode::Bare),
                    ("mirror", CloneMode::Mirror),
                    ("checkout", CloneMode::Checkout),
                ] {
                    let destination = temp.path().join(directory);
                    git.create_fresh_clone(&url, &destination, mode)?;
                    git.update_clone(&url, &destination)?;
                    let repository = gix::open(&destination)?;
                    repository.head_commit()?;
                    let config = std::fs::read_to_string(repository.common_dir().join("config"))?;
                    ensure!(
                        !config.contains(&token),
                        "Credential persisted to repository configuration"
                    );
                    if matches!(mode, CloneMode::Checkout) {
                        repository.index()?;
                    }
                }
                Ok(())
            },
        )
    })
}

fn ssh_executable() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("GIT_SSH") {
        let path = PathBuf::from(path);
        if path.is_absolute() && path.is_file() {
            return Ok(path);
        }
    }
    let name = if cfg!(windows) { "ssh.exe" } else { "ssh" };
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .context("OpenSSH must be installed for the opt-in SSH check")
}

#[test]
#[ignore = "requires gh plus a GitHub-authorized SSH key/agent and trusted GitHub host key"]
fn authenticated_private_ssh_clone_without_git() -> Result<()> {
    isolated("authenticated_private_ssh_clone_without_git", || {
        let (name, _token) = private_repository()?;
        let ssh = ssh_executable()?;
        let mut ssh_command = format!(
            "{} -o StrictHostKeyChecking=yes -o UpdateHostKeys=no",
            shlex::try_quote(ssh.to_str().context("SSH path must be valid UTF-8")?)?,
        );
        // Keep opt-in VM checks isolated from the guest user's SSH configuration.
        if let Some(config) = std::env::var_os("KF_GIT_LIVE_SSH_CONFIG") {
            let config = PathBuf::from(config);
            ensure!(
                config.is_absolute() && config.is_file(),
                "KF_GIT_LIVE_SSH_CONFIG must name an existing absolute file"
            );
            ssh_command.push_str(" -F ");
            ssh_command.push_str(&shlex::try_quote(
                config.to_str().context("SSH configuration path must be valid UTF-8")?,
            )?);
        }
        let url: GitUrl =
            format!("git@github.com:{name}.git").parse().map_err(anyhow::Error::msg)?;
        let temp = tempfile::tempdir()?;
        temp_env::with_vars(
            [
                ("PATH", Some(std::ffi::OsStr::new(""))),
                ("GIT_SSH", Some(ssh.as_os_str())),
                // Require existing trust without adding or rotating known_hosts entries.
                ("GIT_SSH_COMMAND", Some(std::ffi::OsStr::new(&ssh_command))),
                ("KF_GIT_BINARY", Some(std::ffi::OsStr::new("kingfisher-no-git-must-be-needed"))),
                ("KF_GIT_CLONE_TIMEOUT_SECS", Some(std::ffi::OsStr::new("30"))),
                ("KF_GIT_UPDATE_TIMEOUT_SECS", Some(std::ffi::OsStr::new("30"))),
                ("GIT_CONFIG_COUNT", None),
                ("GIT_CONFIG_PARAMETERS", None),
            ],
            || -> Result<()> {
                let destination = temp.path().join("ssh.git");
                let git = Git::default();
                git.create_fresh_clone(&url, &destination, CloneMode::Mirror)?;
                git.update_clone(&url, &destination)?;
                let repository = gix::open(destination)?;
                repository.head_commit()?;
                Ok(())
            },
        )
    })
}
