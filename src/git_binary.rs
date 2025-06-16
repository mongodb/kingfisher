use std::{
    path::Path,
    process::{Command, ExitStatus, Output, Stdio},
};

use tracing::{debug, debug_span};

use crate::git_url::GitUrl;

/// Represents errors that can occur when interacting with the `git` CLI.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git execution failed: {0}")]
    IOError(#[from] std::io::Error),

    #[error(
        "git execution failed\ncode={}\nstdout=```\n{}```\nstderr=```\n{}```",
        .status,
        String::from_utf8_lossy(.stdout),
        String::from_utf8_lossy(.stderr)
    )]
    GitError { stdout: Vec<u8>, stderr: Vec<u8>, status: ExitStatus },
}

/// A helper struct for running `git` commands.
///
/// It supports optional GitHub credentials passed via the
/// `KF_GITHUB_TOKEN` environment variable, and optionally
/// ignores TLS certificate validation if requested.
pub struct Git {
    credentials: Vec<String>,
    ignore_certs: bool,
}

impl Git {
    /// Create a new `Git` instance.
    ///
    /// * `ignore_certs`: If `true`, disables SSL certificate verification for `git` operations.
    pub fn new(ignore_certs: bool) -> Self {
        let credentials = if std::env::var("KF_GITHUB_TOKEN").is_ok() {
            vec![
                "-c".into(),
                r#"credential.helper="#.into(),
                "-c".into(),
                r#"credential.helper=!_ghcreds() { echo username="kingfisher"; echo password="$KF_GITHUB_TOKEN"; }; _ghcreds"#.into(),
            ]
        } else {
            Vec::new()
        };
        Self { credentials, ignore_certs }
    }

    /// Create a basic `git` `Command` with environment variables set to
    /// limit config usage and (optionally) ignore certs. Includes credentials
    /// if a `KF_GITHUB_TOKEN` is present.
    fn git(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
        cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
        if self.ignore_certs {
            cmd.env("GIT_SSL_NO_VERIFY", "1");
        }
        cmd.args(&self.credentials);
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Helper to run the constructed `git` command and capture its output.
    ///
    /// Returns an error if the command fails or exits with a non-zero status.
    fn run_cmd(&self, mut cmd: Command) -> Result<(), GitError> {
        debug!("{cmd:#?}");
        let output: Output = cmd.output()?;
        if !output.status.success() {
            return Err(GitError::GitError {
                stdout: output.stdout,
                stderr: output.stderr,
                status: output.status,
            });
        }
        Ok(())
    }

    /// Update an existing bare or mirror clone by running `git remote update --prune`.
    ///
    /// * `repo_url`: The remote repository URL (only used for logging).
    /// * `output_dir`: The path to the existing bare/mirror clone.
    pub fn update_clone(&self, repo_url: &GitUrl, output_dir: &Path) -> Result<(), GitError> {
        let _span = debug_span!("git_update", "{repo_url} {}", output_dir.display()).entered();
        debug!("Attempting to update clone of {repo_url} at {}", output_dir.display());
        let mut cmd = self.git();
        cmd.arg("--git-dir");
        cmd.arg(output_dir);
        cmd.arg("remote");
        cmd.arg("update");
        cmd.arg("--prune");
        debug!("{cmd:#?}");
        self.run_cmd(cmd)
    }

    /// Create a fresh clone of the specified repository in either bare or mirror mode.
    ///
    /// * `repo_url`: The remote repository URL.
    /// * `output_dir`: Where to place the newly created clone.
    /// * `clone_mode`: Whether to clone as `--bare` or `--mirror`.
    pub fn create_fresh_clone(
        &self,
        repo_url: &GitUrl,
        output_dir: &Path,
        clone_mode: CloneMode,
    ) -> Result<(), GitError> {
        let _span = debug_span!("git_clone", "{repo_url} {}", output_dir.display()).entered();
        debug!("Attempting to create fresh clone of {} at {}", repo_url, output_dir.display());
        let mut cmd = self.git();
        cmd.arg("clone");
        cmd.arg(clone_mode.arg());
        cmd.arg(repo_url.as_str());
        cmd.arg(output_dir);
        debug!("{cmd:#?}");
        self.run_cmd(cmd)
    }
}

impl Default for Git {
    /// Equivalent to `Git::new(false)`
    fn default() -> Self {
        Self::new(false)
    }
}

/// Represents how a repository is cloned.
#[derive(Debug, Clone, Copy)]
pub enum CloneMode {
    /// Equivalent to `git clone --bare`
    Bare,
    /// Equivalent to `git clone --mirror`
    Mirror,
}

impl CloneMode {
    /// Return the CLI argument for this clone mode.
    pub fn arg(&self) -> &str {
        match self {
            Self::Bare => "--bare",
            Self::Mirror => "--mirror",
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_git_new() {
        let git = Git::new(false);
        assert!(!git.ignore_certs);
        assert!(git.credentials.is_empty());

        temp_env::with_var("KF_GITHUB_TOKEN", Some("test_token"), || {
            let git = Git::new(false);
            assert_eq!(git.credentials.len(), 4);
        });
    }

    #[test]
    fn test_clone_mode_arg() {
        assert_eq!(CloneMode::Bare.arg(), "--bare");
        assert_eq!(CloneMode::Mirror.arg(), "--mirror");
    }

    #[test]
    fn test_create_fresh_clone() -> Result<(), GitError> {
        let temp_dir = TempDir::new()?;
        let git = Git::default();
        let url = GitUrl::try_from(
            url::Url::parse("https://github.com/octocat/Hello-World.git").unwrap(),
        )
        .unwrap();
        git.create_fresh_clone(&url, temp_dir.path(), CloneMode::Bare)?;
        assert!(temp_dir.path().join("HEAD").exists());
        Ok(())
    }

    #[test]
    fn test_update_clone() -> Result<(), GitError> {
        let temp_dir = TempDir::new()?;
        let git = Git::default();
        let url = GitUrl::try_from(
            url::Url::parse("https://github.com/octocat/Hello-World.git").unwrap(),
        )
        .unwrap();
        git.create_fresh_clone(&url, temp_dir.path(), CloneMode::Bare)?;
        git.update_clone(&url, temp_dir.path())?;
        Ok(())
    }

    #[test]
    fn test_git_error() {
        let temp_dir = TempDir::new().unwrap();
        let git = Git::default();
        let invalid_url =
            GitUrl::try_from(url::Url::parse("https://invalid.git").unwrap()).unwrap();
        let err =
            git.create_fresh_clone(&invalid_url, temp_dir.path(), CloneMode::Bare).unwrap_err();
        assert!(matches!(err, GitError::GitError { .. }));
    }
}
