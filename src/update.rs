// This module checks GitHub for a newer Kingfisher release and (optionally)
// s.  Our release assets use short, user-friendly names such as
// `kingfisher-linux-arm64.tgz`, `kingfisher-darwin-x64.tgz`, etc.  Those names
// do **not** match the full Rust target triple that the `self_update` crate
// expects (e.g. `aarch64-unknown-linux-musl`).  We therefore map the compile-
// time target to the corresponding asset suffix via `builder.target()`.
//
// Version handling logic covers three scenarios:
//   1. Running version == latest release →                   "up to date".
//   2. Running version  > latest release → print a notice that the binary is **newer** than
//      anything on GitHub (e.g. a dev build).
//   3. Latest release  > running version → offer to self-update.
//
// All informational messages are printed with the
// `style_finding_active_heading` style so that they stand out alongside normal
// scan output.

use std::ffi::OsString;
use std::io::{ErrorKind, Write};

use self_update::{backends::github::Update, cargo_crate_version, errors::Error as UpdError};
use semver::Version;
use tracing::error;
use tracing::warn;

use tokio::task;

use crate::{cli::global::GlobalArgs, reporter::styles::Styles};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateCheckStatus {
    Disabled,
    Failed,
    Ok,
}

impl UpdateCheckStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateCheckStatus::Disabled => "disabled",
            UpdateCheckStatus::Failed => "failed",
            UpdateCheckStatus::Ok => "ok",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateStatus {
    pub message: Option<String>,
    pub styled_message: Option<String>,
    pub is_outdated: bool,
    pub running_version: String,
    pub latest_version: Option<String>,
    pub check_status: UpdateCheckStatus,
    /// True only when the on-disk binary was just replaced by a successful self-update.
    /// Callers use this signal to re-exec into the new binary so the current invocation
    /// runs with the updated code.
    pub was_self_updated: bool,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        UpdateStatus {
            message: None,
            styled_message: None,
            is_outdated: false,
            running_version: cargo_crate_version!().to_string(),
            latest_version: None,
            check_status: UpdateCheckStatus::Disabled,
            was_self_updated: false,
        }
    }
}

fn styled_heading(styles: &Styles, text: &str) -> String {
    styles.style_finding_active_heading.apply_to(text).to_string()
}

/// Check GitHub for a newer Kingfisher release and optionally self-update.
///
/// * `base_url` lets tests point at a mock server.
/// * Self-update is performed only when `global_args.self_update` is set and `--no-update-check`
///   was not passed. If the running binary is installed via a package manager the underlying
///   `self_update` call surfaces a permission error which is reported to the user.
pub fn check_for_update(global_args: &GlobalArgs, base_url: Option<&str>) -> UpdateStatus {
    let running_version = cargo_crate_version!().to_string();

    if global_args.no_update_check {
        return UpdateStatus {
            message: Some("Update check disabled (--no-update-check)".to_string()),
            styled_message: None,
            is_outdated: false,
            running_version,
            latest_version: None,
            check_status: UpdateCheckStatus::Disabled,
            was_self_updated: false,
        };
    }

    // Respect the user's color preferences when printing update
    // by delegating to the same helper used by the main reporter logic. This keeps
    // the update checker in sync with the rest of the application and avoids
    // emitting raw ANSI escape codes when colour output has been disabled.
    let use_color = !global_args.quiet && global_args.use_color(std::io::stderr());
    let styles = Styles::new(use_color);

    let mut builder = Update::configure();
    builder
        .repo_owner("mongodb")
        .repo_name("kingfisher")
        .bin_name("kingfisher")
        .show_download_progress(false)
        .no_confirm(true) // Don't prompt for confirmation when self-updating
        .current_version(cargo_crate_version!());

    // Allow tests to point at a mock HTTP server.
    if let Some(url) = base_url {
        builder.with_url(url);
    }

    // ──────────────────────────────────────────────────────
    // Map the current Rust target triple to our simplified asset names.
    // ──────────────────────────────────────────────────────
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    builder.target("linux-arm64");

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    builder.target("linux-x64");

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    builder.target("darwin-arm64");

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    builder.target("darwin-x64");

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    builder.target("windows-x64");

    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    builder.target("windows-arm64");

    // ──────────────────────────────────────────────────────
    // Disambiguate archive format to avoid picking .deb packages.
    // Linux and macOS releases use `.tgz`; Windows uses `.zip`.
    // ──────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    builder.identifier("zip");

    // Linux releases also ship as .deb and .rpm packages; select the .tgz asset for self-updates
    #[cfg(not(target_os = "windows"))]
    builder.identifier("tgz");

    // Build the updater.
    let Ok(updater) = builder.build() else {
        let plain = "Failed to configure update checker".to_string();
        let styled_message = styled_heading(&styles, &plain);
        let _ = writeln!(std::io::stderr(), "{}", styled_message);
        return UpdateStatus {
            message: Some(plain),
            styled_message: Some(styled_message),
            is_outdated: false,
            running_version,
            latest_version: None,
            check_status: UpdateCheckStatus::Failed,
            was_self_updated: false,
        };
    };

    // Query GitHub.
    let Ok(release) = updater.get_latest_release() else {
        let plain = "Failed to check for updates".to_string();
        let styled_message = styled_heading(&styles, &plain);
        let _ = writeln!(std::io::stderr(), "{}", styled_message);
        return UpdateStatus {
            message: Some(plain),
            styled_message: Some(styled_message),
            is_outdated: false,
            running_version,
            latest_version: None,
            check_status: UpdateCheckStatus::Failed,
            was_self_updated: false,
        };
    };

    // ───────────── Case 1: running == latest ─────────────
    if release.version == running_version {
        let plain = format!("Kingfisher {running_version} is up to date");
        let _ = writeln!(std::io::stderr(), "{plain}");
        return UpdateStatus {
            message: Some(plain.clone()),
            styled_message: Some(plain),
            is_outdated: false,
            running_version,
            latest_version: Some(release.version),
            check_status: UpdateCheckStatus::Ok,
            was_self_updated: false,
        };
    }

    // Try semantic version comparison.  If parsing fails, fall back to the
    // self-update code-path (which will treat the strings lexicographically).
    if let (Ok(curr), Ok(latest)) =
        (Version::parse(&running_version), Version::parse(&release.version))
    {
        // ───────── Case 2: running > latest (dev build) ─────────
        if curr > latest {
            let plain =
                format!("Running Kingfisher {curr} which is newer than latest released {latest}");
            let styled_message = styled_heading(&styles, &plain);
            let _ = writeln!(std::io::stderr(), "{}", styled_message);
            return UpdateStatus {
                message: Some(plain),
                styled_message: Some(styled_message),
                is_outdated: false,
                running_version,
                latest_version: Some(release.version),
                check_status: UpdateCheckStatus::Ok,
                was_self_updated: false,
            };
        }
        // else fall through to Case 3 (latest > running)
    }

    // ───────────── Case 3: latest > running ─────────────
    let plain = format!("New Kingfisher release {} available", release.version);
    let styled_message = styled_heading(&styles, &plain);
    let _ = writeln!(std::io::stderr(), "{}", styled_message);

    // Attempt self-update when allowed and feasible.
    let mut was_self_updated = false;
    if global_args.self_update {
        match updater.update() {
            Ok(status) => {
                if status.updated() {
                    let message = format!("Updated to version {}", status.version());
                    let _ = writeln!(std::io::stderr(), "{}", styled_heading(&styles, &message));
                    was_self_updated = true;
                } else {
                    // Reported `UpToDate` despite the version-comparison branch — race or
                    // tag mismatch. Skip re-exec to avoid pointless fork+exec.
                    let _ = writeln!(
                        std::io::stderr(),
                        "{}",
                        styled_heading(
                            &styles,
                            &format!("Already at version {} — no update applied", status.version()),
                        )
                    );
                }
            }
            Err(e) => match e {
                UpdError::Io(ref io_err) => match io_err.kind() {
                    ErrorKind::PermissionDenied => {
                        let _ = writeln!(
                            std::io::stderr(),
                            "{}",
                            styled_heading(
                                &styles,
                                "Cannot replace the current binary - permission denied.\n\
                                 If you installed via a package manager, run its upgrade command.\n\
                                 Otherwise reinstall to a user-writable directory or re-run with sudo."
                            )
                        );
                    }
                    ErrorKind::NotFound => {
                        let _ = writeln!(
                            std::io::stderr(),
                            "{}",
                            styled_heading(
                                &styles,
                                "Cannot replace the current binary - file not found.\n\
                                 If you installed via a package manager, run its upgrade command.\n\
                                 Otherwise reinstall to a user-writable directory."
                            )
                        );
                    }
                    _ => error!("Failed to update: {e}"),
                },
                _ => error!("Failed to update: {e}"),
            },
        }
    }

    UpdateStatus {
        message: Some(plain),
        styled_message: Some(styled_message),
        is_outdated: true,
        running_version,
        latest_version: Some(release.version),
        check_status: UpdateCheckStatus::Ok,
        was_self_updated,
    }
}

/// Run the update check on a blocking thread so it can safely be invoked from async
/// contexts without creating nested Tokio runtimes.
pub async fn check_for_update_async(
    global_args: &GlobalArgs,
    base_url: Option<&str>,
) -> UpdateStatus {
    let args = global_args.clone();
    let base = base_url.map(str::to_owned);

    match task::spawn_blocking(move || check_for_update(&args, base.as_deref())).await {
        Ok(status) => status,
        Err(err) => {
            warn!("Update check task cancelled: {err}");
            UpdateStatus::default()
        }
    }
}

/// Rewrite the current process argv for re-execution into a freshly self-updated binary.
///
/// - argv[0] is preserved unchanged.
/// - `--self-update` and `--update` (and their `--flag=value` forms) are stripped so the
///   re-exec'd binary does not loop back into another self-update.
/// - `--no-update-check` is appended (idempotently) since we just performed the check.
/// - Tokens after the first `--` separator are passed through untouched (they are positional
///   from clap's perspective and may legitimately contain anything).
/// - If the input has no argv[0] (theoretical — real-world processes always have one), the
///   output is empty too. This avoids producing a broken argv where `--no-update-check` would
///   be promoted to the new process's argv[0].
pub fn rewrite_argv_for_reexec(argv: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    // Byte-level prefix check that works on both UTF-8 and non-UTF-8 OsStrings.
    fn os_starts_with(tok: &OsString, prefix: &[u8]) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            tok.as_os_str().as_bytes().starts_with(prefix)
        }
        #[cfg(windows)]
        {
            // On Windows OsStrings are WTF-16; encode the ASCII prefix the same way and
            // compare wide units. ASCII characters round-trip cleanly to single u16 units.
            use std::os::windows::ffi::OsStrExt;
            let prefix_wide: Vec<u16> = prefix.iter().map(|&b| b as u16).collect();
            let tok_wide: Vec<u16> = tok.as_os_str().encode_wide().collect();
            tok_wide.starts_with(&prefix_wide)
        }
        #[cfg(not(any(unix, windows)))]
        {
            // Fallback for unknown targets: best-effort UTF-8 conversion.
            tok.to_str().map(|s| s.as_bytes().starts_with(prefix)).unwrap_or(false)
        }
    }

    let mut iter = argv.into_iter();
    let mut out: Vec<OsString> = Vec::new();
    let mut already_has_no_update_check = false;
    let mut hit_double_dash = false;
    // Index of the `--` separator inside `out`, if seen. When set, we must
    // insert any synthesized flags (like `--no-update-check`) *before* this
    // index — clap stops parsing flags at `--` and treats everything after
    // as positional.
    let mut double_dash_idx: Option<usize> = None;
    let had_argv0;

    if let Some(argv0) = iter.next() {
        out.push(argv0);
        had_argv0 = true;
    } else {
        had_argv0 = false;
    }

    for tok in iter {
        if hit_double_dash {
            // After `--`, every token is positional and must be passed through verbatim.
            out.push(tok);
            continue;
        }

        if tok == "--" {
            hit_double_dash = true;
            double_dash_idx = Some(out.len());
            out.push(tok);
            continue;
        }

        // Strip the flags that would re-trigger a self-update on the next process.
        if tok == "--self-update" || tok == "--update" {
            continue;
        }
        if os_starts_with(&tok, b"--self-update=") || os_starts_with(&tok, b"--update=") {
            continue;
        }

        if tok == "--no-update-check" {
            already_has_no_update_check = true;
        }

        out.push(tok);
    }

    // Only inject `--no-update-check` when we actually preserved an argv[0].
    // In the theoretical empty-input case, returning an empty Vec keeps the
    // argv shape consistent and lets the caller decide what to do.
    //
    // If a `--` separator was present, insert the flag *before* it — anything
    // after `--` is positional, so appending at the end would silently fail
    // to suppress the update check on the re-exec'd process.
    if had_argv0 && !already_has_no_update_check {
        let flag = OsString::from("--no-update-check");
        match double_dash_idx {
            Some(idx) => out.insert(idx, flag),
            None => out.push(flag),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(|s| os(s)).collect()
    }

    #[test]
    fn rewrite_argv_strips_self_update() {
        let result = rewrite_argv_for_reexec(argv(&["kingfisher", "scan", ".", "--self-update"]));
        assert_eq!(result, argv(&["kingfisher", "scan", ".", "--no-update-check"]));
    }

    #[test]
    fn rewrite_argv_strips_update_alias() {
        let result = rewrite_argv_for_reexec(argv(&["kingfisher", "scan", "foo", "--update"]));
        assert_eq!(result, argv(&["kingfisher", "scan", "foo", "--no-update-check"]));
    }

    #[test]
    fn rewrite_argv_strips_eq_form() {
        let result =
            rewrite_argv_for_reexec(argv(&["kingfisher", "--self-update=true", "scan", "foo"]));
        assert_eq!(result, argv(&["kingfisher", "scan", "foo", "--no-update-check"]));

        let result = rewrite_argv_for_reexec(argv(&["kingfisher", "--update=true", "scan", "foo"]));
        assert_eq!(result, argv(&["kingfisher", "scan", "foo", "--no-update-check"]));
    }

    #[test]
    fn rewrite_argv_appends_no_update_check_when_absent() {
        let result = rewrite_argv_for_reexec(argv(&["kingfisher", "scan", "."]));
        assert_eq!(result, argv(&["kingfisher", "scan", ".", "--no-update-check"]));
    }

    #[test]
    fn rewrite_argv_idempotent_when_no_update_check_already_present() {
        let result = rewrite_argv_for_reexec(argv(&[
            "kingfisher",
            "scan",
            ".",
            "--no-update-check",
            "--self-update",
        ]));
        assert_eq!(result, argv(&["kingfisher", "scan", ".", "--no-update-check"]));
    }

    #[test]
    fn rewrite_argv_preserves_argv0() {
        let result = rewrite_argv_for_reexec(argv(&[
            "/weird path/kingfisher-bin",
            "scan",
            ".",
            "--self-update",
        ]));
        assert_eq!(result, argv(&["/weird path/kingfisher-bin", "scan", ".", "--no-update-check"]));
    }

    #[test]
    fn rewrite_argv_preserves_tokens_after_double_dash() {
        // --self-update appearing AFTER `--` is a positional and must be preserved.
        // The synthesized --no-update-check has to land BEFORE `--`; otherwise it
        // would be parsed as a positional and the re-exec'd process would still
        // perform an update check.
        let result = rewrite_argv_for_reexec(argv(&[
            "kingfisher",
            "scan",
            "--self-update",
            "--",
            "--self-update",
            "--update",
        ]));
        assert_eq!(
            result,
            argv(&["kingfisher", "scan", "--no-update-check", "--", "--self-update", "--update"])
        );
    }

    #[test]
    fn rewrite_argv_does_not_duplicate_no_update_check_when_already_present_before_double_dash() {
        // If --no-update-check is already present before `--`, the function is
        // a no-op for that flag (no duplicate insertion) and tokens after `--`
        // pass through verbatim.
        let result = rewrite_argv_for_reexec(argv(&[
            "kingfisher",
            "scan",
            "--no-update-check",
            "--self-update",
            "--",
            "--self-update",
        ]));
        assert_eq!(
            result,
            argv(&["kingfisher", "scan", "--no-update-check", "--", "--self-update"])
        );
    }

    #[test]
    fn rewrite_argv_empty_input_returns_empty() {
        // If args_os() somehow returns nothing (theoretical), we must not synthesize a
        // bogus argv where --no-update-check becomes argv[0] of the new process.
        let result: Vec<OsString> = rewrite_argv_for_reexec(Vec::<OsString>::new());
        assert!(result.is_empty(), "empty input must produce empty output, got {:?}", result);
    }

    #[test]
    fn rewrite_argv_does_not_strip_unrelated_update_prefixed_flags() {
        // A future flag like --update-rules must NOT be stripped by the --update= prefix check.
        let result = rewrite_argv_for_reexec(argv(&[
            "kingfisher",
            "rules",
            "--update-rules",
            "--self-updateable=ignored",
        ]));
        assert_eq!(
            result,
            argv(&[
                "kingfisher",
                "rules",
                "--update-rules",
                "--self-updateable=ignored",
                "--no-update-check"
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_argv_handles_non_utf8_value_in_eq_form() {
        // On Unix, a --self-update=<bytes> with non-UTF-8 bytes after the `=` must still
        // be stripped — the byte-level prefix check makes this work even when to_str() fails.
        use std::os::unix::ffi::OsStringExt;
        let mut bad = b"--self-update=".to_vec();
        bad.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8 trailer
        let bad_os = OsString::from_vec(bad);
        let input: Vec<OsString> = vec![os("kingfisher"), os("scan"), bad_os, os(".")];
        let result = rewrite_argv_for_reexec(input);
        assert_eq!(result, argv(&["kingfisher", "scan", ".", "--no-update-check"]));
    }
}
