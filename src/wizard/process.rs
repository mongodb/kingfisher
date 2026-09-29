//! Process boundary shared by the optional desktop UI and its headless tests.

use std::{
    collections::VecDeque,
    ffi::{OsStr, OsString},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use command_group::{CommandGroup, GroupChild};
use tempfile::TempDir;

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub target: OsString,
    pub history: bool,
    pub validate: bool,
    pub access_map: bool,
    pub redact: bool,
    pub rule: String,
    pub exclude: String,
    pub extra: Vec<OsString>,
}

impl ScanOptions {
    pub fn command(&self, executable: &Path, report: &Path) -> Result<Command> {
        if self.target.is_empty() && self.extra.is_empty() {
            bail!("Choose a file, folder, or repository URL first.");
        }
        if self.access_map && !self.validate {
            bail!("Blast-radius mapping requires live validation.");
        }
        let mut command = Command::new(executable);
        command.args(["scan", "--no-update-check", "--format", "json", "--output"]);
        command.arg(report);
        if !self.history {
            command.args(["--git-history", "none"]);
        }
        if !self.validate {
            command.arg("--no-validate");
        }
        if self.access_map {
            command.arg("--blast-radius");
        }
        if self.redact {
            command.arg("--redact");
        }
        for (flag, value) in [("--rule", self.rule.trim()), ("--exclude", self.exclude.trim())] {
            if value.is_empty() {
                continue;
            }
            if value.starts_with('-') {
                command.arg(format!("{flag}={value}"));
            } else {
                command.arg(flag).arg(value);
            }
        }
        command.args(&self.extra);
        // Never interpret a path as flags or interpolate user input into a shell.
        if !self.target.is_empty() {
            command.arg("--").arg(crate::util::expand_tilde(Path::new(&self.target)));
        }
        if !self.extra.is_empty() {
            use clap::Parser;
            crate::cli::global::CommandLineArgs::try_parse_from(
                std::iter::once(command.get_program()).chain(command.get_args()),
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        }
        Ok(command)
    }
}

pub fn viewer_command(executable: &Path, report: &Path) -> Command {
    let mut command = Command::new(executable);
    // Port zero lets the OS select a free port, including when another viewer is open.
    command.args(["view", "--no-update-check", "--port", "0", "--address", "127.0.0.1", "--"]);
    command.arg(report);
    command
}

/// Private report storage survives while its scan or viewer is alive.
pub struct Report {
    pub directory: TempDir,
    pub path: PathBuf,
}

impl Report {
    pub fn new() -> Result<Self> {
        let directory = tempfile::Builder::new().prefix("kingfisher-wizard-").tempdir()?;
        let path = directory.path().join("report.json");
        Ok(Self { directory, path })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    Clean,
    NoInputs,
    Findings,
    ValidatedFindings,
}

impl ScanOutcome {
    pub fn from_status(status: ExitStatus) -> Result<Self> {
        match status.code() {
            Some(0) => Ok(Self::Clean),
            Some(3) => Ok(Self::NoInputs),
            Some(200) => Ok(Self::Findings),
            Some(205) => Ok(Self::ValidatedFindings),
            _ => bail!("Kingfisher exited with {status}. See the activity log."),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "Complete · no findings",
            Self::NoInputs => "Complete · nothing to scan",
            Self::Findings => "Complete · findings detected",
            Self::ValidatedFindings => "Complete · validated findings detected",
        }
    }
}

/// Keep the latest diagnostics even when a fast, noisy child outruns the UI.
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<VecDeque<String>>>);
impl Logs {
    pub fn drain(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect()
    }
    fn push(&self, text: String) {
        let mut chunks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if chunks.len() == 256 {
            chunks.pop_front();
        }
        chunks.push_back(text);
    }
}

/// Owns the entire process group, including git children. Dropping a live job stops it.
pub struct Process {
    child: GroupChild,
    pub logs: Logs,
    pub started: Instant,
    finished: bool,
    reader: thread::JoinHandle<()>,
}

impl Process {
    pub fn spawn(mut command: Command) -> Result<Self> {
        command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
        command.env("NO_COLOR", "1").env("GIT_TERMINAL_PROMPT", "0");
        let mut group = command.group();
        #[cfg(windows)]
        group.creation_flags(0x08000000).kill_on_drop(true); // CREATE_NO_WINDOW
        let child = group.spawn();
        let mut child = child.with_context(|| {
            format!(
                "Could not start {}. Check that the Kingfisher executable still exists and is executable.",
                command.get_program().to_string_lossy()
            )
        })?;
        let mut stderr = child.inner().stderr.take().expect("stderr is piped");
        let logs = Logs::default();
        let pending = logs.clone();
        // A bounded ring drops old chunks, retaining the last diagnostic on fast failures.
        let reader = thread::spawn(move || {
            let mut buffer = [0; 2048];
            loop {
                match stderr.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        let text = String::from_utf8_lossy(&buffer[..count]).into_owned();
                        pending.push(text);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });
        Ok(Self { child, logs, started: Instant::now(), finished: false, reader })
    }

    pub fn poll(&mut self) -> Result<Option<ExitStatus>> {
        if self.finished {
            return Ok(self.child.try_wait()?);
        }
        let status = self.child.try_wait()?;
        // Wait for the pipe reader without blocking the UI so even a fast failure's final
        // diagnostic is available before the job is removed from the screen.
        self.finished = status.is_some() && self.reader.is_finished();
        Ok(status.filter(|_| self.finished))
    }

    pub fn cancel(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        if let Err(error) = self.child.kill() {
            // The process can exit between the UI's last poll and this request.
            if self.child.try_wait()?.is_none() {
                return Err(error.into());
            }
        }
        self.child.wait()?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shell {
    Posix,
    PowerShell,
}

impl Shell {
    pub fn native() -> Self {
        if cfg!(windows) { Self::PowerShell } else { Self::Posix }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Posix => "Bash / zsh",
            Self::PowerShell => "PowerShell 7.3+",
        }
    }
}

/// Translate the reporter's single-quoted POSIX argument format into the chosen shell.
/// This is a parser only: imported report commands are never executed by the wizard.
pub fn report_command_preview(source: &str, shell: Shell) -> Result<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut started = false;
    let mut chars = source.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                quoted = !quoted;
                started = true;
            }
            '\\' if !quoted => {
                word.push(chars.next().context("Incomplete command escape")?);
                started = true;
            }
            ch if ch.is_whitespace() && !quoted => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            ch if !quoted && "&|;<>`$(){}\"".contains(ch) => {
                bail!("Report command uses unsupported shell syntax")
            }
            ch => {
                word.push(ch);
                started = true;
            }
        }
    }
    if quoted {
        bail!("Unclosed quote in report command");
    }
    if started {
        words.push(word);
    }
    if words.first().map(String::as_str) != Some("kingfisher")
        || !matches!(words.get(1).map(String::as_str), Some("validate" | "revoke" | "blast-radius"))
    {
        bail!("Not a Kingfisher credential command");
    }
    let mut command = Command::new(&words[0]);
    command.args(&words[1..]);
    command_preview(&command, shell)
}

/// An executable multiline command; never fed back into the GUI's subprocess runner.
pub fn command_preview(command: &Command, shell: Shell) -> Result<String> {
    let quote = |s: &OsStr| -> Result<String> {
        let s =
            s.to_str().context("This path is not valid Unicode; use Browse to run it directly.")?;
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_./:-".contains(&b)) {
            return Ok(s.to_owned());
        }
        Ok(match shell {
            Shell::Posix => format!("'{}'", s.replace('\'', "'\"'\"'")),
            Shell::PowerShell => format!("'{}'", s.replace('\'', "''")),
        })
    };
    let mut lines = vec![format!(
        "{}{}",
        if shell == Shell::PowerShell { "& " } else { "" },
        quote(command.get_program())?
    )];
    let args: Vec<_> = command.get_args().collect();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        let text = arg.to_string_lossy();
        if index == 0 {
            lines[0].push_str(&format!(" {}", quote(arg)?));
            index += 1;
            continue;
        }
        if text == "--no-update-check" {
            index += 1;
            continue;
        }
        let mut line = quote(arg)?;
        if ["--format", "--output", "--git-history", "--rule", "--exclude", "--"]
            .contains(&text.as_ref())
            && index + 1 < args.len()
        {
            index += 1;
            line.push(' ');
            line.push_str(&quote(args[index])?);
        }
        lines.push(line);
        index += 1;
    }
    let command = lines.join(match shell {
        Shell::Posix => " \\\n  ",
        Shell::PowerShell => " `\n  ",
    });
    Ok(if shell == Shell::PowerShell {
        format!("$PSNativeCommandArgumentPassing = 'Standard'\n{command}")
    } else {
        command
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn options() -> ScanOptions {
        ScanOptions {
            extra: Vec::new(),
            target: OsString::from("-folder with spaces; $(echo unsafe)"),
            history: false,
            validate: false,
            access_map: false,
            redact: true,
            rule: "github".into(),
            exclude: "**/vendor/**".into(),
        }
    }

    #[test]
    fn report_commands_translate_quotes_without_interpreting_shell_code() {
        let command = "kingfisher validate --rule 'test.key' 'before'\\''after$HOME'";
        let posix = report_command_preview(command, Shell::Posix).unwrap();
        let powershell = report_command_preview(command, Shell::PowerShell).unwrap();
        assert!(posix.contains("after$HOME"));
        assert!(powershell.contains("'before''after$HOME'"));
        assert!(
            report_command_preview("kingfisher revoke x; echo unsafe", Shell::PowerShell).is_err()
        );
        assert!(report_command_preview("kingfisher validate 'unfinished", Shell::Posix).is_err());
    }
    #[test]
    fn advanced_arguments_use_cli_validation_and_literal_values() {
        let mut options = options();
        options.extra = vec![
            "--jobs=2".into(),
            "--validation-timeout=3".into(),
            "--endpoint=github=https://example.invalid/$HOME".into(),
        ];
        let command = options.command(Path::new("kingfisher"), Path::new("report.json")).unwrap();
        assert!(command.get_args().any(|v| v == "--jobs=2"));
        options.extra = vec!["--validation-timeout=90".into()];
        assert!(options.command(Path::new("kingfisher"), Path::new("report.json")).is_err());
    }
    #[test]
    fn progress_snapshots_are_live_and_keep_credentials_out() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("progress.json");
        let mut child = fixture("progress");
        child.env("KINGFISHER_PROGRESS_FILE", &path);
        let mut process = Process::spawn(child).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut observed = false;
        let mut frozen_scan_seconds = None;
        loop {
            if let Ok(bytes) = std::fs::read(&path)
                && let Ok(snapshot) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && snapshot["bytes"].as_u64() == Some(1_500_000_000)
                && snapshot["phase"] == "Checking credentials"
            {
                assert_eq!(snapshot["blobs"], 1);
                assert_eq!(snapshot["phase"], "Checking credentials");
                assert_eq!(snapshot["kind"], "validation");
                assert_eq!(snapshot["completed"], 1);
                let scan_seconds = snapshot["scan_seconds"].as_f64().unwrap();
                assert!(scan_seconds > 0.);
                if let Some(previous) = frozen_scan_seconds {
                    assert_eq!(scan_seconds, previous);
                }
                frozen_scan_seconds = Some(scan_seconds);
                observed = true;
            }
            if process.poll().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        assert!(observed, "no live progress snapshot received");
    }
    #[test]
    fn scan_arguments_preserve_paths_and_options() {
        let report = PathBuf::from("output folder").join("report.json");
        let command = options().command(Path::new("kingfisher"), &report).unwrap();
        let args: Vec<_> = command.get_args().map(OsStr::to_owned).collect();
        assert_eq!(args.last(), Some(&options().target));
        assert_eq!(args[args.len() - 2], "--");
        assert!(args.windows(2).any(|a| a == [OsStr::new("--output"), report.as_os_str()]));
        assert!(args.windows(2).any(|a| a == ["--git-history", "none"]));
        assert!(!args.iter().any(|a| a == "--git-clone-dir"));
        assert!(args.iter().any(|a| a == "--no-validate"));
        assert!(args.iter().any(|a| a == "--redact"));
        let mut options = options();
        options.exclude = "-folder/**".into();
        let hyphen = options.command(Path::new("kingfisher"), &report).unwrap();
        assert!(hyphen.get_args().any(|arg| arg == "--exclude=-folder/**"));
        options.access_map = true;
        assert!(options.command(Path::new("kingfisher"), &report).is_err());
    }

    #[test]
    fn shell_previews_use_platform_quoting_and_continuations() {
        let mut options = options();
        options.target = "project O'Brien $HOME `whoami` \"quoted\"".into();
        let command = options.command(Path::new("kingfisher"), Path::new("report.json")).unwrap();
        let posix = command_preview(&command, Shell::Posix).unwrap();
        assert!(posix.starts_with("kingfisher scan \\\n  --format json"));
        assert!(posix.contains("O'\"'\"'Brien"));
        let powershell = command_preview(&command, Shell::PowerShell).unwrap();
        assert!(powershell.contains("& kingfisher scan `\n  --format json"));
        assert!(powershell.contains("'project O''Brien $HOME `whoami` \"quoted\"'"));
        assert!(powershell.contains("$PSNativeCommandArgumentPassing = 'Standard'"));
        assert!(!posix.contains("--git-clone-dir"));
        assert!(!powershell.contains("--git-clone-dir"));
    }

    #[cfg(unix)]
    #[test]
    fn posix_copied_command_round_trips_shell_metacharacters() {
        let values = [
            "spaces and 'apostrophe'",
            "$(echo should-not-execute)",
            "back`tick",
            "line\nbreak",
            "a\\b",
            "\"quotes\"",
            "*?[abc]",
        ];
        let mut command = Command::new("printf");
        command.arg("%s\\0").args(values);
        let preview = command_preview(&command, Shell::Posix).unwrap();
        let result = Command::new("sh").arg("-c").arg(preview).output().unwrap();
        assert!(result.status.success());
        let expected =
            values.iter().flat_map(|v| v.as_bytes().iter().copied().chain([0])).collect::<Vec<_>>();
        assert_eq!(result.stdout, expected);
    }

    #[test]
    #[ignore = "requires PowerShell 7.3+ (pwsh) on PATH"]
    fn powershell_copied_command_round_trips_native_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("arguments.json");
        let script = dir.path().join("command.ps1");
        let values = [
            "spaces and 'apostrophe'",
            "$(throw 'should not run')",
            "back`tick",
            "line\nbreak",
            "a\\b",
            "\"quotes\"",
            "*?[abc]",
            "",
        ];
        let mut command = fixture("args");
        command.arg("--").args(values);
        let preview = command_preview(&command, Shell::PowerShell).unwrap();
        std::fs::write(
            &script,
            format!("$ErrorActionPreference = 'Stop'\n{preview}\nexit $LASTEXITCODE\n"),
        )
        .unwrap();
        let result = Command::new("pwsh")
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
            .arg(script)
            .env("KINGFISHER_DESKTOP_TEST_CHILD", "args")
            .env("KINGFISHER_TEST_ARGV_FILE", &output)
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        let actual: Vec<String> = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(actual, values);
    }

    #[test]
    fn viewer_uses_localhost_and_an_available_port() {
        let command = viewer_command(Path::new("kingfisher"), Path::new("-report file.json"));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(
            args,
            [
                "view",
                "--no-update-check",
                "--port",
                "0",
                "--address",
                "127.0.0.1",
                "--",
                "-report file.json"
            ]
        );
    }

    // Reuse the Rust test executable as a portable subprocess fixture (no shell or Unix tools).
    fn fixture(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "wizard::process::tests::process_fixture", "--nocapture"]);
        command.env("KINGFISHER_DESKTOP_TEST_CHILD", mode);
        command
    }

    #[test]
    fn process_fixture() {
        let Ok(mode) = std::env::var("KINGFISHER_DESKTOP_TEST_CHILD") else { return };
        if mode == "progress" {
            let _guard = crate::scan_progress::start().unwrap();
            crate::scan_progress::phase(
                "Scanning files and Git history",
                0,
                crate::scan_progress::PhaseKind::Scan,
            );
            crate::scan_progress::scanned(1_500_000_000);
            thread::sleep(Duration::from_millis(50));
            crate::scan_progress::phase(
                "Checking credentials",
                2,
                crate::scan_progress::PhaseKind::Validation,
            );
            crate::scan_progress::advance();
            thread::sleep(Duration::from_millis(1100));
            return;
        }
        if mode == "args" {
            let values: Vec<String> = std::env::args().skip_while(|a| a != "--").skip(1).collect();
            std::fs::write(
                std::env::var_os("KINGFISHER_TEST_ARGV_FILE").unwrap(),
                serde_json::to_vec(&values).unwrap(),
            )
            .unwrap();
            return;
        }
        if mode == "noisy" {
            for _ in 0..2048 {
                eprintln!("{}", "x".repeat(1024));
            }
            eprintln!("final failure diagnostic");
            std::process::exit(1);
        }
        if mode == "wait" {
            loop {
                thread::sleep(Duration::from_millis(50));
            }
        }
        eprintln!("fixture activity");
        std::process::exit(mode.parse().unwrap());
    }

    #[test]
    fn process_distinguishes_findings_from_failure() {
        for (code, expected) in [
            ("0", Some(ScanOutcome::Clean)),
            ("3", Some(ScanOutcome::NoInputs)),
            ("200", Some(ScanOutcome::Findings)),
            ("205", Some(ScanOutcome::ValidatedFindings)),
            ("1", None),
        ] {
            let mut process = Process::spawn(fixture(code)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = process.poll().unwrap() {
                    break status;
                }
                assert!(Instant::now() < deadline, "child did not exit");
                thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(ScanOutcome::from_status(status).ok(), expected);
            let log: String = process.logs.drain().concat();
            assert!(log.contains("fixture activity"));
        }
    }

    #[test]
    fn fast_noisy_failures_keep_the_final_diagnostic() {
        let mut process = Process::spawn(fixture("noisy")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while process.poll().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        let logs = process.logs.drain().concat();
        assert!(logs.contains("final failure diagnostic"));
        assert!(logs.len() <= 256 * 2048);
    }

    #[test]
    fn cancellation_reaps_the_process() {
        let mut process = Process::spawn(fixture("wait")).unwrap();
        assert!(process.poll().unwrap().is_none());
        process.cancel().unwrap();
        assert!(process.poll().unwrap().is_some());
        process.cancel().unwrap();
    }

    #[test]
    #[ignore = "set KINGFISHER_WIZARD_TEST_BIN to the built GUI-enabled CLI"]
    fn real_cli_scan_loads_in_the_native_report_model() {
        let executable = PathBuf::from(
            std::env::var_os("KINGFISHER_WIZARD_TEST_BIN").expect("set KINGFISHER_WIZARD_TEST_BIN"),
        );
        let fixture = tempfile::tempdir().unwrap();
        let target = fixture.path().join("project O'Brien $HOME with spaces");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("notes.txt"), "A project without credentials.\n").unwrap();
        let report = Report::new().unwrap();
        let mut options = options();
        options.target = target.into_os_string();
        let mut process =
            Process::spawn(options.command(&executable, &report.path).unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut log = String::new();
        let status = loop {
            log.push_str(&process.logs.drain().concat());
            if let Some(status) = process.poll().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "scan timed out: {log}");
            thread::sleep(Duration::from_millis(25));
        };
        log.push_str(&process.logs.drain().concat());
        assert_eq!(
            ScanOutcome::from_status(status).unwrap_or_else(|error| panic!("{error}: {log}")),
            ScanOutcome::Clean
        );
        let data = super::super::report::ReportData::load(&[report.path.clone()]).unwrap();
        assert!(data.findings.is_empty());
    }

    #[test]
    fn missing_executable_is_actionable() {
        let directory = tempfile::tempdir().unwrap();
        let result = Process::spawn(Command::new(directory.path().join("missing-kingfisher")));
        assert!(result.err().unwrap().to_string().contains("Could not start"));
    }
}
