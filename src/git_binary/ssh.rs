//! SSH carries the protocol; gix performs negotiation, pack ingestion and ref updates.
//!
//! Unlike gix's opaque on-demand child, this child is owned here so a total
//! operation deadline also interrupts a blocked pipe read. No local Git program
//! is used. OpenSSH retains its normal host-key verification, config and agent.
#[cfg(windows)]
mod windows;

use std::{
    ffi::{OsStr, OsString},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use gix::{
    bstr::{BString, ByteSlice},
    protocol::transport::{
        Protocol,
        client::{blocking_io::ssh::ProgramKind, git},
    },
};

pub(super) type Connection = git::blocking_io::Connection<ChildStdout, ChildStdin>;

/// Keep the returned guard alive until gix has finished consuming the transport.
/// Dropping it always terminates and reaps the SSH child, including on errors.
pub(super) fn connect(
    repo: &gix::Repository,
    url: gix::Url,
    version: Protocol,
    deadline: Option<Instant>,
    interrupt: Arc<AtomicBool>,
) -> Result<(Connection, ProcessGuard)> {
    ensure!(!interrupt.load(Ordering::Relaxed), "SSH operation interrupted");
    ensure!(deadline.is_none_or(|at| Instant::now() < at), "SSH operation timed out");
    let settings = Settings::from_repo(repo)?;
    let mut command = prepare_command(&settings, &url, version)?;
    let mut child =
        ManagedChild::spawn(&mut command).map_err(|error| spawn_error(error, &settings.command))?;
    let stdout = child.child.stdout.take().expect("SSH stdout is piped");
    let stdin = child.child.stdin.take().expect("SSH stdin is piped");
    let stderr = child.child.stderr.take().map(StderrTail::capture).transpose()?;
    let mut guard = ProcessGuard::new(child, deadline, interrupt)?;
    guard.stderr = stderr;
    let connection = Connection::new(
        stdout,
        stdin,
        version,
        url.path.clone(),
        None::<(&str, Option<u16>)>,
        git::ConnectMode::Process,
        false,
    )
    .custom_url(Some(url.to_bstring()));
    Ok((connection, guard))
}

struct Settings {
    command: OsString,
    arguments: Vec<OsString>,
    kind: ProgramKind,
}

impl Settings {
    fn from_repo(repo: &gix::Repository) -> Result<Self> {
        let config = repo.config_snapshot();
        // Match Git's precedence. Configured command lines support quoted
        // arguments but never a shell; GIT_SSH names one executable.
        let configured = std::env::var_os("GIT_SSH_COMMAND").or_else(|| {
            config.string("core.sshCommand").map(|value| value.to_os_str_lossy().into_owned())
        });
        let (command, arguments) = match configured {
            Some(command) => split_command(&command)?,
            None => (std::env::var_os("GIT_SSH").unwrap_or_else(default_program), Vec::new()),
        };
        let variant = std::env::var("GIT_SSH_VARIANT").ok().or_else(|| {
            config.string("ssh.variant").map(|value| value.to_str_lossy().into_owned())
        });
        let kind = match variant.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("ssh") => ProgramKind::Ssh,
            Some("plink") => ProgramKind::Plink,
            Some("putty") => ProgramKind::Putty,
            Some("tortoiseplink") => ProgramKind::TortoisePlink,
            Some("simple") => ProgramKind::Simple,
            Some(other) if other != "auto" => bail!("Unsupported SSH variant '{other}'"),
            // Git documents `auto` as the default: infer the variant from the command.
            _ => {
                // An unrecognized wrapper is treated as OpenSSH unless the
                // caller explicitly requests the simple variant.
                let inferred = ProgramKind::from(command.as_os_str());
                if inferred == ProgramKind::Simple { ProgramKind::Ssh } else { inferred }
            }
        };
        Ok(Self { command, arguments, kind })
    }
}

fn default_program() -> OsString {
    #[cfg(windows)]
    if let Some(path) =
        find_windows_ssh(std::env::var_os("PATH").as_deref(), |name| std::env::var_os(name))
    {
        return path.into_os_string();
    }
    OsString::from("ssh")
}

/// Windows' optional OpenSSH Client is often absent (Server 2016/2019, Server Core
/// containers), while Git for Windows ships its own `usr\bin\ssh.exe` that Git used to
/// run for us. Prefer an `ssh.exe` on `PATH`, matching the user's shell, then fall back
/// to a Git for Windows installation found via `git.exe` on `PATH` or a standard
/// install location. Relative `PATH` entries are ignored so a scanned working
/// directory can never supply the executable.
#[cfg(any(windows, test))]
fn find_windows_ssh(
    path: Option<&OsStr>,
    var: impl Fn(&str) -> Option<OsString>,
) -> Option<std::path::PathBuf> {
    use std::path::{Path, PathBuf};

    let directories: Vec<PathBuf> = path
        .map(|path| std::env::split_paths(path).filter(|dir| dir.is_absolute()).collect())
        .unwrap_or_default();
    if let Some(ssh) =
        directories.iter().map(|dir| dir.join("ssh.exe")).find(|candidate| candidate.is_file())
    {
        return Some(ssh);
    }
    // git.exe lives in Git\cmd, Git\bin or Git\mingw64\bin.
    let from_path = directories
        .iter()
        .filter(|dir| dir.join("git.exe").is_file())
        .flat_map(|dir| dir.ancestors().skip(1).take(2).map(Path::to_path_buf));
    let installed = ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(|name| var(name).map(|root| PathBuf::from(root).join("Git")))
        .chain(var("LOCALAPPDATA").map(|root| PathBuf::from(root).join("Programs").join("Git")))
        .filter(|root| root.is_absolute());
    from_path
        .chain(installed)
        .map(|root| root.join("usr").join("bin").join("ssh.exe"))
        .find(|candidate| candidate.is_file())
}

fn spawn_error(error: std::io::Error, program: &OsStr) -> anyhow::Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!(
            "SSH client '{}' was not found. Install OpenSSH (on Windows, the \"OpenSSH \
             Client\" optional feature or Git for Windows), set GIT_SSH_COMMAND or GIT_SSH \
             to an SSH client, or scan the repository's HTTPS URL instead",
            program.display()
        )
    } else {
        anyhow::Error::new(error).context("Failed to start SSH transport")
    }
}

fn split_command(command: &OsStr) -> Result<(OsString, Vec<OsString>)> {
    let text = command.to_str().context("SSH command must be valid UTF-8")?;
    ensure!(
        !text.contains(['$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0']),
        "SSH command shell operators and expansions are not supported; use a direct command with quoted arguments or .ssh/config"
    );
    let mut words = shlex::split(text).context("SSH command has invalid quoting")?.into_iter();
    let executable =
        words.next().filter(|word| !word.is_empty()).context("SSH command is empty")?;
    ensure!(!executable.starts_with('~'), "Use an absolute SSH command path, not tilde expansion");
    Ok((executable.into(), words.map(OsString::from).collect()))
}

fn prepare_command(settings: &Settings, url: &gix::Url, version: Protocol) -> Result<Command> {
    use gix::url::ArgumentSafety::{Absent, Dangerous, Usable};
    ensure!(url.scheme == gix::url::Scheme::Ssh, "Expected an SSH repository URL");
    ensure!(url.password().is_none(), "SSH URLs must not contain passwords");
    let host = match url.host_as_argument() {
        Usable(host) => host,
        Dangerous(_) | Absent => bail!("SSH host is missing or could be mistaken for an option"),
    };
    let destination = match url.user_as_argument() {
        Usable(user) => format!("{user}@{host}"),
        Absent => host.to_owned(),
        Dangerous(_) => bail!("SSH username could be mistaken for an option"),
    };
    let path = gix::url::expand_path::for_shell(url.path.clone());
    ensure!(
        !path.is_empty() && !path.trim().starts_with(b"-") && !path.contains(&0),
        "SSH repository path is empty or could be mistaken for an option"
    );
    let mut prepare = gix::command::prepare(&settings.command)
        .args(settings.arguments.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Captured into a bounded tail by a reader thread, so SSH diagnostics such as
        // "Permission denied (publickey)" reach the returned error instead of the
        // terminal, without a pipe that could fill up and block SSH.
        .stderr(Stdio::piped())
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("SSH_ASKPASS_REQUIRE", "never");
    // Never invoke a shell, including for trusted configured command lines.
    prepare.use_shell = false;
    match settings.kind {
        ProgramKind::Ssh => {
            prepare = prepare.args(["-T", "-o", "BatchMode=yes"]);
            if version != Protocol::V1 {
                prepare = prepare
                    .args(["-o", "SendEnv=GIT_PROTOCOL"])
                    .env("GIT_PROTOCOL", format!("version={}", version as usize));
            }
            if let Some(port) = url.port {
                prepare = prepare.args(["-p", &port.to_string()]);
            }
        }
        ProgramKind::Plink | ProgramKind::Putty | ProgramKind::TortoisePlink => {
            prepare = prepare.arg("-batch");
            if let Some(port) = url.port {
                prepare = prepare.args(["-P", &port.to_string()]);
            }
        }
        ProgramKind::Simple => {
            ensure!(url.port.is_none(), "The simple SSH variant cannot select a port");
        }
    }
    // Like Git, pass the remote command as one argument with the repository path
    // quoted by gix's POSIX single-quote implementation. As a single argument it is
    // wrapped in double quotes on Windows whenever it contains a space (always), so
    // MSYS/Cygwin clients such as Git for Windows' ssh.exe keep the inner single
    // quotes instead of treating them as their own command-line quoting.
    let mut remote_command = BString::from("git-upload-pack ");
    remote_command.extend_from_slice(&gix::quote::single(path.as_bstr()));
    prepare = prepare.arg(destination).arg(remote_command.to_os_str_lossy().into_owned());
    let mut command: Command = prepare.try_into().context("Failed to prepare SSH transport")?;
    for variable in [
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_PARAMETERS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_GRAFT_FILE",
        "GIT_INDEX_FILE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_REPLACE_REF_BASE",
        "GIT_PREFIX",
        "GIT_INTERNAL_SUPER_PREFIX",
        "GIT_SHALLOW_FILE",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "SSH_ASKPASS",
    ] {
        command.env_remove(variable);
    }
    if version == Protocol::V1 {
        command.env_remove("GIT_PROTOCOL");
    }
    Ok(command)
}

struct ManagedChild {
    child: Child,
    #[cfg(windows)]
    job: windows::Job,
}

impl ManagedChild {
    fn spawn(command: &mut Command) -> std::io::Result<Self> {
        #[cfg(windows)]
        {
            let (child, job) = windows::spawn(command)?;
            Ok(Self { child, job })
        }
        #[cfg(not(windows))]
        {
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                command.process_group(0);
            }
            command.spawn().map(|child| Self { child })
        }
    }

    fn terminate_and_reap(mut self) {
        #[cfg(windows)]
        drop(self.job);
        #[cfg(unix)]
        {
            // SAFETY: spawn created a new group led by this unreaped child.
            // Its PID cannot be reused while we retain its Child handle.
            unsafe {
                libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Keep this much of the end of SSH's stderr; the last lines carry the reason.
const STDERR_TAIL_BYTES: usize = 4096;

/// Drains a child's stderr on a thread, keeping only a bounded tail.
struct StderrTail {
    tail: Arc<Mutex<Vec<u8>>>,
    finished: mpsc::Receiver<()>,
}

impl StderrTail {
    fn capture(mut stderr: impl std::io::Read + Send + 'static) -> Result<Self> {
        let tail = Arc::new(Mutex::new(Vec::new()));
        let (done, finished) = mpsc::channel();
        let shared = Arc::clone(&tail);
        // Detached: if a descendant kept the pipe open, the thread ends when it closes.
        std::thread::Builder::new()
            .name("kingfisher-ssh-stderr".into())
            .spawn(move || {
                let mut buffer = [0u8; 1024];
                while let Ok(count) = stderr.read(&mut buffer) {
                    if count == 0 {
                        break;
                    }
                    let mut tail = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    tail.extend_from_slice(&buffer[..count]);
                    let excess = tail.len().saturating_sub(STDERR_TAIL_BYTES);
                    tail.drain(..excess);
                }
                let _ = done.send(());
            })
            .context("Failed to start SSH stderr reader")?;
        Ok(Self { tail, finished })
    }

    /// The last non-empty stderr line, after waiting briefly for the pipe to close.
    fn last_line(&self) -> Option<String> {
        let _ = self.finished.recv_timeout(std::time::Duration::from_secs(2));
        let tail = self.tail.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&tail)
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
            .map(str::to_owned)
    }
}

pub(super) struct ProcessGuard {
    child: Arc<Mutex<Option<ManagedChild>>>,
    cancel: Option<mpsc::Sender<()>>,
    timer: Option<JoinHandle<()>>,
    stderr: Option<StderrTail>,
}

impl ProcessGuard {
    fn new(
        child: ManagedChild,
        deadline: Option<Instant>,
        interrupt: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut guard = Self {
            child: Arc::new(Mutex::new(Some(child))),
            cancel: None,
            timer: None,
            stderr: None,
        };
        if let Some(deadline) = deadline {
            let child = Arc::clone(&guard.child);
            let (cancel, receiver) = mpsc::channel();
            guard.cancel = Some(cancel);
            guard.timer = Some(
                std::thread::Builder::new()
                    .name("kingfisher-ssh-timeout".into())
                    .spawn(move || {
                        if matches!(
                            receiver
                                .recv_timeout(deadline.saturating_duration_since(Instant::now())),
                            Err(mpsc::RecvTimeoutError::Timeout)
                        ) {
                            interrupt.store(true, Ordering::Relaxed);
                            terminate_and_reap(&child);
                        }
                    })
                    .context("Failed to start SSH deadline timer")?,
            );
        }
        Ok(guard)
    }
}

impl ProcessGuard {
    /// Ends the SSH process and adds its last stderr line to a failed operation's
    /// error, so authentication and host-key failures are reported with their cause.
    pub(super) fn explain(self, error: anyhow::Error) -> anyhow::Error {
        terminate_and_reap(&self.child);
        match self.stderr.as_ref().and_then(StderrTail::last_line) {
            Some(line) => error.context(format!("SSH reported: {line}")),
            None => error,
        }
    }
}

fn terminate_and_reap(child: &Mutex<Option<ManagedChild>>) {
    let child = child.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    if let Some(child) = child {
        child.terminate_and_reap();
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        terminate_and_reap(&self.child);
        if let Some(timer) = self.timer.take() {
            let _ = timer.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn url(text: &str) -> gix::Url {
        gix::url::parse(text.as_bytes().as_bstr()).unwrap()
    }

    fn openssh() -> Settings {
        Settings { command: "ssh".into(), arguments: Vec::new(), kind: ProgramKind::Ssh }
    }

    fn args(command: &Command) -> Vec<String> {
        command.get_args().map(|value| value.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn openssh_uses_account_port_and_batch_mode_without_disabling_host_keys() {
        let command = prepare_command(
            &openssh(),
            &url("ssh://git@example.com:2222/org/repo.git"),
            Protocol::V2,
        )
        .unwrap();
        // Windows resolves a native .exe before spawning without a shell.
        assert_eq!(
            std::path::Path::new(command.get_program()).file_stem(),
            Some(OsStr::new("ssh"))
        );
        assert_eq!(
            args(&command),
            [
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "SendEnv=GIT_PROTOCOL",
                "-p",
                "2222",
                "git@example.com",
                "git-upload-pack '/org/repo.git'",
            ]
        );
        assert!(!args(&command).iter().any(|arg| arg.contains("StrictHostKeyChecking")));
        let environment: Vec<_> = command.get_envs().collect();
        assert!(environment.contains(&(OsStr::new("GIT_PROTOCOL"), Some(OsStr::new("version=2")))));
        assert!(
            environment.contains(&(OsStr::new("SSH_ASKPASS_REQUIRE"), Some(OsStr::new("never"))))
        );
        assert!(environment.contains(&(OsStr::new("GIT_CONFIG_COUNT"), None)));
    }

    #[test]
    fn remote_paths_are_decoded_once_and_shell_quoted() {
        for (text, quoted) in [
            ("git@example.com:org/repo.git", "'org/repo.git'"),
            ("ssh://git@example.com/org/spaced%20name.git", "'/org/spaced name.git'"),
            ("git@example.com:org/a'b;$(whoami).git", "'org/a'\\''b;$(whoami).git'"),
            ("git@example.com:org/a;touch${IFS}x.git", "'org/a;touch${IFS}x.git'"),
            ("ssh://git@example.com/org/percent%2520.git", "'/org/percent%20.git'"),
        ] {
            let command = prepare_command(&openssh(), &url(text), Protocol::V1).unwrap();
            let arguments = args(&command);
            // One remote-command argument, as Git passes it: MSYS ssh.exe would strip
            // bare single quotes from a separate path argument.
            assert_eq!(arguments.last().unwrap(), &format!("git-upload-pack {quoted}"), "{text}");
            assert!(!arguments.iter().any(|argument| argument == "SendEnv=GIT_PROTOCOL"));
        }
    }

    #[test]
    fn option_looking_hosts_users_and_paths_cannot_inject_arguments() {
        for text in [
            "ssh://-option/repo.git",
            "ssh://-option@example.com/repo.git",
            "git@example.com:-option",
            "ssh://git:secret@example.com/repo.git",
            "https://example.com/repo.git",
        ] {
            assert!(prepare_command(&openssh(), &url(text), Protocol::V1).is_err(), "{text}");
        }
    }

    #[test]
    fn direct_custom_ssh_executable_with_spaces_never_uses_a_shell() {
        let settings = Settings {
            command: OsString::from("directory with spaces/ssh-wrapper"),
            arguments: Vec::new(),
            kind: ProgramKind::Ssh,
        };
        let command =
            prepare_command(&settings, &url("git@example.com:repo.git"), Protocol::V1).unwrap();
        assert_eq!(command.get_program(), settings.command);
    }

    #[test]
    fn plink_uses_batch_mode_and_its_own_port_option() {
        let settings =
            Settings { command: "plink".into(), arguments: Vec::new(), kind: ProgramKind::Plink };
        let command =
            prepare_command(&settings, &url("ssh://git@example.com:2222/repo.git"), Protocol::V2)
                .unwrap();
        assert_eq!(
            args(&command),
            ["-batch", "-P", "2222", "git@example.com", "git-upload-pack '/repo.git'"],
        );
    }

    #[test]
    fn configured_command_is_split_into_direct_arguments_without_a_shell() {
        let (command, arguments) = split_command(OsStr::new(
            "ssh -i 'directory with spaces/private key' -o IdentitiesOnly=yes",
        ))
        .unwrap();
        let settings = Settings { command, arguments, kind: ProgramKind::Ssh };
        let command =
            prepare_command(&settings, &url("git@example.com:repo.git"), Protocol::V1).unwrap();
        // Windows resolves a native .exe before spawning without a shell.
        assert_eq!(
            std::path::Path::new(command.get_program()).file_stem(),
            Some(OsStr::new("ssh"))
        );
        assert_eq!(
            &args(&command)[..4],
            ["-i", "directory with spaces/private key", "-o", "IdentitiesOnly=yes"],
        );
        let (executable, _) =
            split_command(OsStr::new("'directory with spaces/ssh' -F config")).unwrap();
        assert_eq!(executable, OsStr::new("directory with spaces/ssh"));
    }

    #[test]
    fn configured_shell_scripting_is_explicitly_rejected() {
        for text in [
            "",
            " ",
            "ssh '",
            "ssh -i $KEY",
            "ssh $(command)",
            "ssh `command`",
            "ssh | command",
            "ssh; command",
            "ssh && command",
            "ssh > output",
            "ssh < input",
            "ssh\ncommand",
            "~/bin/ssh",
        ] {
            assert!(split_command(OsStr::new(text)).is_err(), "{text:?}");
        }
    }

    fn touch(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }

    fn search_path(dirs: &[&std::path::Path]) -> OsString {
        std::env::join_paths(dirs).unwrap()
    }

    #[test]
    fn windows_ssh_on_path_is_preferred_over_git_bundled_ssh() {
        let root = tempfile::tempdir().unwrap();
        let openssh = root.path().join("OpenSSH");
        let git = root.path().join("Git");
        touch(&openssh.join("ssh.exe"));
        touch(&git.join("cmd").join("git.exe"));
        touch(&git.join("usr").join("bin").join("ssh.exe"));
        let path = search_path(&[&git.join("cmd"), &openssh]);
        assert_eq!(find_windows_ssh(Some(&path), |_| None), Some(openssh.join("ssh.exe")));
    }

    #[test]
    fn windows_ssh_falls_back_to_git_for_windows_found_via_git_on_path() {
        for git_dir in [&["cmd"][..], &["bin"], &["mingw64", "bin"]] {
            let root = tempfile::tempdir().unwrap();
            let git = root.path().join("Git");
            let bin = git_dir.iter().fold(git.clone(), |dir, part| dir.join(part));
            touch(&bin.join("git.exe"));
            let ssh = git.join("usr").join("bin").join("ssh.exe");
            touch(&ssh);
            let path = search_path(&[&bin]);
            assert_eq!(find_windows_ssh(Some(&path), |_| None), Some(ssh), "{git_dir:?}");
        }
    }

    #[test]
    fn windows_ssh_falls_back_to_standard_git_install_locations() {
        let root = tempfile::tempdir().unwrap();
        let program_files = root.path().join("Program Files");
        let local = root.path().join("Local");
        let per_user = local.join("Programs").join("Git").join("usr").join("bin").join("ssh.exe");
        touch(&per_user);
        let lookup = |name: &str| match name {
            "ProgramFiles" => Some(program_files.clone().into_os_string()),
            "LOCALAPPDATA" => Some(local.clone().into_os_string()),
            _ => None,
        };
        assert_eq!(find_windows_ssh(None, lookup), Some(per_user));
        let system = program_files.join("Git").join("usr").join("bin").join("ssh.exe");
        touch(&system);
        assert_eq!(find_windows_ssh(None, lookup), Some(system));
    }

    #[test]
    fn windows_ssh_search_ignores_relative_locations() {
        let root = tempfile::tempdir().unwrap();
        let relative = std::path::Path::new("relative-ssh-dir");
        let path = search_path(&[relative]);
        let lookup = |name: &str| (name == "ProgramFiles").then(|| OsString::from("relative"));
        assert_eq!(find_windows_ssh(Some(&path), lookup), None);
        assert_eq!(find_windows_ssh(Some(&search_path(&[root.path()])), |_| None), None);
    }

    #[test]
    fn missing_ssh_client_error_explains_how_to_fix_it() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let message = format!("{:#}", spawn_error(missing, OsStr::new("ssh")));
        assert!(message.contains("SSH client 'ssh' was not found"), "{message}");
        assert!(message.contains("OpenSSH Client"), "{message}");
        assert!(message.contains("GIT_SSH_COMMAND"), "{message}");
        assert!(message.contains("HTTPS URL"), "{message}");
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let message = format!("{:#}", spawn_error(denied, OsStr::new("ssh")));
        assert!(message.starts_with("Failed to start SSH transport"), "{message}");
    }

    #[test]
    fn remote_command_is_a_single_double_quoted_argument_on_windows() {
        // Rust only adds Windows command-line quotes around arguments with spaces
        // or tabs. The remote command always has one, so MSYS ssh.exe receives
        // "git-upload-pack 'org/a;b.git'" and keeps the inner single quotes.
        let command =
            prepare_command(&openssh(), &url("git@example.com:org/a;b.git"), Protocol::V1).unwrap();
        let last = args(&command).pop().unwrap();
        assert!(last.contains(' ') && last.ends_with("'org/a;b.git'"), "{last}");
    }

    #[test]
    fn stderr_tail_keeps_the_last_line_within_its_bound() {
        let mut text = "x".repeat(STDERR_TAIL_BYTES * 2);
        text.push_str("\ngit@example.com: Permission denied (publickey).\n\n");
        let tail = StderrTail::capture(std::io::Cursor::new(text.into_bytes())).unwrap();
        assert_eq!(
            tail.last_line().as_deref(),
            Some("git@example.com: Permission denied (publickey).")
        );
        assert!(tail.tail.lock().unwrap().len() <= STDERR_TAIL_BYTES);
        let empty = StderrTail::capture(std::io::Cursor::new(Vec::new())).unwrap();
        assert_eq!(empty.last_line(), None);
    }

    #[test]
    fn auto_variant_infers_the_program_kind() {
        temp_env::with_vars(
            [
                ("GIT_SSH_VARIANT", Some("auto")),
                ("GIT_SSH_COMMAND", Some("plink")),
                ("GIT_SSH", None::<&str>),
            ],
            || {
                let dir = tempfile::tempdir().unwrap();
                let repo = gix::init(dir.path()).unwrap();
                let settings = Settings::from_repo(&repo).unwrap();
                assert_eq!(settings.kind, ProgramKind::Plink);
            },
        );
        temp_env::with_var("GIT_SSH_VARIANT", Some("bogus"), || {
            let dir = tempfile::tempdir().unwrap();
            let repo = gix::init(dir.path()).unwrap();
            assert!(Settings::from_repo(&repo).is_err());
        });
    }

    #[test]
    fn simple_variant_rejects_unrepresentable_ports() {
        let settings = Settings {
            command: "custom-ssh".into(),
            arguments: Vec::new(),
            kind: ProgramKind::Simple,
        };
        assert!(
            prepare_command(&settings, &url("ssh://git@example.com:2222/repo.git"), Protocol::V1)
                .is_err()
        );
    }

    fn hanging_child() -> ManagedChild {
        ManagedChild::spawn(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "git_binary::ssh::tests::hanging_child_process"])
                .env("KF_SSH_TIMER_TEST_CHILD", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
        .unwrap()
    }

    #[test]
    #[ignore = "subprocess fixture for SSH lifecycle tests"]
    fn hanging_child_process() {
        if let Some(mode) = std::env::var_os("KF_SSH_TIMER_TEST_CHILD") {
            let _descendant = if mode == "descendant" {
                let child = Command::new(std::env::current_exe().unwrap())
                    .args(["--ignored", "--exact", "git_binary::ssh::tests::hanging_child_process"])
                    .env("KF_SSH_TIMER_TEST_CHILD", "leaf")
                    .stdin(Stdio::null())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                use std::io::Write;
                writeln!(std::io::stdout(), "KF_SSH_DESCENDANT_READY").unwrap();
                Some(child)
            } else {
                None
            };
            loop {
                std::thread::park();
            }
        }
    }

    #[test]
    fn total_deadline_closes_pipes_held_by_transport_descendants() {
        use std::io::Read;
        let started = Instant::now();
        let mut child = ManagedChild::spawn(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "git_binary::ssh::tests::hanging_child_process"])
                .env("KF_SSH_TIMER_TEST_CHILD", "descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null()),
        )
        .unwrap();
        let mut stdout = child.child.stdout.take().unwrap();
        let interrupt = Arc::new(AtomicBool::new(false));
        let _guard = ProcessGuard::new(
            child,
            Some(started + Duration::from_secs(2)),
            Arc::clone(&interrupt),
        )
        .unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut output = Vec::new();
            let result = stdout.read_to_end(&mut output);
            let _ = sender.send((result, output));
        });
        let (result, output) = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("SSH descendants retained the protocol pipe after the operation deadline");
        result.unwrap();
        reader.join().unwrap();
        assert!(String::from_utf8_lossy(&output).contains("KF_SSH_DESCENDANT_READY"));
        assert!(interrupt.load(Ordering::Relaxed));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn total_deadline_kills_and_reaps_a_blocked_child() {
        let interrupt = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let mut guard = ProcessGuard::new(
            hanging_child(),
            Some(started + Duration::from_millis(100)),
            Arc::clone(&interrupt),
        )
        .unwrap();
        guard.timer.take().unwrap().join().unwrap();
        assert!(interrupt.load(Ordering::Relaxed));
        assert!(guard.child.lock().unwrap().is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn drop_cancels_long_timer_and_reaps_child_without_false_interruption() {
        let interrupt = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let guard = ProcessGuard::new(
            hanging_child(),
            Some(started + Duration::from_secs(60)),
            Arc::clone(&interrupt),
        )
        .unwrap();
        let child = Arc::clone(&guard.child);
        drop(guard);
        assert!(child.lock().unwrap().is_none());
        assert!(!interrupt.load(Ordering::Relaxed));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn unlimited_operations_do_not_start_an_ssh_timer() {
        let guard =
            ProcessGuard::new(hanging_child(), None, Arc::new(AtomicBool::new(false))).unwrap();
        assert!(guard.timer.is_none());
        assert!(guard.cancel.is_none());
    }
}
