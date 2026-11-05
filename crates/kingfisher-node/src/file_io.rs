//! Bounded snapshots of caller-owned regular files. Never open a FIFO in blocking mode.
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek},
    path::Path,
};

use kingfisher_scanner::ScanControl;
use napi::Result;

use crate::control::{failure, interrupted};

pub(crate) fn open_regular(path: &Path, control: &ScanControl) -> Result<File> {
    control.check().map_err(interrupted)?;
    // Reject known special files before open, but do not trust path metadata:
    // an attacker can replace a regular file with a FIFO between these calls.
    if !std::fs::metadata(path).map_err(|_| failure("KF_IO", "input could not be read"))?.is_file()
    {
        return Err(failure("KF_IO", "input must be a regular file"));
    }
    let file = open_regular_handle(path)?;
    control.check().map_err(interrupted)?;
    Ok(file)
}

// This is separate so the post-precheck swap state can be tested deterministically.
fn open_regular_handle(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A swapped FIFO must not wait for a writer before we can inspect its
        // handle. O_NONBLOCK has no effect on ordinary regular-file reads.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| failure("KF_IO", "input could not be read"))?;
    if !file.metadata().map_err(|_| failure("KF_IO", "input could not be read"))?.is_file() {
        return Err(failure("KF_IO", "input must be a regular file"));
    }
    Ok(file)
}

pub(crate) fn header(file: &mut File, control: &ScanControl) -> Result<Vec<u8>> {
    let mut output = [0u8; 16];
    let mut count = 0;
    while count < output.len() {
        control.check().map_err(interrupted)?;
        match file.read(&mut output[count..]) {
            Ok(0) => break,
            Ok(read) => count += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(failure("KF_IO", "input could not be read")),
        }
    }
    file.rewind().map_err(|_| failure("KF_IO", "input could not be read"))?;
    Ok(output[..count].to_vec())
}

pub(crate) fn read_bounded(
    mut file: File,
    limit: Option<u64>,
    limit_message: &str,
    control: &ScanControl,
) -> Result<Vec<u8>> {
    let metadata = file.metadata().map_err(|_| failure("KF_IO", "input could not be read"))?;
    if !metadata.is_file() {
        return Err(failure("KF_IO", "input must be a regular file"));
    }
    if limit.is_some_and(|limit| metadata.len() > limit) {
        return Err(failure("KF_LIMIT", limit_message));
    }
    let mut output = Vec::with_capacity(metadata.len().min(64 * 1024 * 1024) as usize);
    let mut buffer = [0u8; 32 * 1024];
    loop {
        control.check().map_err(interrupted)?;
        // Files can grow after metadata: read only one byte beyond the cap and
        // never retain that byte in the returned snapshot.
        let count = limit.map_or(buffer.len(), |limit| {
            limit.saturating_sub(output.len() as u64).saturating_add(1).min(buffer.len() as u64)
                as usize
        });
        let count = match file.read(&mut buffer[..count]) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(failure("KF_IO", "input could not be read")),
        };
        if count == 0 {
            break;
        }
        if limit.is_some_and(|limit| output.len() as u64 + count as u64 > limit) {
            return Err(failure("KF_LIMIT", limit_message));
        }
        output.extend_from_slice(&buffer[..count]);
    }
    control.check().map_err(interrupted)?;
    Ok(output)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{ffi::CString, os::unix::ffi::OsStrExt, sync::mpsc, time::Duration};

    use super::*;

    #[test]
    fn fifo_is_rejected_before_open_and_after_a_path_swap_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.fifo");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a NUL-terminated path retained for the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let direct = open_regular(&path, &ScanControl::default()).unwrap_err();
            // Model a regular path replaced by this FIFO after path metadata.
            // A blocking open would wait forever because there is no writer.
            let swapped = open_regular_handle(&path).unwrap_err();
            send.send((direct.reason, swapped.reason)).unwrap();
        });
        let (direct, swapped) = receive
            .recv_timeout(Duration::from_secs(2))
            .expect("regular-file opens must never wait for a FIFO writer");
        assert!(direct.starts_with("KF_IO:"));
        assert!(swapped.starts_with("KF_IO:"));
    }
}
