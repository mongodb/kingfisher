use std::io::{Read, Write};
use std::path::PathBuf;

use super::{get_reader_for_file_or_stdin, get_writer_for_file_or_stdout};

#[test]
fn test_file_io_binary_buffers_truncation_and_eof() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output.bin");
    let content: Vec<u8> = (0..24_697).map(|n| (n % 256) as u8).collect();
    std::fs::write(&path, vec![b'x'; content.len() + 100]).unwrap();
    let mut writer = get_writer_for_file_or_stdout(Some(&path)).unwrap();
    writer.write_all(&content[..7]).unwrap();
    writer.write_all(&content[7..]).unwrap();
    writer.flush().unwrap();
    drop(writer);
    assert_eq!(std::fs::read(&path).unwrap(), content);

    let mut reader = get_reader_for_file_or_stdin(Some(path.clone())).unwrap();
    let mut prefix = [0; 7];
    reader.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix.as_slice(), &content[..7]);
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, content[7..]);
    assert_eq!(reader.read(&mut prefix).unwrap(), 0);
    drop(reader);

    // Empty writes still create a new empty file, and an existing file is
    // truncated immediately on open, including when nothing is written.
    let writer = get_writer_for_file_or_stdout(Some(&path)).unwrap();
    drop(writer);
    assert!(std::fs::read(&path).unwrap().is_empty());
    std::fs::remove_file(&path).unwrap();
    drop(get_writer_for_file_or_stdout(Some(&path)).unwrap());
    assert!(std::fs::read(&path).unwrap().is_empty());
    let mut writer = get_writer_for_file_or_stdout(Some(&path)).unwrap();
    writer.write_all(b"drop flushes buffered output").unwrap();
    drop(writer);
    assert_eq!(std::fs::read(path).unwrap(), b"drop flushes buffered output");
}

#[test]
fn test_file_io_preserves_open_errors() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent");
    assert_eq!(
        get_reader_for_file_or_stdin(Some(&absent)).err().unwrap().kind(),
        std::io::ErrorKind::NotFound,
    );
    assert_eq!(
        get_writer_for_file_or_stdout(Some(absent.join("output.bin"))).err().unwrap().kind(),
        std::io::ErrorKind::NotFound,
    );
    assert!(get_writer_for_file_or_stdout(Some(dir.path())).is_err());
}

#[test]
fn test_standard_stream_helpers_can_be_constructed_without_io() {
    // Construct the real helpers without consuming stdin or writing stdout;
    // reading stdin in a unit test can hang under an interactive test runner.
    drop(get_reader_for_file_or_stdin::<PathBuf>(None).unwrap());
    drop(get_writer_for_file_or_stdout::<PathBuf>(None).unwrap());
}

#[cfg(unix)]
#[test]
fn test_file_writer_rejects_dangling_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let absent_target = dir.path().join("missing-target");
    let link = dir.path().join("report.json");
    std::os::unix::fs::symlink(&absent_target, &link).unwrap();
    let error = get_writer_for_file_or_stdout(Some(&link)).err().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        error.to_string(),
        format!("refusing to write output through symlink: {}", link.display(),)
    );
    assert!(!absent_target.exists());
    assert!(std::fs::symlink_metadata(link).unwrap().file_type().is_symlink());
}

#[cfg(unix)]
#[test]
fn test_file_reader_follows_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("input.bin");
    let link = dir.path().join("linked-input.bin");
    std::fs::write(&target, b"\0\xffreader bytes").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let mut reader = get_reader_for_file_or_stdin(Some(link)).unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"\0\xffreader bytes");
}
