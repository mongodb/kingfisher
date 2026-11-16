//! The small subset of GitHub releases needed by Kingfisher's updater.
//!
//! Keep executable replacement in `self-replace`: replacing a running Windows
//! image safely is not the same operation as renaming a file on Unix.

use std::{
    fs::File,
    io::{self, Read, Seek, Write},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{blocking::Client, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const API_URL: &str = "https://api.github.com";
const MAX_METADATA_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Deserialize)]
pub(super) struct Asset {
    name: String,
    url: String,
    digest: Option<String>,
}

#[derive(Deserialize)]
struct ReleaseResponse {
    tag_name: String,
    assets: Vec<Asset>,
}

pub(super) struct Release {
    pub version: semver::Version,
    assets: Vec<Asset>,
}

pub(super) struct Updater {
    client: Client,
    api_url: reqwest::Url,
}

impl Updater {
    pub fn new(base_url: Option<&str>) -> Result<Self> {
        let api_url = reqwest::Url::parse(base_url.unwrap_or(API_URL))?;
        ensure!(matches!(api_url.scheme(), "https" | "http"), "Unsupported update URL");
        let client = Client::builder()
            .user_agent(concat!("kingfisher/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            .build()?;
        Ok(Self { client, api_url })
    }

    fn request(
        &self,
        mut url: reqwest::Url,
        accept: &'static str,
    ) -> reqwest::blocking::RequestBuilder {
        // Public updates are always anonymous, including asset downloads. Ignore
        // environment tokens and URL credentials (reqwest otherwise adds Basic auth).
        let _ = url.set_username("");
        let _ = url.set_password(None);
        self.client.get(url).header(header::ACCEPT, accept)
    }

    pub fn get_latest_release(&self) -> Result<Release> {
        let url = reqwest::Url::parse(&format!(
            "{}/repos/mongodb/kingfisher/releases/latest",
            self.api_url.as_str().trim_end_matches('/')
        ))?;
        let response =
            self.request(url, "application/vnd.github+json").send()?.error_for_status()?;
        let mut body = Vec::new();
        copy_limited(response, &mut body, MAX_METADATA_BYTES)?;
        let response: ReleaseResponse = serde_json::from_slice(&body)?;
        let version = semver::Version::parse(response.tag_name.trim_start_matches('v'))?;
        Ok(Release { version, assets: response.assets })
    }

    pub fn install(
        &self,
        release: &Release,
        replace: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<()> {
        let (name, kind) = platform_archive(std::env::consts::OS, std::env::consts::ARCH)?;
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .context("No update archive is available for this platform")?;
        let directory = tempfile::tempdir()?;
        let mut archive = tempfile::tempfile_in(directory.path())?;
        let response = self
            .request(reqwest::Url::parse(&asset.url)?, "application/octet-stream")
            .send()?
            .error_for_status()?;
        copy_limited(response, &mut archive, MAX_ARCHIVE_BYTES)?;
        archive.rewind()?;
        verify_digest(&mut archive, asset.digest.as_deref())?;
        archive.rewind()?;
        // Do not unpack arbitrary paths, links, or permissions from a release.
        // Only copy the root executable to a filename we control.
        let executable = directory.path().join(kind.executable());
        {
            let mut output = File::create(&executable)?;
            extract_executable(archive, kind, &mut output)?;
            output.flush()?;
        }
        replace(&executable).context("Failed to replace the running executable")?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ArchiveKind {
    TarGz,
    Zip,
}

impl ArchiveKind {
    fn executable(self) -> &'static str {
        match self {
            Self::TarGz => "kingfisher",
            Self::Zip => "kingfisher.exe",
        }
    }
}

fn platform_archive(os: &str, arch: &str) -> Result<(&'static str, ArchiveKind)> {
    Ok(match (os, arch) {
        ("linux", "x86_64") => ("kingfisher-linux-x64.tgz", ArchiveKind::TarGz),
        ("linux", "aarch64") => ("kingfisher-linux-arm64.tgz", ArchiveKind::TarGz),
        ("macos", "x86_64") => ("kingfisher-darwin-x64.tgz", ArchiveKind::TarGz),
        ("macos", "aarch64") => ("kingfisher-darwin-arm64.tgz", ArchiveKind::TarGz),
        ("windows", "x86_64") => ("kingfisher-windows-x64.zip", ArchiveKind::Zip),
        ("windows", "aarch64") => ("kingfisher-windows-arm64.zip", ArchiveKind::Zip),
        _ => bail!("Self-update is not supported on {os}/{arch}"),
    })
}

fn copy_limited(reader: impl Read, writer: &mut impl Write, limit: u64) -> Result<u64> {
    let length = io::copy(&mut reader.take(limit + 1), writer)?;
    ensure!(length <= limit, "Update content exceeds its size limit");
    Ok(length)
}

fn verify_digest(archive: &mut File, digest: Option<&str>) -> Result<()> {
    // GitHub publishes a SHA-256 digest for every release asset. Without one the
    // archive is authenticated only by TLS, so refuse to install it.
    let digest = digest.context(
        "The update archive has no published SHA-256 digest; download the release manually",
    )?;
    let expected = digest.strip_prefix("sha256:").context("Unsupported update archive digest")?;
    let expected = hex::decode(expected).context("Invalid update archive digest")?;
    ensure!(expected.len() == 32, "Invalid update archive digest length");
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = archive.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    ensure!(hasher.finalize().as_slice() == expected, "Update archive digest mismatch");
    Ok(())
}

fn is_root_executable(path: &Path, name: &str) -> bool {
    // Release tarballs may include a leading ./; never accept another directory,
    // a parent component, or an absolute/Windows-prefixed path.
    path.strip_prefix(".").unwrap_or(path) == Path::new(name)
}

fn extract_executable(reader: File, kind: ArchiveKind, output: &mut impl Write) -> Result<()> {
    match kind {
        ArchiveKind::TarGz => {
            let decoder = flate2::read::GzDecoder::new(reader).take(MAX_EXECUTABLE_BYTES + 1);
            let mut archive = tar::Archive::new(decoder);
            let mut found = false;
            for entry in archive.entries()? {
                let mut entry = entry?;
                if !is_root_executable(entry.path()?.as_ref(), kind.executable()) {
                    continue;
                }
                ensure!(!found, "Update archive contains duplicate executables");
                ensure!(entry.header().entry_type().is_file(), "Update executable is not a file");
                let size = entry.size();
                ensure!(size > 0, "Update executable is empty");
                ensure!(
                    copy_limited(&mut entry, output, MAX_EXECUTABLE_BYTES)? == size,
                    "Update executable is truncated"
                );
                found = true;
            }
            // Finish the gzip stream too, so CRC/truncation failures cannot be
            // hidden behind a valid tar end marker. Bound all decompression,
            // including unrelated files that occur before/after the executable.
            let mut decoder = archive.into_inner();
            io::copy(&mut decoder, &mut io::sink())?;
            ensure!(decoder.limit() > 0, "Update content exceeds its size limit");
            if found {
                return Ok(());
            }
        }
        ArchiveKind::Zip => {
            let mut archive = zip::ZipArchive::new(reader)?;
            let mut found = None;
            for index in 0..archive.len() {
                let entry = archive.by_index(index)?;
                if is_root_executable(Path::new(entry.name()?.as_ref()), kind.executable()) {
                    ensure!(found.is_none(), "Update archive contains duplicate executables");
                    found = Some(index);
                }
            }
            if let Some(index) = found {
                let mut entry = archive.by_index(index)?;
                let mode = entry.unix_mode().unwrap_or(0) & 0o170000;
                ensure!(
                    entry.is_file() && (mode == 0 || mode == 0o100000),
                    "Update executable is not a file"
                );
                let size = entry.size();
                ensure!(size > 0, "Update executable is empty");
                ensure!(
                    copy_limited(&mut entry, output, MAX_EXECUTABLE_BYTES)? == size,
                    "Update executable is truncated"
                );
                return Ok(());
            }
        }
    }
    bail!("Update archive does not contain {}", kind.executable())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tar_bytes(name: &str, kind: tar::EntryType, bytes: &[u8]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(kind);
        if kind.is_symlink() {
            header.set_link_name("somewhere").unwrap();
        }
        header.set_cksum();
        archive.append_data(&mut header, name, bytes).unwrap();
        archive.into_inner().unwrap().finish().unwrap()
    }

    fn zip_bytes(name: &str, bytes: &[u8], link: bool) -> Vec<u8> {
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        if link {
            archive.add_symlink(name, "somewhere", options).unwrap();
        } else {
            archive.start_file(name, options).unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap().into_inner()
    }

    fn extract(bytes: &[u8], kind: ArchiveKind) -> Result<Vec<u8>> {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        file.rewind()?;
        let mut output = Vec::new();
        extract_executable(file, kind, &mut output)?;
        Ok(output)
    }

    #[test]
    fn extracts_only_regular_root_executables_for_both_platforms() {
        assert_eq!(
            extract(
                &tar_bytes("./kingfisher", tar::EntryType::Regular, b"unix"),
                ArchiveKind::TarGz
            )
            .unwrap(),
            b"unix"
        );
        assert_eq!(
            extract(&zip_bytes("kingfisher.exe", b"windows", false), ArchiveKind::Zip).unwrap(),
            b"windows"
        );
        for name in ["nested/kingfisher", "README.md"] {
            assert!(
                extract(
                    &tar_bytes(name, tar::EntryType::Regular, b"not the binary"),
                    ArchiveKind::TarGz
                )
                .is_err()
            );
        }
        for name in ["../kingfisher.exe", "/kingfisher.exe", "nested/kingfisher.exe"] {
            assert!(extract(&zip_bytes(name, b"not the binary", false), ArchiveKind::Zip).is_err());
        }
    }

    #[test]
    fn rejects_links_empty_files_and_invalid_archives() {
        for (bytes, kind) in [
            (tar_bytes("kingfisher", tar::EntryType::Symlink, b""), ArchiveKind::TarGz),
            (tar_bytes("kingfisher", tar::EntryType::Regular, b""), ArchiveKind::TarGz),
            (zip_bytes("kingfisher.exe", b"", true), ArchiveKind::Zip),
            (zip_bytes("kingfisher.exe", b"", false), ArchiveKind::Zip),
            (b"not gzip".to_vec(), ArchiveKind::TarGz),
            (b"not zip".to_vec(), ArchiveKind::Zip),
        ] {
            assert!(extract(&bytes, kind).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_root_executables() {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for name in ["kingfisher", "./kingfisher"] {
            let mut header = tar::Header::new_gnu();
            header.set_size(6);
            header.set_mode(0o755);
            header.set_cksum();
            archive.append_data(&mut header, name, &b"binary"[..]).unwrap();
        }
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        assert!(extract(&bytes, ArchiveKind::TarGz).is_err());
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for name in ["kingfisher.exe", "./kingfisher.exe"] {
            archive.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
            archive.write_all(b"binary").unwrap();
        }
        assert!(extract(&archive.finish().unwrap().into_inner(), ArchiveKind::Zip).is_err());
    }

    #[test]
    fn gzip_checksum_failure_is_not_hidden_by_tar_end_marker() {
        let mut bytes = tar_bytes("kingfisher", tar::EntryType::Regular, b"binary");
        let crc_index = bytes.len() - 8;
        bytes[crc_index] ^= 1;
        assert!(extract(&bytes, ArchiveKind::TarGz).is_err());
    }

    #[tokio::test]
    async fn install_downloads_only_matching_archive_and_replaces_only_verified_bytes() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };
        let server = MockServer::start().await;
        let (name, kind) = platform_archive(std::env::consts::OS, std::env::consts::ARCH).unwrap();
        let bytes = match kind {
            ArchiveKind::TarGz => {
                tar_bytes("kingfisher", tar::EntryType::Regular, b"new executable")
            }
            ArchiveKind::Zip => zip_bytes("kingfisher.exe", b"new executable", false),
        };
        Mock::given(method("GET"))
            .and(path("/binary"))
            .and(header("accept", "application/octet-stream"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
            .expect(3)
            .mount(&server)
            .await;
        let uri = server.uri();
        let requests = tokio::task::spawn_blocking(move || {
            let updater = Updater::new(Some(&uri)).unwrap();
            let mut release = Release {
                version: semver::Version::new(99, 0, 0),
                assets: vec![
                    Asset {
                        name: "kingfisher-linux-x64.deb".into(),
                        url: format!("{uri}/wrong"),
                        digest: None,
                    },
                    Asset {
                        name: name.into(),
                        url: format!("{uri}/binary"),
                        digest: Some(format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))),
                    },
                ],
            };
            // The callback stands in for self-replace; never replace a test runner.
            let mut replacements = 0;
            updater
                .install(&release, |path| {
                    assert_eq!(std::fs::read(path).unwrap(), b"new executable");
                    replacements += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(replacements, 1);
            let error = updater
                .install(&release, |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)))
                .unwrap_err();
            assert!(error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
            }));
            release.assets[1].digest = Some(format!("sha256:{}", "00".repeat(32)));
            assert!(
                updater.install(&release, |_| panic!("must not replace unverified bytes")).is_err()
            );
            release.assets.remove(1);
            assert!(
                updater
                    .install(&release, |_| panic!(
                        "must not select a package instead of an archive"
                    ))
                    .is_err()
            );
        })
        .await;
        requests.unwrap();
        // Asset downloads are anonymous too, not just release metadata requests.
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| !request.headers.contains_key("authorization"))
        );
    }

    /// End-to-end check against the real GitHub release: anonymous metadata, the
    /// platform asset name, the published digest, and the archive layout must all
    /// still line up, and the extracted executable must run. The replacement callback
    /// never touches the test binary. Run with `cargo test -- --ignored live_`.
    #[test]
    #[ignore = "requires network access to api.github.com"]
    fn live_latest_release_installs_a_runnable_executable() {
        let updater = Updater::new(None).unwrap();
        let release = updater.get_latest_release().unwrap();
        let expected_version = release.version.to_string();
        let mut ran = false;
        updater
            .install(&release, |path| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
                }
                let output = std::process::Command::new(path).arg("--version").output()?;
                assert!(output.status.success(), "{output:?}");
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(stdout.contains(&expected_version), "{stdout}");
                ran = true;
                Ok(())
            })
            .unwrap();
        assert!(ran);
    }

    #[test]
    fn update_requests_are_always_unauthenticated() {
        for token in ["expired-or-enterprise-token", "invalid\r\nheader"] {
            temp_env::with_vars([("GITHUB_TOKEN", Some(token)), ("GH_TOKEN", Some(token))], || {
                let updater = Updater::new(None).unwrap();
                for url in [
                    "https://api.github.com/repos/mongodb/kingfisher/releases/latest",
                    "http://api.github.com/binary",
                    "https://api.github.com:8443/binary",
                    "https://example.com/binary",
                    "https://user:password@api.github.com/binary",
                ] {
                    let request = updater
                        .request(reqwest::Url::parse(url).unwrap(), "application/octet-stream")
                        .build()
                        .unwrap();
                    assert!(!request.headers().contains_key(header::AUTHORIZATION));
                    assert!(request.url().username().is_empty());
                    assert!(request.url().password().is_none());
                }
            });
        }
    }

    #[test]
    fn size_limits_apply_even_without_content_length() {
        let mut output = Vec::new();
        assert_eq!(copy_limited(&b"1234"[..], &mut output, 4).unwrap(), 4);
        assert!(copy_limited(&b"12345"[..], &mut Vec::new(), 4).is_err());
    }

    #[test]
    fn published_sha256_is_required_and_checked() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"archive").unwrap();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"archive")));
        file.rewind().unwrap();
        verify_digest(&mut file, Some(&digest)).unwrap();
        for digest in
            ["sha256:00", "sha256:not-hex", "md5:0000", &format!("sha256:{}", "00".repeat(32))]
        {
            file.rewind().unwrap();
            assert!(verify_digest(&mut file, Some(digest)).is_err());
        }
        file.rewind().unwrap();
        assert!(verify_digest(&mut file, None).is_err());
    }

    #[test]
    fn platform_names_exclude_linux_packages_and_other_architectures() {
        for os in ["linux", "macos", "windows"] {
            for arch in ["x86_64", "aarch64"] {
                let (name, kind) = platform_archive(os, arch).unwrap();
                assert!(name.ends_with(if os == "windows" { ".zip" } else { ".tgz" }));
                assert_eq!(kind.executable().ends_with(".exe"), os == "windows");
            }
        }
        assert!(platform_archive("freebsd", "x86_64").is_err());
        assert!(platform_archive("linux", "riscv64").is_err());
    }
}
