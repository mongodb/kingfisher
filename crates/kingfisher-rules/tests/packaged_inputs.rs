use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

struct GitFixture(PathBuf);

impl GitFixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("kingfisher-inputs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        let output = fixture.git().args(["init", "--quiet"]).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        std::fs::write(fixture.0.join("empty-config"), b"").unwrap();
        std::fs::write(fixture.0.join(".gitattributes"), include_str!("../../../.gitattributes"))
            .unwrap();
        fixture
    }

    fn git(&self) -> Command {
        let mut command = Command::new("git");
        command.current_dir(&self.0).args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
        ]);
        command.env("GIT_CONFIG_NOSYSTEM", "1");
        command.env("GIT_CONFIG_GLOBAL", self.0.join("empty-config"));
        command
    }

    fn hash(&self, bytes: &[u8], path: Option<&str>) -> String {
        let mut command = self.git();
        command.args(["hash-object", "--stdin"]);
        if let Some(path) = path {
            command.arg("--path").arg(path);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}

impl Drop for GitFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

#[test]
fn git_preserves_the_pinned_compressed_wordlist_bytes() {
    let bytes = include_bytes!("../data/betterleaks-words.txt.gz");
    let provenance: serde_json::Value =
        serde_json::from_str(include_str!("../generated/provenance.json")).unwrap();
    let path = "crates/kingfisher-rules/data/betterleaks-words.txt.gz";
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        provenance["artifact_sha256"][path].as_str().unwrap()
    );
    let mut decoded = String::new();
    flate2::read::GzDecoder::new(bytes.as_slice()).read_to_string(&mut decoded).unwrap();
    assert!(!decoded.is_empty());

    let fixture = GitFixture::new();
    assert_eq!(
        fixture.hash(bytes, Some(path)),
        fixture.hash(bytes, None),
        "Git attributes must preserve compressed rule inputs byte for byte"
    );
}
