//! Progress counts reportable observations before report deduplication, not writer batches.
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::Duration,
};

use serde_json::Value;
use tempfile::TempDir;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

struct Fixture {
    _root: TempDir,
    inputs: PathBuf,
    rules: PathBuf,
    progress: PathBuf,
}

impl Fixture {
    fn new(endpoint: &str, contents: &[&str], dependent: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let inputs = root.path().join("inputs with spaces");
        fs::create_dir(&inputs).unwrap();
        for (index, content) in contents.iter().enumerate() {
            fs::write(inputs.join(format!("{index}.txt")), content).unwrap();
        }
        let rules = root.path().join("rules.yml");
        let dependency = if dependent {
            "    depends_on_rule:\n      - rule_id: acme.progress.helper\n        variable: HELPER\n"
        } else {
            ""
        };
        fs::write(
            &rules,
            format!(
                r#"rules:
  - id: acme.progress.helper
    name: Hidden progress helper
    pattern: '(helper_[0-9]{{4}})'
    min_entropy: 0
    confidence: high
    visible: false
  - id: acme.progress.secret
    name: Progress test secret
    pattern: '(secret_[0-9]{{4}})'
    min_entropy: 0
    confidence: high
{dependency}    validation:
      type: Http
      content:
        request:
          method: GET
          url: '{endpoint}/validate'
          headers:
            Authorization: 'Bearer {{{{ TOKEN }}}}'
          response_matcher:
            - type: StatusMatch
              status: [200]
  - id: acme.progress.low
    name: Excluded low confidence match
    pattern: '(low_[0-9]{{4}})'
    min_entropy: 0
    confidence: low
  - id: acme.progress.rejected
    name: Rejected entropy candidate
    pattern: '(rejected_[0-9]{{4}})'
    min_entropy: 99
    confidence: high
"#
            ),
        )
        .unwrap();
        let progress = root.path().join("progress.json");
        Self { _root: root, inputs, rules, progress }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        command
            .arg("scan")
            .arg(&self.inputs)
            .arg("--rules-path")
            .arg(&self.rules)
            .args([
                "--load-builtins=false",
                "--confidence=high",
                "--format=json",
                "--no-update-check",
                "--no-base64",
                "--jobs=2",
                "--allow-internal-ips",
            ])
            .env("NO_COLOR", "1")
            .env("KINGFISHER_PROGRESS_FILE", &self.progress);
        command
    }

    fn snapshot(&self) -> Value {
        let bytes = fs::read(&self.progress).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        for secret in ["secret_1234", "secret_5678", "helper_1234"] {
            assert!(!text.contains(secret), "progress must not include credential material");
        }
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn report(output: &Output) -> Value {
    assert!(
        matches!(output.status.code(), Some(200 | 205)),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Non-quiet JSON scans also emit a separate JSON summary document.
    let report = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .next()
        .unwrap()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(" inputs · "), "non-TTY output must not render live progress");
    assert!(!stderr.contains("findings checked"), "non-TTY output must not render live progress");
    report
}

#[test]
fn occurrences_are_independent_of_final_dedup_and_hidden_helpers() {
    // Distinct blobs containing the same secret exercise storage dedup, not blob reuse.
    let fixture = Fixture::new(
        "http://127.0.0.1:9",
        &[
            "first secret_1234 helper_1234 low_1234 rejected_1234\n",
            "second secret_1234 helper_1234 low_1234 rejected_1234\n",
        ],
        true,
    );
    for (no_dedup, include_hidden, occurrences, reported) in
        [(false, false, 2, 1), (true, false, 2, 2), (false, true, 4, 3)]
    {
        let mut command = fixture.command();
        command.args(["--no-validate", "--quiet"]);
        if no_dedup {
            command.arg("--no-dedup");
        }
        if include_hidden {
            command.arg("--include-hidden-findings");
        }
        let output = command.output().unwrap();
        let report = report(&output);
        assert_eq!(report["findings"].as_array().unwrap().len(), reported);
        let progress = fixture.snapshot();
        assert_eq!(progress["findings"], occurrences);
        assert_eq!(progress["blobs"], 2);
        assert_eq!(progress["completed"], 0);
        // The scan-wide guard must stay alive through reporting, not just matching.
        assert_eq!(progress["phase"], "Writing report");
        assert_eq!(progress["kind"], "other");
        // Quiet machine-readable stdout remains one complete JSON document.
        serde_json::from_slice::<Value>(&output.stdout).unwrap();
    }
}

#[test]
fn identical_blobs_still_contribute_reportable_observations() {
    let fixture = Fixture::new(
        "http://127.0.0.1:9",
        &["secret_1234 helper_1234\n", "secret_1234 helper_1234\n"],
        true,
    );
    for (no_dedup, reported) in [(false, 1), (true, 2)] {
        let mut command = fixture.command();
        command.args(["--no-validate", "--quiet"]);
        if no_dedup {
            command.arg("--no-dedup");
        }
        let output = command.output().unwrap();
        assert_eq!(report(&output)["findings"].as_array().unwrap().len(), reported);
        let snapshot = fixture.snapshot();
        assert_eq!(snapshot["findings"], 2);
        assert_eq!(snapshot["blobs"], 2);
    }
}

#[test]
fn pdf_raw_and_extracted_representations_do_not_inflate_occurrences() {
    let fixture = Fixture::new("http://127.0.0.1:9", &[], false);
    fs::write(
        &fixture.rules,
        "rules:\n  - id: acme.progress.pdf\n    name: PDF token\n    pattern: '(demo_[a-z0-9]{16})'\n    min_entropy: 0\n    confidence: high\n",
    )
    .unwrap();
    let encoded: String =
        include_str!("../crates/kingfisher-scanner/src/extraction/testdata/pages.pdf.hex")
            .split_whitespace()
            .collect();
    let mut pdf = hex::decode(encoded).unwrap();
    // Preserve stream length/xref offsets while exposing page 1 in both raw bytes
    // and extracted text. Page 2 remains extraction-only; metadata is raw-only.
    let start = pdf.windows(7).position(|bytes| bytes == b"stream\n").unwrap() + 7;
    let end = start + pdf[start..].windows(9).position(|bytes| bytes == b"endstream").unwrap();
    pdf[start..end].fill(b' ');
    let content = b"BT /F1 12 Tf (demo_abcd1234efgh5678) Tj ET\n";
    pdf[start..start + content.len()].copy_from_slice(content);
    pdf[end - 1] = b'\n';
    pdf.extend_from_slice(b"\n% metadata-only demo_deadbeef12345678\n");
    for name in ["first.pdf", "second.pdf"] {
        fs::write(fixture.inputs.join(name), &pdf).unwrap();
    }
    for (no_dedup, reported) in [(false, 3), (true, 6)] {
        let mut command = fixture.command();
        command.args(["--no-validate", "--quiet"]);
        if no_dedup {
            command.arg("--no-dedup");
        }
        let output = command.output().unwrap();
        assert_eq!(report(&output)["findings"].as_array().unwrap().len(), reported);
        assert_eq!(fixture.snapshot()["findings"], 6);
    }
}

#[test]
fn duplicate_pdf_pages_do_not_change_reports_when_progress_is_enabled() {
    // Duplicate page observations must not consume raw storage suppression counts.
    let token = "demo_abcd1234efgh5678";
    let mut objects = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [4 0 R 6 0 R 8 0 R] /Count 3 >>".to_owned(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
    ];
    for text in [token.to_owned(), token.to_owned(), format!("prefix {token}")] {
        let page = objects.len() + 1;
        objects.push(format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>", page + 1));
        let stream = format!("BT /F1 12 Tf 72 720 Td <{}> Tj ET\n", hex::encode(text));
        objects.push(format!("<< /Length {} >>\nstream\n{stream}endstream", stream.len()));
    }
    let mut pdf = format!("%PDF-1.4\n% {token}\n% {token}\n");
    let mut offsets = vec![0];
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{object}\nendobj\n", index + 1));
    }
    let xref = pdf.len();
    pdf.push_str(&format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len()));
    for offset in &offsets[1..] {
        pdf.push_str(&format!("{offset:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        offsets.len()
    ));

    let fixture = Fixture::new("http://127.0.0.1:9", &[], false);
    fs::write(
        &fixture.rules,
        "rules:\n  - id: acme.progress.pdf\n    name: PDF token\n    pattern: '(demo_[a-z0-9]{16})'\n    min_entropy: 0\n    confidence: high\n",
    )
    .unwrap();
    fs::write(fixture.inputs.join("duplicate-pages.pdf"), pdf).unwrap();
    let scan = |progress: bool| {
        let mut command = fixture.command();
        command.arg("--no-validate");
        if !progress {
            command.env_remove("KINGFISHER_PROGRESS_FILE");
        }
        report(&command.output().unwrap())
    };
    let without_progress = scan(false);
    let with_progress = scan(true);
    assert!(!with_progress["findings"].as_array().unwrap().is_empty());
    assert_eq!(with_progress["findings"], without_progress["findings"]);
    assert_eq!(fixture.snapshot()["blobs"], 4, "raw PDF and all three pages were observed");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_progress_does_not_interleave_with_stdout_json_reports() {
    use std::{
        fs::File,
        io::Read,
        os::fd::{AsRawFd, FromRawFd},
        process::Stdio,
    };

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/validate"))
        // Ensure the renderer ticks before reporting, even on fast machines.
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(350)))
        .mount(&server)
        .await;
    let content = "secret_1234 helper_1234\n".repeat(2_000);
    let fixture = Fixture::new(&server.uri(), &[&content], false);
    let (mut master, mut slave) = (-1, -1);
    // Match an interactive shell: stdout and stderr share a terminal.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    let mut master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        assert_ne!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) }, -1);
    }
    let mut command = fixture.command();
    command
        .env("TERM", "xterm-256color")
        .env_remove("KINGFISHER_PROGRESS_FILE")
        .arg("--no-dedup")
        .stdin(Stdio::null())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    let mut child = command.spawn().unwrap();
    drop(command);
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => output.extend_from_slice(&buffer[..count]),
                // Linux signals PTY slave closure with EIO; macOS returns EOF.
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("reading terminal: {error}"),
            }
        }
        output
    });
    let status = child.wait().unwrap();
    let output = reader.join().unwrap();
    assert!(matches!(status.code(), Some(200 | 205)), "{}", String::from_utf8_lossy(&output));
    let start =
        output.iter().position(|&byte| byte == b'{').expect("JSON report in terminal output");
    assert!(output[..start].contains(&0x1b), "fixture must render terminal progress");
    let mut documents = serde_json::Deserializer::from_slice(&output[start..]).into_iter::<Value>();
    let report =
        documents.next().unwrap().expect("terminal control sequences must not interrupt JSON");
    assert_eq!(report["findings"].as_array().unwrap().len(), 2_000);
    let report_end = start + documents.byte_offset();
    assert!(
        !output[report_end..].contains(&0x1b),
        "terminal progress must finish before the report"
    );
}

#[tokio::test]
async fn dependent_validation_advances_findings_before_the_blob_finishes() {
    let server = MockServer::start().await;
    for (token, delay) in [("secret_1234", 50), ("secret_5678", 2000)] {
        Mock::given(method("GET"))
            .and(path("/validate"))
            .and(header("Authorization", format!("Bearer {token}")))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(delay)))
            .expect(1)
            .mount(&server)
            .await;
    }
    let fixture = Fixture::new(
        &server.uri(),
        &["secret_1234 secret_5678 helper_1234 low_1234 rejected_1234\n"],
        true,
    );
    let mut command = tokio::process::Command::from(fixture.command());
    command.kill_on_drop(true).stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command.spawn().unwrap();
    // The delayed second check keeps one blob in flight long enough for a live
    // snapshot. Hidden helpers and filtered candidates must not enter either total.
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(bytes) = fs::read(&fixture.progress)
                && let Ok(snapshot) = serde_json::from_slice::<Value>(&bytes)
                && snapshot["kind"] == "validation"
                && snapshot["completed"] == 1
            {
                assert_eq!(snapshot["total"], 2);
                assert_eq!(snapshot["findings"], 2);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("no live per-finding validation snapshot");
    let output = child.wait_with_output().await.unwrap();
    assert_eq!(report(&output)["findings"].as_array().unwrap().len(), 2);
    let progress = fixture.snapshot();
    assert_eq!(progress["completed"], 2);
    assert_eq!(progress["total"], 2);
    assert_eq!(progress["findings"], 2);
    assert_eq!(progress["phase"], "Writing report");
    assert_eq!(progress["kind"], "other");
}

#[tokio::test]
async fn baseline_suppression_preserves_reportable_validation_counts() {
    for dependent in [false, true] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(4)
            .mount(&server)
            .await;
        // Both occurrences share a validation group, but baseline visibility belongs
        // to each stored occurrence, not to the rule or the group's representative.
        let fixture =
            Fixture::new(&server.uri(), &["secret_1234\nsecret_1234\nhelper_1234\n"], dependent);
        let baseline_path = fixture._root.path().join("baseline.yml");
        let mut command = tokio::process::Command::from(fixture.command());
        command
            .args(["--no-validate", "--no-dedup", "--quiet", "--manage-baseline"])
            .arg("--baseline-file")
            .arg(&baseline_path);
        assert_eq!(
            report(&command.output().await.unwrap())["findings"].as_array().unwrap().len(),
            2
        );
        let baseline = kingfisher::baseline::load_baseline(&baseline_path).unwrap();
        for suppressed in [1, 2] {
            let mut baseline = baseline.clone();
            for repository in &mut baseline.repositories {
                repository.findings.retain(|finding| {
                    finding.rule_id == "acme.progress.secret" && finding.line <= suppressed
                });
            }
            kingfisher::baseline::save_baseline(&baseline_path, &baseline).unwrap();
            for include_hidden in [false, true] {
                let mut command = tokio::process::Command::from(fixture.command());
                command.args(["--no-dedup", "--quiet", "--baseline-file"]).arg(&baseline_path);
                if include_hidden {
                    command.arg("--include-hidden-findings");
                }
                let output = command.output().await.unwrap();
                assert!(
                    matches!(output.status.code(), Some(0 | 200 | 205)),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let expected = if include_hidden { 3 } else { 2 - suppressed };
                let report: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(report["findings"].as_array().unwrap().len(), expected);
                let progress = fixture.snapshot();
                assert_eq!(progress["total"], expected);
                assert_eq!(
                    progress["completed"], expected,
                    "dependent={dependent}, suppressed={suppressed}, include_hidden={include_hidden}"
                );
            }
        }
    }
}

#[tokio::test]
async fn simple_validation_groups_advance_all_reportable_occurrences() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let fixture = Fixture::new(
        &server.uri(),
        &["first secret_1234 helper_1234\n", "second secret_1234 helper_1234\n"],
        false,
    );
    let mut command = tokio::process::Command::from(fixture.command());
    command.args(["--no-dedup", "--quiet"]);
    let output = command.output().await.unwrap();
    assert_eq!(report(&output)["findings"].as_array().unwrap().len(), 2);
    let progress = fixture.snapshot();
    assert_eq!(progress["findings"], 2);
    assert_eq!(progress["completed"], 2);
    assert_eq!(progress["total"], 2);
}
