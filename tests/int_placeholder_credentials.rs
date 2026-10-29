//! Placeholder credentials are excluded before live validation.
use std::fs;

#[test]
fn excludes_short_private_keys_and_unresolved_mongodb_passwords() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("fixtures.txt");
    fs::write(
        &input,
        r#"-----BEGIN PRIVATE KEY-----
PRIVATE_KEY
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----\\n"
              + "PRIVATE_KEY\\n"
              + "-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----\\n"
              + privateKeyEncoded
              + "\\n"
              + "-----END PRIVATE KEY-----
mongodb+srv://$(AWS_ACCESS_KEY_ID):$(AWS_SECRET_ACCESS_KEY)@ia-staging-metering-pl-0.nrs6h.mongo.com/mmsdbmetering
mongodb://$(MONGODB_USERNAME):$(MONGODB_PASSWORD)@dev-metering-host:27017/mmsdbmetering?authSource=admin
mongodb://$(MONGODB_USERNAME):$(MONGODB_PASSWORD)@dev-cloud-providers-host:27017/mmsdbcloudproviders?authSource=admin
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g
-----END PRIVATE KEY-----
mongodb://service-user:r4nd0mLiteralSecret@cluster.internal/app
"#,
    )
    .unwrap();
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["--no-update-check", "scan"])
        .arg(&input)
        .args([
            "--rule",
            "betterleaks.private-key",
            "--rule",
            "betterleaks.mongodb-connection-string",
            "--no-validate",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter()
        .next()
        .expect("JSON report")
        .unwrap_or_else(|err| panic!("{err}: {}", String::from_utf8_lossy(&output.stderr)));
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{report}");
    assert!(
        findings
            .iter()
            .any(|record| record["finding"]["snippet"].as_str().unwrap().contains("MC4CAQ"))
    );
    assert!(findings.iter().any(|record| {
        record["finding"]["snippet"].as_str().unwrap().contains("r4nd0mLiteralSecret")
    }));
}

#[test]
fn excludes_ini_private_key_fixtures_without_losing_the_following_key() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("ini_test.go");
    let fake = "-----BEGIN RSA PRIVATE KEY-----\n  foo\n  bar\n  foobar\n  barfoo\n  -----END RSA PRIVATE KEY-----";
    let numbered = (1..=96)
        .map(|index| format!("   {index}{}\n", ["foo", "bar", "foobar", "barfoo"][(index - 1) % 4]))
        .collect::<String>();
    // The final container is synthetic; only its PKCS#8 structure is relevant.
    let content = format!(
        "{fake}\nmultiline_list =\n  first\n  second\n  third\n`))\nrequire.NoError(t, err)\nassert.Equal(t, \"{fake}\")\n-----BEGIN RSA PRIVATE KEY-----\n{numbered}-----END RSA PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g\n-----END PRIVATE KEY-----\n"
    );
    fs::write(&input, content).unwrap();
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["--no-update-check", "scan"])
        .arg(&input)
        .args(["--rule", "betterleaks.private-key", "--no-validate", "--format", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter()
        .next()
        .expect("JSON report")
        .unwrap_or_else(|err| panic!("{err}: {}", String::from_utf8_lossy(&output.stderr)));
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{report}");
    let snippet = findings[0]["finding"]["snippet"].as_str().unwrap();
    assert!(snippet.starts_with("-----BEGIN PRIVATE KEY-----"), "{snippet}");
    assert!(snippet.contains("MC4CAQ"), "{snippet}");
    assert!(snippet.ends_with("-----END PRIVATE KEY-----"), "{snippet}");
    assert!(!snippet.contains("foo"), "{snippet}");
    assert!(!snippet.contains("assert.Equal"), "{snippet}");
}

#[test]
fn excludes_java_private_key_placeholders_without_losing_the_following_key() {
    for newline in ["\n", "\r\n"] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("PrivateKeyExamples.java");
        // This public test seed produces a structurally valid Ed25519 PKCS#8 container.
        let key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g\n-----END PRIVATE KEY-----";
        let identifier = "notEncodedKeyMaterial".repeat(64);
        let content = format!(
            r#"class PrivateKeyExamples {{
    static final String REDACTED = "-----BEGIN PRIVATE KEY-----\n<redacted>\n-----END PRIVATE KEY-----";
    static final String ABSENT = "-----BEGIN PRIVATE KEY-----\n<<payload deliberately unavailable>>\n-----END PRIVATE KEY-----";
    static String removeEnvelope(String pem) {{
        return pem.replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "");
    }}
    static String removeRsaEnvelope(String pem) {{
        return pem.replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
            .replaceAll("-----END RSA PRIVATE KEY-----", "");
    }}
    static final String RUNTIME = "-----BEGIN EC PRIVATE KEY-----\n" + loadSomething() + "\n-----END EC PRIVATE KEY-----";
    static final String IDENTIFIER = "-----BEGIN DSA PRIVATE KEY-----\n" + {identifier} + "\n-----END DSA PRIVATE KEY-----";
    static final String GARBAGE = """
-----BEGIN ENCRYPTED PRIVATE KEY-----
QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=
-----END ENCRYPTED PRIVATE KEY-----
""";
    // DER sequence with an integer whose declared length exceeds its value.
    static final String MALFORMED = """
-----BEGIN PRIVATE KEY-----
MAMCAgA=
-----END PRIVATE KEY-----
""";
    static final String ACTUAL = """
{key}
""";
}}
"#
        )
        .replace('\n', newline);
        let expected = key.replace('\n', newline);
        let start = content.find(&expected).unwrap();
        let line = content[..start].bytes().filter(|byte| *byte == b'\n').count() + 1;
        fs::write(&input, &content).unwrap();
        let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["--no-update-check", "scan"])
            .arg(&input)
            .args(["--rule", "betterleaks.private-key", "--no-validate", "--format", "json"])
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::Deserializer::from_slice(&output.stdout)
            .into_iter()
            .next()
            .expect("JSON report")
            .unwrap_or_else(|err| panic!("{err}: {}", String::from_utf8_lossy(&output.stderr)));
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1, "{report}");
        let finding = &findings[0]["finding"];
        assert_eq!(finding["snippet"].as_str().unwrap(), expected, "{report}");
        assert_eq!(finding["line"].as_u64().unwrap(), line as u64, "{report}");
        assert_eq!(finding["column_start"], 0, "{report}");
        assert_eq!(finding["column_end"], "-----END PRIVATE KEY-----".len() - 1, "{report}");
    }
}
