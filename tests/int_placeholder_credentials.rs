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
