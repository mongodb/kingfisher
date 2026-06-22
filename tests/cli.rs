use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};
use serde_json::Value;
use std::fs;
use tempfile::tempdir;

mod test {

    use super::*;

    fn write_fake_cache_entry(cache_dir: &std::path::Path, cache_key: &str) {
        let header = serde_json::json!({
            "format_version": 1,
            "cache_key": cache_key,
            "rule_count": 1,
            "vectorscan_version": "test",
            "target": "test",
            "database_kind": "block",
        });
        let header_bytes = serde_json::to_vec(&header).expect("header should serialize");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"KFRULEDB");
        bytes.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(b"not-a-real-vectorscan-db");
        fs::write(cache_dir.join(format!("{cache_key}.vscdb")), bytes)
            .expect("cache entry should be written");
    }

    #[test]
    fn cli_lists_rules_pretty() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["rules", "list", "--format", "pretty", "--no-update-check"])
            .assert()
            .success()
            .stdout(contains("kingfisher.aws.").and(contains("Pattern")));
    }
    #[test]
    fn cli_lists_rules_json() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["rules", "list", "--format", "json", "--no-update-check"])
            .assert()
            .success()
            .stdout(contains("kingfisher.aws.").and(contains("pattern")));
    }

    #[test]
    fn cli_version_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("--version")
            .assert()
            .success()
            .stdout(contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn cli_scan_generates_html_audit_report() {
        let temp = tempdir().expect("tempdir should be created");
        let input_dir = temp.path().join("repo");
        let output_html = temp.path().join("audit-report.html");
        fs::create_dir_all(&input_dir).expect("input directory should be created");
        fs::write(input_dir.join("README.txt"), "no credentials here")
            .expect("seed file should be written");

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                input_dir.to_str().unwrap(),
                "--format",
                "html",
                "--output",
                output_html.to_str().unwrap(),
                "--rule",
                "kingfisher.aws.1",
                "--no-validate",
                "--no-update-check",
            ])
            .assert()
            .success();

        let html = fs::read_to_string(&output_html).expect("html report should be written");
        assert!(html.contains("Kingfisher Audit Report"));
        assert!(html.contains("Scan Summary"));
    }

    #[test]
    fn cli_scan_generates_toon_report_for_llms() {
        let temp = tempdir().expect("tempdir should be created");
        let rules_dir = temp.path().join("rules");
        let input_dir = temp.path().join("repo");
        let output_toon = temp.path().join("findings.toon");

        fs::create_dir_all(&rules_dir).expect("rules directory should be created");
        fs::create_dir_all(&input_dir).expect("input directory should be created");
        fs::write(
            rules_dir.join("demo.yml"),
            r#"
rules:
  - id: kingfisher.demo.1
    name: Demo secret
    pattern: '(demo_secret_[0-9]{4})'
    confidence: medium
"#,
        )
        .expect("rule should be written");
        fs::write(input_dir.join("README.txt"), "demo_secret_1234")
            .expect("seed file should be written");

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                input_dir.to_str().unwrap(),
                "--format",
                "toon",
                "--output",
                output_toon.to_str().unwrap(),
                "--rules-path",
                rules_dir.to_str().unwrap(),
                "--load-builtins=false",
                "--no-validate",
                "--no-update-check",
            ])
            .assert()
            .code(200);

        let toon = fs::read_to_string(&output_toon).expect("toon report should be written");
        let decoded: Value = toon_format::decode_default(&toon).expect("toon should decode");
        assert_eq!(decoded["schema"], "kingfisher.toon.v1");
        assert_eq!(decoded["scan"]["summary"]["findings"], 1);
        assert_eq!(decoded["findings"][0]["rule_id"], "kingfisher.demo.1");
        assert_eq!(decoded["findings"][0]["validation_status"], "Not Attempted");
    }

    #[test]
    fn cli_rule_cache_refreshes_when_external_rules_path_changes() {
        let temp = tempdir().expect("tempdir should be created");
        let rules_dir = temp.path().join("rules");
        let input_dir = temp.path().join("repo");
        let cache_dir = temp.path().join("rule-cache");
        let first_output = temp.path().join("first.toon");
        let second_output = temp.path().join("second.toon");

        fs::create_dir_all(&rules_dir).expect("rules directory should be created");
        fs::create_dir_all(&input_dir).expect("input directory should be created");
        fs::write(input_dir.join("README.txt"), "demo_secret_1234\ndemo_secret_abcd\n")
            .expect("seed file should be written");

        let rule_file = rules_dir.join("demo.yml");
        fs::write(
            &rule_file,
            r#"
rules:
  - id: kingfisher.demo.1
    name: Demo secret
    pattern: '(demo_secret_[0-9]{4})'
    confidence: medium
"#,
        )
        .expect("initial rule should be written");

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                input_dir.to_str().unwrap(),
                "--format",
                "toon",
                "--output",
                first_output.to_str().unwrap(),
                "--rules-path",
                rules_dir.to_str().unwrap(),
                "--load-builtins=false",
                "--rule-cache-dir",
                cache_dir.to_str().unwrap(),
                "--no-validate",
                "--no-update-check",
            ])
            .assert()
            .code(200);

        let first_toon = fs::read_to_string(&first_output).expect("first toon should be written");
        let first_decoded: Value =
            toon_format::decode_default(&first_toon).expect("first toon should decode");
        assert_eq!(first_decoded["scan"]["summary"]["findings"], 1);
        assert_eq!(first_decoded["findings"][0]["snippet"], "demo_secret_1234");
        assert_eq!(fs::read_dir(&cache_dir).expect("cache dir should exist").count(), 1);

        fs::write(
            &rule_file,
            r#"
rules:
  - id: kingfisher.demo.1
    name: Demo secret
    pattern: '(demo_secret_[a-z]{4})'
    confidence: medium
"#,
        )
        .expect("updated rule should be written");

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                input_dir.to_str().unwrap(),
                "--format",
                "toon",
                "--output",
                second_output.to_str().unwrap(),
                "--rules-path",
                rules_dir.to_str().unwrap(),
                "--load-builtins=false",
                "--rule-cache-dir",
                cache_dir.to_str().unwrap(),
                "--no-validate",
                "--no-update-check",
            ])
            .assert()
            .code(200);

        let second_toon =
            fs::read_to_string(&second_output).expect("second toon should be written");
        let second_decoded: Value =
            toon_format::decode_default(&second_toon).expect("second toon should decode");
        assert_eq!(second_decoded["scan"]["summary"]["findings"], 1);
        assert_eq!(second_decoded["findings"][0]["snippet"], "demo_secret_abcd");
        assert_eq!(fs::read_dir(&cache_dir).expect("cache dir should exist").count(), 2);
    }

    #[test]
    fn cli_rules_prune_cache_dry_run_does_not_delete_candidates() {
        let temp = tempdir().expect("tempdir should be created");
        let cache_dir = temp.path().join("rule-cache");
        fs::create_dir_all(&cache_dir).expect("cache dir should be created");
        for index in 0..12 {
            write_fake_cache_entry(&cache_dir, &format!("entry-{index:02}"));
        }

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "rules",
                "prune-cache",
                "--rule-cache-dir",
                cache_dir.to_str().unwrap(),
                "--rule-cache-max-entries",
                "10",
                "--rule-cache-max-age",
                "0s",
                "--dry-run",
                "--no-update-check",
            ])
            .assert()
            .success()
            .stdout(contains("would remove 2 entries"));

        assert_eq!(fs::read_dir(&cache_dir).expect("cache dir should exist").count(), 12);
    }

    #[test]
    fn cli_scan_prune_rule_cache_removes_old_excess_entries() {
        let temp = tempdir().expect("tempdir should be created");
        let rules_dir = temp.path().join("rules");
        let input_dir = temp.path().join("repo");
        let cache_dir = temp.path().join("rule-cache");
        let output_toon = temp.path().join("findings.toon");

        fs::create_dir_all(&rules_dir).expect("rules directory should be created");
        fs::create_dir_all(&input_dir).expect("input directory should be created");
        fs::create_dir_all(&cache_dir).expect("cache dir should be created");
        fs::write(input_dir.join("README.txt"), "demo_secret_1234\n")
            .expect("seed file should be written");
        fs::write(
            rules_dir.join("demo.yml"),
            r#"
rules:
  - id: kingfisher.demo.1
    name: Demo secret
    pattern: '(demo_secret_[0-9]{4})'
    confidence: medium
"#,
        )
        .expect("rule should be written");
        for index in 0..12 {
            write_fake_cache_entry(&cache_dir, &format!("entry-{index:02}"));
        }

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "scan",
                input_dir.to_str().unwrap(),
                "--format",
                "toon",
                "--output",
                output_toon.to_str().unwrap(),
                "--rules-path",
                rules_dir.to_str().unwrap(),
                "--load-builtins=false",
                "--rule-cache-dir",
                cache_dir.to_str().unwrap(),
                "--prune-rule-cache",
                "--rule-cache-max-entries",
                "10",
                "--rule-cache-max-age",
                "0s",
                "--no-validate",
                "--no-update-check",
            ])
            .assert()
            .code(200);

        assert_eq!(fs::read_dir(&cache_dir).expect("cache dir should exist").count(), 11);
    }
}
