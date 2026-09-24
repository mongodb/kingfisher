//! Resolve crowded AWS environment dumps using explicit assignment names.
use std::fs;

use serde_json::Value;
use tempfile::TempDir;

const KEY: &str = "AKIAQWERTYUIOPASDFGH";
const SECRET: &str = "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";
const OTHER: &str = "iS/1zHZaYbHWNgX+lmb53lEp33DHIuGFx8n3rZ/M";

fn scan(input: &str) -> Value {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("env.log");
    fs::write(&path, input).unwrap();
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["--no-update-check", "scan"])
        .arg(path)
        .args(["--rule", "betterleaks.aws-access-token", "--no-validate", "--format", "json"])
        .output()
        .unwrap();
    serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .next()
        .expect("JSON report")
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)))
}

#[test]
fn crowded_env_dump_keeps_ranked_contexts_unresolved_without_validation() {
    let input = format!(
        "Env=[backup_aws_secret={OTHER} kms_aws_key={KEY} e2e_aws_key={KEY} \
         kms_aws_secret={SECRET} KMS_AWS_KEY={KEY} e2e_aws_secret={OTHER} \
         mongodb_agent_online_archive_test_aws_access_key={KEY} \
         mongodb_agent_online_archive_test_aws_secret_key={SECRET} ]"
    );
    let report = scan(&input);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{report}");
    for finding in findings {
        let finding = &finding["finding"];
        assert_eq!(finding["ambiguous_dependencies"]["AWS_SECRET_ACCESS_KEY"], 2, "{report}");
        assert!(finding.get("dependent_captures").is_none(), "{report}");
        assert!(finding.get("dependency_candidates").is_none(), "{report}");
    }
}

#[test]
fn conflicting_names_and_unnamed_keys_remain_ambiguous() {
    for input in [
        format!("kms_aws_key={KEY} kms_aws_secret={SECRET} KMS_AWS_SECRET={OTHER}"),
        format!("{KEY} kms_aws_secret={SECRET} e2e_aws_secret={OTHER}"),
        format!("backup_aws_key={KEY} kms_aws_secret={SECRET} e2e_aws_secret={OTHER}"),
        format!("test_kms_aws_key={KEY} kms_aws_secret={SECRET} e2e_aws_secret={OTHER}"),
    ] {
        let report = scan(&input);
        let finding = &report["findings"][0]["finding"];
        assert_eq!(finding["ambiguous_dependencies"]["AWS_SECRET_ACCESS_KEY"], 2, "{report}");
        assert!(finding["dependent_captures"]["AWS_SECRET_ACCESS_KEY"].is_null(), "{report}");
    }
}

#[test]
fn named_pair_must_still_be_inside_the_dependency_window() {
    let report = scan(&format!("kms_aws_secret={SECRET}\n\n\n\n\n\n\nkms_aws_key={KEY}"));
    assert!(report["findings"].as_array().unwrap().is_empty(), "{report}");
}
