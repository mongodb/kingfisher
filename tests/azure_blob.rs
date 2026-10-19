use std::fs;

use anyhow::Result;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, path, query_param},
};

#[tokio::test(flavor = "multi_thread")]
async fn scans_container_with_filters_and_reuses_cached_content_in_full_reports() -> Result<()> {
    let server = MockServer::start().await;
    let root = tempfile::tempdir()?;
    let rules = root.path().join("rules.yml");
    let cache = root.path().join("cache");
    fs::write(
        &rules,
        "rules:\n  - id: acme.azure-blob\n    name: Blob fixture\n    pattern: '(acme_[A-Za-z0-9]{16})'\n    min_entropy: 0\n    confidence: high\n",
    )?;
    let xml = "<EnumerationResults><Blobs><Blob><Name>configs/key.env</Name><Properties><Etag>&quot;v1&quot;</Etag><Content-Length>21</Content-Length></Properties></Blob><Blob><Name>configs/generated/skipped.env</Name><Properties><Etag>&quot;v1&quot;</Etag></Properties></Blob><Blob><Name>configs/skip.yaml</Name><Properties><Etag>&quot;v1&quot;</Etag></Properties></Blob></Blobs><NextMarker /></EnumerationResults>";
    Mock::given(path("/container"))
        .and(query_param("comp", "list"))
        .and(query_param("prefix", "configs/"))
        .and(query_param("sig", "test-sas"))
        .respond_with(ResponseTemplate::new(200).set_body_string(xml))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(path("/container/configs/key.env"))
        .and(query_param("sig", "test-sas"))
        .and(header("if-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(200).set_body_string("acme_A1b2C3d4E5f6G7h8"))
        .expect(1)
        .mount(&server)
        .await;
    let container = format!("{}/container", server.uri());
    let expected_origin = format!("{container}/configs/key.env");
    let outputs = tokio::task::spawn_blocking(move || {
        let mut outputs = Vec::new();
        for _ in 0..2 {
            let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
            command
                .args(["scan", "azure-blob", &container])
                .arg("--rules-path")
                .arg(&rules)
                .arg("--object-cache-dir")
                .arg(&cache)
                .args([
                    "--load-builtins=false",
                    "--no-validate",
                    "--no-update-check",
                    "--format",
                    "json",
                    "--path-prefix",
                    "configs/",
                    "--skip-path-prefix",
                    "configs/generated/",
                    "--file-extension",
                    "env",
                ])
                .env("KF_AZURE_STORAGE_SAS", "sp=rl&sig=test-sas")
                .env_remove("KF_AZURE_STORAGE_KEY")
                .env_remove("KF_AZURE_STORAGE_TOKEN");
            let output = command.assert().code(200).get_output().clone();
            outputs.push((
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap(),
            ));
        }
        outputs
    })
    .await?;
    for (stdout, stderr) in outputs {
        assert!(stdout.contains("acme_A1b2C3d4E5f6G7h8"));
        assert!(stdout.contains(&expected_origin));
        assert!(!stdout.contains("skipped.env"));
        assert!(!stdout.contains("test-sas"));
        assert!(!stderr.contains("test-sas"));
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
    Ok(())
}
