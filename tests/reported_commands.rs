//! Exercise reported commands through scanning, serialization, shell parsing, and the CLI.
//! All credentials are synthetic and every provider request stays on a loopback mock.
use std::{collections::BTreeMap, fs, path::PathBuf};

use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::process::Command;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const TOKEN: &str = "svc_Q7m2V9r4xR4vN8kT' $(literal); \"end\"\\tail";
const HELPER: &str = "acct_N8kT5pL2 O'Reilly $HOME\\realm";
const PRIMARY_CAPTURE: &str = "Q7m2V9r4xR4vN8kT";
const COMPONENT_CAPTURE: &str = "N8kT5pL2";
const FORMATS: [&str; 4] = ["json", "jsonl", "toon", "pretty"];

struct Fixture {
    directory: TempDir,
    rules: PathBuf,
    input: PathBuf,
}

impl Fixture {
    fn new(origin: &str, extension: &str, captures: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        // Apostrophes and spaces must survive the generated POSIX quoting on every OS.
        let rules = directory.path().join(format!("team's rules.{extension}"));
        let input = directory.path().join("input.txt");
        let primary_pattern = r"(svc_(?P<MixedCase>[A-Za-z0-9]{16})[^\r\n]*)";
        let helper_pattern = r"(acct_(?P<Realm>[A-Za-z0-9]{8})[^\r\n]*)";
        let program = |operation: &str, endpoint: &str, status: u16, result: &str| {
            let context = if captures {
                r#", "X-Primary-Capture": finding.captures.MixedCase,
                    "X-Component-Capture": components["helper"].captures.Realm,
                    "X-Rule": finding.rule_id"#
            } else {
                ""
            };
            format!(
                r#"let r = http.{operation}("{origin}/{endpoint}", {{
                    "Authorization": "Bearer " + finding.secret,
                    "X-Helper": components["helper"].secret{context}
                }});
                r.status == {status} ? {{result: "{result}"}} : {{result: "invalid"}}"#
            )
        };
        let validate = program("get", "identity", 200, "valid");
        let revoke = program("delete", "token", 204, "revoked");
        let contents = if extension == "toml" {
            format!(
                r#"[[rules]]
id = 'credential'
description = 'Synthetic credential'
regex = '''{primary_pattern}'''
secretGroup = 1
components = [{{id = 'helper', within = '3L'}}]
validate = '''{validate}'''
revoke = '''{revoke}'''
[[rules]]
id = 'helper'
regex = '''{helper_pattern}'''
secretGroup = 1
skipReport = true
"#
            )
        } else {
            // JSON is valid YAML and avoids hand-escaping the Expr source or regexes.
            json!({"rules": [
                {"id":"custom.credential", "name":"Synthetic credential",
                 "pattern":primary_pattern, "betterleaks_secret_group":1,
                 "depends_on_rule":[{"rule_id":"custom.helper", "variable":"HELPER", "within":"3L"}],
                 "validation":{"type":"Betterleaks", "content":{
                    "expression":validate, "components":{"helper":"HELPER"}}},
                 "revocation":{"type":"Betterleaks", "content":{
                    "expression":revoke, "components":{"helper":"HELPER"}}}},
                {"id":"custom.helper", "name":"Synthetic component",
                 "pattern":helper_pattern, "betterleaks_secret_group":1, "visible":false}
            ]})
            .to_string()
        };
        fs::write(&rules, contents).unwrap();
        fs::write(&input, format!("{TOKEN}\n{HELPER}\n")).unwrap();
        Self { directory, rules, input }
    }

    async fn scan(&self, format: &str) -> (Option<String>, Option<String>) {
        let report = self.directory.path().join(format!("report.{format}"));
        let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["--no-update-check", "--allow-internal-ips", "scan"])
            .arg(&self.input)
            .args(["--git-history=none", "--load-builtins=false", "--no-rule-cache"])
            .arg("--rules-path")
            .arg(&self.rules)
            .args(["--format", format, "--output"])
            .arg(&report)
            .env("NO_COLOR", "1")
            .env("NO_PROXY", "*")
            .env("no_proxy", "*")
            .output()
            .await
            .unwrap();
        assert_eq!(output.status.code(), Some(205), "{}", String::from_utf8_lossy(&output.stderr));
        let text = fs::read_to_string(report).unwrap();
        if format == "pretty" {
            let field = |label: &str| {
                text.lines()
                    .find_map(|line| line.trim_start().strip_prefix(label))
                    .map(str::to_owned)
            };
            return (field("|Validate Cmd....: "), field("|Revoke Cmd......: "));
        }
        let report: Value = if format == "toon" {
            toon_format::decode_default(&text).unwrap()
        } else {
            let documents: Vec<Value> = serde_json::Deserializer::from_str(&text)
                .into_iter()
                .collect::<Result<_, _>>()
                .unwrap();
            if format == "jsonl" {
                Value::Array(documents)
            } else {
                documents.into_iter().find(|document| document["findings"].is_array()).unwrap()
            }
        };
        let records = if format == "jsonl" { &report } else { &report["findings"] };
        let matches: Vec<_> = records
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| {
                if format == "toon" {
                    record["rule_id"] == "custom.credential"
                } else {
                    record["rule"]["id"] == "custom.credential"
                }
            })
            .collect();
        assert_eq!(matches.len(), 1, "{format}: {text}");
        let finding = if format == "toon" { matches[0] } else { &matches[0]["finding"] };
        (
            finding["validate_command"].as_str().map(str::to_owned),
            finding["revoke_command"].as_str().map(str::to_owned),
        )
    }

    fn command_args(&self, command: &str, operation: &str, captures: bool) -> Vec<String> {
        // Parse with an independent POSIX lexer; never execute the text in a shell.
        let args = shlex::split(command).expect("reported command must have valid shell quoting");
        let vars: BTreeMap<_, _> = args
            .windows(2)
            .filter(|pair| pair[0] == "--var")
            .map(|pair| pair[1].split_once('=').expect("NAME=VALUE"))
            .collect();
        let mut expected_vars = vec!["HELPER"];
        if captures {
            expected_vars.extend([
                "__BETTERLEAKS_COMPONENTS",
                "__BETTERLEAKS_FINDING_CAPTURES",
                "__BETTERLEAKS_RULE_ID",
            ]);
            let primary: Value =
                serde_json::from_str(vars["__BETTERLEAKS_FINDING_CAPTURES"]).unwrap();
            let components: Value = serde_json::from_str(vars["__BETTERLEAKS_COMPONENTS"]).unwrap();
            assert_eq!(primary["MixedCase"], PRIMARY_CAPTURE);
            assert_eq!(components["custom.helper"]["captures"]["Realm"], COMPONENT_CAPTURE);
            assert_eq!(vars["__BETTERLEAKS_RULE_ID"], "custom.credential");
        } else {
            assert!(!command.contains("__BETTERLEAKS_"), "{command}");
        }
        // These fixed strings also reject double-quoting that would let a shell
        // expand dollar signs even though a lexical parser preserves them.
        assert!(
            command.contains(r#"'svc_Q7m2V9r4xR4vN8kT'\'' $(literal); "end"\tail'"#),
            "{command}"
        );
        assert!(command.contains(r#"HELPER='acct_N8kT5pL2 O'\''Reilly $HOME\realm'"#), "{command}");
        assert_eq!(vars.keys().copied().collect::<Vec<_>>(), expected_vars, "{command}");
        assert_eq!(vars["HELPER"], HELPER);
        let mut expected = vec![
            "kingfisher".to_owned(),
            operation.to_owned(),
            "--rule".to_owned(),
            "custom.credential".to_owned(),
        ];
        for (name, value) in vars {
            expected.extend(["--var".into(), format!("{name}={value}")]);
        }
        expected.extend([
            TOKEN.into(),
            "--rules-path".into(),
            self.rules.to_str().unwrap().into(),
            "--no-builtins".into(),
        ]);
        assert_eq!(args, expected, "{command}");
        args.into_iter().skip(1).collect()
    }
}

async fn provider(captures: bool) -> MockServer {
    let server = MockServer::start().await;
    for (verb, endpoint, response, count) in [
        ("GET", "/identity", 200, 2 * FORMATS.len() as u64),
        ("DELETE", "/token", 204, FORMATS.len() as u64),
    ] {
        let mut mock = Mock::given(method(verb))
            .and(path(endpoint))
            .and(header("Authorization", format!("Bearer {TOKEN}")))
            .and(header("X-Helper", HELPER));
        if captures {
            mock = mock
                .and(header("X-Primary-Capture", PRIMARY_CAPTURE))
                .and(header("X-Component-Capture", COMPONENT_CAPTURE))
                .and(header("X-Rule", "custom.credential"));
        }
        mock.respond_with(ResponseTemplate::new(response)).expect(count).mount(&server).await;
    }
    server
}

async fn round_trip(captures: bool) {
    for extension in ["toml", "yml"] {
        let server = provider(captures).await;
        let fixture = Fixture::new(&server.uri(), extension, captures);
        for format in FORMATS {
            let (validate, revoke) = fixture.scan(format).await;
            for (operation, command, result) in [
                ("validate", validate.unwrap(), "is_valid"),
                ("revoke", revoke.unwrap(), "revoked"),
            ] {
                let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
                    .args(fixture.command_args(&command, operation, captures))
                    .args([
                        "--no-update-check",
                        "--allow-internal-ips",
                        "--format",
                        "json",
                        "--retries",
                        "0",
                    ])
                    .env("NO_PROXY", "*")
                    .env("no_proxy", "*")
                    .output()
                    .await
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{command}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let response: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(response[result], true, "{response}");
            }
        }
        server.verify().await;
    }
}

#[tokio::test]
async fn reported_secret_only_commands_are_concise_and_replayable_in_every_format() {
    round_trip(false).await;
}

#[tokio::test]
async fn reported_capture_dependent_commands_preserve_exact_context_in_every_format() {
    round_trip(true).await;
}
