use std::{
    fs,
    process::Command,
    sync::{Arc, OnceLock},
};

use assert_cmd::prelude::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use kingfisher_rules::{Confidence, RulesDatabase, get_builtin_rules};
use kingfisher_scanner::{Finding, Scanner};

const RULE_PREFIX: &str = "kingfisher.connection-string.password.";
const ADO_NET: &str = "Server=tcp:acme.database.windows.net,1433;Initial Catalog=prod;User ID=sqladmin;Password=Xk9#mQ2!vL7pR4wZ;Encrypt=True;";
const ODBC: &str = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:acme.database.windows.net,1433;Uid=sqladmin;Pwd=Xk9mQ2vL7pR4wZ8q;";
const NPGSQL: &str =
    "Host=pg.acme.io;Port=5432;Database=app;Username=app;Password=Zq8vN3kL0pW2xR7t";

fn scanner() -> &'static Scanner {
    static SCANNER: OnceLock<Scanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let rules = get_builtin_rules(None).unwrap();
        let connection_rules: Vec<_> =
            rules.rules.values().filter(|rule| rule.id.starts_with(RULE_PREFIX)).collect();
        assert_eq!(connection_rules.len(), 5);
        for rule in connection_rules {
            assert_eq!(rule.as_anchored_regex().unwrap().captures_len(), 2);
            assert!(rule.betterleaks_filter.is_none());
            assert!(rule.validation.is_none());
            assert!(rule.revocation.is_none());
        }
        Scanner::new(Arc::new(RulesDatabase::from_rule_collection(rules).unwrap()))
    })
}

fn connection_findings(input: &str) -> Vec<Finding> {
    scanner()
        .scan_bytes(input.as_bytes())
        .unwrap()
        .into_iter()
        .filter(|finding| finding.rule_id.starts_with(RULE_PREFIX))
        .collect()
}

fn assert_one(input: &str, secret: &str, suffix: &str, encoded: bool) -> Finding {
    let findings = connection_findings(input);
    assert_eq!(findings.len(), 1, "input: {input:?}; findings: {findings:?}");
    let finding = findings.into_iter().next().unwrap();
    assert_eq!(finding.rule_id, format!("{RULE_PREFIX}{suffix}"), "input: {input:?}");
    assert_eq!(finding.secret, secret, "input: {input:?}");
    assert_eq!(finding.confidence, Confidence::Medium);
    assert_eq!(finding.is_base64_encoded, encoded);
    finding
}

#[test]
fn builtin_connection_strings_capture_issue_examples_quotes_and_weak_passwords() {
    let cases = [
        (ADO_NET, "Xk9#mQ2!vL7pR4wZ", "unquoted"),
        (ODBC, "Xk9mQ2vL7pR4wZ8q", "unquoted"),
        (NPGSQL, "Zq8vN3kL0pW2xR7t", "unquoted"),
        (
            "Server=db.internal;User Id=app;Password=\"Xk9mQ2;vL7pR4wZ8q\";",
            "Xk9mQ2;vL7pR4wZ8q",
            "double-quoted",
        ),
        (
            "Data Source=db.internal;User Id=app;Pwd='Zq8;vN3kL0pW2xR7t';",
            "Zq8;vN3kL0pW2xR7t",
            "single-quoted",
        ),
        ("DSN=Production;Uid=app;Pwd={Xk9}}mQ2;vL7pR4wZ8q};", "Xk9}}mQ2;vL7pR4wZ8q", "odbc-braced"),
        ("connection = \"Server=db.internal;Pwd=weak\"", "weak", "unquoted"),
        ("HOST \t= db.internal ; UID=app; PWD \t= S3cret!;", "S3cret!", "unquoted"),
        ("Host=db.internal;Pwd=$money%<call(me)>;", "$money%<call(me)>", "unquoted"),
        ("Host=db.internal;Pwd=\"getPassword()\";", "getPassword()", "double-quoted"),
        (
            "Host=db.internal;Pwd=\"process.env.DB_PASSWORD\";",
            "process.env.DB_PASSWORD",
            "double-quoted",
        ),
        (
            "jdbc:postgresql://pg.internal:5432/app?user=app&password=Zq8vN3kL0pW2xR7t&ssl=true",
            "Zq8vN3kL0pW2xR7t",
            "jdbc-query",
        ),
        (
            "jdbc:mysql://db.internal/app?password=Xk9%23mQ2%21vL7pR4wZ&user=app",
            "Xk9%23mQ2%21vL7pR4wZ",
            "jdbc-query",
        ),
        ("jdbc:mariadb://db.internal/app?user=app&password=weak", "weak", "jdbc-query"),
        (
            "jdbc:postgresql://db.internal/app?ssl&user=app&amp;password=S3cret%23",
            "S3cret%23",
            "jdbc-query",
        ),
        (
            "jdbc:mysql:loadbalance://db1.internal,db2.internal/app?password=S3cret!",
            "S3cret!",
            "jdbc-query",
        ),
        (
            "jdbc:sqlserver://db.internal:1433;databaseName=app;user=app;password=S3cret!;",
            "S3cret!",
            "unquoted",
        ),
        (
            "jdbc:sqlserver://db.internal;password={Xk9}}mQ2;vL7pR4wZ8q};",
            "Xk9}}mQ2;vL7pR4wZ8q",
            "odbc-braced",
        ),
    ];
    for (raw, secret, suffix) in cases {
        for newline in ["\n", "\r\n"] {
            let input = format!("Unicode prefix: ☃{newline}☃ {raw}{newline}");
            let finding = assert_one(&input, secret, suffix, false);
            let start = input.find(secret).unwrap();
            assert_eq!(finding.location.start_offset, start);
            assert_eq!(finding.location.end_offset, start + secret.len());
            assert_eq!(finding.line(), 2);
            let line_start = input[..start].rfind('\n').unwrap() + 1;
            assert_eq!(finding.column(), start - line_start);
        }

        let encoded = STANDARD.encode(format!("prefix padding: {raw}\nend padding"));
        let input = format!("☃ payload=\"{encoded}\";\n");
        let finding = assert_one(&input, secret, suffix, true);
        let start = input.find(&encoded).unwrap();
        assert_eq!(finding.location.start_offset, start);
        assert_eq!(finding.location.end_offset, start + encoded.len());
    }
}

#[test]
fn builtin_connection_strings_reject_unrelated_context_placeholders_and_malformed_values() {
    let cases = [
        "Password=Xk9mQ2vL7pR4wZ8q;",
        "Uid=app;Pwd=Xk9mQ2vL7pR4wZ8q;",
        "HostName=db.internal;Password=Xk9mQ2vL7pR4wZ8q;",
        "Host=db.internal;Driver={Custom;Pwd=S3cret!;};",
        "Host=db.internal;Driver={Custom;Pwd=\"S3cret!\";};",
        "Host=db.internal;Driver={Custom;Pwd='S3cret!';};",
        "Host=db.internal;Driver={Custom;Pwd={S3cret!};};",
        "ProxyServer=db.internal;Password=Xk9mQ2vL7pR4wZ8q;",
        "Host=;Password=Xk9mQ2vL7pR4wZ8q;",
        "Host=\"\";Password=Xk9mQ2vL7pR4wZ8q;",
        "Host=db.internal;Pwd=abc;",
        "Host=db.internal;Pwd=\"abc\";",
        "Host=db.internal;Pwd='abc';",
        "Host=db.internal;Pwd={abc};",
        "Host=db.internal;Pwd=\"${DB_PASSWORD}\";",
        "Host=db.internal;Pwd=%DB_PASSWORD%;",
        "Host=db.internal;Pwd=\"{{ secrets.password }}\";",
        "Host=db.internal;Pwd=$DB_PASSWORD;",
        "Host=db.internal;Pwd=$env:DB_PASSWORD;",
        "Host=db.internal;Pwd=YOUR_PASSWORD_HERE;",
        "Host=db.internal;Pwd=DATABASE_PASSWORD;",
        "Host=db.internal;Pwd=getPassword();",
        "Host=db.internal;Pwd=getenv(DB_PASSWORD);",
        "Host=db.internal;Pwd=process.env.DB_PASSWORD;",
        "Host=db.internal;Pwd=config.database.password;",
        "Host=db.internal;Pwd=\"[REDACTED]\";",
        "Host=db.internal;Pwd=********;",
        "Host=db.internal;Pwd=xxxxxxxx;",
        "Host=db.internal;Pwd=changeme123;",
        "Host=db.internal;Pwd=prefixCHANGE_ME123suffix;",
        "Host=db.internal;Pwd={unterminated;",
        "Host=db.internal;Pwd=\"unterminated;",
        "Host=db.internal;Pwd='unterminated;",
        "Host=db.internal;Pwd={Xk9mQ2}};",
        "Host=db.internal;Pwd=\"Xk9m\"\"Q2;vL7pR4wZ8q\";",
        "Host=db.internal;Pwd='Xk9m''Q2;vL7pR4wZ8q';",
        "Host=db.internal;\nPassword=Xk9mQ2vL7pR4wZ8q;",
        "Host=db.internal;\r\nPassword=Xk9mQ2vL7pR4wZ8q;",
        "connection=\"Host=db.internal\"; password=\"Xk9mQ2vL7pR4wZ8q\";",
        "Pwd=Xk9mQ2vL7pR4wZ8q;Host=db.internal;",
        "jdbc:postgresql://db.internal/app?user=app&ssl=true",
        "jdbc:mysql://db.internal/app?password=",
        "jdbc:mysql://db.internal/app?PASSWORD=S3cret!",
        "jdbc:mariadb://db.internal/app?notpassword=S3cret!",
        "jdbc:postgresql://db.internal/app?passwordHint=S3cret!",
        "jdbc:oracle:thin:@db.internal:1521/APP",
        "jdbc:sqlite:file.db?password=S3cret!",
        "jdbc:sqlserver://db.internal;integratedSecurity=true;",
        "jdbc:sqlserver://db.internal;password=\"S3;cret!\";",
        "jdbc:sqlserver://db.internal;password='S3;cret!';",
        "jdbc:postgresql://db.internal/app?password=${DB_PASSWORD}",
        "jdbc:mysql://db.internal/app?password=CHANGE_ME123",
        "jdbc:mariadb://db.internal/app?password=$DB_PASSWORD",
        "jdbc:sqlserver://db.internal;password={${DB_PASSWORD}};",
        "jdbc:postgresql:///?password=S3cret!",
        "jdbc:mysql://db invalid/app?password=S3cret!",
        "jdbc:sqlserver://;password=S3cret!;",
        "https://db.internal/app?password=S3cret!",
        "postgresql://db.internal/app?password=S3cret!",
    ];
    for raw in cases {
        let padded = format!("prefix padding: {raw}\nend padding");
        for input in [padded.clone(), STANDARD.encode(&padded)] {
            let findings = connection_findings(&input);
            assert!(findings.is_empty(), "input: {raw:?}; findings: {findings:?}");
        }
    }
}

#[test]
fn builtin_connection_strings_enforce_context_and_password_length_bounds() {
    let password = "R3!q".repeat(32);
    let context = format!("A={}", "d".repeat(198));
    assert_one(
        &format!("Host={};{context};Pwd={password};", "d".repeat(128)),
        &password,
        "unquoted",
        false,
    );
    // An ODBC doubled closing brace is one password unit; retain both source bytes.
    let braced_password = "R3!}".repeat(32).replace('}', "}}");
    assert_one(
        &format!("Host=db.internal;Pwd={{{braced_password}}};"),
        &braced_password,
        "odbc-braced",
        false,
    );
    let unicode_password = "é".repeat(64);
    assert_one(
        &format!("Host=db.internal;Pwd={unicode_password};"),
        &unicode_password,
        "unquoted",
        false,
    );
    assert_one(
        &format!("jdbc:postgresql://db.internal/app?password={password}&ssl=true"),
        &password,
        "jdbc-query",
        false,
    );
    assert_one(
        &format!("jdbc:sqlserver://db.internal;password={password};"),
        &password,
        "unquoted",
        false,
    );
    let overlong = format!("{password}x");
    for input in [
        format!("Host={};Pwd=S3cret!;", "d".repeat(129)),
        format!("Host=db.internal;A={};Pwd=S3cret!;", "d".repeat(199)),
        format!("Host=db.internal;Pwd={overlong};"),
        format!("Host=db.internal;Pwd={};", "é".repeat(65)),
        format!("Host=db.internal;Pwd=\"{overlong}\";"),
        format!("Host=db.internal;Pwd='{overlong}';"),
        format!("Host=db.internal;Pwd={{{braced_password}x}};"),
        format!("jdbc:postgresql://db.internal/app?password={overlong}"),
        format!("jdbc:mysql://db.internal/app?password={overlong}&user=app"),
        format!("jdbc:mariadb://db.internal/app?password={overlong}"),
        format!("jdbc:sqlserver://db.internal;password={overlong};"),
        format!("jdbc:sqlserver://db.internal;password={{{braced_password}x}};"),
    ] {
        let findings = connection_findings(&input);
        assert!(findings.is_empty(), "input: {input:?}; findings: {findings:?}");
    }
}

#[test]
fn jdbc_userinfo_credentials_remain_available_through_uri_detection() {
    let uri = "postgresql://app:JdbcLiteral7!@db.internal:5432/app";
    let input = format!("jdbc:{uri}");
    let findings = scanner().scan_bytes(input.as_bytes()).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding.rule_id == "betterleaks.generic-credential-uri")
        .expect("the existing URI detector should match the JDBC sub-URI");
    assert_eq!(finding.secret, "JdbcLiteral7!");
    assert_eq!(finding.captures["uri"], uri);
    assert_eq!(finding.captures["password"], "JdbcLiteral7!");
    assert!(connection_findings(&input).is_empty());
}

#[test]
fn builtin_catalog_keeps_generic_betterleaks_rules_excluded() {
    let rules = get_builtin_rules(Some(Confidence::Low)).unwrap();
    for id in [
        "betterleaks.generic-api-key",
        "betterleaks.generic-password",
        "betterleaks.generic-username",
    ] {
        assert!(!rules.rules.contains_key(id), "unexpected built-in: {id}");
    }
}

#[test]
fn cli_checks_and_scans_with_builtin_connection_string_rules() {
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["rules", "check", "--rule", "kingfisher.connection-string", "--no-update-check"])
        .arg("--warnings-as-errors")
        .assert()
        .success();

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("connection-strings.txt");
    let report = directory.path().join("report.json");
    fs::write(&input, format!("{ADO_NET}\r\n{ODBC}\r\n{NPGSQL}\r\n")).unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&input)
        .args([
            "--git-history=none",
            "--no-validate",
            "--no-update-check",
            "--no-rule-cache",
            "--format=json",
        ])
        .arg("--output")
        .arg(&report)
        .assert()
        .code(200);
    let envelope: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    let findings: Vec<_> = envelope["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["rule"]["id"].as_str().unwrap().starts_with(RULE_PREFIX))
        .collect();
    assert_eq!(findings.len(), 3);
    let mut secrets = Vec::new();
    for record in findings {
        assert_eq!(record["rule"]["id"], format!("{RULE_PREFIX}unquoted"));
        secrets.push(record["finding"]["snippet"].as_str().unwrap());
    }
    secrets.sort_unstable();
    assert_eq!(secrets, ["Xk9#mQ2!vL7pR4wZ", "Xk9mQ2vL7pR4wZ8q", "Zq8vN3kL0pW2xR7t"]);

    // Substring exclusions deliberately apply within a literal too; the documented
    // override must restore these candidates without changing the regex or capture.
    let literal = "prefixCHANGE_ME123suffix";
    fs::write(&input, format!("Host=db.internal;Pwd={literal};")).unwrap();
    for override_substrings in [false, true] {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        command
            .arg("scan")
            .arg(&input)
            .args([
                "--rule=kingfisher.connection-string.password",
                "--git-history=none",
                "--no-validate",
                "--no-update-check",
                "--no-rule-cache",
                "--format=json",
            ])
            .arg("--output")
            .arg(&report);
        if override_substrings {
            command.arg("--no-ignore-if-contains");
        }
        command.assert().code(if override_substrings { 200 } else { 0 });
        let envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        let findings = envelope["findings"].as_array().unwrap();
        assert_eq!(findings.len(), usize::from(override_substrings));
        if override_substrings {
            assert_eq!(findings[0]["finding"]["snippet"], literal);
        }
    }
}
