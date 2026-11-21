//! Verify public commands, help, and report formats.
use std::process::Command;

#[test]
fn removed_native_commands_are_rejected() {
    for name in ["wizard", "gui"] {
        for extra in [vec![], vec!["--help"], vec!["--report", "report.json"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_kingfisher"))
                .arg(name)
                .args(&extra)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2), "{name} {extra:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"),
                "{name} {extra:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn top_level_help_does_not_advertise_removed_native_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_kingfisher")).arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    let advertised: Vec<_> = help
        .lines()
        .filter(|line| line.starts_with("  "))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    for removed in ["wizard", "gui"] {
        assert!(!advertised.contains(&removed), "{help}");
    }
    for command in
        ["scan", "rules", "validate", "revoke", "blast-radius", "view", "config", "update"]
    {
        assert!(advertised.contains(&command), "missing {command}: {help}");
    }
}

#[test]
fn browser_report_viewer_remains_available() {
    let output =
        Command::new(env!("CARGO_BIN_EXE_kingfisher")).args(["view", "--help"]).output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    let command = format!("kingfisher{} view", std::env::consts::EXE_SUFFIX);
    assert!(help.contains(&command), "{help}");
    for format in ["JSON", "JSONL", "SARIF"] {
        assert!(help.contains(format), "missing {format}: {help}");
    }
}

#[test]
fn scan_help_lists_sarif_as_stable_and_supported() {
    let output =
        Command::new(env!("CARGO_BIN_EXE_kingfisher")).args(["scan", "--help"]).output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("SARIF 2.1.0 (stable and supported)"), "{help}");
}
