//! Command discovery works in both headless and GUI-enabled builds.
use std::process::Command;

#[test]
fn wizard_and_gui_alias_offer_the_same_options() {
    for name in ["wizard", "gui"] {
        let output =
            Command::new(env!("CARGO_BIN_EXE_kingfisher")).args([name, "--help"]).output().unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--report"));
        assert!(help.contains("[TARGET]"));
    }
}

#[cfg(not(feature = "gui"))]
#[test]
fn headless_build_explains_how_to_enable_the_wizard() {
    let output = Command::new(env!("CARGO_BIN_EXE_kingfisher")).arg("wizard").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--features gui"));
}

#[test]
fn report_and_scan_target_are_mutually_exclusive() {
    let output = Command::new(env!("CARGO_BIN_EXE_kingfisher"))
        .args(["wizard", "project", "--report", "report.json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
}
