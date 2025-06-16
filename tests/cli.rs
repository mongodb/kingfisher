use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};

mod test {

    use super::*;
    #[test]
    fn cli_lists_rules_pretty() {
        Command::cargo_bin("kingfisher")
            .unwrap()
            .args(["rules", "list", "--format", "pretty"])
            .assert()
            .success()
            .stdout(contains("kingfisher.aws.").and(contains("Pattern")));
    }
    #[test]
    fn cli_lists_rules_json() {
        Command::cargo_bin("kingfisher")
            .unwrap()
            .args(["rules", "list", "--format", "json"])
            .assert()
            .success()
            .stdout(contains("kingfisher.aws.").and(contains("pattern")));
    }
}
