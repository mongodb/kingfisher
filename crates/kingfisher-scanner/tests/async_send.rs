#![cfg(feature = "validation")]

use std::collections::BTreeMap;

use kingfisher_scanner::{Revoker, Rule, RuleSyntax, ValidatedFinding, Validator};

fn require_send<T: Send>(_: T) {}

fn require_send_snapshot(revoker: &Revoker, snapshot: &ValidatedFinding) {
    require_send(revoker.revoke_validated(snapshot));
}

#[test]
fn validation_and_revocation_futures_can_run_on_multithreaded_executors() {
    // Compile-time contracts only: none of these futures are polled, so the test
    // never contacts a provider or mutates a credential.
    let validator = Validator::builder().build().unwrap();
    let context = Vec::new();
    require_send(validator.validate_findings(Vec::new()));
    require_send(validator.validate_prepared_findings(Vec::new(), &context));

    let revoker = Revoker::new().unwrap();
    let rule = Rule::new(RuleSyntax::new("acme.test", "Test", "(acme_[a-z]{8})"));
    let variables = BTreeMap::new();
    require_send(revoker.revoke(&rule, "synthetic", &variables));
    let _snapshot_check: fn(&Revoker, &ValidatedFinding) = require_send_snapshot;
}
