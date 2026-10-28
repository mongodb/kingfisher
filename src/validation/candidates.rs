//! Bounded, opt-in credential combination verification. Context only orders
//! attempts; only an authoritative successful validator selects a combination.
use std::{future::Future, time::Duration};

pub(crate) use candidate_verification::{MAX_COMBINATIONS, eligible_dependency, supported};
use http::StatusCode;
use kingfisher_core::ValidationOutcome;
use kingfisher_scanner::__cli_internals::candidate_verification::{self, CandidateCheck};

use crate::{matcher::OwnedBlobMatch, validation_body};

#[derive(serde::Deserialize)]
struct BetterleaksComponentCandidate {
    rule_id: String,
    secret: String,
    captures: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
pub(crate) fn ready(m: &OwnedBlobMatch) -> bool {
    ready_with_fallbacks(m, false)
}

pub(crate) fn ready_with_fallbacks(m: &OwnedBlobMatch, enabled: bool) -> bool {
    !m.dependency_candidates.is_empty()
        && m.dependency_candidates.len() == m.ambiguous_dependencies.len()
        && candidate_verification::supported_with_fallbacks(m.rule.syntax(), enabled)
        && m.ambiguous_dependencies.keys().all(|variable| {
            m.dependency_candidates.get(variable).is_some_and(|v| !v.is_empty())
                && m.rule.syntax().depends_on_rule.iter().flatten().any(|dep| {
                    eligible_dependency(m.rule.syntax(), dep)
                        && dep.variable.eq_ignore_ascii_case(variable)
                })
        })
}

fn unresolved(m: &mut OwnedBlobMatch, attempted: usize, reason: &str, unavailable: bool) {
    m.validation_success = false;
    m.validation_response_status = if unavailable {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::PRECONDITION_REQUIRED
    };
    m.validation_outcome =
        if unavailable { ValidationOutcome::Unavailable } else { ValidationOutcome::Skipped };
    m.validation_response_body = validation_body::from_string(format!(
        "Credential pairing unresolved after {attempted} candidate combinations: {reason}."
    ));
}

/// The callback must honor its timeout and clean up any in-flight cache entries
/// before returning. The production callback is validate_resolved_match, which
/// owns that cancellation boundary. Never wrap it in a second competing timeout.
pub(super) async fn run<F, Fut>(m: &mut OwnedBlobMatch, timeout: Duration, mut validate: F)
where
    F: FnMut(OwnedBlobMatch, Duration) -> Fut,
    Fut: Future<Output = OwnedBlobMatch>,
{
    let variables: Vec<_> = m.dependency_candidates.keys().cloned().collect();
    let values: Vec<_> = variables.iter().map(|key| m.dependency_candidates[key].clone()).collect();
    let structured_candidates =
        m.dependent_captures.get("__BETTERLEAKS_COMPONENT_CANDIDATES").map(|json| {
            serde_json::from_str::<
                std::collections::BTreeMap<
                    String,
                    std::collections::BTreeMap<String, BetterleaksComponentCandidate>,
                >,
            >(json)
        });
    let structured_candidates = match structured_candidates {
        Some(Ok(candidates)) => candidates,
        Some(Err(_)) => {
            unresolved(m, 0, "invalid component candidate context", false);
            return;
        }
        None => Default::default(),
    };
    if variables.iter().zip(&values).any(|(variable, values)| {
        structured_candidates.get(variable).is_some_and(|candidates| {
            values.iter().any(|identifier| !candidates.contains_key(identifier))
        })
    }) {
        unresolved(m, 0, "missing component candidate context", false);
        return;
    }
    let lengths: Vec<_> = values.iter().map(Vec::len).collect();
    let truncated = variables.iter().zip(&lengths).any(|(variable, length)| {
        m.ambiguous_dependencies.get(variable).is_some_and(|count| count > length)
    });
    let result = candidate_verification::search(&lengths, timeout, |indices, remaining| {
        let mut attempt = m.clone();
        attempt.dependency_candidates.clear();
        attempt.dependent_captures.remove("__BETTERLEAKS_COMPONENT_CANDIDATES");
        let mut components = attempt
            .dependent_captures
            .get("__BETTERLEAKS_COMPONENTS")
            .and_then(|json| {
                serde_json::from_str::<std::collections::BTreeMap<String, serde_json::Value>>(json)
                    .ok()
            })
            .unwrap_or_default();
        for (dimension, variable) in variables.iter().enumerate() {
            attempt.ambiguous_dependencies.remove(variable);
            let identifier = &values[dimension][indices[dimension]];
            let value = if let Some(candidate) = structured_candidates
                .get(variable)
                .and_then(|candidates| candidates.get(identifier))
            {
                components.insert(
                    candidate.rule_id.clone(),
                    serde_json::json!({
                        "secret":candidate.secret,"captures":candidate.captures,
                    }),
                );
                candidate.secret.clone()
            } else {
                identifier.clone()
            };
            attempt.dependent_captures.insert(variable.clone(), value);
        }
        if !components.is_empty() {
            attempt.dependent_captures.insert(
                "__BETTERLEAKS_COMPONENTS".into(),
                serde_json::to_string(&components).expect("component strings serialize"),
            );
        }
        let mut selected_captures = attempt.dependent_captures.clone();
        for (name, value, ..) in super::utils::process_captures(&attempt.captures) {
            if name != "TOKEN" {
                selected_captures.entry(name).or_insert(value);
            }
        }
        let future = validate(attempt, remaining);
        async move {
            let mut result = future.await;
            if result.validation_response_status.is_redirection() {
                return CandidateCheck::Unresolved {
                    reason: "verification returned a redirect",
                    unavailable: true,
                };
            }
            if result.validation_outcome.is_verified_active() {
                result.dependent_captures.extend(selected_captures);
                return CandidateCheck::Accepted(result);
            }
            if result.validation_outcome == ValidationOutcome::VerifiedInactive {
                CandidateCheck::Rejected
            } else {
                let skipped = matches!(
                    result.validation_outcome,
                    ValidationOutcome::Skipped | ValidationOutcome::NotAttempted
                );
                CandidateCheck::Unresolved {
                    reason: if skipped {
                        "verification was skipped"
                    } else {
                        "verification was unavailable or timed out"
                    },
                    unavailable: !skipped,
                }
            }
        }
    })
    .await;
    match result {
        Ok(result) => *m = result,
        Err(failure) => {
            // The matcher may retain only the bounded top-ranked candidates.
            // Rejecting that retained set does not exhaust the original set.
            let reason = if truncated
                && !failure.unavailable
                && failure.reason == "no candidate combination verified"
            {
                "combination budget exhausted"
            } else {
                failure.reason
            };
            unresolved(m, failure.attempted, reason, failure.unavailable);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::rule::{RuleSyntax, Validation};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn structured_candidates_keep_equal_secrets_with_different_captures_separate() {
        let mut finding = finding();
        let mut syntax = finding.rule.syntax().clone();
        syntax.validation = Some(
            serde_json::from_value(serde_json::json!({
                "type":"Betterleaks", "content":{
                    "expression":"http.get(\"https://example.invalid/check\").status == 200",
                    "components":{"helper":"SECRET"}
                }
            }))
            .unwrap(),
        );
        finding.rule = Arc::new(crate::rules::Rule::new(syntax));
        finding.ambiguous_dependencies.insert("SECRET".into(), 2);
        finding.dependency_candidates.insert("SECRET".into(), vec!["0".into(), "1".into()]);
        finding.dependent_captures.insert("__BETTERLEAKS_COMPONENT_CANDIDATES".into(),
            serde_json::json!({"SECRET":{
                "0":{"rule_id":"custom.helper", "secret":"same-secret", "captures":{"MixedCase":"wrong"}},
                "1":{"rule_id":"custom.helper", "secret":"same-secret", "captures":{"MixedCase":"accepted"}}
            }}).to_string());
        let mut keys = Vec::new();
        run(&mut finding, Duration::from_secs(2), |mut attempt, _| {
            assert_eq!(attempt.dependent_captures["SECRET"], "same-secret");
            assert!(!attempt.dependent_captures.contains_key("__BETTERLEAKS_COMPONENT_CANDIDATES"));
            keys.push(super::super::validation_dedup_key(&attempt));
            let components: serde_json::Value =
                serde_json::from_str(&attempt.dependent_captures["__BETTERLEAKS_COMPONENTS"])
                    .unwrap();
            async move {
                let accepted = components["custom.helper"]["captures"]["MixedCase"] == "accepted";
                attempt.validation_outcome = if accepted {
                    ValidationOutcome::VerifiedActive
                } else {
                    ValidationOutcome::VerifiedInactive
                };
                attempt.validation_response_status =
                    if accepted { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
                attempt
            }
        })
        .await;
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0], keys[1]);
        assert_eq!(finding.validation_outcome, ValidationOutcome::VerifiedActive);
        assert_eq!(finding.dependent_captures["SECRET"], "same-secret");
        let components: serde_json::Value =
            serde_json::from_str(&finding.dependent_captures["__BETTERLEAKS_COMPONENTS"]).unwrap();
        assert_eq!(
            components["custom.helper"]["captures"],
            serde_json::json!({"MixedCase":"accepted"})
        );
        assert!(!finding.dependent_captures.contains_key("__BETTERLEAKS_COMPONENT_CANDIDATES"));
    }

    fn finding() -> OwnedBlobMatch {
        let rule: RuleSyntax = serde_yaml::from_str(
            r#"
name: Synthetic candidate test
id: custom.candidate.test
pattern: '(synthetic)'
validation:
  type: Http
  content:
    request:
      method: GET
      url: https://example.test/verify
      headers: { X-Secret: '{{ SECRET }}' }
      response_matcher: [{ type: StatusMatch, status: [200] }]
depends_on_rule:
  - rule_id: custom.candidate.secret
    variable: SECRET
    verify_candidates: true
"#,
        )
        .unwrap();
        OwnedBlobMatch {
            rule: Arc::new(crate::rules::rule::Rule::new(rule)),
            blob_id: crate::blob::BlobId::new(b"synthetic"),
            finding_fingerprint: 0,
            matching_input_offset_span: crate::location::OffsetSpan::from_range(0..9),
            captures: crate::matcher::SerializableCaptures { captures: Default::default() },
            validation_response_body: None,
            validation_response_status: StatusCode::CONTINUE,
            validation_success: false,
            validation_outcome: ValidationOutcome::NotAttempted,
            calculated_entropy: 0.0,
            is_base64: false,
            dependent_captures: Default::default(),
            ambiguous_dependencies: [("SECRET".into(), 2)].into(),
            dependency_candidates: [("SECRET".into(), vec!["first".into(), "second".into()])]
                .into(),
        }
    }

    #[test]
    fn builtin_aws_explicitly_opts_in_to_a_supported_validator() {
        let rules = kingfisher_rules::defaults::get_builtin_rules(None).unwrap();
        let aws = &rules.rules["betterleaks.aws-access-token"];
        assert!(
            aws.depends_on_rule
                .iter()
                .flatten()
                .any(|dep| dep.variable == "AWS_SECRET_ACCESS_KEY" && dep.verify_candidates)
        );
        assert!(supported(aws), "{:?}", aws.validation);
        let mut changed = aws.clone();
        if let Some(Validation::Betterleaks(validation)) = &mut changed.validation {
            validation.expression = crate::rules::rule::BetterleaksExpr::Call {
                callee: Box::new(crate::rules::rule::BetterleaksExpr::Identifier {
                    value: "http.get".into(),
                }),
                arguments: vec![],
            };
        }
        assert!(!supported(&changed));
    }

    #[test]
    fn http_origins_and_headers_are_checked_without_trusting_rule_names() {
        use serde_json::json;
        let rules = kingfisher_rules::defaults::get_builtin_rules(None).unwrap();
        let mut rule = rules.rules["betterleaks.browserstack-access-key.1"].clone();
        let literal = |s: &str| json!({"kind":"string", "value":s});
        let dynamic = json!({"kind":"identifier", "value":"candidate"});
        let concat =
            |left, right| json!({"kind":"binary", "operator":"+", "left":left, "right":right});
        let empty_headers = json!({"kind":"map", "pairs":[]});
        for (url, headers, allowed) in [
            (literal("https://example.com/check"), empty_headers.clone(), true),
            (
                concat(literal("https://example.com/path/"), dynamic.clone()),
                empty_headers.clone(),
                true,
            ),
            (
                concat(literal("https://example.com/?id="), dynamic.clone()),
                empty_headers.clone(),
                true,
            ),
            (concat(literal("https://"), dynamic.clone()), empty_headers.clone(), false),
            (concat(literal("https://example.com"), dynamic.clone()), empty_headers.clone(), false),
            (dynamic.clone(), empty_headers.clone(), false),
            (literal("https://example.com/check"), dynamic.clone(), false),
            (
                literal("https://example.com/check"),
                json!({"kind":"map", "pairs":[{
                    "kind":"pair", "key":literal("hOsT"), "value":dynamic.clone()
                }]}),
                false,
            ),
            (
                literal("https://example.com/check"),
                json!({"kind":"map", "pairs":[{
                    "kind":"pair", "key":dynamic.clone(), "value":literal("anything")
                }]}),
                false,
            ),
            (literal("file:///tmp/check"), empty_headers.clone(), false),
        ] {
            let Some(Validation::Betterleaks(validation)) = &mut rule.validation else { panic!() };
            validation.expression = serde_json::from_value(json!({"kind":"call",
                "callee":{"kind":"identifier", "value":"http.get"},
                "arguments":[url, headers]}))
            .unwrap();
            assert_eq!(supported(&rule), allowed, "{:?}", rule.validation);
        }
        for rule in rules.rules.values() {
            if rule.depends_on_rule.iter().flatten().any(|dep| dep.verify_candidates) {
                assert!(supported(rule), "opt-in must be usable: {}", rule.id);
                for dep in rule.depends_on_rule.iter().flatten().filter(|dep| dep.verify_candidates)
                {
                    assert!(eligible_dependency(rule, dep), "{}: {}", rule.id, dep.variable);
                }
            }
        }
    }

    #[tokio::test]
    async fn candidate_budget_is_independent_of_response_body_limit() {
        use kingfisher_scanner::validation::limits::NetworkLimits;

        for unlimited_results in [false, true] {
            let mut m = finding();
            let count = MAX_COMBINATIONS + 1;
            m.ambiguous_dependencies.insert("SECRET".into(), count);
            m.dependency_candidates.insert(
                "SECRET".into(),
                (0..count).map(|index| format!("candidate-{index}")).collect(),
            );
            let clients = super::super::ValidationClients::with_timeout(
                crate::cli::global::TlsMode::Strict,
                false,
                Duration::ZERO,
                true,
            )
            .unwrap()
            .with_unlimited_results(unlimited_results);
            assert_eq!(clients.unlimited_results, unlimited_results);
            let mut attempts = 0;
            NetworkLimits {
                unlimited_response: clients.unlimited_response,
                unlimited_results: clients.unlimited_results,
                ..Default::default()
            }
            .scope(run(&mut m, Duration::ZERO, |mut attempt, _| {
                attempts += 1;
                async move {
                    attempt.validation_outcome = ValidationOutcome::VerifiedInactive;
                    attempt
                }
            }))
            .await;
            assert_eq!(attempts, if unlimited_results { count } else { MAX_COMBINATIONS });
        }
    }

    #[tokio::test]
    async fn rejected_retained_candidates_preserve_the_original_budget_status() {
        for (original, expected) in [
            (MAX_COMBINATIONS, "no candidate combination verified"),
            (MAX_COMBINATIONS + 4, "combination budget exhausted"),
        ] {
            let mut m = finding();
            m.ambiguous_dependencies.insert("SECRET".into(), original);
            m.dependency_candidates.insert(
                "SECRET".into(),
                (0..MAX_COMBINATIONS).map(|index| format!("candidate-{index}")).collect(),
            );
            let mut attempts = 0;
            run(&mut m, Duration::ZERO, |mut attempt, _| {
                attempts += 1;
                async move {
                    attempt.validation_outcome = ValidationOutcome::VerifiedInactive;
                    attempt
                }
            })
            .await;
            assert_eq!(attempts, MAX_COMBINATIONS);
            assert_eq!(m.validation_outcome, ValidationOutcome::Skipped);
            assert!(validation_body::as_str(&m.validation_response_body).contains(expected));
            assert_eq!(m.ambiguous_dependencies["SECRET"], original);
            assert!(m.dependent_captures.is_empty());
        }
    }

    #[tokio::test]
    async fn truncated_candidates_do_not_override_provider_unavailability() {
        let mut m = finding();
        m.ambiguous_dependencies.insert("SECRET".into(), MAX_COMBINATIONS + 4);
        let mut attempts = 0;
        run(&mut m, Duration::ZERO, |mut attempt, _| {
            attempts += 1;
            async move {
                attempt.validation_outcome = ValidationOutcome::Unavailable;
                attempt
            }
        })
        .await;
        assert_eq!(attempts, 1);
        assert_eq!(m.validation_outcome, ValidationOutcome::Unavailable);
        let response = validation_body::as_str(&m.validation_response_body);
        assert!(response.contains("verification was unavailable or timed out"));
        assert!(!response.contains("combination budget exhausted"));
    }

    #[tokio::test]
    async fn session_token_search_requires_a_verified_three_part_tuple() {
        let rules = kingfisher_rules::defaults::get_builtin_rules(None).unwrap();
        let mut m = finding();
        m.rule = Arc::new(crate::rules::rule::Rule::new(
            rules.rules["betterleaks.aws-session-token"].clone(),
        ));
        m.ambiguous_dependencies = [("AKID".into(), 2), ("AWS_SECRET_ACCESS_KEY".into(), 2)].into();
        m.dependency_candidates = [
            ("AKID".into(), vec!["wrong-id".into(), "right-id".into()]),
            ("AWS_SECRET_ACCESS_KEY".into(), vec!["wrong-secret".into(), "right-secret".into()]),
        ]
        .into();
        assert!(ready(&m));
        let mut attempts = 0;
        run(&mut m, Duration::from_secs(5), |mut attempt, _| {
            attempts += 1;
            async move {
                let valid = attempt.dependent_captures["AKID"] == "right-id"
                    && attempt.dependent_captures["AWS_SECRET_ACCESS_KEY"] == "right-secret";
                attempt.validation_success = valid;
                attempt.validation_outcome = if valid {
                    ValidationOutcome::VerifiedActive
                } else {
                    ValidationOutcome::VerifiedInactive
                };
                attempt
            }
        })
        .await;
        assert_eq!(attempts, 4);
        assert!(m.validation_outcome.is_verified_active());
        assert!(m.ambiguous_dependencies.is_empty());
    }

    #[test]
    fn unrelated_ambiguous_dependency_blocks_the_entire_search() {
        let mut m = finding();
        assert!(ready(&m));
        m.ambiguous_dependencies.insert("BASEURL".into(), 2);
        assert!(!ready(&m));
    }

    #[tokio::test]
    async fn concurrent_searches_are_globally_bounded() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let searches = (0..8).map(|_| {
            let active = active.clone();
            let maximum = maximum.clone();
            async move {
                let mut m = finding();
                run(&mut m, Duration::from_secs(5), |mut attempt, _| {
                    let active = active.clone();
                    let maximum = maximum.clone();
                    async move {
                        maximum
                            .fetch_max(active.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        attempt.validation_success = true;
                        attempt.validation_outcome = ValidationOutcome::VerifiedActive;
                        attempt
                    }
                })
                .await;
                assert!(m.validation_outcome.is_verified_active());
            }
        });
        futures::future::join_all(searches).await;
        assert!(maximum.load(Ordering::SeqCst) <= 4);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn endpoint_candidates_are_ineligible_even_when_explicitly_opted_in() {
        for (variable, helper) in [
            ("BASEURL", "custom.component"),
            ("github_api_base_url", "custom.component"),
            ("HOSTNAME", "custom.component"),
            ("JIRADCDOMAIN", "custom.component"),
            ("SERVICE_ENDPOINT", "custom.component"),
            ("SERVER_ADDRESS", "custom.component"),
            ("SECRET", "custom.service-url.1"),
            ("SECRET", "custom.endpoint"),
        ] {
            let mut m = finding();
            let mut rule = m.rule.syntax().clone();
            let dep = rule.depends_on_rule.iter_mut().flatten().next().unwrap();
            dep.variable = variable.into();
            dep.rule_id = helper.into();
            assert!(!eligible_dependency(
                &rule,
                rule.depends_on_rule.iter().flatten().next().unwrap()
            ));
            m.rule = Arc::new(crate::rules::rule::Rule::new(rule));
            let variable = variable.to_ascii_uppercase();
            m.ambiguous_dependencies = [(variable.clone(), 2)].into();
            m.dependency_candidates = [(variable, vec!["first".into(), "second".into()])].into();
            assert!(!ready(&m), "{helper}");
        }
    }

    #[test]
    fn typed_aws_only_accepts_consumed_credential_dependencies() {
        for (variable, allowed) in
            [("AKID", true), ("AWS_SECRET_ACCESS_KEY", true), ("OTHER", false), ("BASEURL", false)]
        {
            let mut m = finding();
            let mut rule = m.rule.syntax().clone();
            rule.validation = Some(Validation::AWS);
            rule.depends_on_rule.iter_mut().flatten().next().unwrap().variable = variable.into();
            m.rule = Arc::new(crate::rules::rule::Rule::new(rule));
            m.ambiguous_dependencies = [(variable.into(), 2)].into();
            m.dependency_candidates =
                [(variable.into(), vec!["first".into(), "second".into()])].into();
            assert_eq!(ready(&m), allowed, "{variable}");
        }
    }

    #[test]
    fn provider_names_containing_endpoint_fragments_are_not_endpoint_roles() {
        for (variable, helper) in
            [("GHOST_SECRET", "custom.ghost.secret"), ("SUPPORT_TOKEN", "custom.support.token")]
        {
            let mut rule = finding().rule.syntax().clone();
            let dep = rule.depends_on_rule.iter_mut().flatten().next().unwrap();
            dep.variable = variable.into();
            dep.rule_id = helper.into();
            assert!(eligible_dependency(
                &rule,
                rule.depends_on_rule.iter().flatten().next().unwrap()
            ));
        }
    }

    #[tokio::test]
    async fn successful_pair_preserves_validator_metadata() {
        let mut m = finding();
        run(&mut m, Duration::from_secs(5), |mut attempt, _| async move {
            attempt
                .dependent_captures
                .insert("GITHUB_API_BASE_URL".into(), "https://api.github.com".into());
            attempt.validation_outcome = ValidationOutcome::VerifiedActive;
            attempt
        })
        .await;
        assert_eq!(m.dependent_captures["SECRET"], "first");
        assert_eq!(m.dependent_captures["GITHUB_API_BASE_URL"], "https://api.github.com");
    }

    #[tokio::test]
    async fn redirects_stop_search_even_if_a_matcher_accepts_them() {
        for status in [301, 302, 303, 307, 308] {
            for outcome in [ValidationOutcome::VerifiedInactive, ValidationOutcome::VerifiedActive]
            {
                let mut m = finding();
                let mut calls = 0;
                run(&mut m, Duration::from_secs(5), |mut attempt, _| {
                    calls += 1;
                    async move {
                        attempt.validation_response_status = StatusCode::from_u16(status).unwrap();
                        attempt.validation_outcome = outcome;
                        attempt
                    }
                })
                .await;
                assert_eq!(calls, 1);
                assert_eq!(m.validation_outcome, ValidationOutcome::Unavailable);
                assert!(m.dependent_captures.is_empty());
                assert_eq!(m.ambiguous_dependencies["SECRET"], 2);
            }
        }
    }

    #[tokio::test]
    async fn intentional_skip_stops_without_selecting_a_candidate() {
        let mut m = finding();
        let mut calls = 0;
        run(&mut m, Duration::from_secs(5), |mut attempt, _| {
            calls += 1;
            async move {
                attempt.validation_outcome = ValidationOutcome::Skipped;
                attempt
            }
        })
        .await;
        assert_eq!(calls, 1);
        assert_eq!(m.validation_outcome, ValidationOutcome::Skipped);
        assert!(m.dependent_captures.is_empty());
        assert_eq!(m.ambiguous_dependencies["SECRET"], 2);
    }

    #[tokio::test]
    async fn elapsed_budget_prevents_starting_more_attempts() {
        let mut m = finding();
        let mut calls = 0;
        run(&mut m, Duration::from_millis(5), |mut attempt, remaining| {
            calls += 1;
            async move {
                tokio::time::sleep(remaining).await;
                attempt.validation_outcome = ValidationOutcome::VerifiedInactive;
                attempt
            }
        })
        .await;
        // Parallel library tests can consume the shared slots before this
        // short budget expires; queue time is deliberately part of the budget.
        assert!(calls <= 1);
        assert_eq!(m.validation_outcome, ValidationOutcome::Unavailable);
        assert!(m.dependent_captures.is_empty());
    }
}
