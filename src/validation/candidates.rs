//! Bounded, opt-in credential combination verification. Context only orders
//! attempts; only an authoritative successful validator selects a combination.
use std::{
    cmp::Reverse,
    collections::{BTreeSet, BinaryHeap},
    future::Future,
    sync::LazyLock,
    time::Duration,
};

use http::StatusCode;
use kingfisher_core::ValidationOutcome;
use tokio::{sync::Semaphore, time::Instant};

use crate::{
    matcher::OwnedBlobMatch,
    rules::rule::{RuleSyntax, Validation},
    validation_body,
};

pub(crate) const MAX_COMBINATIONS: usize = 16;
const MAX_SEARCH_TIME: Duration = Duration::from_secs(30);
// Searches run sequentially per finding. Across all repositories at most four
// searches can issue requests, in addition to the existing provider rate limits.
static SEARCHES: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(4));

/// Only fixed-destination validators may opt into candidate verification.
/// Betterleaks HTTP calls must have a provably fixed origin and literal header names.
/// Do not trust a rule ID to establish that its expression is safe.
pub(crate) fn supported(rule: &RuleSyntax) -> bool {
    if !rule.is_authoritative() {
        return false;
    }
    match &rule.validation {
        Some(Validation::AWS) => true,
        Some(Validation::Http(http)) => {
            let url = &http.request.url;
            !url.contains(['{', '}'])
                && reqwest::Url::parse(url).is_ok_and(|url| {
                    matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
                })
                && http.multipart.is_none()
                && http.request.multipart.is_none()
                && !http.request.headers.keys().any(|name| name.eq_ignore_ascii_case("host"))
        }
        Some(Validation::Betterleaks(validation)) => {
            fn function_name(value: &serde_json::Value) -> Option<String> {
                match value["kind"].as_str()? {
                    "identifier" => Some(value["value"].as_str()?.to_owned()),
                    "member" => Some(format!(
                        "{}.{}",
                        function_name(&value["node"])?,
                        value["property"]["value"].as_str()?
                    )),
                    _ => None,
                }
            }
            // Only concatenation with a literal prefix ending beyond the authority
            // can contain dynamic URL data. Never infer destinations from rule IDs.
            fn fixed_origin(value: &serde_json::Value) -> bool {
                let mut prefix = value;
                let mut dynamic = false;
                while prefix["kind"] == "binary" && prefix["operator"] == "+" {
                    dynamic = true;
                    prefix = &prefix["left"];
                }
                let Some(raw) = prefix["value"].as_str().filter(|_| prefix["kind"] == "string")
                else {
                    return false;
                };
                if raw.chars().any(|c| c.is_control() || c == '\\') {
                    return false;
                }
                let Ok(url) = reqwest::Url::parse(raw) else { return false };
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    return false;
                }
                !dynamic || raw.split_once("://").is_some_and(|(_, rest)| rest.contains('/'))
            }
            fn safe_headers(value: Option<&serde_json::Value>) -> bool {
                let Some(value) = value else { return true };
                value["kind"] == "map"
                    && value["pairs"].as_array().is_some_and(|pairs| {
                        pairs.iter().all(|pair| {
                            pair["kind"] == "pair"
                                && pair["key"]["kind"] == "string"
                                && pair["key"]["value"]
                                    .as_str()
                                    .is_some_and(|key| !key.trim().eq_ignore_ascii_case("host"))
                        })
                    })
            }
            fn inspect(value: &serde_json::Value, found: &mut bool) -> bool {
                match value {
                    serde_json::Value::Object(map) => {
                        if map.get("kind").and_then(|v| v.as_str()) == Some("call") {
                            match function_name(&value["callee"]).as_deref() {
                                Some("aws.validate") => *found = true,
                                Some("http.get" | "http.post") => {
                                    let Some(args) = value["arguments"].as_array() else {
                                        return false;
                                    };
                                    if !args.first().is_some_and(fixed_origin)
                                        || !safe_headers(args.get(1))
                                    {
                                        return false;
                                    }
                                    *found = true;
                                }
                                // Explicitly allow only pure helpers needed by reviewed rules.
                                Some(
                                    "validate.unknown"
                                    | "bytes"
                                    | "base64.encode"
                                    | "strings.urlQueryEscape",
                                ) => {}
                                _ => return false,
                            }
                        }
                        map.values().all(|v| inspect(v, found))
                    }
                    serde_json::Value::Array(values) => values.iter().all(|v| inspect(v, found)),
                    _ => true,
                }
            }
            let mut found = false;
            serde_json::to_value(&validation.expression)
                .is_ok_and(|value| inspect(&value, &mut found) && found)
        }
        _ => false,
    }
}

pub(crate) fn ready(m: &OwnedBlobMatch) -> bool {
    !m.dependency_candidates.is_empty()
        && m.dependency_candidates.len() == m.ambiguous_dependencies.len()
        && supported(m.rule.syntax())
        && m.ambiguous_dependencies.keys().all(|variable| {
            m.dependency_candidates.get(variable).is_some_and(|v| !v.is_empty())
                && m.rule
                    .syntax()
                    .depends_on_rule
                    .iter()
                    .flatten()
                    .any(|dep| dep.verify_candidates && dep.variable.eq_ignore_ascii_case(variable))
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
    let deadline = Instant::now() + timeout.min(MAX_SEARCH_TIME);
    let Ok(Ok(_permit)) = tokio::time::timeout_at(deadline, SEARCHES.acquire()).await else {
        unresolved(m, 0, "time budget exhausted while waiting for a verification slot", true);
        return;
    };
    let variables: Vec<_> = m.dependency_candidates.keys().cloned().collect();
    let values: Vec<_> = variables.iter().map(|key| m.dependency_candidates[key].clone()).collect();
    let total =
        variables.iter().fold(1usize, |n, key| n.saturating_mul(m.ambiguous_dependencies[key]));
    // Best-first enumeration interleaves alternatives across components rather
    // than exhausting one dimension. Never materialize the Cartesian product.
    let initial = vec![0usize; variables.len()];
    let mut seen = BTreeSet::from([initial.clone()]);
    let mut queue = BinaryHeap::from([Reverse((0usize, initial))]);
    let mut attempted = 0;
    while let Some(Reverse((score, indices))) = queue.pop() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            unresolved(m, attempted, "time budget exhausted", true);
            return;
        }
        let mut attempt = m.clone();
        attempt.dependency_candidates.clear();
        for (dimension, variable) in variables.iter().enumerate() {
            attempt.ambiguous_dependencies.remove(variable);
            attempt
                .dependent_captures
                .insert(variable.clone(), values[dimension][indices[dimension]].clone());
        }
        // Keep the selected input context identical on cache hits and misses.
        // The ordinary validator may attach unrelated default provider endpoints
        // only on a cache miss; none are inputs to these fixed-destination searches.
        let mut selected_captures = attempt.dependent_captures.clone();
        for (name, value, ..) in super::utils::process_captures(&attempt.captures) {
            if name != "TOKEN" {
                selected_captures.entry(name).or_insert(value);
            }
        }
        attempted += 1;
        let mut result = validate(attempt, remaining).await;
        if result.validation_outcome.is_verified_active() {
            result.dependent_captures = selected_captures;
            *m = result;
            return;
        }
        // An outage or throttling is not evidence against a candidate. Stop
        // without labelling the primary credential inactive or hammering the API.
        if result.validation_outcome != ValidationOutcome::VerifiedInactive {
            let skipped = matches!(
                result.validation_outcome,
                ValidationOutcome::Skipped | ValidationOutcome::NotAttempted
            );
            let reason = if skipped {
                "verification was skipped"
            } else {
                "verification was unavailable or timed out"
            };
            unresolved(m, attempted, reason, !skipped);
            return;
        }
        if attempted == MAX_COMBINATIONS {
            break;
        }
        for dimension in 0..variables.len() {
            let mut next = indices.clone();
            next[dimension] += 1;
            if next[dimension] < values[dimension].len() && seen.insert(next.clone()) {
                queue.push(Reverse((score + 1, next)));
            }
        }
    }
    let reason = if attempted < total {
        "combination budget exhausted"
    } else {
        "no candidate combination verified"
    };
    unresolved(m, attempted, reason, false);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn finding() -> OwnedBlobMatch {
        let rule: RuleSyntax = serde_yaml::from_str(
            r#"
name: Synthetic candidate test
id: custom.candidate.test
pattern: '(synthetic)'
validation: { type: AWS }
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
            }
        }
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
