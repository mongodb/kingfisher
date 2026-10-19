//! Shared eligibility and bounded scheduling for explicit credential-component verification.
use kingfisher_rules::{DependsOnRule, RuleSyntax, Validation};
use std::{
    cmp::Reverse,
    collections::{BTreeSet, BinaryHeap},
    future::Future,
    sync::LazyLock,
    time::Duration,
};
use tokio::{sync::Semaphore, time::Instant};

pub const MAX_COMBINATIONS: usize = 16;
const MAX_SEARCH_TIME: Duration = Duration::from_secs(30);
static SEARCHES: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(4));

/// Only fixed-destination validators may opt into candidate verification.
/// Betterleaks HTTP calls must have a provably fixed origin and literal header names.
/// Do not trust a rule ID to establish that its expression is safe.
pub fn supported(rule: &RuleSyntax) -> bool {
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

/// An opt-in cannot turn an endpoint into an authenticated credential component.
/// Check both the variable and helper ID, including legacy concatenated names
/// such as BASEURL and JIRADCDOMAIN. Typed validators additionally restrict inputs
/// to the credential variables they actually consume.
pub fn eligible_dependency(rule: &RuleSyntax, dep: &DependsOnRule) -> bool {
    fn names_endpoint(name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        let endpoint_word = name.split(|c: char| !c.is_ascii_alphabetic()).any(|part| {
            ["url", "uri", "host", "hostname", "domain", "endpoint", "address", "port", "server"]
                .contains(&part)
        });
        let name = name.trim_end_matches(|c: char| !c.is_ascii_alphabetic());
        endpoint_word
            || ["url", "uri", "hostname", "domain", "endpoint"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
    }

    dep.verify_candidates
        && !names_endpoint(&dep.variable)
        && !names_endpoint(&dep.rule_id)
        && match &rule.validation {
            Some(Validation::AWS) => {
                dep.variable.eq_ignore_ascii_case("AKID")
                    || dep.variable.eq_ignore_ascii_case("AWS_SECRET_ACCESS_KEY")
            }
            _ => true,
        }
}

/// Result of one authoritative credential-combination check.
pub enum CandidateCheck<T> {
    Accepted(T),
    Rejected,
    Unresolved { reason: &'static str, unavailable: bool },
}

pub struct SearchFailure {
    pub attempted: usize,
    pub reason: &'static str,
    pub unavailable: bool,
}

/// Try ranked combinations without materializing their Cartesian product.
/// The callback must honor its remaining total deadline and clean up cancelled work.
pub async fn search<T, F, Fut>(
    lengths: &[usize],
    timeout: Duration,
    mut validate: F,
) -> Result<T, SearchFailure>
where
    F: FnMut(Vec<usize>, Duration) -> Fut,
    Fut: Future<Output = CandidateCheck<T>>,
{
    let deadline = (!timeout.is_zero()).then(|| Instant::now() + timeout.min(MAX_SEARCH_TIME));
    let permit = match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, SEARCHES.acquire()).await,
        None => Ok(SEARCHES.acquire().await),
    };
    let Ok(Ok(_permit)) = permit else {
        return Err(SearchFailure {
            attempted: 0,
            reason: "time budget exhausted while waiting for a verification slot",
            unavailable: true,
        });
    };
    let initial = vec![0usize; lengths.len()];
    let mut seen = BTreeSet::from([initial.clone()]);
    let mut queue = BinaryHeap::from([Reverse((0usize, initial))]);
    let mut attempted = 0;
    while let Some(Reverse((score, indices))) = queue.pop() {
        let remaining =
            deadline.map(|d| d.saturating_duration_since(Instant::now())).unwrap_or_default();
        if deadline.is_some() && remaining.is_zero() {
            return Err(SearchFailure {
                attempted,
                reason: "time budget exhausted",
                unavailable: true,
            });
        }
        attempted += 1;
        match validate(indices.clone(), remaining).await {
            CandidateCheck::Accepted(value) => return Ok(value),
            CandidateCheck::Rejected => {}
            CandidateCheck::Unresolved { reason, unavailable } => {
                return Err(SearchFailure { attempted, reason, unavailable });
            }
        }
        if !super::limits::NetworkLimits::current().unlimited_results
            && attempted == MAX_COMBINATIONS
        {
            break;
        }
        for dimension in 0..lengths.len() {
            let mut next = indices.clone();
            next[dimension] += 1;
            if next[dimension] < lengths[dimension] && seen.insert(next.clone()) {
                queue.push(Reverse((score + 1, next)));
            }
        }
    }
    let total = lengths.iter().fold(1usize, |n, &len| n.saturating_mul(len));
    Err(SearchFailure {
        attempted,
        reason: if attempted < total {
            "combination budget exhausted"
        } else {
            "no candidate combination verified"
        },
        unavailable: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejected_searches_stop_at_the_combination_budget() {
        let mut attempts = 0;
        let result = search::<(), _, _>(&[MAX_COMBINATIONS + 1], Duration::from_secs(2), |_, _| {
            attempts += 1;
            async { CandidateCheck::Rejected }
        })
        .await;
        let Err(failure) = result else { panic!("must remain unresolved") };
        assert_eq!(attempts, MAX_COMBINATIONS);
        assert_eq!(failure.attempted, MAX_COMBINATIONS);
        assert!(!failure.unavailable);
    }

    #[tokio::test]
    async fn unavailable_verification_stops_without_trying_other_credentials() {
        let mut attempts = 0;
        let result = search::<(), _, _>(&[4, 4], Duration::from_secs(2), |_, _| {
            attempts += 1;
            async {
                CandidateCheck::Unresolved { reason: "provider unavailable", unavailable: true }
            }
        })
        .await;
        let Err(failure) = result else { panic!("must remain unresolved") };
        assert!(failure.unavailable);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn combinations_interleave_credential_dimensions_and_keep_remaining_deadline() {
        let mut attempts = 0;
        let result = search(&[17, 17], Duration::from_secs(2), |indices, remaining| {
            attempts += 1;
            assert!(!remaining.is_zero() && remaining <= Duration::from_secs(2));
            async move {
                if indices == [1, 0] {
                    CandidateCheck::Accepted(indices)
                } else {
                    CandidateCheck::Rejected
                }
            }
        })
        .await;
        assert!(matches!(result, Ok(indices) if indices == [1, 0]));
        assert_eq!(attempts, 3);
    }
}
