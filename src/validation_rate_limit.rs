use std::{sync::Arc, time::Duration};

use anyhow::{Result, bail};
use dashmap::DashMap;
use tokio::{
    sync::Mutex,
    time::{Instant, sleep_until},
};

use crate::rules::rule::Validation;

const DEFAULT_BUCKET: &str = "__default__";

#[derive(Clone, Debug)]
pub struct ValidationRateLimiter {
    default_rps: Option<f64>,
    per_rule: Vec<(String, f64)>,
    next_allowed: Arc<DashMap<String, Arc<Mutex<Instant>>>>,
}

impl ValidationRateLimiter {
    pub fn from_cli(default_rps: Option<f64>, per_rule: &[String]) -> Result<Option<Self>> {
        let default_rps = default_rps.map(validate_rps).transpose()?;
        let mut normalized = Vec::with_capacity(per_rule.len());
        for item in per_rule {
            let (selector, rps) = parse_rule_rps_mapping(item)?;
            normalized.push((selector, rps));
        }

        if default_rps.is_none() && normalized.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self { default_rps, per_rule: normalized, next_allowed: Arc::new(DashMap::new()) }))
    }

    pub fn effective_rps(&self, rule_id: &str) -> Option<f64> {
        self.effective_limit(rule_id).map(|(_, rps)| rps)
    }

    pub async fn wait_for_rule(&self, rule_id: &str) {
        let Some((bucket, rps)) = self.effective_limit(rule_id) else {
            return;
        };

        let interval = Duration::from_secs_f64(1.0 / rps);
        let gate = self
            .next_allowed
            .entry(bucket)
            .or_insert_with(|| Arc::new(Mutex::new(Instant::now())))
            .clone();

        let mut next_slot = gate.lock().await;
        let now = Instant::now();
        if *next_slot > now {
            sleep_until(*next_slot).await;
        }

        *next_slot = Instant::now() + interval;
    }

    fn effective_limit(&self, rule_id: &str) -> Option<(String, f64)> {
        let mut best: Option<(&str, f64)> = None;
        for (selector, rps) in &self.per_rule {
            if selector_matches(rule_id, selector)
                && best.as_ref().is_none_or(|(current, _)| selector.len() > current.len())
            {
                best = Some((selector.as_str(), *rps));
            }
        }

        if let Some((selector, rps)) = best {
            return Some((selector.to_string(), rps));
        }

        self.default_rps.map(|rps| (DEFAULT_BUCKET.to_string(), rps))
    }
}

pub fn parse_rule_rps_mapping(input: &str) -> Result<(String, f64)> {
    let (raw_selector, raw_rps) = input
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("Invalid value '{input}'. Expected RULE=RPS"))?;
    let selector = normalize_rule_selector(raw_selector)?;
    let rps = validate_rps(raw_rps.parse::<f64>().map_err(|_| {
        anyhow::anyhow!("Invalid RPS value '{raw_rps}' for selector '{raw_selector}'")
    })?)?;
    Ok((selector, rps))
}

pub fn normalize_rule_selector(input: &str) -> Result<String> {
    let selector = input.trim();
    if selector.is_empty() {
        bail!("Rule selector cannot be empty");
    }

    Ok(selector.to_string())
}

fn validate_rps(value: f64) -> Result<f64> {
    if !value.is_finite() || value <= 0.0 {
        bail!("RPS must be a positive number");
    }
    Ok(value)
}

fn selector_matches(rule_id: &str, selector: &str) -> bool {
    let matches_prefix = |id: &str| {
        id == selector
            || id.strip_prefix(selector).is_some_and(|suffix| suffix.starts_with(['.', '-']))
    };

    matches_prefix(rule_id)
        || (!selector.starts_with("betterleaks.")
            && !selector.starts_with("kingfisher.")
            && ["betterleaks.", "kingfisher."]
                .into_iter()
                .any(|namespace| rule_id.strip_prefix(namespace).is_some_and(&matches_prefix)))
}

pub fn should_rate_limit_validation(validation: &Validation) -> bool {
    !matches!(validation, Validation::Assumed | Validation::Ethereum(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rule_selector_allows_short_names() {
        assert_eq!(normalize_rule_selector("github").unwrap(), "github");
        assert_eq!(normalize_rule_selector(" custom.github ").unwrap(), "custom.github");
    }

    #[test]
    fn parse_rule_rps_mapping_parses_rule_and_rate() {
        let (selector, rps) = parse_rule_rps_mapping("github=2.5").unwrap();
        assert_eq!(selector, "github");
        assert_eq!(rps, 2.5);
    }

    #[test]
    fn effective_rps_uses_longest_prefix_match() {
        let limiter = ValidationRateLimiter::from_cli(
            Some(10.0),
            &[
                "github=2".to_string(),
                "github.1=0.5".to_string(),
                "betterleaks.github-pat=1".to_string(),
            ],
        )
        .unwrap()
        .unwrap();

        assert_eq!(limiter.effective_rps("betterleaks.github-pat"), Some(1.0));
        assert_eq!(limiter.effective_rps("betterleaks.github-oauth"), Some(2.0));
        assert_eq!(limiter.effective_rps("kingfisher.github.1"), Some(0.5));
        assert_eq!(limiter.effective_rps("betterleaks.gitlab-pat"), Some(10.0));
    }

    #[tokio::test]
    async fn wait_for_rule_spaces_requests_for_same_bucket() {
        let limiter = ValidationRateLimiter::from_cli(Some(50.0), &[]).unwrap().unwrap();

        limiter.wait_for_rule("betterleaks.github-pat").await;

        let start = std::time::Instant::now();
        limiter.wait_for_rule("betterleaks.github-oauth").await;

        // Allow timing jitter from runtime scheduling while still asserting spacing happened.
        assert!(start.elapsed() >= Duration::from_millis(15));
    }

    #[test]
    fn should_rate_limit_non_http_validators() {
        assert!(should_rate_limit_validation(&Validation::AWS));
        assert!(!should_rate_limit_validation(&Validation::Ethereum(
            kingfisher_rules::EthereumValidation::PrivateKey
        )));
        assert!(should_rate_limit_validation(&Validation::GCP));
        assert!(should_rate_limit_validation(&Validation::MongoDB));
        assert!(should_rate_limit_validation(&Validation::Postgres));
        assert!(should_rate_limit_validation(&Validation::Coinbase));
    }

    #[test]
    fn should_rate_limit_raw_validation() {
        assert!(should_rate_limit_validation(&Validation::Raw("azurebatch".to_string())));
    }
}
