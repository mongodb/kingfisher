use std::{
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;
use futures::{FutureExt, StreamExt, stream};
use indicatif::{ProgressBar, ProgressStyle};
use kingfisher_core::ValidationOutcome;
use liquid::Parser;
use reqwest::StatusCode;
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::sync::Notify;
use tracing::{trace, warn};

use crate::{
    access_map::{AccessMapRequest, CollectedAccessMapRequest},
    blob::BlobId,
    findings_store::{FindingsStore, FindingsStoreMessage},
    location::OffsetSpan,
    matcher::OwnedBlobMatch,
    provider_endpoints::ProviderEndpointOverrides,
    rules::rule::{BetterleaksAccessMapHandler, Rule, Validation},
    validation::{
        CachedResponse, collect_variables_and_dependencies, utils, validate_single_match,
    },
    validation_body,
    validation_rate_limit::ValidationRateLimiter,
};

#[derive(Clone, Default)]
pub struct AccessMapCollector {
    inner: Arc<DashMap<u64, AccessMapRequest>>,
    finding_fingerprints: Arc<DashMap<u64, FxHashSet<String>>>,
}

#[allow(dead_code)] // Retained for standalone providers awaiting compatible Betterleaks validators.
impl AccessMapCollector {
    fn record_request(&self, key: u64, request: AccessMapRequest) {
        self.finding_fingerprints
            .entry(key)
            .or_default()
            .insert(request.finding_fingerprint().to_string());
        self.inner.entry(key).or_insert(request);
    }

    pub fn record_aws(
        &self,
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        fingerprint: String,
    ) {
        let key = xxhash_rust::xxh3::xxh3_64(
            format!("aws|{access_key}|{secret_key}|{}", session_token.unwrap_or_default())
                .as_bytes(),
        );
        self.record_request(
            key,
            AccessMapRequest::Aws {
                access_key: access_key.to_string(),
                secret_key: secret_key.to_string(),
                session_token: session_token.map(str::to_owned),
                fingerprint,
            },
        );
    }

    pub fn record_gcp(&self, credential_json: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(credential_json.as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Gcp { credential_json: credential_json.to_string(), fingerprint },
        );
    }

    pub fn record_azure(
        &self,
        credential_json: &str,
        containers: Option<Vec<String>>,
        fingerprint: String,
    ) {
        let key = xxhash_rust::xxh3::xxh3_64(credential_json.as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Azure {
                credential_json: credential_json.to_string(),
                containers,
                fingerprint,
            },
        );
    }

    pub fn record_azure_devops(&self, token: &str, organization: &str, fingerprint: String) {
        let key =
            xxhash_rust::xxh3::xxh3_64(format!("azure_devops|{organization}|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::AzureDevops {
                token: token.to_string(),
                organization: organization.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_github(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("github|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Github { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_gitlab(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("gitlab|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Gitlab { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_slack(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("slack|{token}").as_bytes());
        self.record_request(key, AccessMapRequest::Slack { token: token.to_string(), fingerprint });
    }

    pub fn record_postgres(&self, uri: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("postgres|{uri}").as_bytes());
        self.record_request(key, AccessMapRequest::Postgres { uri: uri.to_string(), fingerprint });
    }

    pub fn record_mongodb(&self, uri: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("mongodb|{uri}").as_bytes());
        self.record_request(key, AccessMapRequest::MongoDB { uri: uri.to_string(), fingerprint });
    }

    pub fn record_huggingface(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("huggingface|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::HuggingFace { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_gitea(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("gitea|{token}").as_bytes());
        self.record_request(key, AccessMapRequest::Gitea { token: token.to_string(), fingerprint });
    }

    pub fn record_bitbucket(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("bitbucket|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Bitbucket { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_buildkite(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("buildkite|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Buildkite { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_harness(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("harness|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Harness { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_openai(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("openai|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::OpenAI { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_anthropic(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("anthropic|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Anthropic { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_salesforce(&self, token: &str, instance: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("salesforce|{instance}|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Salesforce {
                token: token.to_string(),
                instance: instance.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_weightsandbiases(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("weightsandbiases|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::WeightsAndBiases { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_microsoft_teams(&self, webhook_url: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("microsoft_teams|{webhook_url}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::MicrosoftTeams { webhook_url: webhook_url.to_string(), fingerprint },
        );
    }

    pub fn record_airtable(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("airtable|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Airtable { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_alibaba(
        &self,
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        fingerprint: String,
    ) {
        let key = xxhash_rust::xxh3::xxh3_64(
            format!("alibaba|{access_key}|{secret_key}|{}", session_token.unwrap_or("")).as_bytes(),
        );
        self.record_request(
            key,
            AccessMapRequest::Alibaba {
                access_key: access_key.to_string(),
                secret_key: secret_key.to_string(),
                session_token: session_token.map(|value| value.to_string()),
                fingerprint,
            },
        );
    }

    pub fn record_algolia(&self, app_id: &str, api_key: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("algolia|{app_id}|{api_key}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Algolia {
                app_id: app_id.to_string(),
                api_key: api_key.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_artifactory(&self, token: &str, base_url: Option<&str>, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("artifactory|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Artifactory {
                token: token.to_string(),
                base_url: base_url.map(|s| s.to_string()),
                fingerprint,
            },
        );
    }

    pub fn record_auth0(
        &self,
        client_id: &str,
        client_secret: &str,
        domain: &str,
        fingerprint: String,
    ) {
        let key = xxhash_rust::xxh3::xxh3_64(
            format!("auth0|{domain}|{client_id}|{client_secret}").as_bytes(),
        );
        self.record_request(
            key,
            AccessMapRequest::Auth0 {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                domain: domain.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_circleci(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("circleci|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::CircleCI { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_digitalocean(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("digitalocean|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::DigitalOcean { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_fastly(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("fastly|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Fastly { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_hubspot(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("hubspot|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::HubSpot { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_ibm_cloud(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("ibm_cloud|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::IbmCloud { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_jira(&self, token: &str, base_url: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("jira|{base_url}|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Jira {
                token: token.to_string(),
                base_url: base_url.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_mysql(&self, uri: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("mysql|{uri}").as_bytes());
        self.record_request(key, AccessMapRequest::MySQL { uri: uri.to_string(), fingerprint });
    }

    pub fn record_paypal(&self, client_id: &str, client_secret: &str, fingerprint: String) {
        let key =
            xxhash_rust::xxh3::xxh3_64(format!("paypal|{client_id}|{client_secret}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::PayPal {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_plaid(&self, client_id: &str, secret: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("plaid|{client_id}|{secret}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Plaid {
                client_id: client_id.to_string(),
                secret: secret.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_sendgrid(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("sendgrid|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::SendGrid { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_sendinblue(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("sendinblue|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Sendinblue { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_shopify(&self, token: &str, subdomain: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("shopify|{subdomain}|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Shopify {
                token: token.to_string(),
                subdomain: subdomain.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_square(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("square|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Square { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_stripe(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("stripe|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Stripe { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_terraform(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("terraform|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Terraform { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_xray(&self, token: &str, base_url: Option<&str>, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("xray|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Xray {
                token: token.to_string(),
                base_url: base_url.map(|s| s.to_string()),
                fingerprint,
            },
        );
    }

    pub fn record_zendesk(&self, token: &str, subdomain: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("zendesk|{subdomain}|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Zendesk {
                token: token.to_string(),
                subdomain: subdomain.to_string(),
                fingerprint,
            },
        );
    }

    pub fn record_monday(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("monday|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Monday { token: token.to_string(), fingerprint },
        );
    }

    pub fn record_asana(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("asana|{token}").as_bytes());
        self.record_request(key, AccessMapRequest::Asana { token: token.to_string(), fingerprint });
    }

    pub fn record_pinecone(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("pinecone|{token}").as_bytes());
        self.record_request(
            key,
            AccessMapRequest::Pinecone { token: token.to_string(), fingerprint },
        );
    }

    #[cfg(test)]
    fn into_requests(self) -> Vec<AccessMapRequest> {
        self.into_collected_requests().into_iter().map(|collected| collected.request).collect()
    }

    pub(crate) fn into_collected_requests(self) -> Vec<CollectedAccessMapRequest> {
        let mut requests: Vec<_> = self
            .inner
            .iter()
            .map(|entry| {
                let key = *entry.key();
                let mut finding_fingerprints = self
                    .finding_fingerprints
                    .get(&key)
                    .map(|fingerprints| fingerprints.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_else(|| vec![entry.value().finding_fingerprint().to_string()]);
                finding_fingerprints.sort();
                CollectedAccessMapRequest { request: entry.value().clone(), finding_fingerprints }
            })
            .collect();
        requests.sort_unstable_by(|a, b| {
            a.finding_fingerprints.first().cmp(&b.finding_fingerprints.first())
        });
        requests
    }
}

#[expect(clippy::too_many_arguments)]
pub async fn run_secret_validation(
    datastore: Arc<Mutex<FindingsStore>>,
    parser: &Parser,
    clients: &crate::validation::ValidationClients,
    cache: &Arc<SkipMap<String, CachedResponse>>,
    num_jobs: usize,
    range: Option<std::ops::Range<usize>>,
    access_map: Option<AccessMapCollector>,
    rate_limiter: Option<Arc<ValidationRateLimiter>>,
    provider_endpoints: Arc<ProviderEndpointOverrides>,
    validation_timeout: Duration,
    validation_retries: u32,
    max_body_len: usize,
) -> Result<()> {
    // ── 1. Concurrency & counters ───────────────────────────────────────────
    let concurrency = if num_jobs > 0 {
        num_jobs
    } else {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    };
    let chunk_size = std::cmp::max(concurrency * 50, 200);
    let success_count = Arc::new(AtomicUsize::new(0));
    let fail_count = Arc::new(AtomicUsize::new(0));

    // ── 2. Fetch matches & partition ──────────────────────────────────────
    //  • simple_matches: Vec of Arcs for rules without dependencies
    //  • dependent_blob_ids: just the blob IDs — we re-fetch in Phase 2
    //    so we don't hold two full copies of the match set simultaneously
    let (simple_matches, dependent_blob_ids) = {
        let ds = datastore.lock().unwrap();
        let matches = if let Some(r) = range.clone() {
            ds.get_matches()[r].to_vec()
        } else {
            ds.get_matches().to_vec()
        };

        let mut by_blob: FxHashMap<BlobId, Vec<Arc<FindingsStoreMessage>>> = FxHashMap::default();
        for arc_msg in matches {
            by_blob.entry(arc_msg.1.id).or_default().push(arc_msg);
        }

        let mut simple = Vec::new();
        let mut dep_ids = FxHashSet::default();
        for (blob_id, blob_matches) in by_blob {
            if blob_matches.iter().any(|m| !m.2.rule.syntax().depends_on_rule.is_empty()) {
                dep_ids.insert(blob_id);
                // Arcs dropped here — not held during Phase 1
            } else {
                simple.extend(blob_matches);
            }
        }
        (simple, dep_ids)
    };

    // ── Phase 1: simple, global de-dupe ──────────────────────────────────────
    if !simple_matches.is_empty() {
        // Keep only ONE representative per (rule_id, secret) group.
        // Previous code stored ALL matches per group — holding thousands of
        // Arc clones alive for the entire duration of the concurrent stream.
        let total_simple = simple_matches.len();
        let mut representatives: FxHashMap<String, Arc<FindingsStoreMessage>> =
            FxHashMap::default();
        for arc_msg in simple_matches {
            // VALIDATION DEDUP: Use get(0) to get the first/primary capture for grouping.
            //
            // This differs from fingerprint/reporting code (which uses get(1).or_else(get(0)))
            // for backward compatibility reasons - changing fingerprint calculation would break
            // historical baselines and dedup entries.
            //
            // For validation deduplication, we need the PRIMARY secret value to ensure each
            // unique secret triggers a separate validation request. Using get(1) first would
            // incorrectly pick up inner unnamed groups when patterns have nested captures
            // like (?<REGEX>...(ABC|DEF)...), causing all matches to share the same
            // validation result.
            let secret = arc_msg.2.groups.captures.first().map_or("", |c| c.raw_value());
            let group_key = validation_group_key(arc_msg.2.rule.id(), secret);
            trace!(
                rule_id = %arc_msg.2.rule.id(),
                external_fingerprint = arc_msg.2.finding_fingerprint,
                validation_group_key = %group_key,
                "Grouping finding for validation"
            );
            // Only keep the first representative — extra Arcs are dropped immediately
            representatives.entry(group_key).or_insert(arc_msg);
        }

        trace!(
            total_findings = total_simple,
            unique_validation_groups = representatives.len(),
            "Validation grouping complete (internal dedup)"
        );

        let validation_results = DashMap::<String, CachedResponse>::new();

        let pb = ProgressBar::new(representatives.len() as u64).with_message("Validating secrets…");
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{bar:40.green/blue}] {pos}/{len} ({percent}%) \
                 [{elapsed_precise}]",
            )?
            .progress_chars("=>-")
            .tick_chars("|/-\\"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));

        // Shared empty maps — avoids allocating throwaway DashMaps per task
        let empty_dep_vars: FxHashMap<String, Vec<(String, OffsetSpan)>> = FxHashMap::default();
        let empty_missing: FxHashMap<String, Vec<String>> = FxHashMap::default();
        let empty_cache: Arc<DashMap<String, CachedResponse>> = Arc::new(DashMap::new());
        let empty_inflight: Arc<DashMap<String, ()>> = Arc::new(DashMap::new());

        stream::iter(
            representatives.into_values(), // consumes map, dropping keys
        )
        .for_each_concurrent(concurrency, |rep_arc| {
            let parser = parser.clone();
            let clients = clients.clone();
            let cache_glob = cache.clone();
            let val_res = &validation_results;
            let success = success_count.clone();
            let fail = fail_count.clone();
            let pb = pb.clone();
            let access_map = access_map.clone();
            let rate_limiter = rate_limiter.clone();
            let provider_endpoints = provider_endpoints.clone();
            let empty_dep_vars = &empty_dep_vars;
            let empty_missing = &empty_missing;
            let empty_cache = empty_cache.clone();
            let empty_inflight = empty_inflight.clone();

            async move {
                // VALIDATION DEDUP: Use get(0) for the primary secret value.
                // See comment above for why this differs from fingerprint/reporting code.
                let secret = rep_arc.2.groups.captures.first().map_or("", |c| c.raw_value());
                let key = validation_group_key(rep_arc.2.rule.id(), secret);

                match val_res.entry(key.clone()) {
                    dashmap::mapref::entry::Entry::Occupied(_) => return,
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        entry.insert(CachedResponse {
                            body: validation_body::from_string(String::new()),
                            status: StatusCode::ACCEPTED,
                            is_valid: false,
                            outcome: ValidationOutcome::NotAttempted,
                            timestamp: Instant::now(),
                        });
                    }
                }

                let mut om = OwnedBlobMatch::convert_match_to_owned_blobmatch(
                    &rep_arc.2,
                    rep_arc.2.rule.clone(),
                );

                validate_single(
                    &mut om,
                    &parser,
                    &clients,
                    empty_dep_vars,
                    empty_missing,
                    &empty_cache,
                    &empty_inflight,
                    &success,
                    &fail,
                    &cache_glob,
                    access_map.as_ref(),
                    rate_limiter.as_deref(),
                    &provider_endpoints,
                    validation_timeout,
                    validation_retries,
                    max_body_len,
                )
                .await;

                let cr = CachedResponse {
                    body: om.validation_response_body.clone(),
                    status: om.validation_response_status,
                    is_valid: om.validation_success,
                    outcome: om.validation_outcome,
                    timestamp: Instant::now(),
                };
                val_res.insert(key, cr);

                pb.inc(1);
            }
            .boxed()
        })
        .await;
        pb.finish();

        // Apply Phase 1 results in-place — avoids cloning every Match
        {
            let mut ds = datastore.lock().unwrap();
            let matches = ds.get_matches_mut();
            let slice: &mut [Arc<FindingsStoreMessage>] = if let Some(ref r) = range {
                &mut matches[r.clone()]
            } else {
                matches.as_mut_slice()
            };
            for match_arc in slice.iter_mut() {
                // Skip dependent matches — handled in Phase 2
                if !match_arc.2.rule.syntax().depends_on_rule.is_empty() {
                    continue;
                }
                let secret = match_arc.2.groups.captures.first().map_or("", |c| c.raw_value());
                let key = validation_group_key(match_arc.2.rule.id(), secret);
                if let Some(cr) = validation_results.get(&key) {
                    let (_, _, existing) = Arc::make_mut(match_arc);
                    existing.validation_success = cr.is_valid;
                    existing.validation_response_status = cr.status.as_u16();
                    existing.validation_response_body = cr.body.clone();
                    existing.validation_outcome = cr.outcome;
                }
            }
        }
    }

    // ── Phase 2: blobs with dependencies ─────────────────────────────────────
    //  Re-fetch dependent matches from the datastore so we don't hold two
    //  copies of the full match set in memory simultaneously.
    if !dependent_blob_ids.is_empty() {
        let dependent_blobs: FxHashMap<BlobId, Vec<Arc<FindingsStoreMessage>>> = {
            let ds = datastore.lock().unwrap();
            let slice = if let Some(ref r) = range {
                &ds.get_matches()[r.clone()]
            } else {
                ds.get_matches()
            };
            let mut map: FxHashMap<BlobId, Vec<Arc<FindingsStoreMessage>>> = FxHashMap::default();
            for arc_msg in slice {
                if dependent_blob_ids.contains(&arc_msg.1.id) {
                    map.entry(arc_msg.1.id).or_default().push(arc_msg.clone());
                }
            }
            map
        };

        let blob_ids: Vec<_> = {
            let mut v: Vec<_> = dependent_blobs.keys().cloned().collect();
            v.sort_unstable();
            v
        };

        let total = blob_ids.len();
        let pb = ProgressBar::new(total as u64).with_message("Validating dependent secrets…");
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.yellow} {msg} [{bar:40.yellow/blue}] {pos}/{len} ({percent}%) \
                 [{elapsed_precise}]",
            )?
            .progress_chars("=>-")
            .tick_chars("|/-\\"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));

        let val_cache = Arc::new(DashMap::<String, CachedResponse>::new());
        let in_flight = Arc::new(DashMap::<String, ()>::new());

        // Collect validation results keyed by finding_fingerprint:
        // (validation_success, response_body, response_status_u16, dependent_captures)
        type DepUpdate = (
            bool,
            crate::validation_body::ValidationResponseBody,
            u16,
            kingfisher_core::ValidationOutcome,
            std::collections::BTreeMap<String, String>,
        );
        let mut dep_updates: FxHashMap<u64, DepUpdate> = FxHashMap::default();

        for chunk in blob_ids.chunks(chunk_size) {
            // Lazy iterator — futures are created on-demand by buffer_unordered,
            // not all at once via .collect().
            let validated_blobs: Vec<Vec<OwnedBlobMatch>> =
                stream::iter(chunk.iter().map(|blob_id| {
                    let matches_for_blob = dependent_blobs.get(blob_id).unwrap().clone();
                    let parser = parser.clone();
                    let clients = clients.clone();
                    let val_cache = val_cache.clone();
                    let in_flight = in_flight.clone();
                    let success = success_count.clone();
                    let fail = fail_count.clone();
                    let cache_glob = cache.clone();
                    let access_map = access_map.clone();
                    let rate_limiter = rate_limiter.clone();
                    let provider_endpoints = provider_endpoints.clone();
                    async move {
                        let owned = matches_for_blob
                            .iter()
                            .map(|arc_msg| {
                                OwnedBlobMatch::convert_match_to_owned_blobmatch(
                                    &arc_msg.2,
                                    arc_msg.2.rule.clone(),
                                )
                            })
                            .collect::<Vec<_>>();

                        // Drop Arc clones early — we only need OwnedBlobMatch from here
                        drop(matches_for_blob);

                        let (dep_vars, missing_deps) = collect_variables_and_dependencies(&owned);

                        let mut by_key: FxHashMap<String, Vec<OwnedBlobMatch>> =
                            FxHashMap::default();
                        for om in owned {
                            by_key.entry(build_cache_key(&om)).or_default().push(om);
                        }
                        let reps: Vec<_> =
                            by_key.into_values().map(|mut v| (v.remove(0), v)).collect();

                        let validated: Vec<_> =
                            stream::iter(reps.into_iter().map(|(mut rep, mut dups)| {
                                let parser = parser.clone();
                                let clients = clients.clone();
                                let dep_vars = dep_vars.clone();
                                let miss_deps = missing_deps.clone();
                                let val_cache = val_cache.clone();
                                let in_flight = in_flight.clone();
                                let success = success.clone();
                                let fail = fail.clone();
                                let cache_glob = cache_glob.clone();
                                let access_map = access_map.clone();
                                let rate_limiter = rate_limiter.clone();
                                let provider_endpoints = provider_endpoints.clone();
                                async move {
                                    validate_single(
                                        &mut rep,
                                        &parser,
                                        &clients,
                                        &dep_vars,
                                        &miss_deps,
                                        &val_cache,
                                        &in_flight,
                                        &success,
                                        &fail,
                                        &cache_glob,
                                        access_map.as_ref(),
                                        rate_limiter.as_deref(),
                                        &provider_endpoints,
                                        validation_timeout,
                                        validation_retries,
                                        max_body_len,
                                    )
                                    .await;
                                    for d in &mut dups {
                                        d.validation_success = rep.validation_success;
                                        d.validation_response_body =
                                            rep.validation_response_body.clone();
                                        d.validation_response_status =
                                            rep.validation_response_status;
                                        d.validation_outcome = rep.validation_outcome;
                                    }
                                    let mut out = vec![rep];
                                    out.extend(dups);
                                    out
                                }
                                .boxed()
                            }))
                            .buffer_unordered(concurrency)
                            .collect()
                            .await;

                        validated.into_iter().flatten().collect::<Vec<_>>()
                    }
                    .boxed()
                }))
                .buffer_unordered(concurrency)
                .collect()
                .await;

            for blob_vec in validated_blobs {
                for om in blob_vec {
                    dep_updates.insert(
                        om.finding_fingerprint,
                        (
                            om.validation_success,
                            om.validation_response_body.clone(),
                            om.validation_response_status.as_u16(),
                            om.validation_outcome,
                            om.dependent_captures.clone(),
                        ),
                    );
                }
            }
            pb.inc(chunk.len() as u64);
        }
        pb.finish();

        // Drop dependent blob Arc clones so datastore Arcs reach refcount == 1
        drop(dependent_blobs);

        // Apply Phase 2 results in-place
        if !dep_updates.is_empty() {
            let mut ds = datastore.lock().unwrap();
            let matches = ds.get_matches_mut();
            let slice: &mut [Arc<FindingsStoreMessage>] = if let Some(ref r) = range {
                &mut matches[r.clone()]
            } else {
                matches.as_mut_slice()
            };
            for match_arc in slice.iter_mut() {
                if let Some((success, body, status, outcome, dep_caps)) =
                    dep_updates.get(&match_arc.2.finding_fingerprint).cloned()
                {
                    let (_, _, existing) = Arc::make_mut(match_arc);
                    existing.validation_success = success;
                    existing.validation_response_status = status;
                    existing.validation_response_body = body;
                    existing.validation_outcome = outcome;
                    existing.dependent_captures = dep_caps;
                }
            }
        }
    }

    // Validation intentionally executes once per unique credential, but alert correlation is
    // occurrence-specific: the same credential at two source locations has two finding
    // fingerprints. Revisit the updated store after validation so the collector sees every
    // occurrence, including matches dropped from the Phase 1 representative set. Existing
    // requests are still deduplicated by credential inside AccessMapCollector.
    //
    // Only runs under --access-map, and pre-filters on the stored validation outcome so the
    // per-match `OwnedBlobMatch` clone is paid only for credentials that actually validated
    // — on a large repo the overwhelming majority of matches never reach the mapper.
    if let Some(collector) = access_map.as_ref() {
        let ds = datastore.lock().unwrap();
        let matches = ds.get_matches();
        let slice = if let Some(ref range) = range { &matches[range.clone()] } else { matches };
        for message in slice {
            let stored = &message.2;
            if !is_access_map_candidate(
                &stored.rule,
                stored.validation_success,
                stored.validation_response_status,
            ) {
                continue;
            }
            let om =
                OwnedBlobMatch::convert_match_to_owned_blobmatch(stored, Arc::clone(&stored.rule));
            maybe_record_access_map(&om, Some(collector));
        }
    }

    // Reclaim memory from static caches that accumulated during validation
    crate::validation::clear_validation_caches();

    Ok(())
}

// ---------------------------------------------------
// The core validation logic, used in an async pipeline
// ---------------------------------------------------
#[allow(clippy::too_many_arguments)]
async fn validate_single(
    om: &mut OwnedBlobMatch,
    parser: &Parser,
    clients: &crate::validation::ValidationClients,
    dep_vars: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    missing_deps: &FxHashMap<String, Vec<String>>,
    cache: &DashMap<String, CachedResponse>,
    in_progress: &DashMap<String, ()>,
    success_count: &AtomicUsize,
    fail_count: &AtomicUsize,
    cache2: &Arc<SkipMap<String, CachedResponse>>,
    access_map: Option<&AccessMapCollector>,
    rate_limiter: Option<&ValidationRateLimiter>,
    provider_endpoints: &Arc<ProviderEndpointOverrides>,
    validation_timeout: Duration,
    validation_retries: u32,
    max_body_len: usize,
) {
    if !om.rule.syntax().is_authoritative() {
        om.validation_success = false;
        om.validation_response_body = None;
        om.validation_response_status = StatusCode::CONTINUE;
        om.validation_outcome = ValidationOutcome::NotAttempted;
        return;
    }

    let cache_key = build_cache_key(om);
    // Check cache first
    if let Some(cached) = cache.get(&cache_key) {
        om.validation_success = cached.is_valid;
        om.validation_response_body = cached.body.clone();
        om.validation_response_status = cached.status;
        om.validation_outcome = cached.outcome;
        if om.validation_outcome.is_verified_active()
            || matches!(
                om.validation_outcome,
                ValidationOutcome::Assumed | ValidationOutcome::LocallyDerived
            )
        {
            success_count.fetch_add(1, Ordering::Relaxed);
        } else if matches!(
            om.validation_outcome,
            ValidationOutcome::VerifiedInactive | ValidationOutcome::InvalidMaterial
        ) {
            fail_count.fetch_add(1, Ordering::Relaxed);
        }
        maybe_record_access_map(om, access_map);
        return;
    }

    static NOTIFY: std::sync::LazyLock<DashMap<String, Arc<Notify>>> =
        std::sync::LazyLock::new(DashMap::new);

    let notify = NOTIFY.entry(cache_key.clone()).or_insert_with(|| Arc::new(Notify::new())).clone();
    let first = in_progress.insert(cache_key.clone(), ()).is_none();
    if !first {
        notify.notified().await; // suspend with zero polling
        // cached result now present
        if let Some(cached) = cache.get(&cache_key) {
            om.validation_success = cached.is_valid;
            om.validation_response_body = cached.body.clone();
            om.validation_response_status = cached.status;
            om.validation_outcome = cached.outcome;
            if om.validation_outcome.is_verified_active()
                || matches!(
                    om.validation_outcome,
                    ValidationOutcome::Assumed | ValidationOutcome::LocallyDerived
                )
            {
                success_count.fetch_add(1, Ordering::Relaxed);
            } else if matches!(
                om.validation_outcome,
                ValidationOutcome::VerifiedInactive | ValidationOutcome::InvalidMaterial
            ) {
                fail_count.fetch_add(1, Ordering::Relaxed);
            }
            maybe_record_access_map(om, access_map);
            return; // Exit early if cached result is found
        }
        return;
    }
    // If we reach here, we're the first task to validate this key
    // Perform validation
    let outcome = ValidationRunOutcome::from_panic_result(
        catch_validation_panic(
            validate_single_match(
                om,
                parser,
                clients,
                dep_vars,
                missing_deps,
                cache2,
                validation_timeout,
                validation_retries,
                rate_limiter,
                provider_endpoints.as_ref(),
                max_body_len,
            )
            .boxed(),
        )
        .await,
    );
    apply_validation_outcome(om, &cache_key, outcome, success_count, fail_count, cache);
    maybe_record_access_map(om, access_map);
    // Remove from `in_progress`
    // in_progress.remove(&cache_key);
    in_progress.remove(&cache_key);
    if let Some(n) = NOTIFY.remove(&cache_key) {
        n.1.notify_waiters(); // wake everyone
    }
}

/// Result of attempting to validate a single match.
///
/// Flattens panic handling into a self-describing enum so call sites and
/// signatures stay readable. Validation timeouts are handled inside
/// `validate_single_match`, where the module-local de-dupe state can be cleaned.
enum ValidationRunOutcome {
    /// Validation ran to completion; the match's own fields describe whether it
    /// succeeded or failed.
    Completed,
    /// Validation panicked. The payload is discarded because it may contain secrets.
    Panicked,
}

impl ValidationRunOutcome {
    fn from_panic_result(result: std::result::Result<(), ()>) -> Self {
        match result {
            Ok(()) => ValidationRunOutcome::Completed,
            Err(()) => ValidationRunOutcome::Panicked,
        }
    }
}

fn apply_validation_outcome(
    om: &mut OwnedBlobMatch,
    cache_key: &str,
    outcome: ValidationRunOutcome,
    success_count: &AtomicUsize,
    fail_count: &AtomicUsize,
    cache: &DashMap<String, CachedResponse>,
) {
    match outcome {
        ValidationRunOutcome::Completed => {
            om.refresh_validation_outcome();
            if om.validation_outcome.is_verified_active()
                || matches!(
                    om.validation_outcome,
                    ValidationOutcome::Assumed | ValidationOutcome::LocallyDerived
                )
            {
                success_count.fetch_add(1, Ordering::Relaxed);
            } else if matches!(
                om.validation_outcome,
                ValidationOutcome::VerifiedInactive | ValidationOutcome::InvalidMaterial
            ) {
                fail_count.fetch_add(1, Ordering::Relaxed);
            }
            cache.insert(
                cache_key.to_owned(),
                CachedResponse {
                    is_valid: om.validation_success,
                    status: om.validation_response_status,
                    body: om.validation_response_body.clone(),
                    outcome: om.validation_outcome,
                    timestamp: Instant::now(),
                },
            );
        }
        ValidationRunOutcome::Panicked => {
            warn!(
                rule_id = %om.rule.id(),
                "validator panicked; marking match as failed",
            );
            om.validation_success = false;
            om.validation_response_body = validation_body::from_string(format!(
                "Validation panicked for rule {}",
                om.rule.id()
            ));
            om.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
            om.refresh_validation_outcome();
            cache.insert(
                cache_key.to_owned(),
                CachedResponse {
                    is_valid: om.validation_success,
                    status: om.validation_response_status,
                    body: om.validation_response_body.clone(),
                    outcome: om.validation_outcome,
                    timestamp: Instant::now(),
                },
            );
        }
    }
}

#[cfg(test)]
fn is_counted_validation_status(status: StatusCode) -> bool {
    !matches!(status, StatusCode::CONTINUE | StatusCode::PRECONDITION_REQUIRED)
}

/// Defensive, last-resort boundary around a validator future.
///
/// Validators perform network I/O and parse untrusted responses, so a stray
/// `panic!`/`unwrap` would otherwise tear down the entire scan. We catch the
/// unwind here and fail just the one match. The panic payload is discarded
/// immediately because it may contain secret material.
///
/// `AssertUnwindSafe` is required because the future borrows `&mut om`. It is
/// sound for this use because the unwind is never observed as a partial result:
/// on the panic path [`apply_validation_outcome`] unconditionally overwrites the
/// match's validation fields (`validation_success`, `validation_response_status`,
/// `validation_response_body`) with a deterministic failure state. The shared
/// counters and response cache are only mutated *after* this boundary returns,
/// so a panic cannot leave them inconsistent.
async fn catch_validation_panic<F>(future: F) -> std::result::Result<(), ()>
where
    F: Future<Output = ()>,
{
    match AssertUnwindSafe(future).catch_unwind().await {
        Ok(()) => Ok(()),
        Err(_payload) => Err(()),
    }
}

// Helper to compute the cache key for an OwnedBlobMatch.
fn build_cache_key(om: &OwnedBlobMatch) -> String {
    let capture0 = om.captures.captures.first().map_or("", |c| c.raw_value());
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kingfisher.validation-cache.v1\0");
    hash_cache_key_part(&mut hasher, om.rule.id().as_bytes());
    hash_cache_key_part(&mut hasher, capture0.as_bytes());

    let has_context_dependency = om
        .rule
        .syntax()
        .depends_on_rule
        .iter()
        .flatten()
        .any(|dep| !dep.variable.eq_ignore_ascii_case("TOKEN"));
    if has_context_dependency {
        hash_cache_key_part(&mut hasher, om.blob_id.to_string().as_bytes());
        hash_cache_key_part(&mut hasher, &om.matching_input_offset_span.start.to_le_bytes());
        hash_cache_key_part(&mut hasher, &om.matching_input_offset_span.end.to_le_bytes());
    }

    hasher.finalize().to_hex().to_string()
}

fn validation_group_key(rule_id: &str, secret: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kingfisher.validation-group.v1\0");
    hash_cache_key_part(&mut hasher, rule_id.as_bytes());
    hash_cache_key_part(&mut hasher, secret.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn hash_cache_key_part(hasher: &mut blake3::Hasher, part: &[u8]) {
    hasher.update(&(part.len() as u64).to_le_bytes());
    hasher.update(part);
}

/// Whether a match is worth handing to the access mapper.
///
/// Split out so the post-validation sweep in `run_secret_validation` can apply
/// the same gate to a stored `Match` *before* paying for an `OwnedBlobMatch`
/// conversion, which clones the match's captures and blob metadata.
fn is_access_map_candidate(
    rule: &Rule,
    validation_success: bool,
    validation_response_status: u16,
) -> bool {
    if !rule.syntax().is_authoritative() {
        return false;
    }
    validation_success
        || (matches!(
            &rule.syntax().validation,
            Some(Validation::Betterleaks(validation))
                if validation
                    .capabilities
                    .access_map
                    .as_ref()
                    .is_some_and(|mapping| mapping.reachable_2xx)
        ) && (200..300).contains(&validation_response_status))
        || (rule.id().starts_with("kingfisher.gitlab.")
            && (200..300).contains(&validation_response_status))
}

fn maybe_record_access_map(om: &OwnedBlobMatch, collector: Option<&AccessMapCollector>) {
    let validation_ok = is_access_map_candidate(
        &om.rule,
        om.validation_success,
        om.validation_response_status.as_u16(),
    );
    let collector = match collector {
        Some(c) if validation_ok => c,
        _ => return,
    };

    let captures = utils::process_captures(&om.captures);
    let fp = om.finding_fingerprint.to_string();

    match &om.rule.syntax().validation {
        Some(Validation::AWS) => {
            let token = captures
                .iter()
                .find(|(name, ..)| name == "TOKEN")
                .map(|(_, value, ..)| value.clone())
                .unwrap_or_default();
            let is_session_token_rule = crate::validation::is_aws_session_token_rule(&om.rule);
            let secret = if is_session_token_rule {
                om.dependent_captures.get("AWS_SECRET_ACCESS_KEY").cloned().unwrap_or_default()
            } else {
                token.clone()
            };
            let session_token = is_session_token_rule.then_some(token.as_str());

            let mut akid = utils::find_closest_variable(&captures, token.as_str(), "TOKEN", "AKID")
                .or_else(|| om.dependent_captures.get("AKID").cloned())
                .unwrap_or_default();

            if akid.is_empty() {
                akid = extract_akid_from_body(&om.validation_response_body).unwrap_or_default();
            }

            if !akid.is_empty() && !secret.is_empty() {
                collector.record_aws(&akid, &secret, session_token, fp.clone());
            }
        }
        Some(Validation::GCP) => {
            if let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_gcp(value, fp.clone());
            }
        }
        Some(Validation::AzureStorage) => {
            let storage_key = captures
                .iter()
                .find(|(name, ..)| name == "TOKEN")
                .map(|(_, value, ..)| value.clone())
                .unwrap_or_default();
            let storage_account =
                utils::find_closest_variable(&captures, storage_key.as_str(), "TOKEN", "AZURENAME")
                    .unwrap_or_default();

            let mut storage_account = storage_account;
            if storage_account.is_empty() {
                storage_account =
                    extract_azure_storage_account_from_body(&om.validation_response_body)
                        .unwrap_or_default();
            }
            let containers_hint =
                extract_azure_storage_containers_from_body(&om.validation_response_body);

            if !storage_account.is_empty() && !storage_key.is_empty() {
                let creds_json = format!(
                    r#"{{"storage_account":"{}","storage_key":"{}"}}"#,
                    storage_account, storage_key
                );
                collector.record_azure(&creds_json, containers_hint, fp.clone());
            }
        }
        Some(Validation::JWT) => {
            record_rule_id_access_map(om, collector, &captures, &fp);
        }
        Some(Validation::Postgres) => {
            if let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_postgres(value, fp.clone());
            }
        }
        Some(Validation::MongoDB) => {
            if let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_mongodb(value, fp.clone());
            }
        }
        Some(Validation::MySQL) => {
            if let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_mysql(value, fp.clone());
            }
        }
        Some(Validation::Betterleaks(validation)) => {
            record_betterleaks_access_map(om, validation, collector, &captures, &fp);
        }
        _ => record_rule_id_access_map(om, collector, &captures, &fp),
    }
}

/// Access-map dispatch for rules that do not carry a Betterleaks `access_map`
/// capability, keyed on rule ID.
///
/// Two populations reach here:
///
/// * **Veles rules** (`veles.*`), which use `Validation::Http` and so never hit
///   the Betterleaks handler dispatch.
/// * **Kingfisher 1.x rules** (`kingfisher.*`), which are still loadable via
///   `--rules-path` even though the built-in 2.x catalog no longer contains
///   them.
fn record_rule_id_access_map(
    om: &OwnedBlobMatch,
    collector: &AccessMapCollector,
    captures: &[(String, String, usize, usize)],
    fingerprint: &str,
) {
    if record_veles_access_map(om, collector, captures, fingerprint) {
        return;
    }
    record_legacy_access_map(om, collector, captures, fingerprint);
}

/// Access-map dispatch for validated Veles rules.
///
/// Veles detectors validate through `Validation::Http`, so without this they
/// would fall through to the `kingfisher.*` chain and match nothing, silently
/// dropping access mapping for providers Kingfisher still fully supports.
///
/// Only rules whose reported secret is directly usable as a bearer credential
/// against the provider API are wired up. Deliberately excluded:
///
/// * `veles.secrets/bitbucketcredentials` — the secret is a git URL with
///   embedded basic-auth credentials, not an API token.
///   Returns `true` when the rule was handled.
fn record_veles_access_map(
    om: &OwnedBlobMatch,
    collector: &AccessMapCollector,
    captures: &[(String, String, usize, usize)],
    fingerprint: &str,
) -> bool {
    let id = om.rule.id();
    if !id.starts_with("veles.") {
        return false;
    }

    let token = captures
        .iter()
        .find(|(name, ..)| name == "TOKEN")
        .map(|(_, value, ..)| value.as_str())
        .unwrap_or_default();
    if token.is_empty() {
        return false;
    }
    let fp = || fingerprint.to_string();

    match id {
        "veles.secrets/slackappleveltoken"
        | "veles.secrets/slackappconfigaccesstoken"
        | "veles.secrets/slackappconfigrefreshtoken" => {
            collector.record_slack(token, fp());
            true
        }
        "veles.secrets/digitaloceanapikey" => {
            collector.record_digitalocean(token, fp());
            true
        }
        "veles.secrets/sendgrid" => {
            collector.record_sendgrid(token, fp());
            true
        }
        _ => false,
    }
}

/// Access-map dispatch for Kingfisher 1.x (`kingfisher.*`) rules.
///
/// **This is live code, not dead code.** The built-in 2.x catalog contains no
/// `kingfisher.*` IDs, so none of these arms fire on a default scan — but the
/// 1.x YAML catalog is still a supported input via `--rules-path`, and these
/// arms are the only way those rules reach the access-map collectors. Removing
/// them would silently break blast-radius mapping for every operator who kept
/// the legacy catalog.
///
/// See `crates/kingfisher-rules/data/legacy-rule-aliases.yml` for the 1.x → 2.x
/// provider mapping.
fn record_legacy_access_map(
    om: &OwnedBlobMatch,
    collector: &AccessMapCollector,
    captures: &[(String, String, usize, usize)],
    fingerprint: &str,
) {
    let id = om.rule.id();
    let capture = |names: &[&str]| {
        captures
            .iter()
            .find(|(name, ..)| names.contains(&name.as_str()))
            .map(|(_, value, ..)| value.clone())
            .unwrap_or_default()
    };
    let capture_or_dependency = |names: &[&str], dependency: &str| {
        let value = capture(names);
        if value.is_empty() {
            om.dependent_captures.get(dependency).cloned().unwrap_or_default()
        } else {
            value
        }
    };
    let token = capture(&["TOKEN"]);
    let fp = || fingerprint.to_string();

    if id == "kingfisher.azure.10" && matches!(&om.rule.syntax().validation, Some(Validation::JWT))
    {
        if !token.is_empty() {
            let credentials = serde_json::json!({ "access_token": token });
            collector.record_azure(&credentials.to_string(), None, fp());
        }
        return;
    }

    if id.starts_with("kingfisher.github.") && !token.is_empty() {
        collector.record_github(&token, fp());
    } else if id.starts_with("kingfisher.gitlab.") && !token.is_empty() {
        collector.record_gitlab(&token, fp());
    } else if id.starts_with("kingfisher.slack.") && !token.is_empty() {
        collector.record_slack(&token, fp());
    } else if id.starts_with("kingfisher.huggingface.") && !token.is_empty() {
        collector.record_huggingface(&token, fp());
    } else if id.starts_with("kingfisher.gitea.") && !token.is_empty() {
        collector.record_gitea(&token, fp());
    } else if id.starts_with("kingfisher.bitbucket.") && !token.is_empty() {
        collector.record_bitbucket(&token, fp());
    } else if id.starts_with("kingfisher.buildkite.") && !token.is_empty() {
        collector.record_buildkite(&token, fp());
    } else if id.starts_with("kingfisher.harness.") && !token.is_empty() {
        collector.record_harness(&token, fp());
    } else if id.starts_with("kingfisher.openai.") && !token.is_empty() {
        collector.record_openai(&token, fp());
    } else if id.starts_with("kingfisher.anthropic.") && !token.is_empty() {
        collector.record_anthropic(&token, fp());
    } else if id.starts_with("kingfisher.wandb.") && !token.is_empty() {
        collector.record_weightsandbiases(&token, fp());
    } else if (id.starts_with("kingfisher.msteams.")
        || id.starts_with("kingfisher.microsoftteamswebhook."))
        && !token.is_empty()
    {
        collector.record_microsoft_teams(&token, fp());
    } else if id.starts_with("kingfisher.airtable.") && !token.is_empty() {
        collector.record_airtable(&token, fp());
    } else if id.starts_with("kingfisher.circleci.") && !token.is_empty() {
        collector.record_circleci(&token, fp());
    } else if id.starts_with("kingfisher.digitalocean.") && !token.is_empty() {
        collector.record_digitalocean(&token, fp());
    } else if id.starts_with("kingfisher.fastly.") && !token.is_empty() {
        collector.record_fastly(&token, fp());
    } else if id.starts_with("kingfisher.hubspot.") && !token.is_empty() {
        collector.record_hubspot(&token, fp());
    } else if id.starts_with("kingfisher.ibm.") && !token.is_empty() {
        collector.record_ibm_cloud(&token, fp());
    } else if id.starts_with("kingfisher.sendgrid.") && !token.is_empty() {
        collector.record_sendgrid(&token, fp());
    } else if (id.starts_with("kingfisher.sendinblue.") || id.starts_with("kingfisher.brevo."))
        && !token.is_empty()
    {
        collector.record_sendinblue(&token, fp());
    } else if id.starts_with("kingfisher.square.") && !token.is_empty() {
        collector.record_square(&token, fp());
    } else if id.starts_with("kingfisher.stripe.") && !token.is_empty() {
        collector.record_stripe(&token, fp());
    } else if id.starts_with("kingfisher.terraform.") && !token.is_empty() {
        collector.record_terraform(&token, fp());
    } else if id.starts_with("kingfisher.monday.") && !token.is_empty() {
        collector.record_monday(&token, fp());
    } else if matches!(id, "kingfisher.asana.3" | "kingfisher.asana.4" | "kingfisher.asana.5")
        && !token.is_empty()
    {
        collector.record_asana(&token, fp());
    } else if id == "kingfisher.pinecone.1" && !token.is_empty() {
        collector.record_pinecone(&token, fp());
    } else if id.starts_with("kingfisher.azure.devops.") {
        let mut organization =
            utils::find_closest_variable(captures, &token, "TOKEN", "AZURE_DEVOPS_ORG")
                .unwrap_or_default();
        if organization.is_empty() {
            organization = extract_azure_devops_org_from_body(&om.validation_response_body)
                .unwrap_or_default();
        }
        if !token.is_empty() && !organization.is_empty() {
            collector.record_azure_devops(&token, &organization, fp());
        }
    } else if matches!(id, "kingfisher.azure.6" | "kingfisher.azure.9") {
        let tenant_id = utils::find_closest_variable(captures, &token, "TOKEN", "AZURE_TENANT_ID")
            .or_else(|| om.dependent_captures.get("AZURE_TENANT_ID").cloned())
            .unwrap_or_default();
        let client_id = utils::find_closest_variable(captures, &token, "TOKEN", "AZURE_CLIENT_ID")
            .or_else(|| om.dependent_captures.get("AZURE_CLIENT_ID").cloned())
            .unwrap_or_default();
        if !tenant_id.is_empty() && !client_id.is_empty() && !token.is_empty() {
            let credentials = serde_json::json!({
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": token,
            });
            collector.record_azure(&credentials.to_string(), None, fp());
        }
    } else if id == "kingfisher.alibabacloud.2" {
        let access_key = utils::find_closest_variable(captures, &token, "TOKEN", "AKID")
            .or_else(|| om.dependent_captures.get("AKID").cloned())
            .unwrap_or_default();
        if !access_key.is_empty() && !token.is_empty() {
            collector.record_alibaba(&access_key, &token, None, fp());
        }
    } else if id == "kingfisher.alibabacloud.5" {
        let access_key = utils::find_closest_variable(captures, &token, "TOKEN", "STS_AKID")
            .or_else(|| om.dependent_captures.get("STS_AKID").cloned())
            .unwrap_or_default();
        let session_token =
            utils::find_closest_variable(captures, &token, "TOKEN", "SECURITY_TOKEN")
                .or_else(|| om.dependent_captures.get("SECURITY_TOKEN").cloned())
                .unwrap_or_default();
        if !access_key.is_empty() && !token.is_empty() && !session_token.is_empty() {
            collector.record_alibaba(&access_key, &token, Some(&session_token), fp());
        }
    } else if id.starts_with("kingfisher.salesforce.") {
        let instance = capture_or_dependency(&["INSTANCE"], "INSTANCE");
        if !token.is_empty() && !instance.is_empty() {
            collector.record_salesforce(&token, &instance, fp());
        }
    } else if id.starts_with("kingfisher.algolia.") {
        let app_id = capture_or_dependency(&["APPID"], "APPID");
        if !token.is_empty() && !app_id.is_empty() {
            collector.record_algolia(&app_id, &token, fp());
        }
    } else if id.starts_with("kingfisher.artifactory.") && !token.is_empty() {
        let host = capture_or_dependency(&["HOST", "URL"], "HOST");
        collector.record_artifactory(&token, (!host.is_empty()).then_some(host.as_str()), fp());
    } else if id.starts_with("kingfisher.auth0.") {
        let client_id = capture_or_dependency(&["CLIENTID"], "CLIENTID");
        let domain = capture_or_dependency(&["DOMAIN"], "DOMAIN");
        if !token.is_empty() && !client_id.is_empty() && !domain.is_empty() {
            collector.record_auth0(&client_id, &token, &domain, fp());
        }
    } else if id.starts_with("kingfisher.jira.") {
        let domain = capture_or_dependency(&["DOMAIN", "URL"], "DOMAIN");
        if !token.is_empty() && !domain.is_empty() {
            let base_url =
                if domain.starts_with("http") { domain } else { format!("https://{domain}") };
            collector.record_jira(&token, &base_url, fp());
        }
    } else if id.starts_with("kingfisher.paypal.") {
        let client_id = capture_or_dependency(&["CLIENTID"], "CLIENTID");
        if !token.is_empty() && !client_id.is_empty() {
            collector.record_paypal(&client_id, &token, fp());
        }
    } else if id.starts_with("kingfisher.plaid.") {
        let client_id = capture_or_dependency(&["CLIENTID"], "CLIENTID");
        if !token.is_empty() && !client_id.is_empty() {
            collector.record_plaid(&client_id, &token, fp());
        }
    } else if id.starts_with("kingfisher.shopify.") {
        let subdomain = capture_or_dependency(&["DOMAIN", "SUBDOMAIN"], "DOMAIN");
        if !token.is_empty() && !subdomain.is_empty() {
            collector.record_shopify(&token, &subdomain, fp());
        }
    } else if id.starts_with("kingfisher.jfrog.") || id.starts_with("kingfisher.xray.") {
        if !token.is_empty() {
            let host = capture_or_dependency(&["HOST", "URL"], "HOST");
            collector.record_xray(&token, (!host.is_empty()).then_some(host.as_str()), fp());
        }
    } else if id.starts_with("kingfisher.zendesk.") {
        let subdomain = capture_or_dependency(&["SUBDOMAIN", "DOMAIN"], "SUBDOMAIN");
        if !token.is_empty() && !subdomain.is_empty() {
            collector.record_zendesk(&token, &subdomain, fp());
        }
    }
}

fn record_betterleaks_access_map(
    om: &OwnedBlobMatch,
    validation: &kingfisher_rules::rule::BetterleaksValidation,
    collector: &AccessMapCollector,
    captures: &[(String, String, usize, usize)],
    fingerprint: &str,
) {
    let Some(mapping) = validation.capabilities.access_map.as_ref() else {
        return;
    };
    let token = captures
        .iter()
        .find(|(name, ..)| name == "TOKEN")
        .map(|(_, value, ..)| value.as_str())
        .unwrap_or_default();
    if token.is_empty() {
        return;
    }
    let value = |input: &str| {
        let Some(source) = mapping.inputs.get(input).map(String::as_str) else {
            return "";
        };
        if source == "finding.secret" {
            return token;
        }
        source
            .strip_prefix("components.")
            .and_then(|id| validation.components.get(id))
            .and_then(|variable| om.dependent_captures.get(variable))
            .map(String::as_str)
            .unwrap_or_default()
    };
    let fp = || fingerprint.to_string();

    match mapping.handler {
        BetterleaksAccessMapHandler::Aws => {
            let secret = value("secret");
            if !secret.is_empty() {
                collector.record_aws(token, secret, None, fp());
            }
        }
        BetterleaksAccessMapHandler::Gcp => {
            collector.record_gcp(token, fp());
        }
        BetterleaksAccessMapHandler::AzureClientSecret => {
            let tenant_id = value("tenant_id");
            let client_id = value("client_id");
            if !tenant_id.is_empty() && !client_id.is_empty() {
                let credentials = serde_json::json!({
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "client_secret": token,
                });
                collector.record_azure(&credentials.to_string(), None, fp());
            }
        }
        BetterleaksAccessMapHandler::AzureStorage => {
            let account = value("account");
            if !account.is_empty() {
                let credentials = serde_json::json!({
                    "storage_account": account,
                    "storage_key": token,
                });
                collector.record_azure(&credentials.to_string(), None, fp());
            }
        }
        BetterleaksAccessMapHandler::Algolia => {
            let app_id = value("app_id");
            if !app_id.is_empty() {
                collector.record_algolia(app_id, token, fp());
            }
        }
        BetterleaksAccessMapHandler::Alibaba => {
            let access_key = value("access_key");
            if !access_key.is_empty() {
                let session_token = value("session_token");
                collector.record_alibaba(
                    access_key,
                    token,
                    (!session_token.is_empty()).then_some(session_token),
                    fp(),
                );
            }
        }
        BetterleaksAccessMapHandler::Artifactory => {
            let host = value("host");
            let base_url = if host.is_empty() {
                None
            } else if host.starts_with("http") {
                Some(host.to_string())
            } else {
                Some(format!("https://{host}"))
            };
            collector.record_artifactory(token, base_url.as_deref(), fp());
        }
        BetterleaksAccessMapHandler::Salesforce => {
            let instance = value("instance");
            if !instance.is_empty() {
                collector.record_salesforce(token, instance, fp());
            }
        }
        BetterleaksAccessMapHandler::Airtable => collector.record_airtable(token, fp()),
        BetterleaksAccessMapHandler::Anthropic => collector.record_anthropic(token, fp()),
        BetterleaksAccessMapHandler::Auth0 => {
            let client_id = value("client_id");
            let domain = value("domain");
            if !client_id.is_empty() && !domain.is_empty() {
                collector.record_auth0(client_id, token, domain, fp());
            }
        }
        BetterleaksAccessMapHandler::Buildkite => collector.record_buildkite(token, fp()),
        BetterleaksAccessMapHandler::Circleci => collector.record_circleci(token, fp()),
        BetterleaksAccessMapHandler::Fastly => collector.record_fastly(token, fp()),
        BetterleaksAccessMapHandler::Github => collector.record_github(token, fp()),
        BetterleaksAccessMapHandler::Gitlab => collector.record_gitlab(token, fp()),
        BetterleaksAccessMapHandler::Harness => collector.record_harness(token, fp()),
        BetterleaksAccessMapHandler::Huggingface => collector.record_huggingface(token, fp()),
        BetterleaksAccessMapHandler::IbmCloud => collector.record_ibm_cloud(token, fp()),
        BetterleaksAccessMapHandler::Monday => collector.record_monday(token, fp()),
        BetterleaksAccessMapHandler::Openai => collector.record_openai(token, fp()),
        BetterleaksAccessMapHandler::Paypal => {
            let client_id = value("client_id");
            if !client_id.is_empty() {
                collector.record_paypal(client_id, token, fp());
            }
        }
        BetterleaksAccessMapHandler::Pinecone => collector.record_pinecone(token, fp()),
        BetterleaksAccessMapHandler::Sendinblue => collector.record_sendinblue(token, fp()),
        BetterleaksAccessMapHandler::Stripe => collector.record_stripe(token, fp()),
        BetterleaksAccessMapHandler::WeightsAndBiases => {
            collector.record_weightsandbiases(token, fp());
        }
    }
}

fn extract_akid_from_body(body: &validation_body::ValidationResponseBody) -> Option<String> {
    static AKID_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?xi)\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b",
        )
        .expect("valid regex")
    });

    let text = validation_body::clone_as_string(body);
    AKID_RE.find(&text).map(|m| m.as_str().to_string())
}

fn extract_azure_storage_account_from_body(
    body: &validation_body::ValidationResponseBody,
) -> Option<String> {
    static ACCOUNT_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)Account:\s*([a-z0-9]{3,24})").expect("valid regex")
    });

    let text = validation_body::clone_as_string(body);
    ACCOUNT_RE.captures(&text).and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
}

fn extract_azure_storage_containers_from_body(
    body: &validation_body::ValidationResponseBody,
) -> Option<Vec<String>> {
    static CONTAINERS_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)Containers:\s*(\\[[^\\]]*\\])").expect("valid regex")
    });

    let text = validation_body::clone_as_string(body);
    let capture = CONTAINERS_RE
        .captures(&text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))?;
    serde_json::from_str::<Vec<String>>(&capture).ok()
}

#[allow(dead_code)] // Retained with the Azure DevOps access-map collector above.
fn extract_azure_devops_org_from_body(
    body: &validation_body::ValidationResponseBody,
) -> Option<String> {
    static ORG_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"(?i)https?://dev\.azure\.com/([a-z0-9][a-z0-9-]{0,61}[a-z0-9])"#)
            .expect("valid regex")
    });

    let text = validation_body::clone_as_string(body);
    ORG_RE.captures(&text).and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob::BlobId,
        matcher::{OwnedBlobMatch, SerializableCapture, SerializableCaptures},
        rules::rule::{Confidence, Rule, RuleSyntax},
        util::intern,
    };
    use smallvec::smallvec;
    use std::sync::Arc;

    fn make_owned_blob_match() -> OwnedBlobMatch {
        OwnedBlobMatch {
            rule: Arc::new(Rule::new(RuleSyntax {
                name: "panic-test".to_string(),
                id: "test.panic".to_string(),
                pattern: "panic".to_string(),
                min_entropy: 0.0,
                confidence: Confidence::Low,
                visible: true,
                examples: vec![],
                negative_examples: vec![],
                references: vec![],
                validation: None,
                revocation: None,
                depends_on_rule: vec![],
                pattern_requirements: None,
                tls_mode: None,
                path: None,
                betterleaks_filter: None,
                betterleaks_secret_group: None,
                authoritative: true,
                vectorscan_compatible: true,
            })),
            blob_id: BlobId::new(b"panic-test-blob"),
            finding_fingerprint: 1,
            matching_input_offset_span: OffsetSpan { start: 0, end: 5 },
            captures: SerializableCaptures {
                captures: smallvec![SerializableCapture {
                    name: None,
                    match_number: 0,
                    start: 0,
                    end: 5,
                    value: intern("panic"),
                }],
            },
            validation_response_body: None,
            validation_response_status: StatusCode::CONTINUE,
            validation_success: false,
            validation_outcome: kingfisher_core::ValidationOutcome::NotAttempted,
            calculated_entropy: 0.0,
            is_base64: false,
            dependent_captures: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn counted_validation_status_excludes_skipped_statuses() {
        assert!(!is_counted_validation_status(StatusCode::CONTINUE));
        assert!(!is_counted_validation_status(StatusCode::PRECONDITION_REQUIRED));
        assert!(is_counted_validation_status(StatusCode::OK));
        assert!(is_counted_validation_status(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn access_map_collector_dedupes_monday_and_asana_tokens() {
        let collector = AccessMapCollector::default();
        collector.record_monday("monday-token-1", "fp-2".into());
        collector.record_asana("2/asana-token-1", "fp-4".into());
        collector.record_monday("monday-token-1", "fp-1".into());
        collector.record_asana("2/asana-token-1", "fp-3".into());

        let requests = collector.into_collected_requests();
        assert_eq!(requests.len(), 2);
        match &requests[0].request {
            AccessMapRequest::Monday { token, .. } => assert_eq!(token, "monday-token-1"),
            other => panic!("unexpected request: {other:?}"),
        }
        assert_eq!(requests[0].finding_fingerprints, ["fp-1", "fp-2"]);
        match &requests[1].request {
            AccessMapRequest::Asana { token, .. } => assert_eq!(token, "2/asana-token-1"),
            other => panic!("unexpected request: {other:?}"),
        }
        assert_eq!(requests[1].finding_fingerprints, ["fp-3", "fp-4"]);
    }

    #[test]
    fn access_map_collector_dedupes_alibaba_credentials() {
        let collector = AccessMapCollector::default();
        collector.record_alibaba("LTAIexample", "secret-value", None, "fp-1".to_string());
        collector.record_alibaba("LTAIexample", "secret-value", None, "fp-2".to_string());

        let requests = collector.into_requests();
        assert_eq!(requests.len(), 1);
        match &requests[0] {
            AccessMapRequest::Alibaba { access_key, secret_key, session_token, .. } => {
                assert_eq!(access_key, "LTAIexample");
                assert_eq!(secret_key, "secret-value");
                assert!(session_token.is_none());
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn betterleaks_composite_aws_validation_feeds_access_map() {
        let mut rules = kingfisher_rules::get_betterleaks_rules(Some(Confidence::Low)).unwrap();
        let syntax = rules.rules.remove("betterleaks.aws-access-token").unwrap();
        let Some(Validation::Betterleaks(validation)) = syntax.validation.clone() else {
            panic!("expected Betterleaks validation");
        };
        let secret_variable = validation.components["aws-secret-access-key"].clone();
        let access_key = "AKIAIOSFODNN7EXAMPLE";
        let mut matched = make_owned_blob_match();
        matched.rule = Arc::new(Rule::new(syntax));
        matched.captures = SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: Some(intern("TOKEN")),
                match_number: 1,
                start: 0,
                end: access_key.len(),
                value: intern(access_key),
            }],
        };
        matched.dependent_captures.insert(secret_variable, "secret-access-key".to_string());
        let captures = utils::process_captures(&matched.captures);
        let collector = AccessMapCollector::default();

        record_betterleaks_access_map(&matched, &validation, &collector, &captures, "fp-aws");

        let requests = collector.into_requests();
        assert_eq!(requests.len(), 1);
        match &requests[0] {
            AccessMapRequest::Aws { access_key, secret_key, session_token, fingerprint } => {
                assert_eq!(access_key, "AKIAIOSFODNN7EXAMPLE");
                assert_eq!(secret_key, "secret-access-key");
                assert!(session_token.is_none());
                assert_eq!(fingerprint, "fp-aws");
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    fn betterleaks_match(
        syntax: RuleSyntax,
        token: &str,
        dependencies: &[(&str, &str)],
    ) -> OwnedBlobMatch {
        let mut matched = make_owned_blob_match();
        matched.rule = Arc::new(Rule::new(syntax));
        matched.captures = SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: Some(intern("TOKEN")),
                match_number: 1,
                start: 0,
                end: token.len(),
                value: intern(token),
            }],
        };
        matched.validation_success = true;
        matched
            .dependent_captures
            .extend(dependencies.iter().map(|(name, value)| (name.to_string(), value.to_string())));
        matched
    }

    #[test]
    fn new_betterleaks_rules_route_to_existing_access_map_handlers() {
        let mut rules = kingfisher_rules::get_betterleaks_rules(Some(Confidence::Low)).unwrap();
        let cases: [(&str, &str, &[(&str, &str)]); 3] = [
            (
                "betterleaks.auth0-client-secret.1",
                "auth0-client-secret",
                &[("AUTH0_CLIENT_ID_1", "auth0-client-id"), ("AUTH0_DOMAIN_1", "tenant.auth0.com")],
            ),
            ("betterleaks.monday-api-token.1", "monday-api-token", &[]),
            (
                "betterleaks.paypal-client-secret.1",
                "paypal-client-secret",
                &[("PAYPAL_CLIENT_ID_1", "paypal-client-id")],
            ),
        ];
        let collector = AccessMapCollector::default();

        for (id, token, dependencies) in cases {
            let syntax = rules.rules.remove(id).expect("generated rule should exist");
            let Some(Validation::Betterleaks(validation)) = syntax.validation.clone() else {
                panic!("{id} should use Betterleaks validation");
            };
            let matched = betterleaks_match(syntax, token, dependencies);
            let captures = utils::process_captures(&matched.captures);
            record_betterleaks_access_map(&matched, &validation, &collector, &captures, id);
        }

        let requests = collector.into_requests();
        assert!(requests.iter().any(|request| matches!(
            request,
            AccessMapRequest::Auth0 { client_id, client_secret, domain, .. }
                if client_id == "auth0-client-id"
                    && client_secret == "auth0-client-secret"
                    && domain == "tenant.auth0.com"
        )));
        assert!(requests.iter().any(|request| matches!(
            request,
            AccessMapRequest::Monday { token, .. } if token == "monday-api-token"
        )));
        assert!(requests.iter().any(|request| matches!(
            request,
            AccessMapRequest::PayPal { client_id, client_secret, .. }
                if client_id == "paypal-client-id" && client_secret == "paypal-client-secret"
        )));
    }

    fn legacy_match(id: &str, token: &str, dependencies: &[(&str, &str)]) -> OwnedBlobMatch {
        let mut matched = make_owned_blob_match();
        let mut syntax = matched.rule.syntax().clone();
        syntax.id = id.to_string();
        syntax.name = id.to_string();
        matched.rule = Arc::new(Rule::new(syntax));
        matched.captures = SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: Some(intern("TOKEN")),
                match_number: 1,
                start: 0,
                end: token.len(),
                value: intern(token),
            }],
        };
        matched.validation_success = true;
        matched
            .dependent_captures
            .extend(dependencies.iter().map(|(name, value)| (name.to_string(), value.to_string())));
        matched
    }

    #[test]
    fn legacy_ids_route_to_token_access_map_handlers() {
        let collector = AccessMapCollector::default();

        for (id, token) in [
            ("kingfisher.github.2", "github-token"),
            ("kingfisher.slack.1", "slack-token"),
            ("kingfisher.bitbucket.1", "bitbucket-token"),
        ] {
            maybe_record_access_map(&legacy_match(id, token, &[]), Some(&collector));
        }

        let requests = collector.into_requests();
        assert!(requests.iter().any(
            |request| matches!(request, AccessMapRequest::Github { token, .. } if token == "github-token")
        ));
        assert!(requests.iter().any(
            |request| matches!(request, AccessMapRequest::Slack { token, .. } if token == "slack-token")
        ));
        assert!(requests.iter().any(
            |request| matches!(request, AccessMapRequest::Bitbucket { token, .. } if token == "bitbucket-token")
        ));
    }

    #[test]
    fn veles_ids_route_to_token_access_map_handlers() {
        // Veles rules validate through `Validation::Http`, so they reach the
        // rule-ID dispatch rather than the Betterleaks handler dispatch. Without
        // an explicit arm they match nothing and access mapping is silently lost.
        let collector = AccessMapCollector::default();

        for (id, token) in [
            ("veles.secrets/slackappleveltoken", "xapp-token"),
            ("veles.secrets/digitaloceanapikey", "dop_v1_token"),
            ("veles.secrets/sendgrid", "SG.token"),
        ] {
            maybe_record_access_map(&legacy_match(id, token, &[]), Some(&collector));
        }

        let requests = collector.into_requests();
        assert!(requests.iter().any(
            |request| matches!(request, AccessMapRequest::Slack { token, .. } if token == "xapp-token")
        ));
        assert!(requests.iter().any(
            |request| matches!(request, AccessMapRequest::DigitalOcean { token, .. } if token == "dop_v1_token")
        ));
        assert!(requests.iter().any(
            |request| matches!(request, AccessMapRequest::SendGrid { token, .. } if token == "SG.token")
        ));
    }

    #[test]
    fn veles_rules_without_a_bearer_credential_are_not_access_mapped() {
        // The reported secret is a git URL, not an API bearer token.
        let collector = AccessMapCollector::default();

        maybe_record_access_map(
            &legacy_match(
                "veles.secrets/bitbucketcredentials",
                "https://u:p@bitbucket.org/t/r.git",
                &[],
            ),
            Some(&collector),
        );

        assert!(collector.into_requests().is_empty());
    }

    #[test]
    fn legacy_auth0_id_routes_multipart_credentials() {
        let collector = AccessMapCollector::default();
        let matched = legacy_match(
            "kingfisher.auth0.1",
            "client-secret",
            &[("CLIENTID", "client-id"), ("DOMAIN", "tenant.auth0.com")],
        );

        maybe_record_access_map(&matched, Some(&collector));

        let requests = collector.into_requests();
        assert!(matches!(
            requests.as_slice(),
            [AccessMapRequest::Auth0 { client_id, client_secret, domain, .. }]
                if client_id == "client-id"
                    && client_secret == "client-secret"
                    && domain == "tenant.auth0.com"
        ));
    }

    #[test]
    fn access_map_collector_keeps_aws_session_tokens() {
        let collector = AccessMapCollector::default();
        collector.record_aws(
            "ASIAIOSFODNN7EXAMPLE",
            "secret-value",
            Some("session-token"),
            "fp-1".to_string(),
        );

        let requests = collector.into_requests();
        assert_eq!(requests.len(), 1);
        match &requests[0] {
            AccessMapRequest::Aws { access_key, secret_key, session_token, .. } => {
                assert_eq!(access_key, "ASIAIOSFODNN7EXAMPLE");
                assert_eq!(secret_key, "secret-value");
                assert_eq!(session_token.as_deref(), Some("session-token"));
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[tokio::test]
    async fn catch_validation_panic_discards_panic_message() {
        let result = catch_validation_panic(async {
            panic!("validator blew up");
        })
        .await;

        assert_eq!(result.unwrap_err(), ());
    }

    #[tokio::test]
    async fn panic_outcome_is_reported_as_unavailable_and_cached() {
        let mut om = make_owned_blob_match();
        let cache_key = build_cache_key(&om);
        let cache = DashMap::new();
        let success_count = AtomicUsize::new(0);
        let fail_count = AtomicUsize::new(0);

        let outcome = ValidationRunOutcome::from_panic_result(
            catch_validation_panic(async {
                panic!("validator blew up");
            })
            .await,
        );

        apply_validation_outcome(&mut om, &cache_key, outcome, &success_count, &fail_count, &cache);

        assert!(!om.validation_success);
        assert_eq!(om.validation_response_status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(om.validation_outcome, kingfisher_core::ValidationOutcome::Unavailable);
        let body = validation_body::clone_as_string(&om.validation_response_body);
        assert!(body.contains("Validation panicked for rule test.panic"));
        // The raw panic payload must never leak into the user-visible body.
        assert!(!body.contains("validator blew up"));
        assert_eq!(success_count.load(Ordering::Relaxed), 0);
        assert_eq!(fail_count.load(Ordering::Relaxed), 0);

        let cached = cache.get(&cache_key).expect("panic result should be cached");
        assert!(!cached.is_valid);
        assert_eq!(cached.status, StatusCode::INTERNAL_SERVER_ERROR);
        let cached_body = validation_body::clone_as_string(&cached.body);
        assert!(cached_body.contains("Validation panicked for rule test.panic"));
        // The cached body must not retain the raw panic payload either.
        assert!(!cached_body.contains("validator blew up"));
    }
}
