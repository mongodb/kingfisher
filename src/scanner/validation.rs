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
use liquid::Parser;
use reqwest::StatusCode;
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::sync::Notify;
use tracing::{debug, trace, warn};

use crate::{
    access_map::AccessMapRequest,
    blob::BlobId,
    findings_store::{FindingsStore, FindingsStoreMessage},
    location::OffsetSpan,
    matcher::OwnedBlobMatch,
    provider_endpoints::ProviderEndpointOverrides,
    rules::rule::Validation,
    validation::{
        CachedResponse, collect_variables_and_dependencies, utils, validate_single_match,
    },
    validation_body,
    validation_rate_limit::ValidationRateLimiter,
};

#[derive(Clone, Default)]
pub struct AccessMapCollector {
    inner: Arc<DashMap<u64, AccessMapRequest>>,
}

impl AccessMapCollector {
    pub fn record_aws(&self, access_key: &str, secret_key: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("aws|{access_key}|{secret_key}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Aws {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            session_token: None,
            fingerprint,
        });
    }

    pub fn record_gcp(&self, credential_json: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(credential_json.as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Gcp {
            credential_json: credential_json.to_string(),
            fingerprint,
        });
    }

    pub fn record_azure(
        &self,
        credential_json: &str,
        containers: Option<Vec<String>>,
        fingerprint: String,
    ) {
        let key = xxhash_rust::xxh3::xxh3_64(credential_json.as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Azure {
            credential_json: credential_json.to_string(),
            containers,
            fingerprint,
        });
    }

    pub fn record_azure_devops(&self, token: &str, organization: &str, fingerprint: String) {
        let key =
            xxhash_rust::xxh3::xxh3_64(format!("azure_devops|{organization}|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::AzureDevops {
            token: token.to_string(),
            organization: organization.to_string(),
            fingerprint,
        });
    }

    pub fn record_github(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("github|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Github { token: token.to_string(), fingerprint });
    }

    pub fn record_gitlab(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("gitlab|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Gitlab { token: token.to_string(), fingerprint });
    }

    pub fn record_slack(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("slack|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Slack { token: token.to_string(), fingerprint });
    }

    pub fn record_postgres(&self, uri: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("postgres|{uri}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Postgres { uri: uri.to_string(), fingerprint });
    }

    pub fn record_mongodb(&self, uri: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("mongodb|{uri}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::MongoDB { uri: uri.to_string(), fingerprint });
    }

    pub fn record_huggingface(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("huggingface|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::HuggingFace {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_gitea(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("gitea|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Gitea { token: token.to_string(), fingerprint });
    }

    pub fn record_bitbucket(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("bitbucket|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Bitbucket {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_buildkite(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("buildkite|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Buildkite {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_harness(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("harness|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Harness { token: token.to_string(), fingerprint });
    }

    pub fn record_openai(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("openai|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::OpenAI { token: token.to_string(), fingerprint });
    }

    pub fn record_anthropic(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("anthropic|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Anthropic {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_salesforce(&self, token: &str, instance: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("salesforce|{instance}|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Salesforce {
            token: token.to_string(),
            instance: instance.to_string(),
            fingerprint,
        });
    }

    pub fn record_weightsandbiases(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("weightsandbiases|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::WeightsAndBiases {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_microsoft_teams(&self, webhook_url: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("microsoft_teams|{webhook_url}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::MicrosoftTeams {
            webhook_url: webhook_url.to_string(),
            fingerprint,
        });
    }

    pub fn record_airtable(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("airtable|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Airtable {
            token: token.to_string(),
            fingerprint,
        });
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
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Alibaba {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            session_token: session_token.map(|value| value.to_string()),
            fingerprint,
        });
    }

    pub fn record_algolia(&self, app_id: &str, api_key: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("algolia|{app_id}|{api_key}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Algolia {
            app_id: app_id.to_string(),
            api_key: api_key.to_string(),
            fingerprint,
        });
    }

    pub fn record_artifactory(&self, token: &str, base_url: Option<&str>, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("artifactory|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Artifactory {
            token: token.to_string(),
            base_url: base_url.map(|s| s.to_string()),
            fingerprint,
        });
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
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Auth0 {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            domain: domain.to_string(),
            fingerprint,
        });
    }

    pub fn record_circleci(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("circleci|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::CircleCI {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_digitalocean(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("digitalocean|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::DigitalOcean {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_fastly(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("fastly|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Fastly { token: token.to_string(), fingerprint });
    }

    pub fn record_hubspot(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("hubspot|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::HubSpot { token: token.to_string(), fingerprint });
    }

    pub fn record_ibm_cloud(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("ibm_cloud|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::IbmCloud {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_jira(&self, token: &str, base_url: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("jira|{base_url}|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Jira {
            token: token.to_string(),
            base_url: base_url.to_string(),
            fingerprint,
        });
    }

    pub fn record_mysql(&self, uri: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("mysql|{uri}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::MySQL { uri: uri.to_string(), fingerprint });
    }

    pub fn record_paypal(&self, client_id: &str, client_secret: &str, fingerprint: String) {
        let key =
            xxhash_rust::xxh3::xxh3_64(format!("paypal|{client_id}|{client_secret}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::PayPal {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            fingerprint,
        });
    }

    pub fn record_plaid(&self, client_id: &str, secret: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("plaid|{client_id}|{secret}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Plaid {
            client_id: client_id.to_string(),
            secret: secret.to_string(),
            fingerprint,
        });
    }

    pub fn record_sendgrid(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("sendgrid|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::SendGrid {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_sendinblue(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("sendinblue|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Sendinblue {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_shopify(&self, token: &str, subdomain: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("shopify|{subdomain}|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Shopify {
            token: token.to_string(),
            subdomain: subdomain.to_string(),
            fingerprint,
        });
    }

    pub fn record_square(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("square|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Square { token: token.to_string(), fingerprint });
    }

    pub fn record_stripe(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("stripe|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Stripe { token: token.to_string(), fingerprint });
    }

    pub fn record_terraform(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("terraform|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Terraform {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn record_xray(&self, token: &str, base_url: Option<&str>, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("xray|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Xray {
            token: token.to_string(),
            base_url: base_url.map(|s| s.to_string()),
            fingerprint,
        });
    }

    pub fn record_zendesk(&self, token: &str, subdomain: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("zendesk|{subdomain}|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Zendesk {
            token: token.to_string(),
            subdomain: subdomain.to_string(),
            fingerprint,
        });
    }

    pub fn record_monday(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("monday|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Monday { token: token.to_string(), fingerprint });
    }

    pub fn record_asana(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("asana|{token}").as_bytes());
        self.inner
            .entry(key)
            .or_insert_with(|| AccessMapRequest::Asana { token: token.to_string(), fingerprint });
    }

    pub fn record_pinecone(&self, token: &str, fingerprint: String) {
        let key = xxhash_rust::xxh3::xxh3_64(format!("pinecone|{token}").as_bytes());
        self.inner.entry(key).or_insert_with(|| AccessMapRequest::Pinecone {
            token: token.to_string(),
            fingerprint,
        });
    }

    pub fn into_requests(self) -> Vec<AccessMapRequest> {
        self.inner.iter().map(|entry| entry.value().clone()).collect()
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
            let group_key = format!("{}|{}", arc_msg.2.rule.id(), secret);
            trace!(
                rule_id = %arc_msg.2.rule.id(),
                secret_value = %secret,
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
                let key = format!("{}|{}", rep_arc.2.rule.id(), secret);

                match val_res.entry(key.clone()) {
                    dashmap::mapref::entry::Entry::Occupied(_) => return,
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        entry.insert(CachedResponse {
                            body: validation_body::from_string(String::new()),
                            status: StatusCode::ACCEPTED,
                            is_valid: false,
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
                let key = format!("{}|{}", match_arc.2.rule.id(), secret);
                if let Some(cr) = validation_results.get(&key) {
                    let (_, _, existing) = Arc::make_mut(match_arc);
                    existing.validation_success = cr.is_valid;
                    existing.validation_response_status = cr.status.as_u16();
                    existing.validation_response_body = cr.body.clone();
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
                if let Some((success, body, status, dep_caps)) =
                    dep_updates.get(&match_arc.2.finding_fingerprint).cloned()
                {
                    let (_, _, existing) = Arc::make_mut(match_arc);
                    existing.validation_success = success;
                    existing.validation_response_status = status;
                    existing.validation_response_body = body;
                    existing.dependent_captures = dep_caps;
                }
            }
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
    let cache_key = build_cache_key(om);
    // Check cache first
    if let Some(cached) = cache.get(&cache_key) {
        om.validation_success = cached.is_valid;
        om.validation_response_body = cached.body.clone();
        om.validation_response_status = cached.status;
        if om.validation_success && is_counted_validation_status(om.validation_response_status) {
            success_count.fetch_add(1, Ordering::Relaxed);
        } else if is_counted_validation_status(om.validation_response_status) {
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
            if om.validation_success && is_counted_validation_status(om.validation_response_status)
            {
                success_count.fetch_add(1, Ordering::Relaxed);
            } else if is_counted_validation_status(om.validation_response_status) {
                fail_count.fetch_add(1, Ordering::Relaxed);
            }
            maybe_record_access_map(om, access_map);
            return; // Exit early if cached result is found
        }
        return;
    }
    // If we reach here, we're the first task to validate this key
    // Perform validation
    let outcome = ValidationOutcome::from_panic_result(
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
enum ValidationOutcome {
    /// Validation ran to completion; the match's own fields describe whether it
    /// succeeded or failed.
    Completed,
    /// Validation panicked. The payload is captured for logging only and must
    /// never be surfaced to the user or cache (it may embed secret material).
    Panicked(String),
}

impl ValidationOutcome {
    fn from_panic_result(result: std::result::Result<(), String>) -> Self {
        match result {
            Ok(()) => ValidationOutcome::Completed,
            Err(panic_message) => ValidationOutcome::Panicked(panic_message),
        }
    }
}

fn apply_validation_outcome(
    om: &mut OwnedBlobMatch,
    cache_key: &str,
    outcome: ValidationOutcome,
    success_count: &AtomicUsize,
    fail_count: &AtomicUsize,
    cache: &DashMap<String, CachedResponse>,
) {
    match outcome {
        ValidationOutcome::Completed => {
            if om.validation_success && is_counted_validation_status(om.validation_response_status)
            {
                success_count.fetch_add(1, Ordering::Relaxed);
            } else if is_counted_validation_status(om.validation_response_status) {
                fail_count.fetch_add(1, Ordering::Relaxed);
            }
            cache.insert(
                cache_key.to_owned(),
                CachedResponse {
                    is_valid: om.validation_success,
                    status: om.validation_response_status,
                    body: om.validation_response_body.clone(),
                    timestamp: Instant::now(),
                },
            );
        }
        ValidationOutcome::Panicked(panic_message) => {
            // The panic payload can embed secret material (e.g. a token captured
            // in a debug string), so it must never reach the cached or
            // user-visible body. Keep WARN free of the payload too; truncated
            // panic detail is only emitted at DEBUG for troubleshooting.
            warn!(
                rule_id = %om.rule.id(),
                "validator panicked; marking match as failed",
            );
            debug!(
                rule_id = %om.rule.id(),
                panic = %truncate_for_log(&panic_message),
                "validator panic detail",
            );
            om.validation_success = false;
            om.validation_response_body = validation_body::from_string(format!(
                "Validation panicked for rule {}",
                om.rule.id()
            ));
            om.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
            fail_count.fetch_add(1, Ordering::Relaxed);
            cache.insert(
                cache_key.to_owned(),
                CachedResponse {
                    is_valid: om.validation_success,
                    status: om.validation_response_status,
                    body: om.validation_response_body.clone(),
                    timestamp: Instant::now(),
                },
            );
        }
    }
}

fn is_counted_validation_status(status: StatusCode) -> bool {
    !matches!(status, StatusCode::CONTINUE | StatusCode::PRECONDITION_REQUIRED)
}

/// Defensive, last-resort boundary around a validator future.
///
/// Validators perform network I/O and parse untrusted responses, so a stray
/// `panic!`/`unwrap` would otherwise tear down the entire scan. We catch the
/// unwind here and surface it as `Err(message)` so the caller can fail just the
/// one match.
///
/// `AssertUnwindSafe` is required because the future borrows `&mut om`. It is
/// sound for this use because the unwind is never observed as a partial result:
/// on the panic path [`apply_validation_outcome`] unconditionally overwrites the
/// match's validation fields (`validation_success`, `validation_response_status`,
/// `validation_response_body`) with a deterministic failure state. The shared
/// counters and response cache are only mutated *after* this boundary returns,
/// so a panic cannot leave them inconsistent.
async fn catch_validation_panic<F>(future: F) -> std::result::Result<(), String>
where
    F: Future<Output = ()>,
{
    match AssertUnwindSafe(future).catch_unwind().await {
        Ok(()) => Ok(()),
        Err(payload) => Err(describe_panic_payload(payload)),
    }
}

fn describe_panic_payload(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Bound a panic message before it reaches the logs. Panic payloads are
/// unbounded in length and may be influenced by scanned content, so cap them at
/// a fixed length on a UTF-8 boundary.
fn truncate_for_log(message: &str) -> String {
    const MAX_LEN: usize = 256;
    if message.len() <= MAX_LEN {
        return message.to_string();
    }
    let mut end = MAX_LEN;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… (truncated)", &message[..end])
}

// Helper to compute the cache key for an OwnedBlobMatch.
fn build_cache_key(om: &OwnedBlobMatch) -> String {
    let capture0 =
        om.captures.captures.first().map_or(String::new(), |c| c.raw_value().to_string());

    let has_context_dependency = om
        .rule
        .syntax()
        .depends_on_rule
        .iter()
        .flatten()
        .any(|dep| !dep.variable.eq_ignore_ascii_case("TOKEN"));
    if has_context_dependency {
        return format!(
            "{}|{}|{}|{}|{}",
            om.rule.name(),
            capture0,
            om.blob_id,
            om.matching_input_offset_span.start,
            om.matching_input_offset_span.end
        );
    }

    format!("{}|{}", om.rule.name(), capture0)
}

fn maybe_record_access_map(om: &OwnedBlobMatch, collector: Option<&AccessMapCollector>) {
    let is_gitlab_rule = om.rule.id().starts_with("kingfisher.gitlab.");
    let validation_ok =
        om.validation_success || (is_gitlab_rule && om.validation_response_status.is_success());
    let collector = match collector {
        Some(c) if validation_ok => c,
        _ => return,
    };

    let captures = utils::process_captures(&om.captures);
    let fp = om.finding_fingerprint.to_string();

    match om.rule.syntax().validation {
        Some(Validation::AWS) => {
            let secret = captures
                .iter()
                .find(|(name, ..)| name == "TOKEN")
                .map(|(_, value, ..)| value.clone())
                .unwrap_or_default();

            let mut akid =
                utils::find_closest_variable(&captures, secret.as_str(), "TOKEN", "AKID")
                    .unwrap_or_default();

            if akid.is_empty() {
                akid = extract_akid_from_body(&om.validation_response_body).unwrap_or_default();
            }

            if !akid.is_empty() && !secret.is_empty() {
                collector.record_aws(&akid, &secret, fp.clone());
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
        _ => {
            if om.rule.id().starts_with("kingfisher.github.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_github(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.azure.devops.") {
                let token = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let mut organization = utils::find_closest_variable(
                    &captures,
                    token.as_str(),
                    "TOKEN",
                    "AZURE_DEVOPS_ORG",
                )
                .unwrap_or_default();
                if organization.is_empty() {
                    organization = extract_azure_devops_org_from_body(&om.validation_response_body)
                        .unwrap_or_default();
                }

                if !token.is_empty() && !organization.is_empty() {
                    collector.record_azure_devops(&token, &organization, fp.clone());
                }
            }
            if om.rule.id() == "kingfisher.alibabacloud.2" {
                let secret_key = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let access_key =
                    utils::find_closest_variable(&captures, secret_key.as_str(), "TOKEN", "AKID")
                        .or_else(|| om.dependent_captures.get("AKID").cloned())
                        .unwrap_or_default();

                if !access_key.is_empty() && !secret_key.is_empty() {
                    collector.record_alibaba(&access_key, &secret_key, None, fp.clone());
                }
            }
            if om.rule.id() == "kingfisher.alibabacloud.5" {
                let secret_key = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let access_key = utils::find_closest_variable(
                    &captures,
                    secret_key.as_str(),
                    "TOKEN",
                    "STS_AKID",
                )
                .or_else(|| om.dependent_captures.get("STS_AKID").cloned())
                .unwrap_or_default();
                let session_token = utils::find_closest_variable(
                    &captures,
                    secret_key.as_str(),
                    "TOKEN",
                    "SECURITY_TOKEN",
                )
                .or_else(|| om.dependent_captures.get("SECURITY_TOKEN").cloned())
                .unwrap_or_default();

                if !access_key.is_empty() && !secret_key.is_empty() && !session_token.is_empty() {
                    collector.record_alibaba(
                        &access_key,
                        &secret_key,
                        Some(&session_token),
                        fp.clone(),
                    );
                }
            }
            if is_gitlab_rule
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_gitlab(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.slack.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_slack(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.huggingface.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_huggingface(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.gitea.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_gitea(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.bitbucket.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_bitbucket(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.buildkite.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_buildkite(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.harness.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_harness(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.openai.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_openai(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.anthropic.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_anthropic(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.salesforce.") {
                let token = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let instance = captures
                    .iter()
                    .find(|(name, ..)| name == "INSTANCE")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("INSTANCE").cloned())
                    .unwrap_or_default();

                if !token.is_empty() && !instance.is_empty() {
                    collector.record_salesforce(&token, &instance, fp.clone());
                }
            }
            if om.rule.id().starts_with("kingfisher.wandb.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_weightsandbiases(value, fp.clone());
            }
            if (om.rule.id().starts_with("kingfisher.msteams.")
                || om.rule.id().starts_with("kingfisher.microsoftteamswebhook."))
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_microsoft_teams(value, fp.clone());
            }
            // --- New providers ---
            if om.rule.id().starts_with("kingfisher.airtable.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_airtable(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.algolia.") {
                let api_key = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let app_id = captures
                    .iter()
                    .find(|(name, ..)| name == "APPID")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("APPID").cloned())
                    .unwrap_or_default();
                if !api_key.is_empty() && !app_id.is_empty() {
                    collector.record_algolia(&app_id, &api_key, fp.clone());
                }
            }
            if om.rule.id().starts_with("kingfisher.artifactory.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                let base_url = captures
                    .iter()
                    .find(|(name, ..)| name == "HOST" || name == "URL")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("HOST").cloned());
                collector.record_artifactory(value, base_url.as_deref(), fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.auth0.") {
                let client_secret = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let client_id = captures
                    .iter()
                    .find(|(name, ..)| name == "CLIENTID")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("CLIENTID").cloned())
                    .unwrap_or_default();
                let domain = captures
                    .iter()
                    .find(|(name, ..)| name == "DOMAIN")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("DOMAIN").cloned())
                    .unwrap_or_default();
                if !client_secret.is_empty() && !client_id.is_empty() && !domain.is_empty() {
                    collector.record_auth0(&client_id, &client_secret, &domain, fp.clone());
                }
            }
            if om.rule.id().starts_with("kingfisher.circleci.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_circleci(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.digitalocean.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_digitalocean(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.fastly.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_fastly(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.hubspot.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_hubspot(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.ibm.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_ibm_cloud(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.jira.") {
                let token = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let base_url = captures
                    .iter()
                    .find(|(name, ..)| name == "DOMAIN" || name == "URL")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("DOMAIN").cloned())
                    .unwrap_or_default();
                if !token.is_empty() && !base_url.is_empty() {
                    let url = if base_url.starts_with("http") {
                        base_url
                    } else {
                        format!("https://{base_url}")
                    };
                    collector.record_jira(&token, &url, fp.clone());
                }
            }
            if om.rule.id().starts_with("kingfisher.paypal.") {
                let client_secret = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let client_id = captures
                    .iter()
                    .find(|(name, ..)| name == "CLIENTID")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("CLIENTID").cloned())
                    .unwrap_or_default();
                if !client_secret.is_empty() && !client_id.is_empty() {
                    collector.record_paypal(&client_id, &client_secret, fp.clone());
                }
            }
            if om.rule.id().starts_with("kingfisher.plaid.") {
                let secret = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let client_id = captures
                    .iter()
                    .find(|(name, ..)| name == "CLIENTID")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("CLIENTID").cloned())
                    .unwrap_or_default();
                if !secret.is_empty() && !client_id.is_empty() {
                    collector.record_plaid(&client_id, &secret, fp.clone());
                }
            }
            if om.rule.id().starts_with("kingfisher.sendgrid.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_sendgrid(value, fp.clone());
            }
            if (om.rule.id().starts_with("kingfisher.sendinblue.")
                || om.rule.id().starts_with("kingfisher.brevo."))
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_sendinblue(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.shopify.") {
                let token = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let subdomain = captures
                    .iter()
                    .find(|(name, ..)| name == "DOMAIN" || name == "SUBDOMAIN")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("DOMAIN").cloned())
                    .unwrap_or_default();
                if !token.is_empty() && !subdomain.is_empty() {
                    collector.record_shopify(&token, &subdomain, fp.clone());
                }
            }
            if om.rule.id().starts_with("kingfisher.square.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_square(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.stripe.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_stripe(value, fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.terraform.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_terraform(value, fp.clone());
            }
            if (om.rule.id().starts_with("kingfisher.jfrog.")
                || om.rule.id().starts_with("kingfisher.xray."))
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                let base_url = captures
                    .iter()
                    .find(|(name, ..)| name == "HOST" || name == "URL")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("HOST").cloned());
                collector.record_xray(value, base_url.as_deref(), fp.clone());
            }
            if om.rule.id().starts_with("kingfisher.zendesk.") {
                let token = captures
                    .iter()
                    .find(|(name, ..)| name == "TOKEN")
                    .map(|(_, value, ..)| value.clone())
                    .unwrap_or_default();
                let subdomain = captures
                    .iter()
                    .find(|(name, ..)| name == "SUBDOMAIN" || name == "DOMAIN")
                    .map(|(_, value, ..)| value.clone())
                    .or_else(|| om.dependent_captures.get("SUBDOMAIN").cloned())
                    .unwrap_or_default();
                if !token.is_empty() && !subdomain.is_empty() {
                    collector.record_zendesk(&token, &subdomain, fp.clone());
                }
            }
            if om.rule.id().starts_with("kingfisher.monday.")
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_monday(value, fp.clone());
            }
            // Only Asana rules whose TOKEN capture is a standalone access/PAT:
            // .3 (legacy 0/...), .4 (V1 1/...), .5 (V2 2/...). Rule .1 is a client ID
            // and .2 is a client secret that cannot be used alone to enumerate resources.
            if matches!(
                om.rule.id(),
                "kingfisher.asana.3" | "kingfisher.asana.4" | "kingfisher.asana.5"
            ) && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_asana(value, fp.clone());
            }
            if om.rule.id() == "kingfisher.pinecone.1"
                && let Some((_, value, ..)) = captures.iter().find(|(name, ..)| name == "TOKEN")
                && !value.is_empty()
            {
                collector.record_pinecone(value, fp.clone());
            }
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
        collector.record_monday("monday-token-1", "fp-1".into());
        collector.record_monday("monday-token-1", "fp-2".into());
        collector.record_asana("2/asana-token-1", "fp-3".into());
        collector.record_asana("2/asana-token-1", "fp-4".into());

        let mut requests = collector.into_requests();
        requests.sort_by_key(|r| match r {
            AccessMapRequest::Monday { .. } => 0,
            AccessMapRequest::Asana { .. } => 1,
            _ => 2,
        });
        assert_eq!(requests.len(), 2);
        match &requests[0] {
            AccessMapRequest::Monday { token, .. } => assert_eq!(token, "monday-token-1"),
            other => panic!("unexpected request: {other:?}"),
        }
        match &requests[1] {
            AccessMapRequest::Asana { token, .. } => assert_eq!(token, "2/asana-token-1"),
            other => panic!("unexpected request: {other:?}"),
        }
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

    #[tokio::test]
    async fn catch_validation_panic_returns_panic_message() {
        let result = catch_validation_panic(async {
            panic!("validator blew up");
        })
        .await;

        assert_eq!(result.unwrap_err(), "validator blew up");
    }

    #[tokio::test]
    async fn panic_outcome_is_reported_as_failure_and_cached() {
        let mut om = make_owned_blob_match();
        let cache_key = build_cache_key(&om);
        let cache = DashMap::new();
        let success_count = AtomicUsize::new(0);
        let fail_count = AtomicUsize::new(0);

        let outcome = ValidationOutcome::from_panic_result(
            catch_validation_panic(async {
                panic!("validator blew up");
            })
            .await,
        );

        apply_validation_outcome(&mut om, &cache_key, outcome, &success_count, &fail_count, &cache);

        assert!(!om.validation_success);
        assert_eq!(om.validation_response_status, StatusCode::INTERNAL_SERVER_ERROR);
        let body = validation_body::clone_as_string(&om.validation_response_body);
        assert!(body.contains("Validation panicked for rule test.panic"));
        // The raw panic payload must never leak into the user-visible body.
        assert!(!body.contains("validator blew up"));
        assert_eq!(success_count.load(Ordering::Relaxed), 0);
        assert_eq!(fail_count.load(Ordering::Relaxed), 1);

        let cached = cache.get(&cache_key).expect("panic result should be cached");
        assert!(!cached.is_valid);
        assert_eq!(cached.status, StatusCode::INTERNAL_SERVER_ERROR);
        let cached_body = validation_body::clone_as_string(&cached.body);
        assert!(cached_body.contains("Validation panicked for rule test.panic"));
        // The cached body must not retain the raw panic payload either.
        assert!(!cached_body.contains("validator blew up"));
    }
}
