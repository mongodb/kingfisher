use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;
use futures::{stream, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use liquid::Parser;
use reqwest::{Client, StatusCode};
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::{sync::Notify, time::timeout};

use crate::{
    blob::BlobId,
    findings_store::{FindingsStore, FindingsStoreMessage},
    location::OffsetSpan,
    matcher::{Match, OwnedBlobMatch},
    rules::rule,
    validation::{collect_variables_and_dependencies, validate_single_match, CachedResponse},
};

#[allow(clippy::too_many_arguments)]
pub async fn run_secret_validation(
    datastore: Arc<Mutex<FindingsStore>>,
    parser: &Parser,
    client: &Client,
    cache: &Arc<SkipMap<String, CachedResponse>>,
    num_jobs: usize,
) -> Result<()> {
    // ── 1. Concurrency & counters ───────────────────────────────────────────
    let concurrency = if num_jobs > 0 { num_jobs } else { num_cpus::get() };
    let chunk_size = std::cmp::max(concurrency * 50, 200);
    let success_count = Arc::new(AtomicUsize::new(0));
    let fail_count = Arc::new(AtomicUsize::new(0));

    // ── 2. Fetch rules + matches ────────────────────────────────────────────
    let (all_rules, all_matches_by_blob) = {
        let ds = datastore.lock().unwrap();
        let rules = ds.get_rules()?;
        let mut map: FxHashMap<BlobId, Vec<Arc<FindingsStoreMessage>>> = FxHashMap::default();
        for arc_msg in ds.get_matches().iter().map(Arc::clone) {
            map.entry(arc_msg.1.id).or_default().push(arc_msg);
        }
        (rules, map)
    };

    // ── 3. Partition blobs ──────────────────────────────────────────────────
    let rules_with_deps: FxHashSet<&str> = all_rules
        .iter()
        .filter(|r| !r.syntax().depends_on_rule.is_empty())
        .map(|r| r.id())
        .collect();

    let mut simple_matches = Vec::new();
    let mut dependent_blobs = FxHashMap::default(); // blob_id -- Vec<Arc<…>>
    for (blob_id, matches) in all_matches_by_blob {
        if matches.iter().any(|m| rules_with_deps.contains(m.2.rule_text_id)) {
            dependent_blobs.insert(blob_id, matches);
        } else {
            simple_matches.extend(matches);
        }
    }

    // Result accumulator
    let mut updated_arcs: Vec<Arc<FindingsStoreMessage>> = Vec::new();

    // ── Phase 1: simple, global de-dupe ──────────────────────────────────────
    if !simple_matches.is_empty() {
        let mut groups: FxHashMap<String, Vec<Arc<FindingsStoreMessage>>> = FxHashMap::default();
        for arc_msg in simple_matches {
            let secret = arc_msg
                .2
                .groups
                .captures
                .get(1)
                .or_else(|| arc_msg.2.groups.captures.get(0))
                .map_or("", |c| c.value.as_ref());
            groups
                .entry(format!("{}|{}", arc_msg.2.rule_text_id, secret))
                .or_default()
                .push(arc_msg);
        }

        let validation_results = DashMap::<String, CachedResponse>::new();

        let pb = ProgressBar::new(groups.len() as u64).with_message("Validating secrets…");
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{bar:40.green/blue}] {pos}/{len} ({percent}%) \
                 [{elapsed_precise}]",
            )?
            .progress_chars("=>-")
            .tick_chars("|/-\\"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));

        stream::iter(
            groups.values().map(|v| v[0].clone()), // one representative
        )
        .for_each_concurrent(concurrency, |rep_arc| {
            // clones into task
            let parser = parser.clone();
            let client = client.clone();
            let cache_glob = cache.clone();
            let val_res = &validation_results;
            let rules = &all_rules;
            let success = success_count.clone();
            let fail = fail_count.clone();
            // *** FIX: Clone the progress bar for each concurrent task ***
            let pb = pb.clone();

            async move {
                let secret = rep_arc
                    .2
                    .groups
                    .captures
                    .get(1)
                    .or_else(|| rep_arc.2.groups.captures.get(0))
                    .map_or("", |c| c.value.as_ref());
                let key = format!("{}|{}", rep_arc.2.rule_text_id, secret);

                match val_res.entry(key.clone()) {
                    dashmap::mapref::entry::Entry::Occupied(_) => return,
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        // *** FIX: Corrected placeholder to match struct definition ***
                        entry.insert(CachedResponse {
                            body: String::new(),
                            status: StatusCode::ACCEPTED,
                            is_valid: false,
                            timestamp: Instant::now(),
                        });
                    }
                }

                let rule = find_rule_for_match(rules, rep_arc.2.rule_text_id).unwrap();
                let mut om = OwnedBlobMatch::convert_match_to_owned_blobmatch(&rep_arc.2, rule);

                validate_single(
                    &mut om,
                    &parser,
                    &client,
                    &FxHashMap::default(),
                    &FxHashMap::default(),
                    &Arc::new(DashMap::new()),
                    &Arc::new(DashMap::new()),
                    &success,
                    &fail,
                    &cache_glob,
                )
                .await;

                let cr = CachedResponse {
                    body: om.validation_response_body.clone(),
                    status: om.validation_response_status,
                    is_valid: om.validation_success,
                    timestamp: Instant::now(),
                };
                val_res.insert(key, cr);

                // Now we use the cloned `pb`
                pb.inc(1);
            }
        })
        .await;
        // This is now valid because the original `pb` was never moved
        pb.finish();

        for (key, group) in groups {
            let cr = validation_results.get(&key).expect("missing cached result");
            for arc_msg in group {
                let (origin, blob_md, old_match) = &*arc_msg;
                updated_arcs.push(Arc::new((
                    origin.clone(),
                    blob_md.clone(),
                    Match {
                        validation_success: cr.is_valid,
                        validation_response_status: cr.status.as_u16(),
                        validation_response_body: cr.body.clone(),
                        ..old_match.clone()
                    },
                )));
            }
        }
    }

    // ── Phase 2: blobs with dependencies (original logic) ───────────────────
    if !dependent_blobs.is_empty() {
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
        let rules_ref = Arc::new(all_rules.clone());

        for chunk in blob_ids.chunks(chunk_size) {
            let tasks: Vec<_> = chunk
                .iter()
                .map(|blob_id| {
                    let matches_for_blob = dependent_blobs.get(blob_id).unwrap().clone();
                    let parser = parser.clone();
                    let client = client.clone();
                    let val_cache = val_cache.clone();
                    let in_flight = in_flight.clone();
                    let success = success_count.clone();
                    let fail = fail_count.clone();
                    let cache_glob = cache.clone();
                    let rules = rules_ref.clone();

                    async move {
                        let owned = matches_for_blob
                            .iter()
                            .map(|arc_msg| {
                                let rule = find_rule_for_match(&rules, arc_msg.2.rule_text_id)
                                    .expect("rule");
                                OwnedBlobMatch::convert_match_to_owned_blobmatch(&arc_msg.2, rule)
                            })
                            .collect::<Vec<_>>();

                        let (dep_vars, missing_deps) = collect_variables_and_dependencies(&owned);

                        let mut by_key: FxHashMap<String, Vec<OwnedBlobMatch>> =
                            FxHashMap::default();
                        for om in owned {
                            by_key.entry(build_cache_key(&om, &dep_vars)).or_default().push(om);
                        }
                        let reps: Vec<_> =
                            by_key.into_iter().map(|(_k, mut v)| (v.remove(0), v)).collect();

                        let validated: Vec<_> =
                            stream::iter(reps.into_iter().map(|(mut rep, mut dups)| {
                                let parser = parser.clone();
                                let client = client.clone();
                                let dep_vars = dep_vars.clone();
                                let miss_deps = missing_deps.clone();
                                let val_cache = val_cache.clone();
                                let in_flight = in_flight.clone();
                                let success = success.clone();
                                let fail = fail.clone();
                                let cache_glob = cache_glob.clone();

                                async move {
                                    validate_single(
                                        &mut rep,
                                        &parser,
                                        &client,
                                        &dep_vars,
                                        &miss_deps,
                                        &val_cache,
                                        &in_flight,
                                        &success,
                                        &fail,
                                        &cache_glob,
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
                            }))
                            .buffer_unordered(concurrency)
                            .collect()
                            .await;

                        validated.into_iter().flatten().collect::<Vec<_>>()
                    }
                })
                .collect();

            let validated_blobs: Vec<Vec<OwnedBlobMatch>> =
                stream::iter(tasks).buffer_unordered(concurrency).collect().await;

            for blob_vec in validated_blobs {
                if blob_vec.is_empty() {
                    continue;
                }

                let map_original: FxHashMap<u64, _> = dependent_blobs
                    .get(&blob_vec[0].blob_id)
                    .unwrap()
                    .iter()
                    .map(|arc_msg| (arc_msg.2.finding_fingerprint, arc_msg.clone()))
                    .collect();

                for om in blob_vec {
                    let orig = map_original.get(&om.finding_fingerprint).unwrap();

                    updated_arcs.push(Arc::new((
                        orig.0.clone(),
                        orig.1.clone(),
                        Match {
                            validation_success: om.validation_success,
                            validation_response_body: om.validation_response_body.clone(),
                            validation_response_status: om.validation_response_status.as_u16(),
                            ..orig.2.clone()
                        },
                    )));
                }
            }
            pb.inc(chunk.len() as u64);
        }
        pb.finish();
    }

    // ── 4. Persist all updates ──────────────────────────────────────────────
    {
        let mut ds = datastore.lock().unwrap();
        ds.replace_matches(updated_arcs);
    }

    // ── 5. Done ─────────────────────────────────────────────────────────────
    println!(
        "Validation complete – {} succeeded, {} failed",
        success_count.load(Ordering::Relaxed),
        fail_count.load(Ordering::Relaxed)
    );
    Ok(())
}

/// Returns `Some(Arc<Rule>)` if a matching rule is found; otherwise returns `None`.
/// Callers can decide how to handle the `None` case (e.g., skip processing).
fn find_rule_for_match(
    all_rules: &[Arc<rule::Rule>],
    rule_text_id: &str,
) -> Option<Arc<rule::Rule>> {
    match all_rules.iter().find(|r| r.syntax().id == rule_text_id).cloned() {
        Some(rule) => Some(rule),
        None => {
            eprintln!("Warning: no rule found with id '{}'. Skipping.", rule_text_id);
            None
        }
    }
}

// ---------------------------------------------------
// The core validation logic, used in an async pipeline
// ---------------------------------------------------
async fn validate_single(
    om: &mut OwnedBlobMatch,
    parser: &Parser,
    client: &Client,
    dep_vars: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    missing_deps: &FxHashMap<String, Vec<String>>,
    cache: &DashMap<String, CachedResponse>,
    in_progress: &DashMap<String, ()>,
    success_count: &AtomicUsize,
    fail_count: &AtomicUsize,
    cache2: &Arc<SkipMap<String, CachedResponse>>,
) {
    // Bypass validation if the rule is prevalidated (eg a Private Key)
    if om.rule.syntax().prevalidated {
        om.validation_success = true;
        om.validation_response_status = http::StatusCode::OK;
        om.validation_response_body = "Prevalidated".to_string();
        success_count.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Build key
    let dep_vars_str = dep_vars
        .get(om.rule.id())
        .map(|hm| {
            let mut sorted: Vec<_> = hm.iter().collect();
            sorted.sort_by(|(k, _), (k2, _)| k.cmp(k2));
            sorted.into_iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("|")
        })
        .unwrap_or_default();
    let capture0 = om.captures.captures.get(0).map_or(String::new(), |c| c.value.to_string());
    let cache_key = format!("{}|{}|{}", om.rule.name(), capture0, dep_vars_str);
    // Check cache first
    if let Some(cached) = cache.get(&cache_key) {
        om.validation_success = cached.is_valid;
        om.validation_response_body = cached.body.clone();
        om.validation_response_status = cached.status;
        if om.validation_success {
            success_count.fetch_add(1, Ordering::Relaxed);
        } else if om.validation_response_status != http::StatusCode::CONTINUE {
            fail_count.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }

    static NOTIFY: once_cell::sync::Lazy<DashMap<String, Arc<Notify>>> =
        once_cell::sync::Lazy::new(DashMap::new);

    let notify = NOTIFY.entry(cache_key.clone()).or_insert_with(|| Arc::new(Notify::new())).clone();
    let first = in_progress.insert(cache_key.clone(), ()).is_none();
    if !first {
        notify.notified().await; // suspend with zero polling
                                 // cached result now present
        if let Some(cached) = cache.get(&cache_key) {
            om.validation_success = cached.is_valid;
            om.validation_response_body = cached.body.clone();
            om.validation_response_status = cached.status;
            if om.validation_success {
                success_count.fetch_add(1, Ordering::Relaxed);
            } else if om.validation_response_status != http::StatusCode::CONTINUE {
                fail_count.fetch_add(1, Ordering::Relaxed);
            }
            return; // Exit early if cached result is found
        }
        return;
    }
    // If we reach here, we're the first task to validate this key
    // Perform validation
    let outcome = timeout(Duration::from_secs(30), async {
        validate_single_match(om, parser, client, dep_vars, missing_deps, cache2).await
    })
    .await;
    // Store result in cache
    match outcome {
        Ok(_) => {
            if om.validation_success {
                success_count.fetch_add(1, Ordering::Relaxed);
            } else if om.validation_response_status != http::StatusCode::CONTINUE {
                fail_count.fetch_add(1, Ordering::Relaxed);
            }
            cache.insert(
                cache_key.clone(),
                CachedResponse {
                    is_valid: om.validation_success,
                    status: om.validation_response_status,
                    body: om.validation_response_body.clone(),
                    timestamp: Instant::now(),
                },
            );
        }
        Err(_) => {
            om.validation_success = false;
            om.validation_response_body = "Validation timed out".to_string();
            om.validation_response_status = http::StatusCode::REQUEST_TIMEOUT;
            fail_count.fetch_add(1, Ordering::Relaxed);
        }
    }
    // Remove from `in_progress`
    // in_progress.remove(&cache_key);
    in_progress.remove(&cache_key);
    if let Some(n) = NOTIFY.remove(&cache_key) {
        n.1.notify_waiters(); // wake everyone
    }
}

// Helper to compute the cache key for an OwnedBlobMatch
fn build_cache_key(
    om: &OwnedBlobMatch,
    dep_vars: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
) -> String {
    // Build key
    let dep_vars_str = dep_vars
        .get(om.rule.id())
        .map(|hm| {
            let mut sorted: Vec<_> = hm.iter().collect();
            sorted.sort_by(|(k, _), (k2, _)| k.cmp(k2));
            sorted.into_iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("|")
        })
        .unwrap_or_default();
    // For demonstration, we’ll do a simplistic approach
    // You can adapt from your existing logic
    let capture0 = om.captures.captures.get(0).map_or(String::new(), |c| c.value.to_string());
    format!("{}|{}|{}", om.rule.name(), capture0, dep_vars_str)
}
