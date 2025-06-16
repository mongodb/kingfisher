use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use serde::Serialize;
#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleStats {
    pub rule_id: String,
    pub rule_name: String,
    pub pattern: String,
    pub total_matches: u64,
    pub false_positives: u64,
    pub total_processing_time: Duration,
    pub average_match_time: Duration,
    pub slowest_match_time: Duration,
    pub fastest_match_time: Duration,
    pub slowest_filename: String,
    pub fastest_filename: String,
}
#[derive(Debug, Default, Clone)]
pub struct RuleProfile {
    pub stats: HashMap<String, RuleStats>,
}
// Thread-safe wrapper for concurrent profiling
pub struct ConcurrentRuleProfiler {
    // Change to store rules and times in the same RwLock
    inner: Arc<RwLock<ProfilerState>>,
}
#[derive(Default)]
struct ProfilerState {
    rules: HashMap<String, RuleStats>,
    start_times: HashMap<(String, String), (Instant, String)>, /* (rule_id, filename) ->
                                                                * (start_time, filename) */
}
impl ConcurrentRuleProfiler {
    pub fn new() -> Self {
        Self { inner: Arc::new(RwLock::new(ProfilerState::default())) }
    }

    pub fn start_rule(&self, rule_id: &str, rule_name: &str, pattern: &str, filename: &str) {
        let mut state = self.inner.write();
        // debug!("Starting rule: {} ({})", rule_name, rule_id);
        // Create composite key
        let key = (rule_id.to_string(), filename.to_string());
        state.start_times.insert(key, (Instant::now(), filename.to_string()));
        state.rules.entry(rule_id.to_string()).or_insert_with(|| {
            // debug!("Creating new stats for rule: {} ({})", rule_name, rule_id);
            RuleStats {
                rule_id: rule_id.to_string(),
                rule_name: rule_name.to_string(),
                pattern: pattern.to_string(),
                total_matches: 0,
                false_positives: 0,
                total_processing_time: Duration::default(),
                average_match_time: Duration::default(),
                slowest_match_time: Duration::default(),
                fastest_match_time: Duration::from_secs(u64::MAX),
                slowest_filename: String::new(),
                fastest_filename: String::new(),
            }
        });
        // debug!("Current rules count: {}", state.rules.len());
    }

    pub fn end_rule(
        &self,
        rule_id: &str,
        matched: bool,
        matches: u64,
        false_positives: u64,
        filename: &str,
    ) {
        let mut state = self.inner.write();
        let key = (rule_id.to_string(), filename.to_string());
        if let Some((start_time, filename)) = state.start_times.remove(&key) {
            let elapsed = start_time.elapsed();
            if let Some(stats) = state.rules.get_mut(rule_id) {
                stats.total_processing_time += elapsed;
                stats.total_matches += matches;
                stats.false_positives += false_positives;
                if matched {
                    if elapsed > stats.slowest_match_time {
                        stats.slowest_match_time = elapsed;
                        stats.slowest_filename = filename.clone();
                    }
                    if elapsed < stats.fastest_match_time {
                        stats.fastest_match_time = elapsed;
                        stats.fastest_filename = filename;
                    }
                    if stats.total_matches > 0 {
                        stats.average_match_time = Duration::from_nanos(
                            (stats.total_processing_time.as_nanos() / stats.total_matches as u128)
                                as u64,
                        );
                    }
                }
                // debug!(
                //     "Updated stats for rule {}: matches={}, false_pos={}",
                //     rule_id, stats.total_matches, stats.false_positives
                // );
            }
        }
    }

    fn generate_report_internal(&self, state: &ProfilerState) -> Vec<RuleStats> {
        // debug!("Generating report. Rules count: {}", state.rules.len());
        // let rules_present: Vec<_> = state.rules.keys().collect();
        // debug!("Rules present: {:?}", rules_present);
        let mut stats: Vec<_> = state.rules.values().cloned().collect();
        stats.sort_by(|a, b| b.slowest_match_time.cmp(&a.slowest_match_time));
        stats
    }

    pub fn generate_report(&self) -> Vec<RuleStats> {
        let state = self.inner.read();
        self.generate_report_internal(&state)
    }
    // pub fn export_json(&self) -> String {
    //     self.inner.read().export_json()
    // }
}
// Convenience RAII guard for timing rule execution
pub struct RuleTimer<'a> {
    profiler: &'a ConcurrentRuleProfiler,
    rule_id: String,
    filename: String,
    // start_time: Instant,
}
impl<'a> RuleTimer<'a> {
    pub fn new(
        profiler: &'a ConcurrentRuleProfiler,
        rule_id: &str,
        rule_name: &str,
        pattern: &str,
        filename: &str,
    ) -> Self {
        profiler.start_rule(rule_id, rule_name, pattern, filename);
        Self {
            profiler,
            rule_id: rule_id.to_string(),
            filename: filename.to_string(),
            // start_time: Instant::now(),
        }
    }

    pub fn end(self, matched: bool, matches: u64, false_positives: u64) {
        self.profiler.end_rule(&self.rule_id, matched, matches, false_positives, &self.filename);
    }
}
impl<'a> Drop for RuleTimer<'a> {
    fn drop(&mut self) {
        // In case end() wasn't called explicitly, record as no match
        if !std::thread::panicking() {
            self.profiler.end_rule(&self.rule_id, false, 0, 0, &self.filename);
        }
    }
}
