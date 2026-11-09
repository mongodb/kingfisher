use std::{
    collections::HashMap,
    sync::Arc,
    thread::{self, ThreadId},
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
    /// Aggregate confirmation/filter-stage time, excluding native scanning and candidate indexing.
    pub total_processing_time: Duration,
    /// Aggregate stage time divided by accepted matches, not candidate latency.
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

pub struct ConcurrentRuleProfiler {
    inner: Arc<RwLock<ProfilerState>>,
}

#[derive(Default)]
struct ProfilerState {
    rules: HashMap<String, RuleStats>,
    // Preserve the explicit start/end API, including nested calls on one thread.
    // RAII timers keep their own Instant and never populate this map.
    start_times: HashMap<(ThreadId, String, String), Vec<Instant>>,
}

impl Default for ConcurrentRuleProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl ConcurrentRuleProfiler {
    pub fn new() -> Self {
        Self { inner: Arc::new(RwLock::new(ProfilerState::default())) }
    }

    fn ensure_rule(&self, rule_id: &str, rule_name: &str, pattern: &str) {
        if self.inner.read().rules.contains_key(rule_id) {
            return;
        }
        self.inner.write().rules.entry(rule_id.to_string()).or_insert_with(|| RuleStats {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            pattern: pattern.to_string(),
            fastest_match_time: Duration::from_secs(u64::MAX),
            ..RuleStats::default()
        });
    }

    pub fn start_rule(&self, rule_id: &str, rule_name: &str, pattern: &str, filename: &str) {
        self.ensure_rule(rule_id, rule_name, pattern);
        let key = (thread::current().id(), rule_id.to_string(), filename.to_string());
        self.inner.write().start_times.entry(key).or_default().push(Instant::now());
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
        let key = (thread::current().id(), rule_id.to_string(), filename.to_string());
        let started = state.start_times.get_mut(&key).and_then(Vec::pop);
        if state.start_times.get(&key).is_some_and(Vec::is_empty) {
            state.start_times.remove(&key);
        }
        if let Some(started) = started
            && let Some(stats) = state.rules.get_mut(rule_id)
        {
            record_elapsed(stats, started.elapsed(), matched, matches, false_positives, filename);
        }
    }

    fn record_rule(
        &self,
        rule_id: &str,
        elapsed: Duration,
        matched: bool,
        matches: u64,
        false_positives: u64,
        filename: &str,
    ) {
        if let Some(stats) = self.inner.write().rules.get_mut(rule_id) {
            record_elapsed(stats, elapsed, matched, matches, false_positives, filename);
        }
    }

    pub fn generate_report(&self) -> Vec<RuleStats> {
        let mut stats: Vec<_> = self.inner.read().rules.values().cloned().collect();
        stats.sort_by_key(|b| std::cmp::Reverse(b.slowest_match_time));
        stats
    }
}

fn record_elapsed(
    stats: &mut RuleStats,
    elapsed: Duration,
    matched: bool,
    matches: u64,
    false_positives: u64,
    filename: &str,
) {
    stats.total_processing_time += elapsed;
    stats.total_matches += matches;
    stats.false_positives += false_positives;
    if matched {
        if elapsed > stats.slowest_match_time {
            stats.slowest_match_time = elapsed;
            stats.slowest_filename = filename.to_string();
        }
        if elapsed < stats.fastest_match_time {
            stats.fastest_match_time = elapsed;
            stats.fastest_filename = filename.to_string();
        }
    }
    // Include later rejected candidates as well as the last accepted candidate.
    if stats.total_matches > 0 {
        stats.average_match_time = Duration::from_nanos(
            (stats.total_processing_time.as_nanos() / u128::from(stats.total_matches))
                .min(u128::from(u64::MAX)) as u64,
        );
    }
}

pub struct RuleTimer<'a> {
    profiler: &'a ConcurrentRuleProfiler,
    rule_id: String,
    filename: String,
    started: Option<Instant>,
}

impl<'a> RuleTimer<'a> {
    pub fn new(
        profiler: &'a ConcurrentRuleProfiler,
        rule_id: &str,
        rule_name: &str,
        pattern: &str,
        filename: &str,
    ) -> Self {
        profiler.ensure_rule(rule_id, rule_name, pattern);
        Self {
            profiler,
            rule_id: rule_id.to_string(),
            filename: filename.to_string(),
            started: Some(Instant::now()),
        }
    }

    fn finish(&mut self, matched: bool, matches: u64, false_positives: u64) {
        if let Some(started) = self.started.take() {
            self.profiler.record_rule(
                &self.rule_id,
                started.elapsed(),
                matched,
                matches,
                false_positives,
                &self.filename,
            );
        }
    }

    pub fn end(mut self, matched: bool, matches: u64, false_positives: u64) {
        self.finish(matched, matches, false_positives);
    }
}

impl Drop for RuleTimer<'_> {
    fn drop(&mut self) {
        if !thread::panicking() {
            self.finish(false, 0, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_timers_do_not_replace_each_other() {
        let profiler = ConcurrentRuleProfiler::new();
        let first = RuleTimer::new(&profiler, "id", "Name", "pattern", "same-file");
        let second = RuleTimer::new(&profiler, "id", "Name", "pattern", "same-file");
        first.end(true, 2, 1);
        second.end(true, 3, 2);
        let report = profiler.generate_report();
        assert_eq!(report[0].total_matches, 5);
        assert_eq!(report[0].false_positives, 3);
        assert!(profiler.inner.read().start_times.is_empty());
    }

    #[test]
    fn concurrent_same_rule_and_file_keep_all_results() {
        let profiler = ConcurrentRuleProfiler::new();
        let barrier = std::sync::Barrier::new(8);
        thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let timer = RuleTimer::new(&profiler, "id", "Name", "pattern", "same-file");
                    barrier.wait();
                    timer.end(true, 1, 1);
                });
            }
        });
        let report = profiler.generate_report();
        assert_eq!(report[0].total_matches, 8);
        assert_eq!(report[0].false_positives, 8);
    }

    #[test]
    fn explicit_timers_remain_compatible_and_nestable() {
        let profiler = ConcurrentRuleProfiler::new();
        profiler.start_rule("id", "Name", "pattern", "same-file");
        profiler.start_rule("id", "Ignored later metadata", "other", "same-file");
        profiler.end_rule("id", true, 2, 1, "same-file");
        profiler.end_rule("id", true, 3, 2, "same-file");
        profiler.end_rule("id", true, 100, 100, "same-file");
        let report = profiler.generate_report();
        assert_eq!(report[0].total_matches, 5);
        assert_eq!(report[0].false_positives, 3);
        assert_eq!(report[0].rule_name, "Name");
        assert_eq!(report[0].pattern, "pattern");
        assert!(profiler.inner.read().start_times.is_empty());
    }

    #[test]
    fn rejected_filter_time_updates_amortized_cost() {
        let mut stats = RuleStats::default();
        record_elapsed(&mut stats, Duration::from_millis(10), true, 2, 0, "first");
        record_elapsed(&mut stats, Duration::from_millis(30), false, 0, 1, "rejected");
        assert_eq!(stats.total_processing_time, Duration::from_millis(40));
        assert_eq!(stats.average_match_time, Duration::from_millis(20));
        assert_eq!(stats.slowest_match_time, Duration::from_millis(10));
        assert_eq!(stats.slowest_filename, "first");
    }
}
