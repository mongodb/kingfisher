use clap::{Args, ValueEnum};
use strum::Display;
use tracing::debug;

use crate::{
    cli::{
        commands::{
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::RuleSpecifierArgs,
        },
        global::RAM_GB,
    },
    rules::rule::Confidence,
};


/// Determine the default number of parallel scan jobs.
///
/// * Target = `num_cpus * 2`.
/// * Cap by RAM at ≈ 1 GiB per job (so 16 GiB ⇒ max 16 jobs).
/// * Always ≥ 1.
/// * When `-v/--verbose` is passed, the computed value is logged at DEBUG.
fn default_scan_jobs() -> usize {
    // How many logical CPUs do we see? (Falls back to 1 on error.)
    let cpu_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);

    // Desired parallelism is CPU * 2.
    let desired = cpu_count * 2;

    match *RAM_GB {
        // If we know how much RAM we have, cap by a 1 GiB-per-job heuristic.
        Some(ram_gb) => {
            let max_by_ram = ram_gb.ceil() as usize;     // 1 GiB per job
            let jobs       = desired.min(max_by_ram).max(1);

            debug!(
                "Using {jobs} parallel scan jobs \
                 (cpus = {cpu_count}, desired = {desired}, \
                 ram = {ram_gb:.1} GiB, cap_by_ram = {max_by_ram})"
            );
            jobs
        }
        // If RAM is unknown, just use the desired value.
        None => {
            debug!(
                "Using {desired} parallel scan jobs (cpus = {cpu_count}, ram unknown)"
            );
            desired
        }
    }
}

/// `kingfisher scan` command and flags
#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// Number of parallel scanning threads
    #[arg(long = "jobs", short = 'j', default_value_t = default_scan_jobs())]
    pub num_jobs: usize,

    #[command(flatten)]
    pub rules: RuleSpecifierArgs,

    #[command(flatten)]
    pub input_specifier_args: InputSpecifierArgs,

    #[command(flatten)]
    pub content_filtering_args: ContentFilteringArgs,

    /// Minimum confidence level for reporting findings
    #[arg(long, short = 'c', default_value = "medium")]
    pub confidence: ConfidenceLevel,

    /// Disable secret validation
    #[arg(long, short = 'n', default_value_t = false)]
    pub no_validate: bool,

    /// Display only validated findings
    #[arg(long, default_value_t = false)]
    pub only_valid: bool,

    /// Override the default minimum entropy threshold
    #[arg(long, short = 'e')]
    pub min_entropy: Option<f32>,

    /// Show performance statistics for each rule
    #[arg(long, default_value_t = false)]
    pub rule_stats: bool,

    /// Display every occurrence of a finding
    #[arg(long, default_value_t = false)]
    pub no_dedup: bool,

    /// Redact findings values using a secure hash
    #[arg(long, short = 'r', default_value_t = false)]
    pub redact: bool,

    /// Timeout for Git repository scanning in seconds
    #[arg(long, default_value_t = 1800, value_name = "SECONDS")]
    pub git_repo_timeout: u64,

    #[command(flatten)]
    pub output_args: OutputArgs<ReportOutputFormat>,

    /// Bytes of context before and after each match
    #[arg(long, default_value_t = 256, value_name = "BYTES")]
    pub snippet_length: usize,
}

/// Confidence levels for findings
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl From<ConfidenceLevel> for Confidence {
    fn from(level: ConfidenceLevel) -> Self {
        match level {
            ConfidenceLevel::Low => Confidence::Low,
            ConfidenceLevel::Medium => Confidence::Medium,
            ConfidenceLevel::High => Confidence::High,
        }
    }
}
