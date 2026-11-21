use std::path::PathBuf;

use clap::{Args, ValueEnum, ValueHint};

use crate::util::get_writer_for_file_or_stdout;

// -----------------------------------------------------------------------------
// Output Options
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Output Options")]
pub struct OutputArgs<Format: ValueEnum + Send + Sync + 'static> {
    /// Write output to the specified path (stdout if not given)
    #[arg(global = true, long, short, value_hint = ValueHint::FilePath)]
    pub output: Option<PathBuf>,

    /// Output format (defaults to `pretty`; use `toon` for LLM/agent integrations)
    #[arg(global = true, long, short, default_value = "pretty")]
    pub format: Format,
}

impl<Format: ValueEnum + Send + Sync> OutputArgs<Format> {
    /// Return a writer for the specified output destination
    pub fn get_writer(&self) -> std::io::Result<Box<dyn std::io::Write>> {
        get_writer_for_file_or_stdout(self.output.as_ref())
    }

    /// Check if an output path was specified
    pub fn has_output(&self) -> bool {
        self.output.is_some()
    }
}

// -----------------------------------------------------------------------------
// Report Output Format
// -----------------------------------------------------------------------------
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ReportOutputFormat {
    /// A human-friendly text-based format
    Pretty,

    /// Compact JSON report envelope
    Json,

    /// JSON Lines (one JSON object per line)
    Jsonl,

    /// BSON (binary JSON) format
    Bson,

    /// TOON format optimized for LLMs and agents
    Toon,

    /// SARIF 2.1.0 (stable)
    Sarif,

    /// Standalone HTML audit report
    Html,
}

// -----------------------------------------------------------------------------
// GitHub Output Format
// -----------------------------------------------------------------------------
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum GitHubOutputFormat {
    /// A human-friendly text-based format
    Pretty,

    /// Pretty-printed JSON
    Json,

    /// JSON Lines (one JSON object per line)
    Jsonl,

    /// BSON (binary JSON) format
    Bson,

    Sarif,
}

crate::cli::impl_value_enum_display!(ReportOutputFormat, GitHubOutputFormat);
