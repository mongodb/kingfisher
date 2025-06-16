use std::path::PathBuf;

use clap::{Args, ValueEnum, ValueHint};
use strum::Display;

use crate::util::get_writer_for_file_or_stdout;

// -----------------------------------------------------------------------------
// Output Options
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Output Options")]
pub struct OutputArgs<Format: ValueEnum + Send + Sync + 'static> {
    /// Write output to the specified path (stdout if not given)
    #[arg(long, short, value_hint = ValueHint::FilePath)]
    pub output: Option<PathBuf>,

    /// Output format (defaults to `pretty` if not specified)
    #[arg(long, short, default_value = "pretty")]
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
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum ReportOutputFormat {
    /// A human-friendly text-based format
    Pretty,

    /// Pretty-printed JSON
    Json,

    /// JSON Lines (one JSON object per line)
    Jsonl,

    /// BSON (binary JSON) format
    Bson,

    /// SARIF format (experimental)
    Sarif,
}

// -----------------------------------------------------------------------------
// GitHub Output Format
// -----------------------------------------------------------------------------
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum GitHubOutputFormat {
    /// A human-friendly text-based format
    Pretty,

    /// Pretty-printed JSON
    Json,

    /// JSON Lines (one JSON object per line)
    Jsonl,

    /// BSON (binary JSON) format
    Bson,

    /// SARIF format (experimental)
    Sarif,
}
