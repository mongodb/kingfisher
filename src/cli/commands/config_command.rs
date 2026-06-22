//! `kingfisher config init` — turn an existing CLI invocation into a reusable
//! `kingfisher.yaml` project config.
//!
//! The user runs the same flags they would normally pass to `kingfisher
//! scan`, prefixed with `config init`. We walk the resulting `ArgMatches`,
//! pick out only the values the user actually supplied (CLI defaults stay
//! out so the emitted YAML is minimal), and serialize a [`KingfisherConfig`]
//! to stdout (or to `--out FILE`).
//!
//! Scan-target inputs (positional paths, `--git-url`, GitHub/GitLab/etc.
//! flags, S3/GCS buckets, Docker images, Slack/Teams queries) are
//! deliberately omitted — the config file is project-default policy, not a
//! frozen target list.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::cli::commands::scan::ScanArgs;

/// `kingfisher config <subcommand>` umbrella.
#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum ConfigSubcommand {
    /// Convert the supplied CLI flags into a reusable `kingfisher.yaml`.
    ///
    /// Pass any flag you would normally use with `kingfisher scan`
    /// (e.g. `--confidence high`, `--exclude vendor/`, `--alert-webhook URL`).
    /// Only flags you actually supplied appear in the output — built-in
    /// defaults are omitted to keep the emitted file minimal.
    ///
    /// Scan-target inputs (positional paths, `--git-url`, provider
    /// `--user`/`--org`/`--bucket` flags) are dropped: the config is for
    /// project policy, not for pinning a specific scan target.
    Init(ConfigInitArgs),
}

#[derive(Args, Debug)]
pub struct ConfigInitArgs {
    /// Where to write the generated YAML. Default: stdout.
    #[arg(long = "out", value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub out: Option<PathBuf>,

    /// Overwrite `--out` if it already exists. Without this flag, an existing
    /// file is left untouched and the command exits non-zero.
    #[arg(long = "force", default_value_t = false)]
    pub force: bool,

    #[command(flatten)]
    pub scan_args: ScanArgs,
}
