use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};

use super::{
    enumerate::inspect_pre_commit_files,
    preview_inputs::write_inputs_and_filters,
    preview_rules::write_rules,
    runner::{scan_preflight, validate_input_paths},
};
use crate::cli::{GlobalArgs, commands::scan::ScanArgs};

/// Write the resolved scan preview without acquiring sources or running the scan.
pub fn write_scan_preview(
    out: &mut impl Write,
    args: &ScanArgs,
    global_args: &GlobalArgs,
    pre_commit_files: Option<&[PathBuf]>,
) -> Result<()> {
    let preflight = scan_preflight(args, global_args, pre_commit_files.is_some())?;
    let allow_stdin = !io::stdin().is_terminal();
    validate_input_paths(args, allow_stdin)?;
    if let Some(files) = pre_commit_files {
        let root = args
            .input_specifier_args
            .path_inputs
            .first()
            .context("Missing pre-commit scan root")?;
        inspect_pre_commit_files(root, files, preflight.exclude_globset.as_deref(), |_, _| Ok(()))?;
    }

    // Resolve the full preview before writing so invalid rules or globs cannot produce a
    // partial plan on stdout.
    let mut preview = Vec::new();
    writeln!(preview, "Scan preview")?;
    write_inputs_and_filters(&mut preview, args, pre_commit_files, allow_stdin)?;
    write_rules(&mut preview, args, &preflight.rule_internal_ip_policy)?;
    out.write_all(&preview)?;
    Ok(())
}
