---
date: 2026-11-19
title: "Embed a SIMD Secret Scanner in Your Rust Build — and Stop Leaks Before They Ship"
description: >
  Embed Kingfisher's SIMD scanning engine in your Rust build tooling, fail the
  build when a secret lands in an artifact, then trace and triage the leak.
categories:
  - Tutorials
tags:
  - rust
  - sdk
  - secret-scanning
  - git
  - validation
---

# Embed a SIMD Secret Scanner in Your Rust Build — and Stop Leaks Before They Ship

Secrets don't only leak from source files. They show up in the things a build
produces: a config rendered from a template, a `.env` copied into a container
layer, a test fixture bundled into a release tarball. A pre-commit hook never
sees those files. Your build does, because it just made them.

`kingfisher-scanner` puts the Kingfisher detection engine, with hundreds of
built-in rules, inside your Rust program as a library. There's no subprocess to
spawn and no CLI output to parse. You hand it paths or bytes and get typed
`Finding` values back. So the code that assembles your artifact can also
refuse to ship it. Get the crate on [crates.io](https://crates.io/crates/kingfisher-scanner).

<!-- more -->

## Fail the build when a secret is in the artifact

In a project using Rust 1.99 or newer, add the scanner, `anyhow` for error
handling, and `walkdir` to enumerate artifact files.

```sh
cargo add kingfisher-scanner anyhow walkdir
```

Save this as `src/bin/secret-gate.rs` in your build tooling, or fold it into an
existing `xtask`. It takes files or directories, scans regular files without
following symlinks, and fails if it finds a secret or has no files to scan.

```rust
use std::{process::ExitCode, sync::Arc};

use kingfisher_scanner::{RulesDatabase, Scanner, ScannerConfig, get_builtin_rules};
use walkdir::WalkDir;

fn main() -> anyhow::Result<ExitCode> {
    let mut paths = std::env::args_os().skip(1).peekable();
    anyhow::ensure!(paths.peek().is_some(), "provide at least one artifact path");

    let rules = RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?;
    let scanner = Scanner::with_config(
        Arc::new(rules),
        ScannerConfig { redact_secrets: true, ..Default::default() },
    );

    let mut scanned = 0;
    let mut leaks = 0;
    for path in paths {
        for entry in WalkDir::new(path).follow_root_links(false) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let findings = scanner.scan_file(path)?;
            scanned += 1;
            for finding in findings.into_iter().filter(|finding| finding.rule().visible()) {
                eprintln!(
                    "error: {}:{}:{}: {}",
                    path.display(),
                    finding.line(),
                    finding.column(),
                    finding.rule_id
                );
                leaks += 1;
            }
        }
    }

    anyhow::ensure!(scanned > 0, "no artifact files found");
    if leaks > 0 {
        eprintln!("{leaks} secret(s) found, refusing to ship");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}
```

Run it over the staged artifact as the last step before you publish:

```sh
cargo run --release --bin secret-gate -- target/dist
```

```text
error: target/dist/app.env:1:18: betterleaks.aws-access-token
error: target/dist/app.env:3:13: betterleaks.github-pat
2 secret(s) found, refusing to ship
```

A few details make this safe to run on every build:

- **The secret never reaches your logs.** `redact_secrets: true` removes the
  credential value from each finding. The gate reports only the rule, path, and
  position.
- **Discovery errors fail the build.** The gate needs at least one regular
  file and stops on any directory traversal, read, or scan error. It passes
  each filename directly to the scanner, including names with spaces or
  shell metacharacters.
- **Helper matches stay quiet.** Some rules match a component, such as the
  secret half of an AWS key pair, only to support another rule. Filtering on
  `rule().visible()` reports what a person needs to act on.

Already have the bytes in memory, such as a template you just rendered? Call
`scan_bytes` and skip writing a temporary file. If path-aware rules should see
the logical filename too, use `scan_blob_at_path`.

## Why it's fast enough to run on every build

Kingfisher compiles its whole rule catalog into a single
[Vectorscan](https://github.com/VectorCamp/vectorscan) database. Vectorscan
uses SIMD instructions to match every pattern in one pass over the bytes. It
doesn't run a separate regex per rule. Only the candidates it finds go to the
Rust regex engine to extract captures, followed by entropy thresholds and
other rule checks. Compile the database once and reuse the `Scanner` for the
whole batch. That keeps regex compilation out of the per-file path.

If your tooling runs on Tokio, you can scan on blocking workers with a cap on
concurrency. See the [Tokio example](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-scanner/examples/scan_async.rs).
For a JSON Lines report instead of a pass/fail gate, see the
[file batch example](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-scanner/examples/scan_files.rs).

## When a leak gets past the gate, find where it started

The gate checks what you're about to ship. It can't tell you whether that key
was also committed six months ago and is still sitting in history. For that,
enable the `git` feature and use `GitInputs` to enumerate content from a local
repository. By default it walks commits reachable from `HEAD`, including merge
parents. It reads Git objects in-process, with no `git` subprocess, and yields
bytes, a repository-relative path, and provenance for each input. Send them
through the same `Scanner` you built for the gate. Keep that provenance in
your report and you can see which commits carried the credential.

The example sets commit, input, and blob size limits and reports skipped blobs
so you can see gaps in coverage. Its source is in
[git_inputs.rs](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-scanner/examples/git_inputs.rs).

```sh
cargo run -p kingfisher-scanner --features git --example git_inputs -- path/to/repo
```

## Triage: is the leaked key still live?

The gate runs entirely offline and blocks on any finding, which is the right
default for a build. When a leak does get out, the next question is how urgent
it is. Enable the `validation` feature and pass the findings to
`Validator::validate_findings`. Kingfisher asks each provider whether the
credential still authenticates. That call contacts the network, so keep it in
a triage worker, not the build.

A verified active result means the key works right now, so send it to whoever
can rotate it. A connection failure or rate limit can leave the result
unavailable. Keep those for follow-up and don't treat them as safe.

Pass the full findings list to the validator so rules can use supporting
matches, such as the key ID that pairs with an AWS secret. Redact before you
log or export the results.

The checkout includes an example that tests active, inactive, and unavailable
outcomes with a synthetic token and a local mock server. See the [HTTP validation example](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-scanner/examples/http_validation.rs).

```sh
cargo run -p kingfisher-scanner --features validation --example http_validation
```

For a complete example using the built-in rules and live provider checks, see
[validate_file.rs](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-scanner/examples/validate_file.rs).
The SDK guide covers custom rules, Git scopes, and native build prerequisites in
[Kingfisher Library Crates](../../reference/library.md).
