# Kingfisher CLI (`kingfisher-bin`)

**Find leaked secrets. Validate what is live. Map access. Revoke supported credentials.**

[Kingfisher](https://github.com/mongodb/kingfisher) is MongoDB's open-source secret scanner
and credential response tool, built in Rust. Scan source code, Git history, archives,
cloud storage, container images, and developer platforms with a bundled rule catalog.

`kingfisher-bin` installs the **`kingfisher` command**, including a precompiled binary for
your platform. You do not need Rust or a separate Kingfisher installation.

**No Git executable required.** The CLI reads local Git history and staged changes
and clones repositories over HTTPS using native Rust libraries. SSH remotes require
an SSH client.

**Looking for a Python API?** Install
[`kingfisher-secret-scanner`](https://pypi.org/project/kingfisher-secret-scanner/)
and import `kingfisher_sdk` for native, in-process scanning. The CLI and SDK can be
installed together.

## What you can do

- Detect exposed credentials in local files, repositories, Git history, and archives.
- Scan remote repositories, cloud storage, Docker images, and collaboration platforms.
- Validate credentials, inspect supported identities and permissions, and explicitly revoke
  supported secrets.
- Export JSON, JSONL, SARIF, TOON, BSON, or HTML reports and triage findings in a local browser.
- Use custom Kingfisher YAML or Betterleaks TOML rules alongside the built-in catalog.

## Install

With [uv](https://docs.astral.sh/uv/) (recommended):

```sh
uv tool install kingfisher-bin
kingfisher --version
```

To upgrade an existing uv tool installation, run `uv tool upgrade kingfisher-bin`.

Or with pip, preferably inside a virtual environment:

```sh
python -m pip install --upgrade kingfisher-bin
kingfisher --help
```

You can also run `uvx --from kingfisher-bin kingfisher --help` without a persistent tool installation.
If the console command is not on your `PATH`, use `python -m kingfisher` in the environment
where you installed the package.

Run `kingfisher --help` to explore commands or `kingfisher scan --help` for scanning options.

## Run your first scan

Replace `./my-project` with a directory or local repository you are authorized to inspect:

```sh
kingfisher scan ./my-project --no-validate --no-update-check --redact
```

This performs local detection without credential-validation requests or release update checks.
Git history is scanned by default when present; add `--git-history=none` for working-tree files
only. `--redact` protects finding values in the output.

**Live validation is enabled by default** when `--no-validate` is omitted and can send discovered
credentials to provider APIs. Only validate credentials you are authorized to test.
Blast-radius mapping is available with `--blast-radius`; revocation is a separate, explicit action.

## Save and inspect reports

Write a redacted JSON report, then open it in the bundled browser-based viewer:

```sh
kingfisher scan ./my-project --no-validate --no-update-check --redact --format json --output findings.json
kingfisher view findings.json
```

Reports can still contain sensitive paths, source context, and metadata. Store and share them
securely, even when redaction is enabled.

For LLM and agent workflows, use token-efficient TOON output:

```sh
kingfisher scan ./my-project --no-validate --no-update-check --redact --format toon
```

## Automation and exit codes

Finding secrets is an expected scan outcome, not a crash. Account for these exit codes
in scripts and CI:

| Exit code | Meaning |
| --- | --- |
| `0` | No visible findings. |
| `200` | Visible findings. |
| `205` | Visible findings confirmed active by validation. |

Choose how findings should affect your CI policy rather than treating every nonzero
exit code as a scanner failure. Finding exit codes do not guarantee complete scan
coverage; inspect coverage errors too.
See the [exit-code reference](https://mongodb.github.io/kingfisher/usage/basic-scanning/#exit-codes)
for error codes and coverage guidance.

## Compatibility

Requires **Python 3.8+**. Published wheels cover:

| Platform | Architectures |
| --- | --- |
| Linux (glibc or musl) | x86-64, ARM64 |
| macOS | Intel x86-64, Apple silicon (ARM64) |
| Windows | x86-64, ARM64 |

Wheels are platform-specific. If pip cannot find a matching distribution, check that pip is
current and your environment matches a supported platform. Other installation methods are
listed in the [installation guide](https://mongodb.github.io/kingfisher/getting-started/installation/).

## Documentation and support

- [Usage and scan targets](https://mongodb.github.io/kingfisher/usage/basic-scanning/)
- [Integrations and authentication](https://mongodb.github.io/kingfisher/usage/integrations/)
- [Defender workflow](https://github.com/mongodb/kingfisher/blob/main/docs/DEFENDER_WORKFLOW.md)
- [Python SDK guide](https://mongodb.github.io/kingfisher/reference/python-bindings/)
- [Releases and release notes](https://github.com/mongodb/kingfisher/releases)
- [Report an issue](https://github.com/mongodb/kingfisher/issues)

Kingfisher is licensed under [Apache 2.0](https://github.com/mongodb/kingfisher/blob/main/LICENSE).

For package development, build the Rust binary for your target first, then use the repository's
[wheel-builder script](https://github.com/mongodb/kingfisher/blob/main/scripts/build-pypi-wheel.sh)
to package it. This is not required to install a published wheel.
