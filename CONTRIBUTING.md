# Contributing to Kingfisher

Thank you for your interest in contributing to Kingfisher.

Kingfisher is an open-source project owned by MongoDB and licensed under the
[Apache License 2.0](LICENSE). We welcome bug reports, feature requests,
documentation improvements, rule additions, validation improvements, and code
contributions.

## Before You Start

- Be respectful and collaborative. Participation in this project is covered by
  the [MongoDB Community Code of Conduct](https://www.mongodb.com/community-code-of-conduct).
- If you plan to submit a pull request, sign the
  [MongoDB Contributor Agreement](https://www.mongodb.com/legal/contributor-agreement)
  first.
- For security vulnerabilities, do not open a public issue. Follow
  [SECURITY.md](SECURITY.md) instead.

## Ways to Contribute

- Report bugs with clear reproduction steps, environment details, and logs when
  possible.
- Propose features or usability improvements through GitHub issues.
- Improve documentation in `README.md`, `docs/`, or `docs-site/`.
- Add or refine generally useful detection rules in the
  [Betterleaks repository](https://github.com/betterleaks/betterleaks).
- Improve validation, revocation, scanning performance, output formats, or
  integrations.

## Reporting Bugs and Requesting Features

Before opening a new issue:

- Check whether an existing issue already covers the problem or request.
- Confirm the issue still reproduces on a recent `main` checkout or current
  release when practical.
- Include the smallest reproducible example you can provide.

Use the repository issue templates when they fit your case.

## Development Setup

Kingfisher is a Rust workspace. The workspace minimum Rust version is `1.99`.

The workspace uses the published [`kingfisher-vectorscan`](https://crates.io/crates/kingfisher-vectorscan)
crate, pinned to **0.1.4**. On supported Linux GNU/musl, macOS, and Windows
GNU/LLVM or MSVC targets, Cargo downloads
the checksum-verified Vectorscan archive, so Vectorscan itself does not need a local
CMake/Boost build. Cargo still builds Rust code and other native dependencies, and
needs the target linker/runtime libraries and network access for the archive.
Windows MSVC x64/ARM64 consumers need the matching Microsoft target SDK/linker and
C++ runtime, not MinGW libraries. The published MSVC archives use the **MSVC 14.44
(Visual Studio 2022)** STL/CRT baseline and support newer compatible toolsets,
including VS 2026, without disabling engine or STL SIMD optimizations. The existing
Makefile CLI packaging targets keep using MSYS2 MINGW64 x64 and CLANGARM64 ARM64.
MSVC Vectorscan source builds use
clang-cl, Ninja and standalone Boost headers rather than cl.exe. See the crate's
[build guide](https://github.com/micksmix/kingfisher-vectorscan#build-requirements-and-portability)
for offline and source-build options.

Helpful commands:

```bash
cargo build
make tests
cargo test --workspace --all-targets
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

For repository layout and project-specific guidance, see:

- [README.md](README.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/USAGE.md](docs/USAGE.md)
- [docs/RULES.md](docs/RULES.md)

### JavaScript/TypeScript SDK Development

The `kingfisher-secret-scanner` npm SDK **1.0.0** is a stable release.
Its version is independent of the CLI, Python SDK, and Rust crates. Use the
checkout instructions below for SDK development.

Use **Node 22, 24 or 26 only**, tested minimum **22.13.0**, and Rust **1.99** with the
[native build prerequisites](docs/LIBRARY.md#build-and-deployment). From the repository root:

```sh
cd javascript
npm ci --ignore-scripts
npm run build:debug
npm test
npm run test:types
```

The facade calls the same core, rules, and scanner crates in process through
[the Node-API bridge](crates/kingfisher-node), not through Python or the CLI.
Read [Node contributor guidance](javascript/AGENTS.md) for Node-facing changes,
including behavior implemented in shared Rust crates. See the
[SDK guide](docs/JAVASCRIPT.md) and [runnable examples](javascript/examples) for APIs
and the canonical runtime support contract; Vectorscan's broader Rust target support
above does not imply Node SDK musl or additional Node-major support.

Rebuild the addon after native changes. For loader/packaging changes, also run
`npm run test:package` against a correctly staged release tree to verify a clean,
offline consumer install from packed tarballs without source-tree addon fallback or
a consumer Rust build. Follow the [npm publishing guide](docs/PUBLISHING.md#npm-publishing-with-github-actions)
for staging and release checks; these development commands do not publish anything.
Documentation-only changes do not require a native rebuild.

### Third-party license notices

After locked native dependency changes, run from the repository root:

```sh
cargo fetch --locked
cargo install --locked cargo-bundle-licenses --version 4.2.0
make notices
make check-notices
```

The generator derives the **exact locked third-party crate/version union** across
**all workspace members, features and targets**, including normal/build dependencies
and proc macros (also optional allocators, GUI and tools). Dev-only dependencies and
first-party crates are excluded; stale Cargo entries are removed. Independent
non-Cargo notices for the project, rule sources and Vectorscan are preserved, and
the SDK's packaged notices are synchronized. Identical license/evidence texts are
stored once using standard YAML anchors and aliases, preserving every original
text and copyright notice offline. Do not replace required notices with URLs.
These are distribution files, not imported JavaScript or embedded executable data;
normal JS bundlers do not include them, although whole-directory deployment copies do.

From `javascript/`, `npm run check:notices` provides the same read-only check. Missing,
stale or incomplete license texts (including `NOT FOUND` placeholders) fail closed;
unavailable upstream texts require reviewed, pinned license-source overrides rather
than a waiver. Preserve packaged license/notice files when staging releases.

## Contribution Guidelines

### Keep changes focused

- Prefer small, reviewable pull requests over large mixed changes.
- Avoid unrelated refactors in the same PR unless they are necessary for the
  fix.
- Update tests and docs when behavior changes.

### Do not commit real secrets

Kingfisher is a secret scanner. Never add live credentials, customer data, or
real tokens anywhere in the repository, including:

- tests
- fixtures
- examples
- docs
- screenshots
- benchmark artifacts

Use clearly fake placeholders or provider-documented example values only.

### Rule contributions

If you are adding or updating a generally useful rule, contribute it to Betterleaks first. For
custom rules, both the Kingfisher rule format (`.yml`/`.yaml`) and Betterleaks TOML (`.toml`)
are fully supported through `--rules-path`. Custom rules may be shared or private.

For Kingfisher custom rules:

- Follow the schema and authoring guidance in [docs/RULES.md](docs/RULES.md).
- Prefer YAML-defined validation and revocation when the provider API supports
  it.
- Keep patterns specific and efficient.
- Add realistic examples and relevant tests.
- Choose a static rule confidence appropriate to the detector; filters cannot upgrade or
  downgrade findings. See the [configured-confidence policy](docs/RULES.md#configured-confidence).

Useful validation commands:

```bash
cargo test -p kingfisher-rules
cargo test --workspace --all-targets
kingfisher scan ./testdata --rule <rule-family-or-id> --rule-stats
kingfisher validate --rule <rule-id> <token-or-secret>
```

## Testing Expectations

Run the narrowest relevant checks for your change before opening a PR, then run
broader checks when practical.

Examples:

- Rule-only changes: `cargo test -p kingfisher-rules`
- General Rust changes: `make tests`
- Node SDK changes: rebuild with `npm run build:debug`, then `npm test` and
  `npm run test:types` from `javascript/`; include packed-tarball checks for packaging changes.
- Formatting: `cargo fmt --all`
- Linting: `cargo clippy --workspace --all-targets -- -D warnings`

If you cannot run a relevant check locally, say so in the pull request and
explain why.

## Documentation Changes

- Keep examples consistent with current CLI behavior.
- Update related docs when flags, outputs, or workflows change.
- After changing `docs-site/` sources, rebuild the site when practical:

```bash
docs-site/.venv/bin/mkdocs build -f docs-site/mkdocs.yml
```

## Pull Request Checklist

Before opening a PR, make sure you have:

- signed the MongoDB Contributor Agreement
- kept the change focused
- added or updated tests where needed
- updated docs where needed
- run the relevant local checks
- avoided adding any real secrets or sensitive data

In the PR description, include:

- what changed
- why it changed
- how you tested it
- any follow-up work or known limitations

## Questions

If you are unsure whether a change is in scope, open an issue first so the
approach can be discussed before you spend time on implementation.
