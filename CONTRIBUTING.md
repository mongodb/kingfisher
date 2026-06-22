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
- Add or refine detection rules under
  `crates/kingfisher-rules/data/rules/`.
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

Kingfisher is a Rust workspace. The workspace minimum Rust version is `1.94`,
and CI currently uses Rust `1.94.1`.

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

If you are adding or updating a rule:

- Follow the schema and authoring guidance in [docs/RULES.md](docs/RULES.md).
- Prefer YAML-defined validation and revocation when the provider API supports
  it.
- Keep patterns specific and efficient.
- Add realistic examples and relevant tests.
- Set rule confidence to `medium`.

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
