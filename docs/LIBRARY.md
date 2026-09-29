# Kingfisher Library Crates

[← Back to README](../README.md)

Kingfisher's three embeddable crates are prepared for their first stable **1.0.0**
release. They require Rust **1.96** or newer and are versioned independently of the
`kingfisher-bin` CLI, currently **2.8.0**. See [publishing](PUBLISHING.md).

## Crate Overview

| Crate | Use it for |
| ----- | ---------- |
| `kingfisher-core` | Content buffers (`Blob`), identifiers, locations, provenance, entropy, `ValidationOutcome` |
| `kingfisher-rules` | Custom rule loading, embedded catalog, `RuleSyntax`, compiled `RulesDatabase` |
| `kingfisher-scanner` | Synchronous `Scanner`, `ScannerConfig`, owned `Finding` results, optional validators |

The scanner re-exports `Blob`, `Rule`, `RuleSyntax`, `RulesDatabase`, and
`get_builtin_rules` for common embedding tasks. Depend on the other crates directly
when you need their additional APIs. None of the three depends on `kingfisher-bin`.

## Quick Start

After publication, use registry dependencies:

```toml
[dependencies]
kingfisher-scanner = "1.0.0"
anyhow = "1"
```

```rust
use std::sync::Arc;
use kingfisher_scanner::{get_builtin_rules, RulesDatabase, Scanner};

fn main() -> anyhow::Result<()> {
    let database = RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?;
    let scanner = Scanner::new(Arc::new(database));
    let findings = scanner.scan_bytes(b"ordinary application configuration")?;
    for finding in findings.into_iter().filter(|finding| finding.rule().visible()) {
        // Avoid logging the secret or capture values.
        println!("{} at line {}", finding.rule_id, finding.line());
    }
    Ok(())
}
```

The quick starts in each crate README are also its rustdoc documentation, and Cargo
executes their Rust examples as doctests. This keeps the advertised entry points
checked against the implementation.

## Runnable Examples

Each publishable package includes runnable source examples. Run these from the repository:

| Package | Example | Command |
| ------- | ------- | ------- |
| `kingfisher-core` | [Borrow a blob and resolve locations](../crates/kingfisher-core/examples/blob_locations.rs) | `cargo run -p kingfisher-core --example blob_locations` |
| `kingfisher-rules` | [Load and compile rules](../crates/kingfisher-rules/examples/load_rules.rs) | `cargo run -p kingfisher-rules --example load_rules` |
| `kingfisher-scanner` | [Scan, redact, and share across threads](../crates/kingfisher-scanner/examples/scan_content.rs) | `cargo run -p kingfisher-scanner --example scan_content` |
| `kingfisher-scanner` | [Explicit local validation](../crates/kingfisher-scanner/examples/local_validation.rs) | `cargo run -p kingfisher-scanner --example local_validation --features validation-ethereum` |
| `kingfisher-scanner` | [Scan file batches to JSON Lines](../crates/kingfisher-scanner/examples/scan_files.rs) | `cargo run -p kingfisher-scanner --example scan_files -- Cargo.toml README.md` |
| `kingfisher-scanner` | [Scan with private YAML/TOML rules](../crates/kingfisher-scanner/examples/scan_custom_rules.rs) | `cargo run -p kingfisher-scanner --example scan_custom_rules -- crates/kingfisher-scanner/examples/fixtures/acme-http.yml README.md` |
| `kingfisher-scanner` | [Bound scanning work in Tokio](../crates/kingfisher-scanner/examples/scan_async.rs) | `cargo run -p kingfisher-scanner --example scan_async` |
| `kingfisher-scanner` | [Validate a file with built-in rules](../crates/kingfisher-scanner/examples/validate_file.rs) | `cargo run -p kingfisher-scanner --example validate_file --features validation-http -- path/to/config.env` |
| `kingfisher-scanner` | [Scan and validate via YAML HTTP](../crates/kingfisher-scanner/examples/http_validation.rs) | `cargo run -p kingfisher-scanner --example http_validation --features validation-http` |
| `kingfisher-bin` | [Embed the full application's library](../examples/embedded_application.rs) | `cargo run -p kingfisher-bin --example embedded_application` |

The `load_rules` example accepts a custom TOML/YAML path after `--`. The
`scan_content` example accepts a file path after `--` to use the built-in catalog;
with no arguments it scans synthetic tokens, redacts output, and makes no network
requests. `scan_files` and `scan_custom_rules` require the paths shown above.
CI exercises these examples, including both custom rule formats and HTTP outcome
classification. They are included in the published crate archives. The HTTP example
starts its own loopback mock; it makes no external provider requests.
`validate_file` explicitly contacts providers for detected credentials; enable the
additional validator features your project needs.

For the CLI after publication:

```sh
cargo install --locked kingfisher-bin --version 2.8.0
kingfisher scan path/to/project --no-validate --format toon --no-update-check
```

For the `kingfisher-bin` library example in your own application, use
`kingfisher = { package = "kingfisher-bin", version = "2.8.0" }` and `anyhow = "1"`.
The three focused library examples use the corresponding crate at `1.0.0`;
`kingfisher-rules` and `kingfisher-scanner` examples also use `anyhow = "1"`.

## Integration Recipes for Rust Projects and LLM Agents

Start with a complete example above and copy it into `src/main.rs` in a small Rust
application. These are public-API consumers; no CLI process or private Kingfisher
module is required. Choose dependencies from this table in addition to
`kingfisher-scanner = "1.0.0"` and `anyhow = "1"`:

| Recipe | Additional dependencies / features |
| ------ | ---------------------------------- |
| `scan_content` | None |
| `scan_files` | `serde_json = "1"` |
| `scan_custom_rules` | `kingfisher-rules = "1.0.0"` |
| `scan_async` | `tokio = { version = "1.53", features = ["macros", "rt", "sync"] }` |
| `local_validation` | Scanner feature `validation-ethereum`; `kingfisher-rules = "1.0.0"` |
| `http_validation` | Complete manifest below; also copy `fixtures/acme-http.yml` and `support/mod.rs` into `src/fixtures/` and `src/support/` |
| `validate_file` | Scanner feature `validation-http`; `serde_json = "1"`; `tokio = { version = "1.53", features = ["macros", "rt"] }` |

The registry manifests apply after publication. Before publication, replace each
Kingfisher dependency's version with a `path` to the corresponding crate in a local
checkout, preserving its features. Use Rust 1.96+ and the native build prerequisites
in [Build and Deployment](#build-and-deployment).

### Scan strings, uploads, and application configuration

Use `scan_content` for the smallest integration. Compile the rules once at startup
and retain an `Arc<Scanner>` in application state. Pass bytes from configuration,
uploads, or generated source to `scan_bytes`; use `scan_blob_at_path` when a logical
filename matters to rule filters. Decide whether your product blocks on any
visible finding or only flags it for review. An empty successful scan means no
matches under the selected rules, not proof that the input contains no secrets.

### Scan files in a build tool or CI gate

`scan_files` accepts paths as OS strings, preserves each file's source path, and
emits one JSON object per visible finding. Identical credentials in separate files
remain separately reportable because cross-call deduplication is off. Select files
using your application's existing traversal or Git integration; the scanner itself
does not traverse a repository. The example returns errors for unreadable files and
reports findings without failing the process. For an enforcing gate, track whether
any findings were returned and choose a separate nonzero exit code for detections.

The report deliberately includes only path, rule ID, location, and validation state.
Avoid serializing entire `Finding` objects into logs or API responses.

### Add private detectors without rebuilding Kingfisher

`scan_custom_rules` loads a YAML file, a Betterleaks TOML file, or a directory of
both formats, then compiles and scans with that collection. This example uses only
the custom collection; it does not implicitly add built-ins. TOML IDs gain a
`custom.` prefix. The included [Acme YAML fixture](../crates/kingfisher-scanner/examples/fixtures/acme-http.yml)
contains a synthetic token pattern, positive/negative samples, and a validation
request. Loading it still performs detection only. See [rule authoring](RULES.md)
for adapting patterns and adding supporting credential components.

### Add scanning to an async request handler or ingestion worker

`scan_async` compiles on a blocking worker, shares the resulting scanner, moves
owned input into `spawn_blocking`, and holds a semaphore permit until scanning
finishes. Both task failures and scan failures propagate with `await??`. Retain the
scanner and semaphore in your service state instead of rebuilding them per request.
The example processes two small inputs; for an unbounded stream, also drain completed
results incrementally and enforce input-size limits. Cancelling the async caller
does not stop an already-running blocking scan.

### Scan and validate HTTP credentials end to end

Copy `http_validation.rs` and its YAML fixture with this manifest:

```toml
[package]
name = "secret-check"
version = "0.1.0"
edition = "2024"
rust-version = "1.96"

[dependencies]
anyhow = "1"
kingfisher-scanner = { version = "1.0.0", features = ["validation-http"] }
kingfisher-rules = "1.0.0"
serde_json = "1"
tokio = { version = "1.53", features = ["macros", "rt", "net", "io-util", "time"] }
```

Run `cargo run`. The four output rows have outcomes `verified_active`,
`verified_inactive`, `unavailable`, and `unavailable`. The mock checks that the
synthetic token reached its Authorization header. A 200 response with unrelated
content does not count as active; a rate limit does not count as inactive.

The example loads a YAML rule, scans, and passes the full result set to
`Validator::validate_findings`. The validator binds captures and supporting
credentials, renders templates with Kingfisher's filters, dispatches the rule's
validator family, and returns `ValidatedFinding` values. Each contains the original
finding, a `ValidationOutcome`, an optional credential-free `ValidationReason`, and
an optional HTTP status. Call `into_redacted()` after validation, then emit the
metadata your application needs. Redacting before validation yields `Skipped` with
`RedactedInput` rather than sending `[REDACTED]` to a provider.

For your own service, replace the mock and synthetic detector with the built-in
catalog or your private rules. The [validate_file example](../crates/kingfisher-scanner/examples/validate_file.rs)
shows a complete application using the built-ins. Provider requests happen only
when you call the validator; scanning alone remains network-free.

### Use the validation builder

```rust
use std::time::Duration;
use kingfisher_scanner::Validator;

let validator = Validator::builder()
    .timeout(Duration::from_secs(10))
    .concurrency(4)
    .max_response_bytes(1024 * 1024)
    .build()?;
let results = validator.validate_findings(findings).await;
for result in results {
    if result.finding.rule().visible() {
        println!("{}: {:?}", result.finding.rule_id, result.outcome);
    }
}
```

Reuse the scanner and validator in application state. `validate_finding(&finding)`
checks a standalone finding. Use `validate_finding_with_context(&finding, &findings)`
for one finding with supporting credentials, or `validate_findings(findings)` for a
whole scan. Batch results preserve input order and include invisible helpers; filter
those only after validation. Clones share the client's connection pool and the
concurrency limit. Dropping the validation future cancels its pending orchestration;
no detached validation tasks are created by the batch runner.

| Builder option | Default / behavior |
| -------------- | ------------------ |
| `concurrency(n)` | 8 checks across the validator and its clones; zero is rejected |
| `timeout(duration)` | 10 seconds per started check, including waiting for a shared permit, DNS, and multi-step requests; zero is rejected |
| `retries(n)` | Zero YAML HTTP retries by default; retries share the total deadline and rebuild multipart bodies |
| `max_response_bytes(n)` | 1 MiB for YAML HTTP responses; oversized bodies yield `Unavailable` |
| `client(reqwest_client)` | Default client verifies TLS and disables redirects; injected clients must supply their own TLS, proxy, and no-redirect policy |
| `variable(name, value)` | Trusted template/Betterleaks environment variable, for example `GITHUB_API_BASE_URL`; capture/component values take precedence |
| `allow_internal_ips(true)` | Opt in for trusted local/private services; false by default |

The HTTP client is used by YAML HTTP, Betterleaks HTTP requests, Raw HTTP flows,
and Coinbase. SDK, database, and gRPC helpers own their transports. All dispatches
share the outer deadline and concurrency bound; protocol helpers can retain their
own limits and process-wide settings. The body-size setting applies to YAML HTTP;
the Betterleaks interpreter and gRPC transport have their own 1 MiB limits. The resolver checks are not a
DNS-pinning guarantee or a substitute for application network policy.

### Shared execution with the CLI

`Validator`, CLI scans, and `kingfisher validate` all call the same
`validation::ValidationEngine`. It dispatches rules, executes protocols, and returns
explicit outcomes. CLI candidate selection, rate limiting, and scan caches remain
outside the engine. Provider responses cannot silently turn an inconclusive outcome
into an inactive credential through HTTP-status inference.

Most applications should use `Validator`. Advanced integrations that already resolve
rule variables can use `ValidationEngine::new(&client, &parser).validate(&rule, &globals)`.
Supply uppercase scalar variables including `TOKEN`, a parser configured with
`kingfisher_rules::register_liquid_filters`, and a client with redirects disabled.
Configure its deadline, retries, private-network policy, and typed-validator TLS policy
explicitly. This lower-level API does not associate findings or bound concurrency.
`ValidationResult` exposes outcome, reason, HTTP status, and a potentially sensitive
`response_body`; Debug omits that body and the type has no Serialize implementation.
The high-level `ValidatedFinding` omits provider responses entirely.

YAML HTTP checks require a nonempty status, word, or header matcher. Empty matchers
and JSON-validity checks alone cannot prove authentication. Multipart `file` parts
send rendered content as bytes; they do not read paths from the host filesystem.

### Supporting credentials and validation outcomes

Pass the complete raw results from **one scan input** into each batch. Components
must have the same blob ID and encoding as the primary finding, and satisfy the
rule's `within` constraint when present. Distinct competing values yield `Skipped`
with `AmbiguousDependency`; required absent values yield `MissingDependency`.
Repeated occurrences of the same component value are accepted. The API deliberately
does not try multiple credential combinations, even for `verify_candidates` rules.
For ambiguous inputs, scan a narrower credential block with its needed context.
Do not combine unrelated file results into one batch.

The dispatcher supports YAML HTTP (including inline multipart), Betterleaks
expressions and multi-step flows, and the enabled typed/Raw/gRPC validator families.
`validation-http` exposes the high-level API. Add `validation-ethereum` for offline
key-material checks, or other features from the table below. Disabled families
produce `Skipped` rather than successful validation. Rules without a validator produce
`NotAttempted`; `Assumed` stays distinct from live proof; non-authoritative rules
remain `NotAttempted` with a `NonAuthoritative` reason. The API does not revoke credentials or perform access mapping.

HTTP matchers must encode reliable authentication evidence; negative matchers retain
the YAML rule semantics. A matching response reports activity;
HTTP 401 is rejection, while unexpected bodies, 403, rate limits, redirects, server
errors, and network failures remain inconclusive unless a provider-specific
validator has stronger evidence. Legacy protocol helpers that return an ambiguous
`false` are conservatively reported as `Unavailable`. Local Ethereum derivation
remains `LocallyDerived`, not `VerifiedActive`. Inspect outcomes directly instead
of inferring them from the optional HTTP status.

`ValidatedFinding` retains raw credentials until explicitly redacted. Its debug
output omits credentials and it has no automatic serialization implementation.
Serialize selected metadata or its redacted finding. Error reasons omit raw
provider bodies, URLs, and capture values.

### Verify an integration before shipping it

Run copied examples with synthetic inputs before connecting real providers. Cover a
clean input, a detected token, unreadable input, and provider rejection, throttling,
and unexpected-success bodies. Preserve detection results when validation is
inconclusive. In this repository, run the portable example checks with:

```sh
python3 -m unittest discover -s scripts/tests -p test_library_examples.py -v
```

## Loading and Compiling Rules

Compile once and share the database. Preserve catalog metadata with
`RulesDatabase::from_rule_collection`; converting the loaded collection into a
`Vec<Rule>` loses its database-level source prefilter.

For custom files, add `kingfisher-rules = "1.0.0"` and use:

```rust
use kingfisher_rules::{Confidence, Rules, RulesDatabase};

let rules = Rules::from_paths(["rules/company.toml"], Confidence::Low)?;
let database = RulesDatabase::from_rule_collection(rules)?;
```

Both the Kingfisher rule format (`.yml`/`.yaml`) and Betterleaks TOML (`.toml`) are
fully supported by `Rules::from_paths`, including directories containing both formats.
Betterleaks TOML rules receive the `custom.` namespace. See [rule authoring](RULES.md).
Missing files, malformed rules, and compilation failures return errors.
The built-in catalog is embedded; loading it performs no rule downloads.

Programmatic private rules can use a constructor instead of a complete schema literal:

```rust
use kingfisher_scanner::{Rule, RuleSyntax, RulesDatabase};

let mut syntax = RuleSyntax::new(
    "acme.service-token", "Acme service token", r"(acme_[a-z0-9]{16})",
);
syntax.min_entropy = 2.0;
let database = RulesDatabase::from_rules(vec![Rule::new(syntax)])?;
```

Construction supplies medium confidence, visibility, and no validators, filters,
or entropy threshold. Compilation validates the pattern. Use one capture for the
reported secret; Vectorscan patterns cannot use lookaround.

## Scanner Configuration

```rust
use kingfisher_scanner::ScannerConfig;

let config = ScannerConfig {
    redact_secrets: true,
    enable_dedup: false,
    ..Default::default()
};
```

Pass it to `Scanner::with_config(Arc::clone(&database), config)`.

| Setting | Default | Contract |
| ------- | ------- | -------- |
| `enable_base64_decoding` | `true` | Scan one Base64 decoding layer in addition to ordinary content |
| `enable_dedup` | `false` | Opt in to suppressing previously reported content at the same source path |
| `min_entropy_override` | `None` | Use each rule's threshold; an override applies to every rule |
| `redact_secrets` | `false` | Replace returned secret and capture values with `[REDACTED]` |

Deduplication is scoped to one scanner and cleared by `reset_dedup()` or dropping
that scanner. Concurrent first scans may both report findings. Source paths are
compared as supplied, without canonicalization. The cache retains entries for scans
that returned findings; it grows until reset. Leave it disabled for request-oriented
services or when every file occurrence must be reported.

## Scanning Methods

All scanning methods return `anyhow::Result<Vec<Finding>>`; propagate or explicitly
handle errors. A failed scan is not an empty successful scan.

An error evaluating a Betterleaks filter, including a malformed custom
`betterleaks_filter`, fails the entire scan call for that input. No partial findings
are returned, including findings from other rules. This applies to ordinary and
Base64-decoded content: propagating the error prevents a failed filter from silently
keeping a finding that should have been filtered. Fix the rule and retry the input.

| Method | Input and behavior |
| ------ | ------------------ |
| `scan_bytes(&[u8])` | Borrows input except when encoding normalization requires allocation; no source path |
| `scan_file(path)` | Opens a file, preserving its path for path-aware rules; returns I/O errors |
| `scan_blob(&Blob)` | Reuses an existing blob; no source path |
| `scan_blob_at_path(&Blob, &str)` | Reuses a blob with an explicit path for filters and path predicates |

A scan performs detection and filtering, including entropy, catalog filters, and
component requirements. It does not run validators, revoke credentials, traverse
repositories, decompress arbitrary archives, or reproduce every CLI pipeline stage.
Enabling a validation feature does not change this boundary.

## Working with Findings

Findings own their strings and remain usable after the scan input is dropped.
They hold an `Arc<Rule>` for rule metadata. Results may include invisible component
helpers; filter with `finding.rule().visible()` when displaying user-facing detections.
Use `rule_id`, `rule_name`, `confidence`,
`entropy`, `location`, and `is_base64_encoded` for reporting. `secret` and `captures`
contain credentials unless redaction is enabled.

Redaction happens after component matching and fingerprint computation. It covers
all returned capture values as well as the primary secret. It is output redaction,
not secure erasure of input, rules, or temporary memory. Findings can still contain
sensitive metadata such as locations and fingerprints.

Offsets are zero-based, end-exclusive byte offsets; lines are one-based and columns
are zero-based byte columns. UTF-16/32 input is normalized to UTF-8, and reported
positions refer to that normalized content. For Base64 matches, the location covers
the encoded region in the outer content. It is not a decoded-secret offset.
Finding order is unspecified. Numeric fingerprints and native database caches are
implementation details, not stable persisted identifiers or storage formats.

## Parallel Scanning

`Scanner`, `RulesDatabase`, and `ScannerPool` are `Send + Sync`. Compile once and share
with `Arc`; native scratch space is allocated per worker thread. Default scans are
independent, including repeated scans of the same content.

The API is synchronous and CPU-bound. Async applications should use blocking workers
or their own bounded thread pool. The library does not initialize a Tokio runtime,
logging subscriber, process allocator, or global executor for scanning.

`ScannerPool` is a lower-level API for native scanners. Prefer `try_with`, which
returns allocation and reentrant-borrow errors. A callback must not recursively
borrow the same pool on the same thread. `with` panics for those errors; it does not
permit overlapping mutable borrows.

## Credential Validation (Optional)

No validator features are enabled by default:

```toml
[dependencies]
kingfisher-scanner = { version = "1.0.0", features = ["validation-http"] }
```

| Feature | Exposes |
| ------- | ------- |
| `validation` | Alias for `validation-http` |
| `validation-http` | HTTP request, response, and template helpers |
| `validation-raw` | Provider/protocol-specific raw validators |
| `validation-grpc` | Unary gRPC validators with HTTP/2 trailer matching |
| `validation-ethereum` | Network-free Ethereum key parsing and address derivation |
| `validation-aws` | AWS validators |
| `validation-azure` | Azure Storage validators |
| `validation-coinbase` | Coinbase validators |
| `validation-gcp` | GCP validators |
| `validation-jwt` | JWT validators |
| `validation-database` | MongoDB, MySQL, PostgreSQL, JDBC validators |
| `validation-all` | All validator features and their dependencies |

Prefer `Validator` for rule dispatch and result handling; low-level protocol helpers
remain available. Call validation explicitly. Embedding applications own clients, runtime,
timeouts, and concurrency. Some validator helpers expose process-wide configuration;
isolate or coordinate such configuration instead of changing it per concurrent request.
`ValidationOutcome` distinguishes verified activity from assumptions and local
cryptographic derivation. Do not equate an actionable finding with a live credential.
Provider behavior and network availability are outside the Rust API contract.

## Build and Deployment

The native Vectorscan backend supports the repository's macOS, Linux, and Windows
builds. Windows uses GNU/LLVM MinGW targets; MSVC is not supported by the
standard native backend. Cargo builds may download its platform archive. For offline builds, cache
Cargo dependencies and native prerequisites, configure `VECTORSCAN_PREBUILT_DIR`
or `HYPERSCAN_ROOT`, and set `VECTORSCAN_OFFLINE=1`. See [publishing](PUBLISHING.md)
for extracted-package verification. `--offline` alone does not sandbox build scripts.

The rules and scanner crates configure docs.rs to compile vendored Vectorscan source
for Linux x64, avoiding archive downloads in its network-blocked build environment.

Large files can be memory-mapped by `Blob::from_file`; the application must ensure
mapped files are not modified or truncated while in use. Set application-level
input limits and bound worker counts for untrusted or large workloads.

The full application's library is available separately:

```toml
kingfisher = { package = "kingfisher-bin", version = "2.8.0" }
```

It carries CLI dependencies and all validator features. The stable embedding contract
described here applies to the three `1.x` library crates; prefer those for integration.

## API Stability

The first published `1.0.0` establishes the stable contract. Within `1.x`:

- Existing reachable public Rust items, signatures, fields, trait implementations,
  and feature names remain compatible. Hidden-but-public items are not exempt.
- Removing public items, changing field types, adding fields to exhaustive structs,
  adding variants to exhaustive enums, or incompatible public dependency type changes
  requires a major release. Deprecation can precede removal but does not permit it in `1.x`.
- Documented defaults, error propagation, location semantics, and redaction behavior
  are behavioral contracts covered by regression tests.
- Existing documented serialized field names and enum spellings are retained. New
  optional data may be added where compatible; consumers should accept unknown fields.
- Rust 1.96 remains the minimum supported compiler for `1.x`. Dependency updates must
  preserve that minimum and pass feature and consumer checks.

Catalog content, match counts, provider responses, diagnostics, finding order,
fingerprints, and native cache bytes can change without a major API release.
Fixing incorrect detections is not a promise to preserve previous findings.
Pin exact crate versions and retain `Cargo.lock` when reproducible detector results
matter, and review catalog provenance when upgrading.

CI runs public consumer regression tests, README doctests, default/all-validator
builds, and `cargo-semver-checks` against the pull request's base revision. After
publication, release checks must also compare against the last published compatible
library version (see [publishing](PUBLISHING.md)). Static API checks do not prove all
behavior; review and behavioral tests remain required.

### Migrating from the 0.1 API

- `scan_bytes` now returns a `Result`; use `?` or handle the error.
- Repeated calls return findings by default; explicitly enable cross-call deduplication
  when wanted. Deduplication now includes the source path.
- Remove unused `language_hint` and `max_base64_depth` fields from `ScannerConfig`.
  Base64 detection currently scans one decoding layer.
- Redaction now uses `[REDACTED]` for secrets and captures, and preserves the unredacted
  fingerprint. It no longer reveals a secret prefix.
- `SerializableCapture` owns its name and value strings. The leaking `intern` helper
  is removed; use owned strings. `raw_value()` borrows from the capture.

## See Also

- [Rule authoring](RULES.md)
- [Publishing and package versions](PUBLISHING.md)
- [CLI usage](USAGE.md)
