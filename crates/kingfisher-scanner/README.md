# kingfisher-scanner

Embeddable, synchronous secret detection for Rust 1.96+. The `1.x` public Rust API
follows semantic versioning; breaking changes require a new major version.

```toml
[dependencies]
kingfisher-scanner = "1.0.0"
anyhow = "1"
```

## Quick start

Load and compile once, then reuse the scanner. Scanning does not contact providers,
validate credentials, revoke credentials, or initialize an async runtime.

```rust
use std::sync::Arc;
use kingfisher_scanner::{get_builtin_rules, RulesDatabase, Scanner};

fn main() -> anyhow::Result<()> {
    let database = RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?;
    let scanner = Scanner::new(Arc::new(database));
    let findings = scanner.scan_bytes(b"ordinary text")?;
    assert!(findings.is_empty());
    Ok(())
}
```

## Custom rules and configuration

```rust
use std::sync::Arc;
use kingfisher_scanner::{Rule, RuleSyntax, RulesDatabase, Scanner, ScannerConfig};

let rule = Rule::new(RuleSyntax::new(
    "acme.service-token", "Acme service token", r"(acme_[a-z0-9]{16})",
));
let database = Arc::new(RulesDatabase::from_rules(vec![rule])?);
let scanner = Scanner::with_config(database, ScannerConfig {
    redact_secrets: true,
    ..Default::default()
});
let findings = scanner.scan_bytes(b"token=acme_abcd1234efgh5678")?;
assert_eq!(findings.len(), 1);
assert_eq!(findings[0].secret, "[REDACTED]");
# Ok::<(), anyhow::Error>(())
```

Use `scan_file(path)?`, `scan_blob(&blob)?`, or `scan_blob_at_path(&blob, source_path)?`
when scanning files or applying path-aware rules. Errors propagate; an empty successful
result means no findings for that call, subject to configured filters and deduplication.

`Scanner` and `RulesDatabase` are `Send + Sync`. Share a scanner with `Arc` across worker
threads. Each thread gets its own native scratch space. In async applications, schedule
CPU-bound scanning on blocking workers. Callbacks into `ScannerPool::try_with` must not
recursively borrow the same pool on the same thread; this returns an error.

## Behavior contract

- Defaults: Base64 detection enabled (one decoding layer), redaction disabled,
  cross-call deduplication disabled, rule-defined entropy thresholds.
- `enable_dedup` suppresses previously reported content at the same source path.
  Concurrent first scans may both return findings. This cache grows until
  `reset_dedup()` or scanner drop; leave it disabled for independent requests.
- UTF-16/32 content is normalized to UTF-8. Offsets and byte columns refer to the
  normalized content, with zero-based offsets/columns and one-based lines.
  Base64 locations cover the encoded region, not the decoded secret's byte position.
- `redact_secrets` replaces the secret and every returned capture value with
  `[REDACTED]`. Fingerprints are computed before redaction. This does not zeroize
  caller-owned input or turn findings into non-sensitive data.
- Results may include invisible component helpers. Filter with
  `finding.rule().visible()` for user-facing reports.
- Finding order, numeric fingerprints, native cache formats, and built-in detector
  contents are not persistent storage contracts. Catalog updates may change findings.
- The detector applies candidate rules, filters, entropy, and component requirements.
  It is not the CLI's complete repository traversal, reporting, or live validation pipeline.

## Optional validation

No validator features are enabled by default. Enable only the protocols needed:

```toml
kingfisher-scanner = { version = "1.0.0", features = ["validation-http"] }
```

`validation` aliases `validation-http`. Other features are `validation-raw`,
`validation-grpc`, `validation-ethereum`, `validation-aws`, `validation-azure`, `validation-coinbase`,
`validation-gcp`, `validation-jwt`, and `validation-database`. `validation-all`
enables all validators and their dependencies. Enabling a feature exposes validation
functions; it does not make `Scanner` perform network requests automatically.
Validation clients and runtime lifecycles are managed by the embedding application.

Vectorscan is a native dependency. Its build may download a platform archive;
compiling the embedded rule catalog does not download rules. For offline builds,
prepare `VECTORSCAN_PREBUILT_DIR` or `HYPERSCAN_ROOT` and set `VECTORSCAN_OFFLINE=1`.
See the repository's [library guide](https://github.com/mongodb/kingfisher/blob/main/docs/LIBRARY.md)
for versioning, deployment, and migration details.

## Scan and validate

Enable `validation-http` for the high-level API. Add provider features as needed,
or `validation-all` for all supported families. Keep raw findings until validation
finishes and pass the full result set so hidden supporting credentials are available.

```rust,no_run
# #[cfg(feature = "validation-http")]
# async fn example() -> anyhow::Result<()> {
use std::{sync::Arc, time::Duration};
use kingfisher_scanner::{get_builtin_rules, RulesDatabase, Scanner, Validator};

// Initialize once. In async services, compile and scan on blocking workers.
let database = RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?;
let scanner = Scanner::new(Arc::new(database));
let validator = Validator::builder()
    .timeout(Duration::from_secs(10))
    .concurrency(4)
    .build()?;

let findings = scanner.scan_bytes(b"application configuration")?;
for result in validator.validate_findings(findings).await {
    if result.finding.rule().visible() {
        let result = result.into_redacted();
        println!("{}: {:?}", result.finding.rule_id, result.outcome);
    }
}
# Ok(())
# }
```

For one independent finding, use `validator.validate_finding(&finding).await`.
For one finding with supporting credentials, use
`validate_finding_with_context(&finding, &same_input_findings)`.
`ValidatedFinding` pairs the original finding with its outcome, optional reason,
and HTTP status. Its debug output omits credentials; it deliberately does not
implement serialization. `into_redacted()` redacts secret and capture values.

Validators are cloneable and share their concurrency limit. Defaults use strict
TLS, no redirects, and block internal addresses. Inject an HTTP client with
`client(...)`, trusted endpoint variables with `variable(...)`, and opt into local
services with `allow_internal_ips(true)`. SDK/database/gRPC transports retain their
own clients; the outer deadline applies to all families. See the library guide for
[association rules and outcome semantics](https://github.com/mongodb/kingfisher/blob/main/docs/LIBRARY.md#supporting-credentials-and-validation-outcomes).

## Runnable examples

From the repository checkout:

```sh
cargo run --locked -p kingfisher-scanner --example scan_content
```

The packaged [`scan_content` example](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-scanner/examples/scan_content.rs) is also available
in the crate source.

Scan a real file with the built-in catalog, or exercise explicitly enabled local validation:

```sh
cargo run --locked -p kingfisher-scanner --example scan_content -- path/to/config.env
cargo run --locked -p kingfisher-scanner --example local_validation --features validation-ethereum
```

These examples avoid network validation and print no unredacted secrets.

More complete integrations (all included in the crate source):

| Example | Demonstrates |
| ------- | ------------ |
| `scan_files` | File batches, path-aware detection, JSON Lines reports without credentials |
| `scan_custom_rules` | Load private YAML/TOML rules and scan a file |
| `scan_async` | Shared scanner, Tokio blocking workers, bounded concurrency |
| `http_validation` | Scan and validate against a loopback mock with `Validator` |
| `validate_file` | Scan a file with built-ins and validate against actual providers |

```sh
cargo run -p kingfisher-scanner --example scan_files -- Cargo.toml README.md
cargo run -p kingfisher-scanner --example scan_custom_rules -- crates/kingfisher-scanner/examples/fixtures/acme-http.yml README.md
cargo run -p kingfisher-scanner --example scan_async
cargo run -p kingfisher-scanner --example http_validation --features validation-http
```

The HTTP example uses a local mock with synthetic credentials. It checks active,
rejected, rate-limited, and unexpected-success responses without contacting a provider.
Keep raw findings until validation finishes, then report only selected metadata;
`redact_secrets: true` before validation replaces the token the validator needs.
Use `Validator` to dispatch enabled rule families and bind supporting credentials.
It uses the same `validation::ValidationEngine` as CLI scans and direct `validate`.
The engine owns protocol dispatch and outcome classification; applications own input
association, concurrency, and reporting. Advanced callers with resolved Liquid globals
can call the engine directly. Its `ValidationResult::response_body` may contain
credentials and is omitted from Debug output. Prefer the high-level finding API for
ordinary integrations. `.retries(n)` enables YAML HTTP retries within the total deadline.
Disabled features, missing or ambiguous components, redacted inputs, and timeouts
produce explicit outcomes and credential-free reasons.

See the [integration recipes](https://github.com/mongodb/kingfisher/blob/main/docs/LIBRARY.md#integration-recipes-for-rust-projects-and-llm-agents)
for copyable dependency manifests and instructions for adapting each example.
