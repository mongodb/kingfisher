# kingfisher-scanner

Embeddable, synchronous secret detection for Rust 1.99+. The `1.x` public Rust API
follows semantic versioning; breaking changes require a new major version.

```toml
[dependencies]
kingfisher-scanner = "1.2.0"
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

For an optional per-call deadline or cancellation signal, use `ScanControl` with
`scan_bytes_with_control`, `scan_file_with_control`, or `scan_blob_at_path_with_control`:

```rust
# fn example(scanner: &kingfisher_scanner::Scanner, bytes: &[u8]) -> anyhow::Result<()> {
use std::time::Duration;
use kingfisher_scanner::{CancellationToken, ScanControl};
let cancellation = CancellationToken::default();
let control = ScanControl::default()
    .with_timeout(Duration::from_secs(2))?
    .with_cancellation(cancellation.clone());
let findings = scanner.scan_bytes_with_control(bytes, &control)?;
// Another thread can call cancellation.cancel() while the scan runs.
# Ok(())
# }
```

Interruption returns an error containing `ScanAborted::TimedOut` or
`ScanAborted::Cancelled`, without partial results or a dedup-cache entry.
Cancellation tokens remain cancelled; create a fresh token for new work. Checks
run between matching/filtering operations, in native match callbacks, and during
Base64 enumeration. Individual native operations, file reads, decoding and rule
compilation cannot be preempted. Use process isolation when a hard wall-clock
limit is required. Existing scan methods remain unlimited.

`Scanner` and `RulesDatabase` are `Send + Sync`. Share a scanner with `Arc` across worker
threads. Each thread gets its own native scratch space. In async applications, schedule
CPU-bound scanning on blocking workers. Callbacks into `ScannerPool::try_with` must not
recursively borrow the same pool on the same thread; this returns an error.
The CLI matcher and rule-filter helpers use the same pool implementation. Existing
pool import paths remain compatible. The pool retains its database until all
thread-local scanners have been dropped, and its callback cannot return a scanner
borrowing that database. Fallible callbacks return a nested `Result`; handle both
the pool error and the callback error. The compatibility `with` method panics on
scratch allocation or reentrant borrowing errors; prefer `try_with`.

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

Validation is disabled by default. Enable all supported validators and revocation:

```toml
kingfisher-scanner = { version = "1.2.0", features = ["validation"] }
```

`validation` enables every supported family and its dependencies. Legacy
`validation-*` feature names remain compatibility aliases that enable the same
complete feature. Enabling validation does not make `Scanner` perform network
requests automatically.
Validation clients and runtime lifecycles are managed by the embedding application.

Vectorscan is a native dependency. Its build may download a platform archive;
compiling the embedded rule catalog does not download rules. For offline builds,
prepare `VECTORSCAN_PREBUILT_DIR` or `HYPERSCAN_ROOT` and set `VECTORSCAN_OFFLINE=1`.
See the repository's [library guide](https://github.com/mongodb/kingfisher/blob/main/docs/LIBRARY.md)
for versioning, deployment, and migration details.

## Scan and validate

Enable `validation` for the high-level API and all supported families. Keep raw findings until validation
finishes and pass the full result set so hidden supporting credentials are available.

```rust,no_run
# #[cfg(feature = "validation")]
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

## Inspect rules and configured actions

`RulesDatabase::rules()` exposes the loaded catalog and each rule's serializable
`RuleSyntax`. Inspection works without the `validation` feature and makes no
provider requests:

```rust
use kingfisher_scanner::{get_builtin_rules, Confidence, RulesDatabase};

let database = RulesDatabase::from_rule_collection(
    get_builtin_rules(Some(Confidence::Low))?,
)?;
for rule in database.rules().iter().filter(|r| r.syntax().revocation.is_some()) {
    println!("{}: {}", rule.id(), rule.name());
}
let (index, rule) = database.rules().iter().enumerate()
    .find(|(_, r)| r.id() == "betterleaks.aws-access-token")
    .ok_or_else(|| anyhow::anyhow!("rule not loaded"))?;
println!("{}", rule.syntax().pattern);
println!("{}", database.anchored_regexes()[index].as_str());
println!("{}", serde_json::to_string_pretty(&rule.syntax().validation)?);
println!("{}", serde_json::to_string_pretty(&rule.syntax().revocation)?);
# Ok::<(), anyhow::Error>(())
```

Add `serde_json = "1"` when copying this into your project. The compiled regex
has rule comments removed; the historical `anchored_regexes()` name does not
mean these patterns are endpoint-constrained. Regex matches are candidates and
still pass capture selection, entropy, filters and dependency checks.
`RuleSyntax` also includes path predicates, pattern requirements, examples,
references and dependency bindings. HTTP/gRPC definitions expose configured
requests and matchers; Betterleaks exposes an expression tree. Typed/raw handlers
show their dispatch type/name rather than their Rust implementation code. Original
Betterleaks expression text may be absent in release builds. Missing actions
serialize as `null`; configuration presence does not prove an action will succeed.

The packaged [inspection example](examples/inspect_rules.rs) lists summaries,
filters by ID prefix or action support, and prints full or selected details:

```sh
cargo run --locked -p kingfisher-scanner --example inspect_rules -- --with-revocation
cargo run --locked -p kingfisher-scanner --example inspect_rules -- --id-prefix betterleaks.aws
cargo run --locked -p kingfisher-scanner --example inspect_rules -- betterleaks.aws-access-token --field pattern --field validation --field revocation
```

Use repeated `--rules-path PATH` to add custom YAML/TOML rules and `--no-builtins`
to inspect only your custom catalog. Output contains rule configuration, including
custom literals, rather than redacted findings. See `--help` for all options.

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
cargo run --locked -p kingfisher-scanner --example local_validation --features validation
```

These examples avoid network validation and print no unredacted secrets.

More complete integrations (all included in the crate source):

| Example | Demonstrates |
| ------- | ------------ |
| `inspect_rules` | Catalog summaries, exact definitions, regexes, filters, validation/revocation configurations |
| `scan_files` | File batches, path-aware detection, JSON Lines reports without credentials |
| `scan_custom_rules` | Load private YAML/TOML rules and scan a file |
| `scan_async` | Shared scanner, Tokio blocking workers, bounded concurrency |
| `http_validation` | Scan and validate against a loopback mock with `Validator` |
| `validate_file` | Scan a file with built-ins and validate against actual providers |

```sh
cargo run -p kingfisher-scanner --example scan_files -- Cargo.toml README.md
cargo run -p kingfisher-scanner --example scan_custom_rules -- crates/kingfisher-scanner/examples/fixtures/acme-http.yml README.md
cargo run -p kingfisher-scanner --example scan_async
cargo run -p kingfisher-scanner --example http_validation --features validation
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
`.timeout(Duration::ZERO)` disables Kingfisher validation timeouts, and
`.max_response_bytes(0)` disables YAML HTTP, Betterleaks, and gRPC response caps.
Injected HTTP clients retain their own timeout settings; concurrency remains bounded.
Disabled features, missing or ambiguous components, redacted inputs, and timeouts
produce explicit outcomes and credential-free reasons.

See the [integration recipes](https://github.com/mongodb/kingfisher/blob/main/docs/LIBRARY.md#integration-recipes-for-rust-projects-and-llm-agents)
for copyable dependency manifests and instructions for adapting each example.

## Credential revocation

With `validation`, `Revoker` provides explicit rule-driven revocation without
CLI dependencies:

```rust,no_run
# #[cfg(feature = "validation")]
# mod revocation_example {
use std::collections::BTreeMap;
use kingfisher_scanner::{Revoker, Rule};

async fn revoke_selected(rule: &Rule, secret: &str) -> anyhow::Result<bool> {
    let result = Revoker::new()?.revoke(rule, secret, &BTreeMap::new()).await?;
    Ok(result.revoked)
}
# }
```

Pass required companion variables and endpoint overrides in the map; `TOKEN` is
reserved for the secret argument. HTTP and multi-step rules are supported, with
AWS and GCP included in `validation`. The default client uses
strict TLS and disables redirects. Calls have a 10-second total deadline and no
automatic HTTP retries; AWS retains its provider-specific retry policy. Customize with `Revoker::with_client` and `Revoker::timeout`.
Callers own authorization and endpoint policy; internal HTTP addresses are allowed.
A timeout may occur after a credential was revoked. Scanning and validation never
invoke revocation. Provider responses and errors may contain secrets.

See [`examples/revoke.rs`](examples/revoke.rs) for a runnable example.

## Shared revocation execution

With `validation`, `validation::revocation` exposes the HTTP and multi-step
revocation helpers used by the CLI and Python SDK. These low-level async helpers
require an explicit rule configuration, resolved Liquid globals, client, parser,
timeout and retry count. Callers own authorization, endpoint policy and the total
deadline; use a client with redirects disabled and zero retries for destructive
operations. AWS and GCP helpers are included in the same feature.
