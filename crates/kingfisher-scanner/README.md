# kingfisher-scanner

Embeddable, synchronous secret detection for Rust 1.99+. The public Rust API
follows semantic versioning; breaking changes require a new major version.

```toml
[dependencies]
kingfisher-scanner = "3.0.1"
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

Custom YAML HTTP validators can authenticate to a configured verifier with
OAuth2. Reuse a `Validator` to share token refresh and failure cooldowns across
checks; scanning itself remains offline. See the
[auth configuration](../../docs/RULES.md#oauth2-authentication-for-http-verification-services)
and [runnable example](examples/oauth2_validation.rs). OAuth2 HTTPS token/verifier
requests retain strict TLS and environment proxy/`NO_PROXY` behavior. Only explicitly
allowed loopback plain-HTTP token/verifier requests bypass proxies; redirects stay
disabled for both transports.

Betterleaks v2 rules can include explicit Expr analysis and revocation. Use
`Validator::analyze_validated` after validation and `Revoker::revoke_validated`
for deliberate revocation; neither runs during scanning. HTTP fallbacks are off
by default; use `Validator::builder().http_fallbacks(true)` to enable up to two
named alternatives. Validation logic reuse is explicit (`reuse_primary_validation_logic: true`),
defaults to false, and does not imply revocation reuse. Independently opt in with
`reuse_primary_revocation_logic: true` and explicit replacement URL(s), or define an independent
action. The CLI uses `--fallbacks`; mutations never fail over between environments.
CLI `revoke --fallbacks` validates to select its target; SDK result-based revocation
reuses the retained snapshot without another validation request.
Direct `Revoker::revoke` uses only the primary action and rejects reserved HTTP
endpoint-selection variables; use `revoke_validated` for fallback environments.
Existing YAML/TOML rules need no edits.
Reuse shares logic, not the primary destination.
The selected environment stays in the private credential snapshot. See the
[runnable fallback example](examples/http_fallbacks.rs). Source-aware
custom filters can use `Scanner::scan_blob_with_attributes` with caller-supplied
`path`, `git.sha`, or other metadata. See the [library guide](../../docs/LIBRARY.md)
and [rule format guide](../../docs/RULES.md).

## Migrating to 3.0

Use rules/scanner `3.0.0` together. Existing YAML/TOML rule files remain compatible;
public Rust schema fields and enum variants require source updates. See the
[3.0 migration guide](../../docs/LIBRARY.md#migrating-to-rules-and-scanner-30).
Core uses the compatible 1.0.6 patch; Python SDK 1.6.0 preserves its existing Python API.

## Migrating to 2.0

This is a **Rust source/type migration, not a rule-file migration**. Existing
Kingfisher YAML and Betterleaks TOML rule files need no changes. HTTP service
authentication (`validation.content.auth`) is optional: omitting it preserves
existing HTTP requests, candidate-token headers, body and response matchers,
without requiring OAuth2 credentials or a token exchange.

Upgrade direct `kingfisher-rules` dependencies to `"2.0.0"` alongside this crate.
The scanner's public `Rule`, `RuleSyntax` and `RulesDatabase` types/re-exports now
come from rules 2.x and cannot be mixed with rules 1.x types. Existing
`HttpValidation` Rust struct literals need `auth: None`, or
`auth: Some(Box::new(HttpValidationAuth { oauth2: config }))` with the new
`kingfisher_rules::{HttpValidationAuth, OAuth2Config, OAuth2PasswordCredentials}` types.
Core uses the compatible 1.0.4 patch release; Python SDK 1.5.0 remains compatible with the existing Python API. See the
[library migration guide](../../docs/LIBRARY.md#migrating-to-rules-and-scanner-20).

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

Raw and Base64 matches enforce `pattern_requirements` before component resolution:
character minimums, ignored substrings and Liquid checksum templates, including
`luhn_valid` and `iban_valid`. See the [rule guide](../../docs/RULES.md#character-requirements).

For exact full-match component windows and candidate ranking, use
`scan_blob_with_context(&blob, path)?`, then pass its context to
`validator.clone().with_scan_context(output.context)` before validating
`output.findings`. Without detection options, component matching uses full-match
windows and isolates raw input and each decoded buffer, preventing sibling Base64
values from satisfying one another's required components. Explicit
`DetectionOptions` retain their chosen `cli_match_semantics` policy even when
context is collected; collecting metadata does not override that flag.
Context retains compact spans and assignment/scope metadata, not source payloads.
Existing finding fields and serialization are unchanged; vector-only APIs retain
their historical finding-location association. See the
[runnable HTTP example](examples/http_validation.rs).

With `validation`, typed credential URI syntax checks run offline during detection.
Explicit `verify_candidates` opt-ins use shared fixed-origin eligibility and bounded
credential pairing; unresolved searches never establish inactivity. Identical rules
and resolved inputs reuse definitive active/inactive results within each validation
batch, preserving all occurrences even when remaining attempt budgets differ. Inconclusive failures and
cancellations are not memoized; later occurrences can retry and separate batches recheck.

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
  In-flight scans may commit entries after a reset; finish them before resetting a batch.
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
kingfisher-scanner = { version = "3.0.1", features = ["validation"] }
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

SMTP URIs dispatch through `CredentialUri`; separate host/username/password fields
use `Raw` content `smtp` and associated helpers. Both authenticate with PLAIN or
LOGIN over mandatory TLS without sending email. See the
[SMTP rule example and input contract](https://github.com/mongodb/kingfisher/blob/main/docs/RULES.md#smtp-authentication).

See the [integration recipes](https://github.com/mongodb/kingfisher/blob/main/docs/LIBRARY.md#integration-recipes-for-rust-projects-and-llm-agents)
for copyable dependency manifests and instructions for adapting each example.

## Credential revocation

Offline preparation is available with `validation`:
`Scanner::scan_blob_for_preparation_with_control(&blob, path, &control)` retains
primary candidates missing required components and overlapping catalog candidates.
Preparation neither reads nor changes scan deduplication state. With `context`,
`scan_blob_for_preparation_with_options_and_control` also applies detection policies.
Other detection filters and normal scanning remain unchanged. `Validator::input_diagnostics(&candidate, &same_input_findings)` returns
credential-free `CredentialInputDiagnostic` names/categories using native windows,
defaults and request templates. Conditional templates can over-report names after
render errors; Betterleaks branches and provider constraints are not fully proven.
`Validator::with_variables(mapping)` clones policy and the pooled client with
explicit overrides. `validate_prepared_findings(candidates, &context).await`
checks only selected candidates, skips missing inputs and ambiguities without supported verification opt-ins
before network work and associates supporting context without validating helpers.
`ValidatedFinding::input_diagnostics` retains unresolved input diagnostics; verified
candidate selection clears dependency ambiguity. Missing
revocation-only variables prevent resolved action inputs even after active validation.
`same_revocation_target(&other)` compares original rule/action definitions and
complete resolved action inputs for application-owned deduplication.

The Python SDK builds text/file preparation and batch convenience methods on
these shared primitives; see the [SDK guide](../../docs/PYPI.md).

With `validation`, `Revoker` provides explicit rule-driven revocation without
CLI dependencies:

For scan/validate workflows, call `Revoker::revoke_validated(&result).await?` on a
verified active `ValidatedFinding`. Its `credential: Option<ResolvedCredential>`
retains the exact validation variables and supporting findings plus resolved
`RevocationInputs`; AWS secret-key/`AKID` remapping follows the catalog bindings.
The original rule and inputs are reused without environment lookup or component
re-association. Missing inputs and non-active results are rejected before requests.
`revocation_supported()` reports rule support. `into_redacted()` drops the retained
inputs; their `Debug` implementations omit credential values. Validation alone never
revokes. The low-level API is also available:

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
strict TLS and disables redirects. Calls have a 10-second total deadline. HTTP rule
requests are not retried. AWS STS identity lookup may retry transient failures, but
IAM mutations retry only definitive throttling responses, with at most three attempts and SDK retries disabled. Customize with
`Revoker::with_client` and `Revoker::timeout`.
Callers own authorization and endpoint policy; internal HTTP addresses are allowed.
A timeout may occur after a credential was revoked. Scanning and validation never
invoke revocation. Provider responses and errors may contain secrets.

For structured AWS outcomes and explicit action or signer selection, use
`validation::revoke_aws_access_key_with_options` with `AwsRevocationOptions` and
inspect its `AwsRevocationResult`. `AwsRevocationCredentials` supports self or
responder signing; use `AwsRevocationOptions::responder(&SdkConfig)` and optionally
`with_target_user_name`, `with_region`, or `with_attempt_timeout`. The name is used
directly for a responder and checked against the STS identity for self-revocation.
Responder configurations retain their region unless overridden; self-revocation defaults
to `us-east-1`. Deactivation is the default; deletion requires
`AwsRevocationAction::Delete`. Verify the key state before retrying an
`AwsRevocationStatus::Unknown` result.

See [`examples/revoke.rs`](examples/revoke.rs) for a runnable example.

## Shared revocation execution

With `validation`, `validation::revocation` exposes the HTTP and multi-step
revocation helpers used by the CLI and Python SDK. These low-level async helpers
require an explicit rule configuration, resolved Liquid globals, client, parser,
timeout and retry count. Callers own authorization, endpoint policy and the total
deadline; use a client with redirects disabled and zero retries for destructive
operations. AWS and GCP helpers are included in the same feature.

## Optional archive extraction

The `archives` feature exposes the shared CLI/Python extraction helpers under
`archive::decompress` and resource budgets under `archive::limits`. It is disabled
by default so byte-only Rust embedders do not pull in archive dependencies.
Extraction is separate from `Scanner`: use `scan_blob_at_path` to scan extracted
bytes with their logical source path. Extraction is best effort and format limits
can skip entries or truncate content. The Python SDK offers a composable input
layer with filesystem/history iterators and bounded archive expansion; see
[the Python guide](../../docs/PYPI.md#compose-filesystem-git-history-and-archives).

For strict byte budgets, use
`archive::decompress::decompress_file_with_strict_single_stream_cap_and_limits`
with `ResourceLimits::default()`. It fails on stream-cap exhaustion before parsing
a partially decoded TAR. Existing best-effort entry points keep their truncation
behavior. TAR members use independent physical staging paths while
preserving their logical names, including repeated names.
`decompress_file_with_budget` and `extract_zip_archive_in_memory_with_budget`
also enforce strict byte/entry budgets with `ScanControl` and return inspected
entry usage, allowing nested callers to debit one aggregate root budget.

Owned directories from `decompress_file_to_temp` use Unix mode 0700; standalone
decoded files created without an output directory use mode 0600 and require caller
cleanup. The umask may restrict these modes further. Windows inherits the
temporary parent's DACL. Choose a protected temporary parent on every platform;
caller-supplied output directories retain their permissions and must also be
protected. Cleanup is not secure erasure and can leave remnants after a crash;
use encrypted or memory-backed storage when needed.

## Optional CLI detection policies and content extraction

Enable `context` for opt-in CLI matching, bounded Base64 decoding, inline-ignore
and HTML/CSS parser policies.
Existing `ScannerConfig` and scanner methods retain their signatures and behavior.
Use `context::DetectionOptions` with `scan_blob_at_path_with_options` for unlimited
controls, or `scan_blob_at_path_with_options_and_control` for a deadline/cancellation:

```rust
# use std::sync::Arc;
# use kingfisher_scanner::{Blob, RulesDatabase, Scanner, ScanControl, get_builtin_rules};
# #[cfg(feature = "context")]
# fn main() -> anyhow::Result<()> {
# let scanner = Scanner::new(Arc::new(RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?));
use kingfisher_scanner::context::DetectionOptions;
let blob = Blob::from_bytes(b"ordinary configuration".to_vec());
let findings = scanner.scan_blob_at_path_with_options_and_control(
    &blob, "config.html", &DetectionOptions::default(), &ScanControl::default(),
)?;
# Ok(())
# }
# #[cfg(not(feature = "context"))]
# fn main() {}
```

The options entry point enables CLI matching by default: a 4 KiB initial
confirmation window (widened when needed), full-match component windows,
per-rule secret containment suppression, and overlapping Betterleaks credential-URI
fallback suppression. `cli_match_semantics = false` retains the SDK's 64 KiB
confirmation alignment and secret-based component windows. Full-match metadata
stays private; reported locations and the public `Finding` shape are unchanged.

Base64 decoding defaults to two layers and skips the Base64 pass when the
original input exceeds 64 MiB. Raw matching still runs above that limit.
Set `base64_max_depth` independently (zero disables decoding), and use
`base64_max_input_bytes = None` to remove the input cap. `ScannerConfig`'s
`enable_base64_decoding = false` disables decoding regardless of these options.
Nested findings keep the outer encoded region's offsets. Existing scanner methods
retain their one-layer, uncapped Base64 behavior.

Inline-ignore and containment filtering run before markup verification, followed
by component requirements, URI fallback suppression, catalog deduplication and
redaction. Interrupted calls return no partial findings and do not commit dedup
state. The dedup key is the blob ID and path; it does not include detection options.
With deduplication enabled, use a separate scanner per detection policy.
The markup gate uses shared language inference, bypasses self-identifying/Base64
candidates and retains candidates above 2 MiB or with invalid UTF-8 secrets.
Set `inline_ignores = false` or `markup_context = false` independently.
Dense candidate confirmation reuses complete indexed matches for consuming
rules with no assertions, certified using the rule builder's flags. This avoids
repeated end-anchored searches over long lazy spans; partial endpoints resume
after the last complete indexed match. EOF-sensitive alternatives
and word boundaries retain the guarded confirmation and original iterator;
arbitrary regex builders receive no such certificate.
The parser, inline-ignore, index and confirmation helpers are isolated behind
the explicitly unstable `__cli-internals` feature for CLI orchestration. Embedders should use the supported scanner entry points.

The optional `extraction` feature enables `archives` and exposes
`extraction::sqlite::extract_sqlite_contents[_with_limits]` and
`extraction::pyc::extract_pyc_strings[_with_limits]`. SQLite extraction opens the
supplied file read-only and emits SQL per user table; bytecode parsing extracts
marshal strings without executing Python. These low-level helpers use the CLI's
best-effort limits and may skip/truncate content. The strict
`extract_sqlite_contents_with_budget` and `extract_pyc_strings_from_bytes_with_budget`
counterparts enforce output budgets and controls during extraction, propagating
`ExtractionLimitExceeded` without partial text. Extraction is explicit and
separate from scanning; findings refer to extracted content. The Python
`expand_content()` adapter stages a separate copy and adds per-input budgets and
cooperative controls. Choose a protected `temp_dir` parent on every platform.
SDK staging directories use owner-only Unix mode 0700 (the umask may restrict it
further); Windows inherits the parent DACL. See
[the SDK guide](../../docs/PYPI.md#extract-sqlite-and-python-bytecode).

The same `extraction` feature provides
`extraction::pdf::extract_pdf_text_from_bytes_with_budget(bytes, max_bytes, &control)`.
It returns `(page-N.txt, UTF-8 bytes)` pairs with separate input/aggregate-output
caps, `min(max_bytes, 32 MiB)` per decoded page/font stream, and a 10,000-page
cap. Loading divides the byte budget across a conservative count of literal stream
markers, at most 32 MiB each, bounding aggregate eager decompression before allocation.
Overcounted markers can cause valid large streams to be rejected.
Errors return no partial pages. Controls run around parsing and between pages;
individual parser calls cannot be preempted, and caps are not a process-memory
bound. CLI-policy variants accept file paths or resident bytes with `ResourceLimits`.
`extract_pdf_text_from_bytes_with_control(bytes, resources, &control)` also retains
the caller's deadline/cancellation while applying CLI resource policy.
Finding offsets refer to extracted page text; retain original provenance separately.
No OCR, encrypted PDFs, embedded files, annotations, or Form XObject text extraction.
See the [PDF example](examples/pdf.rs) and [library guide](../../docs/LIBRARY.md#pdf-page-text).

## Offline Git inputs (`git` feature)

Enable `git` for `git::{GitInputs, GitScope, GitMode, GitOptions, GitEvent}`.
This is a read-only input source independent of detection and validation. No Git
executable, network, checkout, or repository writes are required. History visits
all merge parents, compares each selected commit with its first parent, and skips
identical subtrees. Snapshot, net-diff, and staged-index scopes are also available.

Descriptors and ancestry are prepared eagerly; blob payloads are loaded lazily.
Commit metadata uses shared `Arc<GitCommit>` instances across file versions.
`max_commits` bounds visited ancestry and `max_inputs` bounds distinct raw-path/blob
versions; exceeding either limit fails preparation. `max_blob_size` checks object
headers before reading and yields explicit `GitEvent::Skipped` coverage gaps.
Limits default to unlimited. Missing blobs fail by default; the explicit
`skip_missing_blobs` option yields coverage gaps instead. Partial clones never
fetch automatically; missing trees/commits and corruption remain errors.

Repository discovery searches ancestors by default for Python compatibility;
set `discover: false` to require an explicit repository root/Git directory. Git
revision grammar includes reflogs and `@{...}` forms, evaluated locally. Raw path
bytes remain available when lossy display paths collide. Shared controls cover
preparation and iterator lifetime, including consumer processing time; individual
native reads cannot be preempted. Payloads, messages, and email addresses are
excluded from default debug output. Finding redaction does not scrub provenance.

See the commented [Git example](examples/git_inputs.rs):

```sh
cargo run -p kingfisher-scanner --features git --example git_inputs -- /path/to/repo
```

Archive helpers return TAR/ZIP member bytes in memory when no output directory
is supplied. Use `decompress_file_to_temp_with_limits` and retain its `TempDir`
for disk-backed members. Strict extraction propagates corrupt-member errors;
best-effort SQLite extraction warns when a table cannot be dumped and caps
schema-list storage. Git `since_hours` must fit in signed 64-bit seconds.
