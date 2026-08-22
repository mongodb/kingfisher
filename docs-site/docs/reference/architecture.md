---
title: "Architecture"
description: "High-level architecture of Kingfisher: CLI, scanner pipeline, rule engine, validation, blast-radius mapping, and output formats."
---

# Kingfisher Architecture

This document focuses on the runtime architecture of Kingfisher as implemented in this repository today.

It shows:

- a high-level component map of the main crates, modules, command paths, and outputs
- the execution flow for `kingfisher scan`

## Component Map

```mermaid
flowchart LR
    User[User or CI] --> CLI[kingfisher CLI] --> Main[Dispatch and runtime]

    subgraph Commands[Commands]
        ScanCmd[scan]
        ValidateCmd[validate]
        RevokeCmd[revoke]
        AccessMapCmd[access-map]
        ViewCmd[view]
        RulesCmd[rules]
    end

    Main --> ScanCmd
    Main --> ValidateCmd
    Main --> RevokeCmd
    Main --> AccessMapCmd
    Main --> ViewCmd
    Main --> RulesCmd

    subgraph Inputs[Inputs]
        FS[Files and dirs]
        Git[Git repos and history]
        Hosts[Git hosts]
        Docs[Jira Confluence Slack Teams]
        Remote[S3 GCS Docker]
    end

    subgraph Pipeline[Scan pipeline]
        Runner[Scan runner]
        Enumerate[Enumerate and fetch]
        Process[Process blobs]
        Match[Match secrets]
        Store[FindingsStore]
        Filter[Dedup baseline safelist]
        Validate[Validate]
        Map[Blast radius]
        Report[Report]
        Viewer[Viewer]
    end

    subgraph Crates[Reusable crates]
        Core[kingfisher-core]
        Rules[kingfisher-rules]
        ScannerLib[kingfisher-scanner]
    end

    subgraph Engines[Engines]
        Vector[vectorscan]
        ScanPool[scanner pool]
        Context["context verifier"]
        Liquid[Liquid templates]
    end

    APIs[Provider APIs]
    Output[Terminal and report files]
    Browser[Browser UI]

    ScanCmd --> Runner --> Enumerate --> Process --> Match --> Store --> Filter
    Filter --> Validate
    Filter --> Report
    Validate --> Map
    Validate --> Report
    Map --> Report
    Report --> Output
    Report --> Viewer --> Browser

    FS --> Enumerate
    Git --> Enumerate
    Hosts --> Enumerate
    Docs --> Enumerate
    Remote --> Enumerate

    Core --> Process
    Core --> Match
    Rules --> Match
    ScannerLib --> Match
    ScannerLib --> Validate

    Match --> Vector --> ScanPool
    Match --> Context
    Validate --> Liquid
    Validate --> APIs

    ValidateCmd --> Liquid
    ValidateCmd --> APIs
    RevokeCmd --> Liquid
    RevokeCmd --> APIs
    AccessMapCmd --> APIs
    ViewCmd --> Viewer
```

## What Lives Where

- `src/main.rs`: top-level command dispatch, Tokio runtime setup, allocator selection (mimalloc/jemalloc/system), update checks, and command routing.
- `src/scanner/runner.rs`: the orchestration hub for `scan`, including repo enumeration, clone streaming, artifact fetching, validation setup, sequential or parallel scan execution (threshold: >10 git repos triggers parallel mode), reporting, and summary generation.
- `src/scanner/*`: input enumeration (`enumerate.rs`), repository handling and artifact fetching (`repos.rs`), blob processing (`processing.rs`), validation coordination (`validation.rs`), scan summaries (`summary.rs`), Docker image scanning (`docker.rs`), and utilities (`util.rs`).
- `src/matcher/*`: the main detection engine (`mod.rs`), including vectorscan callbacks, regex helpers, Base64 discovery (`base64_decode.rs`), capture group handling (`captures.rs`), dedup support (`dedup.rs`), filtering (`filter.rs`), and finding fingerprinting (`fingerprint.rs`).
- `src/parser.rs` and `src/parser/*`: parser-based context verification for language-aware matching, with handwritten lexers plus lightweight HTML and CSS parsers.
- `src/scanner_pool.rs`: thread-local vectorscan `BlockScanner` pool, providing safe reuse of compiled pattern databases across scan threads.
- `src/reporter.rs` and `src/reporter/*`: report rendering for pretty, JSON, BSON, TOON, SARIF, and HTML outputs, plus the data model used by the viewer.
- `src/direct_validate.rs`: direct validation of a known secret without going through pattern matching. Supports HTTP, gRPC, plus schema-level typed validators such as AWS, AzureStorage, CredentialUri, GCP, JDBC, MongoDB, MySQL, PostgreSQL, JWT, and Coinbase, and delegates ad-hoc `Raw` validators to `crates/kingfisher-scanner/src/validation/raw.rs`.
- `src/direct_revoke.rs`: direct revocation of a known secret without going through the scan pipeline. Uses Liquid templates for revocation configurations and supports multi-step HTTP revocation flows.
- `src/access_map.rs` and `src/access_map/*`: standalone blast-radius mapping with 24 provider implementations including AWS, Azure, GCP, GitHub, GitLab, Slack, Bitbucket, Gitea, Hugging Face, Buildkite, Anthropic, OpenAI, and more.
- `crates/kingfisher-rules/build.rs` and `build_support/betterleaks.rs`: download and translate
  Betterleaks' canonical TOML into the embedded default rule database. No built-in rule catalog is
  stored in the repository.
- `crates/kingfisher-rules/data/imported-rules-capabilities.yml`: Kingfisher-only operational bindings
  and selected safe revocation actions keyed by upstream Betterleaks ID. It contains no detection
  rules; the build rejects stale IDs and component references.

## Notes And Boundaries

- The main CLI scan path is implemented primarily in the application modules under `src/`, not in `kingfisher-scanner`.
- `kingfisher-scanner` is still important: it provides the embeddable scanner API plus shared validation and primitive functionality reused by the application.
- The shared validation layer in `crates/kingfisher-scanner/src/validation/` contains reusable typed
  validator families and the `Raw` exception-path validators retained for Kingfisher 1.x custom YAML.
- Direct `validate`, `revoke`, and standalone `access-map` are sibling command paths. They are not downstream stages of `FindingsStore`.
- Reporting is downstream from the datastore, which lets Kingfisher emit multiple output formats and drive the local viewer from the same finding set.
- Every rule uses Vectorscan's high-throughput SIMD-accelerated database for candidate detection. The exact Rust regex then confirms captures before Betterleaks filters, Base64 handling, and parser-based context verification improve accuracy and reduce false positives. No rule performs an unconditional whole-blob regex scan.
- Betterleaks' top-level source prefilter is compiled once into a separate Vectorscan database and
  evaluated per source path before content matching. Keyword hints are not imported because
  Vectorscan already supplies content-candidate selection. Only the global finding filter and
  per-rule finding filter are combined.
- Regex helpers inside the combined Betterleaks finding filters are also compiled once into shared
  Vectorscan databases. `findMatch` uses start-of-match tracking; boolean helpers use normal block
  matching.
- `FindingsStore` uses an in-memory store with a Bloom filter for deduplication, replacing the earlier SQLite-based storage model.
- Betterleaks validation expressions run through a portable Rust AST evaluator. Kingfisher 1.x custom-rule
  validation and revocation templates use Liquid for HTTP request sequences, variable extraction,
  and multi-step flows.
- Betterleaks access-map and revocation behavior is capability-driven. Runtime dispatch uses typed
  handlers and declarative finding/component bindings, never old `kingfisher.*` rule IDs.
