---
title: "Kingfisher Capabilities & Open-Source Benchmarks"
description: "Compare published benchmarks, live verification, revocation, and licenses across Kingfisher, Betterleaks, TruffleHog OSS, and Gitleaks."
---

# Kingfisher Capabilities and Open-Source Comparisons

## Runtime Comparison (seconds)

These are published reference results, not a fresh benchmark of the current release.
Repository revisions, rule catalogs, network conditions and tool versions affect
runtime and findings. See the [benchmark harness](https://github.com/mongodb/kingfisher/blob/main/docs/benchmark/README.md) to generate
a new report recording tool versions and raw results.

*Lower runtimes are better.*

| Repository | Kingfisher Runtime | TruffleHog Runtime | Gitleaks Runtime |
|------------|--------------------|--------------------|------------------|
| croc | 2.64 | 10.36 | 3.10 |
| rails | 8.75 | 24.19 | 24.24 |
| ruby | 22.93 | 132.68 | 61.37 |
| gitlab | 135.41 | 325.93 | 350.84 |
| django | 6.91 | 227.63 | 59.50 |
| lucene | 15.62 | 89.11 | 76.24 |
| mongodb | 25.37 | 174.93 | 175.80 |
| linux | 205.19 | 597.51 | 548.96 |
| typescript | 64.99 | 183.04 | 232.34 |

<p align="center">
  <img src="../assets/images/runtime-comparison.png" alt="Kingfisher Runtime Comparison" style="vertical-align: center;" />
</p>

### Validated/Verified Findings Comparison

Gitleaks does not perform live validation; its verified counts are **N/A**, not zero.

| Repository | Kingfisher Validated | TruffleHog Verified | Gitleaks Verified |
|------------|----------------------|---------------------|-------------------|
| croc | 0 | 0 | N/A |
| rails | 0 | 0 | N/A |
| ruby | 0 | 0 | N/A |
| gitlab | **6** | **6** | N/A |
| django | 0 | 0 | N/A |
| lucene | 0 | 0 | N/A |
| mongodb | 0 | 0 | N/A |
| linux | 0 | 0 | N/A |
| typescript | 0 | 0 | N/A |

### Network Requests Comparison
*'Network Requests' counts plain HTTP requests and HTTPS CONNECT tunnels observed by the benchmark proxy. TLS is not decrypted, so individual requests inside a tunnel are not counted; clients that bypass the proxy are not observed. Gitleaks does not perform live validation; zero describes these runs, not every possible network interaction.*

| Repository | Kingfisher Network Requests | TruffleHog Network Requests | Gitleaks Network Requests |
|------------|-----------------------------|-----------------------------|---------------------------|
| croc | 0 | 17 | 0 |
| rails | 1 | 25 | 0 |
| ruby | 3 | 33 | 0 |
| gitlab | 17 | **15624** | 0 |
| django | 0 | 66 | 0 |
| lucene | 0 | 116 | 0 |
| mongodb | 1 | 191 | 0 |
| linux | 0 | 287 | 0 |
| typescript | 0 | 10 | 0 |

*Lower runtimes are better. Validated/Verified counts are reported where available. 'Network Requests' is the benchmark proxy's request/tunnel count.*

## Benchmark Environment

OS: darwin
Architecture: arm64
CPU Cores: 16
RAM: 48.00 GB


All four tools detect secrets. Kingfisher and Betterleaks 2.0 RC5 also include
credential revocation for supported providers.

| Built-in capability | Kingfisher | Betterleaks 2.0 RC5 | TruffleHog OSS | Gitleaks |
|---|:---:|:---:|:---:|:---:|
| Secret discovery | ✅ | ✅ | ✅ | ✅ |
| Live credential verification | ✅ | ✅ | ✅ | ❌ |
| Credential revocation | ✅ | ✅ | ❌ | ❌ |
| License | Apache-2.0 | MIT | AGPL-3.0 | MIT |

✅ Built in · ❌ Not supported as a built-in capability.

General capability references: [Betterleaks 2.0 RC5](https://github.com/betterleaks/betterleaks/blob/b1aa878bc41b06583f6ce83bf0ffcc5e6ed8f4f3/README.md),
[TruffleHog OSS](https://github.com/trufflesecurity/trufflehog/blob/662edea3ea7987aafe71580da817e2ee4e8a8783/README.md),
and [Gitleaks](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md).

Kingfisher also extracts PDF page text in CLI file, Git-history, and archive scans;
the SDK exposes it explicitly through `expand_content(..., pdf=True)`. This is
bounded text extraction, not OCR or encrypted-PDF support. See
[coverage and limits](../usage/advanced.md#pdf-text-extraction).
