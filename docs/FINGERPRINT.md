# Finding Fingerprints

[← Back to README](../README.md)

Every reported finding carries a **64-bit fingerprint** that identifies the detected value and
its position. Kingfisher uses this reported fingerprint for output, baseline matching, and
downstream correlation.

Default scan deduplication is related, but deliberately uses a different identity. It groups
identical detected credentials without using their file path or byte offset. This distinction lets
Kingfisher present one actionable credential while retaining a location-sensitive fingerprint for
the occurrence that is reported.

```bash
🔓 AWS ACCESS TOKEN => [BETTERLEAKS.AWS-ACCESS-TOKEN]
 |Finding.........: 4HKmwiS1GzI[...]2TF6zYz7
 |Fingerprint.....: 14085685380484734428
 |Confidence......: medium
 |Entropy.........: 5.12
 |Blast Radius Cmd: kingfisher blast-radius --rule betterleaks.aws-access-token '<REDACTED>'
[...]

```
---

### How the *reported* fingerprint is calculated

1. **Finding Bytes** – the matched finding pattern

2. **Origin label** – one of  
   *`"git"`*, *`"file"`*, *`"ext"`*, identifying whether the hit came from a Git
   history, a plain on-disk file, or an extended source.

3. **Byte offsets** – `offset_start` and `offset_end`, the exact byte range of
   the match inside the blob/file (little-endian `u64` each).

Those four fields are concatenated:

```bash
< finding_bytes> + <origin_label> + <offset_start> + <offset_end>
```

The resulting buffer is hashed with **XXH3-64**, producing a single unsigned-64 value:

```bash
finding-bytes + origin + start-offset + end-offset -> XXH3-64 -> finding_fingerprint
```


This fingerprint is what you see reported in the finding output. It is rendered as an unsigned decimal `u64` in every output format (pretty, JSON, JSONL, and SARIF) and is the same value written into [baseline files](./BASELINE.md), so a fingerprint copied from a report can be pasted directly into a baseline.

---

### Why content-based hashing is used

The fingerprint is a [XXH3-64](https://github.com/Cyan4973/xxHash) hash of the following components concatenated together:

* The content of the matched secret.
* A coarse-grained origin label (`git`, `file`, or `ext`).
* The start and end byte-offsets of the match.

This content-aware approach provides several benefits:

| Reason                      | Benefit                                                                                                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Accurate Secret Tracking** | If a key is rotated (e.g., from `AKIA…AAA` to `AKIA…BBB`), the new key correctly receives a new fingerprint. This allows for precise tracking of a secret's lifecycle. |
| **Location Uniqueness** | Because byte offsets are part of the hash, two identical secrets found on different lines will have separate fingerprints.                             |
| **Privacy-Safe by Design** | The fingerprint is a one-way hash, not the raw secret itself. This prevents sensitive credential data from being exposed in reports and logs.          |
| **Light-weight Origin** | Using a coarse origin label (`git`, `file`, etc.) avoids fingerprint churn across commits while still separating findings from different types of scans. |

This method ensures that every unique secret is tracked precisely, providing a clear and accurate picture of sensitive data exposure.

---
### Why deduplication is credential-focused

By default, Kingfisher reports one finding for identical matched credential content detected by the
same rule and broad origin class. The deduplication identity intentionally excludes the file path
and byte offset. As a result, copying the same credential into many files or carrying it through
many Git revisions does not produce dozens of equivalent findings.

This behavior is designed around remediation. A credential leaked in 50 locations still represents
one credential that must be investigated and revoked. Repeating the same credential for every
location can obscure the number of distinct credentials requiring action and make scan output,
alerts, and downstream triage unnecessarily noisy.

The reported finding still includes the location selected for presentation. Deduplication therefore
reduces repeated credential findings; it does not imply that the credential appeared only once.

### Controlling deduplication

To investigate propagation, enumerate every affected location, or perform forensic analysis, disable
default deduplication with `--no-dedup`:

```bash
kingfisher scan /path/to/repo --no-dedup
```

With this option, Kingfisher reports individual occurrences instead of collapsing repeated
credential content into one actionable finding.
