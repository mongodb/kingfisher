## Finding Fingerprints

Every reported finding carries a **64-bit fingerprint** that acts as a stable, privacy-safe ID.
It lets the scanner **deduplicate** repeated hits of the *same logical issue* while still treating different locations as distinct.

```bash
🔓 AWS SECRET ACCESS KEY => [KINGFISHER.AWS.2]
 |Finding.......: 4HKmwiS1GzI[...]2TF6zYz7
 |Fingerprint...: 14085685380484734428
 |Confidence....: medium
 |Entropy.......: 5.12
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


This fingerprint is what you see reported in the finding output.

---

### Why the rule’s SHA-1 is used (and not the secret)

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
### Controlling deduplication

By default the CLI **deduplicates** findings that share the same fingerprint, so you see only one entry even if the secret appears in multiple commits.


If you want to see **every individual occurrence**, run with `--no-dedup`:

```bash
kingfisher scan /path/to/repo --no-dedup
```