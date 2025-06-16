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

1. **Rule SHA-1** – a hex digest of the rule’s pattern  
   (`Rule::finding_sha1_fingerprint`, computed once when the rule is loaded).

2. **Origin label** – one of  
   *`"git"`*, *`"file"`*, *`"ext"`*, identifying whether the hit came from a Git
   history, a plain on-disk file, or an extended source.

3. **Byte offsets** – `offset_start` and `offset_end`, the exact byte range of
   the match inside the blob/file (little-endian `u64` each).

Those four fields are concatenated:

```bash
<rule_sha1_hex> + <origin_label> + <offset_start> + <offset_end>
```

The resulting buffer is hashed with **XXH3-64**, producing a single unsigned-64 value:

```bash
rule-SHA1 + origin + start-offset + end-offset -> XXH3-64 -> finding_fingerprint
```


This fingerprint is what you see reported in the finding output.

---

### Why the rule’s SHA-1 is used (and not the secret)

| Reason | Benefit |
|--------|---------|
| **No secret leakage** | Only the pattern’s hash is stored, never the credential text. |
| **Stable across rotations** | If a key on the same line changes from `AKIA…AAA` to `AKIA…BBB`, the fingerprint stays the same, so dashboards don’t fill with near-duplicates. |
| **Location uniqueness** | Offsets remain part of the hash, so two different lines (or two hits on one line) still get separate fingerprints. |
| **Light-weight origin** | Using a coarse origin label avoids churn across commits while still separating Git-history scans from local-file scans. |

*Engine-internal* code paths may use a secret-based fingerprint for caching and
validation, but **all external reports use this rule-based fingerprint** to
guarantee privacy.

---

### Controlling deduplication

By default the CLI **deduplicates** findings that share the same fingerprint, so you see only one entry even if the secret appears in multiple commits.


If you want to see **every individual occurrence**, run with `--no-dedup`:

```bash
kingfisher scan /path/to/repo --no-dedup
```