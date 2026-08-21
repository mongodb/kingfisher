---
title: "LLM & Agent Integration"
description: "Use Kingfisher with LLMs and AI agents. TOON output format for token-efficient scanning, prompt redaction, and structured output for automated workflows."
---

# LLM & Agent Integration

Kingfisher is designed to work seamlessly with LLMs and AI agent workflows. Whether you're building an automated security pipeline, using an AI coding assistant, or need to redact secrets from prompts before sending them to an LLM, Kingfisher has you covered.

## TOON Output Format

The **TOON** (Token-Optimized Output Notation) format is purpose-built for LLM consumption. It produces a flattened, token-efficient output that's easy for AI models to parse and reason about.

```bash
# Use TOON format for LLM-friendly output
kingfisher scan /path/to/code --format toon
```

TOON is also available for `validate` and `revoke` subcommands:

```bash
kingfisher validate --rule github "ghp_xxx" --format toon
kingfisher revoke --rule github-pat "ghp_xxx" --format toon
```

Betterleaks rules provide default validation where upstream defines it. Kingfisher supplies
selected safe revocation actions through a build-validated capability overlay; Kingfisher 1.x custom YAML
rules may also define a `revocation:` block.

!!! tip "When to use TOON"
    Prefer `--format toon` when calling Kingfisher from an LLM or agent.
    It uses fewer tokens than JSON while retaining all essential information,
    and its flat row-based structure is easier for models to process than deeply nested JSON.

## JSON Output for Agents

For agents that need structured data for programmatic processing, JSON works well:

```bash
# JSON output for structured processing
kingfisher scan /path/to/code --format json --output findings.json

# JSONL for streaming line-by-line processing
kingfisher scan /path/to/code --format jsonl
```

## Redacting Secrets from LLM Prompts

A key use case is scanning text for secrets **before** sending it to an LLM. This prevents accidentally leaking credentials through AI prompts:

```bash
# Pipe text through Kingfisher to check for secrets before sending to an LLM
cat prompt.txt | kingfisher scan - --format toon --no-validate
```

If Kingfisher finds secrets, your agent can redact them before forwarding the text.

## CI/CD Integration with Agents

Combine Kingfisher with your CI/CD pipeline and agent workflows:

```bash
# Scan only staged changes (pre-commit)
kingfisher scan . --staged --quiet --no-update-check

# Scan changes since a branch point (CI)
kingfisher scan . --since-commit origin/main --format json

# Exit codes for automated decision-making:
# 0   = no findings
# 200 = findings discovered
# 205 = validated (live) findings discovered
```

## Available Output Formats

| Format | Best For | Flag |
|--------|----------|------|
| **TOON** | LLM/agent consumption | `--format toon` |
| **JSON** | Structured processing | `--format json` |
| **JSONL** | Streaming/line processing | `--format jsonl` |
| **SARIF** | IDE and GitHub integration | `--format sarif` |
| **HTML** | Human review/audit reports | `--format html` |
| **Pretty** | Terminal output (default) | `--format pretty` |

## Embedding in Rust Applications

For deep integration, use Kingfisher as a library in your Rust-based agent:

```rust
use std::sync::Arc;
use kingfisher_rules::defaults::get_builtin_rules;
use kingfisher_rules::RulesDatabase;
use kingfisher_scanner::Scanner;

// Load the built-in rules and compile the scanner database
let rules = get_builtin_rules(None)?;
let rules_db = Arc::new(RulesDatabase::from_rules(rules.into_rules())?);
let mut scanner = Scanner::new(rules_db);

// Scan a byte slice for secrets
let findings = scanner.scan_bytes(b"AKIA...");
```

See [Rust Library Crates](../reference/library.md) for complete documentation.

## Python Integration

Kingfisher is available as a Python package for integration with Python-based agent frameworks:

```bash
uv tool install kingfisher-bin
```

Then call it from your Python agent:

```python
import subprocess
import json

result = subprocess.run(
    ["kingfisher", "scan", "-", "--format", "json", "--no-validate"],
    input=user_prompt,
    capture_output=True,
    text=True,
)
findings = json.loads(result.stdout) if result.stdout else []
```
