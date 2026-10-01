# Kingfisher Secret Scanner for Python

Fast secret detection, credential validation and revocation for Python, powered
by [Kingfisher's Rust libraries](https://github.com/mongodb/kingfisher).
Native, in-process execution; no CLI subprocess required. Requires CPython 3.10+.

## Install

```bash
uv add kingfisher-secret-scanner
```

The **PyPI distribution** is `kingfisher-secret-scanner`; the **Python import** is
`kingfisher_sdk`. It coexists with the separately distributed `kingfisher-bin` CLI.

## Scan offline

```python
from kingfisher_sdk import Scanner

scanner = Scanner()  # Compile the bundled rules once and reuse the scanner.
for finding in scanner.scan_file("application.conf"):
    if finding.visible:
        print(finding.to_dict())  # Secrets and captures are redacted by default.
```

## Validate explicitly

```python
from kingfisher_sdk import Scanner, Validator

findings = Scanner().scan_file("application.conf")
for result in Validator(timeout=10, concurrency=4).validate(findings):
    if result.finding.visible:
        print(result.to_dict())
```

Scanning is offline. Validation may contact providers using detected credentials.
Keep the complete scan result, including invisible supporting findings, until
validation finishes. Report redacted results; do not log `finding.secret`.

Revocation is available through `Revoker.revoke()` and requires `confirm=True`.
It can disable or delete real credentials. The
[local lifecycle example](https://github.com/mongodb/kingfisher/blob/main/python/examples/local_workflow.py)
demonstrates detection, validation and revocation against a loopback mock with a
synthetic credential. Blocking SDK operations release the GIL; use
`asyncio.to_thread` in async applications.

## Documentation and examples

- [Python guide on GitHub](https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md):
  API reference, custom YAML/TOML rules, validation outcomes, revocation, local
  `uv` builds and tests, supported platforms, and publishing.
- [Runnable Python examples](https://github.com/mongodb/kingfisher/tree/main/python/examples):
  offline scans, live validation, explicit revocation and a safe local lifecycle.
- [Kingfisher repository](https://github.com/mongodb/kingfisher): source, project
  documentation, CLI features and contributions.
- [Report an issue](https://github.com/mongodb/kingfisher/issues).

For a source checkout, build and run the local example from the repository root:

```bash
uv sync --locked --no-install-project
uv run --no-sync maturin develop --locked --profile dev
uv run --no-sync python python/examples/local_workflow.py
```

For a downloaded example and a published package, use:

```bash
uv run --no-project --with kingfisher-secret-scanner python local_workflow.py
```

Download `demo.yml` beside `local_workflow.py`; the example loads that synthetic
rule by its location. Source archives include the examples and fixture together.
