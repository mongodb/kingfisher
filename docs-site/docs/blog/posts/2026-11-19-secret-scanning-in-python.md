---
date: 2026-11-19
title: "Find Leaked Keys and Prove They Still Work — From Any Python Service"
description: >
  Embed Kingfisher's native scanning engine in a Python worker, web handler, or
  Lambda, find credentials in the bytes you already have, and check with each
  provider whether they still work.
categories:
  - Tutorials
tags:
  - python
  - sdk
  - secret-scanning
  - git
  - validation
---

# Find Leaked Keys and Prove They Still Work — From Any Python Service

Most secret scanners can tell you a string looks like an AWS key. That still
leaves the question your on-call engineer actually cares about: does it work?
A dead test token and a live production key look the same to a regex. Only
one of them justifies paging someone.

The `kingfisher-secret-scanner` package gives any Python service both answers.
It finds credentials in files, byte buffers, or Git history using the same
Rust engine as the Kingfisher CLI. Then it asks each credential's provider
whether the key still authenticates. You can run it in a Celery task, a FastAPI
upload handler, a Lambda that watches a bucket, or a script on your laptop. It
runs in-process with no CLI to shell out to. Get it on [PyPI](https://pypi.org/project/kingfisher-secret-scanner/).

<!-- more -->

## Scan the bytes your service already has

Install the package on CPython 3.10 or later. The distribution is
`kingfisher-secret-scanner` and the import is `kingfisher_sdk`.

```bash
python -m pip install kingfisher-secret-scanner
```

```python
from kingfisher_sdk import Scanner

scanner = Scanner()
for finding in scanner.scan_file("application.conf"):
    if finding.visible:
        print(finding.to_dict())
```

`scan_file()` gives path-aware rules the filename. If your service already
holds the content, such as an upload or a message off a queue, call
`scanner.scan(data)` and skip the temporary file. When the logical filename
matters, wrap the bytes as `ScanInput(path="application.conf", data=data)` and
pass them to `scan_input()`. `to_dict()` redacts the secret and captures by
default, so findings are safe to log.

Create one `Scanner` and keep it for the life of the process. Kingfisher
compiles every built-in rule into a single
[Vectorscan](https://github.com/VectorCamp/vectorscan) database. Vectorscan
uses SIMD to match them all in one pass over the bytes, then hands candidates
to Rust for capture confirmation. Scans release the GIL, so a thread pool can
scan in parallel. A new worker process can load compiled rules from the
on-disk cache and skip recompiling. See [how the compiled rule cache works](../../reference/python-bindings.md#reuse-the-compiled-rule-cache).

## Prove which keys still work

Detection runs offline. A `Validator` goes one step further and asks each
provider whether a credential still authenticates. That might be the GitHub
API for a personal access token or AWS STS for an access key pair. Here's a
handler you can call from a queue consumer, a web route, or a Lambda:

```python
from kingfisher_sdk import ScanInput, Scanner, Validator

scanner = Scanner()
validator = Validator(timeout=5, concurrency=4)


def check_upload(filename: str, data: bytes) -> list[dict]:
    """Return the credentials in this upload that still work."""
    findings = scanner.scan_input(ScanInput(path=filename, data=data))
    live = []
    # Validate the input's complete findings list so paired values, such as
    # an AWS key ID and its secret, can find each other.
    for result in validator.validate(findings):
        if result.finding.visible and result.outcome == "verified_active":
            live.append(result.to_dict())  # redacted by default
    return live
```

Each result has an `outcome`. Only `verified_active` proves the key works right
now. Rotate it, or page someone. `verified_inactive` means the provider
rejected it. It's still worth cleaning up, but it's no longer an incident.
`unavailable` means the check couldn't finish, perhaps after a timeout or rate
limit. Queue those for a retry and don't treat them as safe. Some findings come
back `skipped` on purpose. For example, Kingfisher won't call AWS for keys that
belong to known canary-token accounts, so the check doesn't trip the canary.

Three details keep this fast and correct inside a service:

- **Pass the whole list, then filter.** Some credentials only work as a pair,
  such as an AWS key ID and its secret. The validator needs the helper findings
  from the same input to build the request. Filter on `visible` afterward.
- **Bound the network work.** `timeout` caps each provider request and
  `concurrency` caps how many run at once. Pass `timeout=` to `validate()` for a
  deadline on the whole batch.
- **Keep the scanner and validator for the process lifetime.** Both release
  the GIL and are safe to share across threads. In an async framework such as
  FastAPI, call the handler with `await asyncio.to_thread(check_upload, name, data)`
  to keep the event loop free.

See the [Python validation guide](../../reference/python-bindings.md#validate-explicitly)
for every outcome, custom variables, and response limits.

## Look through Git history with the same scanner

Deleting a key from the latest commit doesn't remove it from the repository.
Feed the current files and every historical file version into `scan_inputs()`
using ordinary Python iterators:

```python
from itertools import chain

from kingfisher_sdk import Scanner, Validator, filesystem, git_history

scanner = Scanner()
validator = Validator(timeout=5, concurrency=4)
sources = chain(filesystem(["./repo"]), git_history("./repo", refs=["HEAD"]))

for group in scanner.scan_inputs(sources):
    for result in validator.validate(group.findings):
        if result.finding.visible and result.outcome == "verified_active":
            print(group.input.path, group.input.commit, result.to_dict())
```

That loop finds every credential in the repository's history that still works.
It reports the file path and the commit where it appeared. Kingfisher reads
commits reachable from `HEAD` in the local repository and loads file contents
as needed. Wrap the iterator in `expand_archives(sources)` to scan inside zips
and tarballs, or yield `ScanInput` objects from your own storage adapter. The
reporting loop stays the same. See the [Git history example](https://github.com/mongodb/kingfisher/blob/main/python/examples/git_history.py)
and the [input pipeline example](https://github.com/mongodb/kingfisher/blob/main/python/examples/inputs.py).

## Try the whole flow without touching a real provider

The local workflow example runs the full lifecycle against a mock HTTP server
on localhost. It scans a synthetic token, proves it's active, revokes it, and
checks again to confirm it's dead. Run it from a Kingfisher checkout. See the [local workflow example](https://github.com/mongodb/kingfisher/blob/main/python/examples/local_workflow.py).

```bash
uv run --no-project --with kingfisher-secret-scanner python python/examples/local_workflow.py
```
