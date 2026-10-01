# Kingfisher Secret Scanner for Python

The `kingfisher-secret-scanner` PyPI package provides native Python secret detection,
credential validation and revocation. Install it with `uv add kingfisher-secret-scanner`;
import it as `kingfisher_sdk` (the distribution and import names differ).
See the [Kingfisher GitHub repository](https://github.com/mongodb/kingfisher)
for the full project, source code and broader CLI capabilities.

Kingfisher has two independent Python distributions:

| Distribution | Import / command | Purpose |
| --- | --- | --- |
| `kingfisher-secret-scanner` | `import kingfisher_sdk` | Native, in-process bindings to the Rust core, rules, scanner, validation and revocation code |
| `kingfisher-bin` | `uvx kingfisher-bin` / `kingfisher` | Existing packaged CLI; full repository, archive and remote-source enumeration |

They can be installed together without module or entry-point conflicts. The SDK
requires CPython 3.10+ with the standard GIL build. Wheels target Linux x64/ARM64
(glibc 2.28+), macOS x64/ARM64 (11+), and native Windows x64/ARM64. PyPy,
free-threaded Python and musl wheels are not currently part of the release matrix.

## Install and scan

```bash
uv init my-scanner
cd my-scanner
uv add kingfisher-secret-scanner
```

```python
from kingfisher_sdk import Scanner

scanner = Scanner()  # Compile the embedded catalog once and reuse it.
for finding in scanner.scan("text to inspect"):
    if finding.visible:
        print(finding.to_dict())  # Redacts the secret and all captures.
```

Scanning is offline. `scan(str | bytes)` scans a buffer; `scan_file(path)` scans
one file with path-aware filters. The SDK does not walk directories, fetch
repositories, unpack archives or enumerate cloud sources; use Python to supply
files or use the CLI for those operations.

## API modules

| Module | Public API |
| --- | --- |
| `kingfisher_sdk.core` | `Finding`, `shannon_entropy(bytes)` |
| `kingfisher_sdk.rules` | `Rules(paths=(), builtins=True, confidence="medium")` |
| `kingfisher_sdk.scanner` | `Scanner(rules=None, base64=True, dedup=False, redact=False, min_entropy=None)` |
| `kingfisher_sdk.validation` | `Validator`, `ValidationResult` |
| `kingfisher_sdk.revocation` | `Revoker`, `RevocationResult` |

These names are also exported from `kingfisher_sdk`. Python modules wrap one
PyO3 extension, sharing the Rust types and compiled rule database. Official wheels
enable all scanner validator features, including HTTP, Betterleaks expressions,
gRPC, raw/provider-specific validators, AWS, Azure, Coinbase, GCP, JWT, databases
and local Ethereum key derivation.

`Rules` accepts files and directories containing Kingfisher YAML and Betterleaks
TOML. Custom TOML IDs receive the `custom.` prefix. Use `builtins=False` for
custom-only rules. `Rules.metadata()` lists exact IDs, names, visibility and
whether each rule has validation/revocation. It does not expose pattern internals.

```python
from kingfisher_sdk import Rules, Scanner

rules = Rules(["company.yml", "team.toml"], builtins=False)
scanner = Scanner(rules, dedup=True)
findings = scanner.scan_file("application.conf")
scanner.reset_dedup()
```

`Finding.rule_id`, `.visible` and `.secret` expose the matching ID, visibility and
raw secret. `to_dict()` includes rule name, confidence, entropy, fingerprint,
captures, blob ID, encoding indicator and location. Location offsets are bytes,
the end is exclusive, lines start at 1 and columns start at 0. UTF-16/32 inputs
may be normalized before scanning. `to_dict(redact=False)` explicitly exposes
secret material. Repr omits credentials. Redaction does not erase earlier copies.

## Validate explicitly

```python
from kingfisher_sdk import Scanner, Validator

findings = Scanner().scan_file("application.conf")
validator = Validator(timeout=10, concurrency=4)
for result in validator.validate(findings):
    if result.finding.visible:
        print(result.to_dict())
```

Keep the complete result list from one input, including invisible helper rules,
until validation finishes: the Rust validator associates multi-part credentials
using blob identity, encoding and proximity. Do not merge unrelated inputs into
one validation call. `Scanner(redact=True)` prevents subsequent validation;
retain raw findings internally and redact when reporting instead.

`Validator` accepts `timeout` (seconds), `concurrency`, `retries` (default 0),
`max_response_bytes` (default 1 MiB for YAML HTTP), `allow_internal_ips` (default
false) and `variables` (trusted template variables/endpoints). Response-size
limits for other validator families remain provider-specific. TLS verification
is enabled and the shared HTTP client disables redirects. The internal-address
check is not a network sandbox or DNS-pinning guarantee.

Results preserve input order and include `finding`, `outcome`, `reason` and
`http_status`. Outcomes are `verified_active`, `verified_inactive`, `unavailable`,
`skipped`, `not_attempted`, `assumed`, `locally_derived` and `invalid_material`.
An unavailable check is inconclusive; assumed validity and locally derived
cryptographic material are not proof of live account access. Provider responses
are intentionally omitted from the Python result.

## Revoke explicitly

```python
import os
from kingfisher_sdk import Revoker

result = Revoker().revoke(
    "betterleaks.aws-access-token",  # Select an exact ID with revocation support.
    os.environ["AWS_SECRET_ACCESS_KEY"],
    variables={"AKID": os.environ["AWS_ACCESS_KEY_ID"]},
    confirm=True,
)
print(result.revoked, result.http_status)
```

Check `Rules.metadata()` for the exact supported ID before calling. Revocation
can disable or delete real credentials. `confirm=True` is mandatory, rules are
matched exactly, and requests are not automatically retried. HTTP, multi-step
HTTP, AWS deactivation and GCP service-account key deletion run in-process through
`kingfisher-scanner::Revoker`, using the same execution helpers as the CLI. Only load trusted rules: revocation sends credentials to the
configured URLs, including private addresses. Pass supporting credentials and
endpoint variables explicitly; revocation does not infer them from scan results
or read the CLI configuration/environment. Variable names are uppercased; avoid
keys that differ only by case, since they resolve to the same variable. `TOKEN`
is always the explicit secret.

A `RevocationResult` contains `rule_id`, `revoked`, `http_status`; it never contains
provider bodies. Missing/unsupported rules and invalid configuration raise
`ValueError` or `RuntimeError`. A timeout or transport failure may occur after the
provider applied revocation: inspect provider state before retrying.

## Runnable examples

Run these from a checkout after the local setup below. Each link opens the full
program, and the example files are also included in the source distribution.

- [Offline file scanning](../python/examples/scan.py):
  `uv run --no-sync python python/examples/scan.py path/to/file`
- [Live validation](../python/examples/validate.py):
  `uv run --no-sync python python/examples/validate.py path/to/file`
- [Explicit live revocation](../python/examples/revoke.py):
  `uv run --no-sync python python/examples/revoke.py EXACT_RULE_ID --confirm`
  reads `KINGFISHER_SECRET` and optional JSON `KINGFISHER_VARIABLES` from the environment.
- [Complete local lifecycle](../python/examples/local_workflow.py), using a
  [synthetic rule](../python/examples/demo.yml):
  `uv run --no-sync python python/examples/local_workflow.py`.
  It starts a loopback mock provider, detects a fake credential, proves it active,
  revokes it, and proves it inactive. No real provider is contacted.

All SDK operations are synchronous. Compilation, scanning, validation and
revocation release the GIL; reuse scanners and validators across threads. In an
async application use `await asyncio.to_thread(validator.validate, findings)`.
Cancelling that Python await does not stop the worker; the configured native
deadline still applies. Never assume cancellation cancelled provider revocation.

## Build and test locally with uv

Prerequisites: Rust 1.96+, `uv`, a C/C++ toolchain, platform SDK/linker and `curl`.
Default builds download checksum-verified Vectorscan static archives. See
[installation](INSTALLATION.md) for platform prerequisites. Windows uses MSYS2
MINGW64 with `x86_64-pc-windows-gnu`, or CLANGARM64 with
`aarch64-pc-windows-gnullvm`; MSVC requires a separate compatible Vectorscan
installation. Do not relabel an x64 extension wheel as ARM64.

From the repository root:

```bash
uv sync --locked --no-install-project
uv run --no-sync maturin develop --locked --profile dev
uv run --no-sync python -m pytest python/tests -q
uv run --no-sync python python/examples/local_workflow.py
```

On Windows, use native CPython (not MSYS2 Python), install the matching MSYS2
C/C++ toolchain, CMake and pkgconf, and select the Rust target explicitly. For x64
in MINGW64:

```bash
rustup target add x86_64-pc-windows-gnu
CC=gcc CXX=g++ CMAKE_GENERATOR="MinGW Makefiles" uv run --no-sync maturin develop --locked --profile dev --target x86_64-pc-windows-gnu
```

For ARM64 in CLANGARM64, use `aarch64-pc-windows-gnullvm`, `CC=clang` and
`CXX=clang++`. Keep the MSYS2 toolchain on PATH while testing development builds;
the CI release job repairs wheels so installed users do not need that toolchain.

`--no-sync` preserves the explicitly built development extension. Plain `uv sync`
also works, but builds the installable extension with the `python-release`
profile. Python builds use unwind panics so PyO3 can contain Rust panics; the CLI's
release profile remains unchanged.

Build and test the actual distributable wheel in a fresh environment:

```bash
uv run --no-sync maturin build --locked --profile python-release --out dist-python
uv venv .venv-wheel --python 3.13
uv pip install --python .venv-wheel dist-python/*.whl pytest
uv run --no-project --python .venv-wheel python -m pytest python/tests -q
uv run --no-sync maturin sdist --out dist-python
```

On PowerShell, expand wheel paths with `Get-ChildItem` instead of a shell glob.
Use a clean output directory per build to avoid installing multiple versions.
Local Linux builds may need `--compatibility linux` for local-only wheels; public
Linux wheels are built from vendored Vectorscan source inside manylinux 2.28,
because the prebuilt Linux archives require glibc 2.35.

Shared Rust revocation tests:

```bash
cargo test --locked -p kingfisher-scanner --features validation validation::revocation
```

The Python tests cover custom YAML/TOML loading, built-in metadata, byte/file
scanning, paths with spaces, concurrency, deduplication, redaction, validation,
revocation authorization and the mock provider lifecycle. They do not revoke real
credentials. Windows verification requires both architecture jobs to pass; a
successful macOS or Linux run does not establish Windows compatibility.

## GitHub Actions and PyPI publishing

[Python SDK workflow](../.github/workflows/python-sdk.yml) builds and tests six
native wheels on pull requests, main-branch pushes, SDK tag pushes, and manual runs. Linux wheels use manylinux 2.28;
Windows wheels bundle runtime DLLs using delvewheel and are tested under ordinary
CPython outside MSYS2. A separate job builds an sdist, installs it with CPython
3.10, and runs the same tests. Wheel jobs use CPython 3.13. Publishing depends on
all wheel and source tests succeeding.

Merging to `main` automatically builds, tests, and publishes `kingfisher-secret-scanner`
through this workflow. The CLI release separately publishes `kingfisher-bin`.
PR/manual SDK builds upload artifacts without publishing. Publishing is restricted
to `mongodb/kingfisher` and uses the protected `pypi-sdk` environment.

The SDK version comes from `crates/kingfisher-python/Cargo.toml` and is independent
of the CLI version. Increment it when SDK code or its embedded Rust dependencies
change. Already-published files are skipped on unrelated main merges and retries;
PyPI does not replace existing files. Optional `python-v<version>` tag pushes can
also publish, and the tag must exactly match the SDK package version.

Maintainer release checklist:

1. Review the changes, increment the SDK version for subsequent releases, update
   `uv.lock` and `Cargo.lock`, regenerate the rule provenance as described in
   [publishing guidance](PUBLISHING.md), and merge through the normal process.
2. Inspect all six tested wheels and the source artifact in the main-branch run.
   The protected publish job runs after every build and test succeeds.
3. Configure PyPI Trusted Publishing for owner `mongodb`, repository `kingfisher`,
   workflow `python-sdk.yml`, and environment `pypi-sdk`. The GitHub environment
   must allow the `main` branch (and `python-v*` tags if using tag releases).

Publishing uses PyPI Trusted Publishing without a stored API token. A local TestPyPI rehearsal can use
`uv publish --publish-url https://test.pypi.org/legacy/ dist-python/*` after
configuring credentials outside the repository. Linux/Windows public artifacts
should come from the repaired CI builds, not an arbitrary local platform tag.

Packaging follows the [Maturin mixed-project layout](https://www.maturin.rs/project_layout.html).

## Existing CLI wheel distribution

The following commands package `kingfisher-bin`, not the SDK.

### Build prerequisites

1. Build the Kingfisher binary for your target platform (see
   [INSTALLATION.md](INSTALLATION.md) for `make` targets).
2. Install `uv`; the commands below supply the Python build tooling in an isolated environment.

### Build a wheel

Run the helper script from the repo root:

```bash
uv run --no-project --with build scripts/build-pypi-wheel.sh \
  --binary ./path/to/kingfisher \
  --version 1.2.3 \
  --plat-name manylinux_2_17_x86_64
```

For Windows, pass the `.exe` binary and a Windows platform tag:

```bash
uv run --no-project --with build scripts/build-pypi-wheel.sh \
  --binary .\\path\\to\\kingfisher.exe \
  --version 1.2.3 \
  --plat-name win_amd64
```

If you only build a Windows x64 binary, you can still ship a `win_arm64` wheel
using the same executable (it runs under emulation on ARM64 Windows):

```bash
uv run --no-project --with build scripts/build-pypi-wheel.sh \
  --binary .\\path\\to\\kingfisher.exe \
  --version 1.2.3 \
  --plat-name win_arm64
```

The resulting wheel will be placed in `dist-pypi/` by default.

### Test locally

```bash
uv venv .venv-cli
uv pip install --python .venv-cli dist-pypi/kingfisher_bin-*.whl
uv run --no-project --python .venv-cli kingfisher --help
```

### Publish

Upload the wheels to PyPI using `twine` (or your preferred tool):

```bash
uvx twine upload dist-pypi/*
```

#### GitHub Actions (recommended)

The repository includes a `pypi-wheels` workflow that:

1. Downloads the release binaries.
2. Builds platform-tagged wheels.
3. Publishes them to PyPI using Trusted Publishing (OIDC).

To use Trusted Publishing, create a PyPI project named `kingfisher-bin` and
enable GitHub Actions as a trusted publisher for this repository and workflow.
No API token is required once Trusted Publishing is configured.

If you do not use Trusted Publishing, generate a PyPI API token and provide it
to `twine` (for example via `TWINE_USERNAME=__token__` and
`TWINE_PASSWORD=<pypi-token>`).
