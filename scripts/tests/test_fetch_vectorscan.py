"""Exercise API downloads and workflow wiring without network or native builds."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("fetch_vectorscan", ROOT / "scripts/fetch-vectorscan.py")
FETCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FETCH)
TARGET = "aarch64-apple-darwin"
VERSION = "0.1.4"
NAME = f"vectorscan-{VERSION}-{TARGET}.tar.gz"
DATA = b"immutable native archive fixture"
SHA256 = hashlib.sha256(DATA).hexdigest()
ACTION = "uses: ./.github/actions/vectorscan-prebuilt"


def response(data):
    return io.BytesIO(data)


def metadata(**overrides):
    asset = {"id": 42, "name": NAME, "size": len(DATA),
             "url": "https://untrusted.invalid/never-use-this", "digest": "sha256:" + "0" * 64}
    asset.update(overrides)
    return json.dumps({"assets": [asset]}).encode()


def job(workflow, name):
    match = re.search(rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow)
    if not match:
        raise AssertionError(f"Missing job {name}")
    return match.group(1)


class FetchVectorscanTests(unittest.TestCase):
    def test_api_download_uses_immutable_hash_and_ignores_release_urls_and_digest(self):
        opener = Mock()
        opener.open.side_effect = [response(metadata()), response(DATA)]
        with tempfile.TemporaryDirectory(prefix="vectorscan archives ") as directory:
            archive = FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)
            self.assertEqual(archive.read_bytes(), DATA)
            self.assertEqual(archive.parent, Path(directory).resolve())
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([request.full_url for request in requests], [
            f"https://api.github.com/repos/micksmix/kingfisher-vectorscan/releases/tags/v{VERSION}",
            "https://api.github.com/repos/micksmix/kingfisher-vectorscan/releases/assets/42",
        ])
        self.assertEqual(requests[1].get_header("Accept"), "application/octet-stream")

    def test_verified_cache_is_checked_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / NAME
            path.write_bytes(DATA)
            opener = Mock()
            self.assertEqual(FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener), path.resolve())
            opener.open.assert_not_called()
            path.write_bytes(b"corrupt cache")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)
            opener.open.assert_not_called()

    def test_hash_mismatch_never_promotes_archive_or_leaves_partial_files(self):
        opener = Mock()
        opener.open.side_effect = [response(metadata()), response(b"X" * len(DATA))]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_size_limit_and_metadata_size_are_enforced(self):
        for asset, body, error in (
            ({"size": FETCH.MAX_ARCHIVE + 1}, DATA, "invalid.*asset"),
            ({}, DATA + b"extra", "size does not match"),
        ):
            with self.subTest(asset=asset), tempfile.TemporaryDirectory() as directory:
                opener = Mock()
                opener.open.side_effect = [response(metadata(**asset)), response(body)]
                with self.assertRaisesRegex(ValueError, error):
                    FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)
                self.assertFalse((Path(directory) / NAME).exists())
        with tempfile.TemporaryDirectory() as directory, patch.object(FETCH, "MAX_ARCHIVE", len(DATA)):
            opener = Mock()
            opener.open.side_effect = [response(metadata()), response(DATA + b"extra")]
            with self.assertRaisesRegex(ValueError, "exceeds size limit"):
                FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)

    def test_invalid_asset_ids_and_duplicate_assets_fail_closed(self):
        cases = [metadata(id=-1), metadata(id="42"), metadata(id=True),
                 metadata(name="wrong-target.tar.gz")]
        duplicate = json.loads(metadata())
        duplicate["assets"] *= 2
        cases.append(json.dumps(duplicate).encode())
        for value in cases:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                opener = Mock()
                opener.open.return_value = response(value)
                with self.assertRaisesRegex(ValueError, "invalid.*asset"):
                    FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)
                self.assertEqual(opener.open.call_count, 1)

    def test_transient_api_failure_retries_but_missing_release_does_not(self):
        for code, calls in ((503, 2), (404, 1)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                opener = Mock()
                error = urllib.error.HTTPError("https://api.github.com/fixture", code, "fixture", {}, None)
                opener.open.side_effect = [error, response(metadata()), response(DATA)]
                with patch.object(FETCH.time, "sleep"):
                    if code == 503:
                        FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)
                        self.assertEqual(opener.open.call_count, calls + 1)
                    else:
                        with self.assertRaises(urllib.error.HTTPError):
                            FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)
                        self.assertEqual(opener.open.call_count, calls)

    def test_interrupted_download_is_restarted_before_atomic_promotion(self):
        class Interrupted(io.BytesIO):
            def read(self, size=-1):
                if self.tell():
                    raise ConnectionError("fixture connection reset")
                return super().read(8)

        opener = Mock()
        opener.open.side_effect = [response(metadata()), Interrupted(DATA), response(DATA)]
        with tempfile.TemporaryDirectory() as directory, patch.object(FETCH.time, "sleep"):
            archive = FETCH.fetch(VERSION, NAME, SHA256, Path(directory), opener)
            self.assertEqual(archive.read_bytes(), DATA)
            self.assertEqual(list(Path(directory).resolve().iterdir()), [archive])

    def test_environment_export_occurs_only_after_verified_fetch(self):
        with tempfile.TemporaryDirectory(prefix="vectorscan env ") as directory:
            root = Path(directory)
            environment = root / "github env.txt"
            archive = root / NAME
            argv = ["fetch-vectorscan.py", "--target", TARGET, "--directory", directory, "--github-env"]
            with patch("sys.argv", argv), patch.dict(os.environ, {"GITHUB_ENV": str(environment)}), \
                    patch.object(FETCH, "pinned_archive", return_value=(VERSION, NAME, SHA256)), \
                    patch.object(FETCH, "fetch") as fetch, patch("builtins.print"):
                fetch.side_effect = ValueError("unverified fixture")
                with self.assertRaisesRegex(ValueError, "unverified"):
                    FETCH.main()
                self.assertFalse(environment.exists())
                fetch.side_effect = None
                fetch.return_value = archive
                FETCH.main()
                self.assertEqual(environment.read_text(encoding="utf-8"),
                                 f"VECTORSCAN_PREBUILT_DIR={root.as_posix()}\n")
                unsafe = Mock()
                unsafe.name = NAME
                unsafe.parent.as_posix.return_value = "unsafe\nINJECTED=value"
                fetch.return_value = unsafe
                with self.assertRaisesRegex(ValueError, "Invalid GitHub environment path"):
                    FETCH.main()
                self.assertEqual(len(environment.read_text(encoding="utf-8").splitlines()), 1)

    def test_archive_destination_cannot_escape_selected_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            opener = Mock()
            with self.assertRaisesRegex(ValueError, "Unsafe.*destination"):
                FETCH.fetch(VERSION, "../escape.tar.gz", SHA256, Path(directory), opener)
            opener.open.assert_not_called()

    def test_token_is_api_only_and_redirects_require_https(self):
        with patch.dict(os.environ, {"GH_TOKEN": "private-fixture-token"}):
            request = FETCH.api_request("releases/assets/42", "application/octet-stream")
        self.assertEqual(request.get_header("Authorization"), "Bearer private-fixture-token")
        redirect = FETCH.SafeRedirect()
        redirected = redirect.redirect_request(request, None, 302, "Found", {},
                                               "https://release-assets.githubusercontent.com/asset")
        self.assertIsNone(redirected.get_header("Authorization"))
        # Defense in depth for callers which used a normal rather than unredirected header.
        request.add_header("Authorization", "Bearer private-fixture-token")
        redirected = redirect.redirect_request(request, None, 302, "Found", {},
                                               "https://untrusted.invalid/asset")
        self.assertIsNone(redirected.get_header("Authorization"))
        for url in ("http://release-assets.githubusercontent.com/asset", "file:///fixture"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "HTTPS"):
                redirect.redirect_request(request, None, 302, "Found", {}, url)

    def test_hash_pin_comes_from_locked_registry_sys_crate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "prebuilt-manifest.txt"
            manifest.write_text(f"# immutable crate pins\n{VERSION} {TARGET} {SHA256}\n", encoding="utf-8")
            package = {"name": "kingfisher-vectorscan-sys", "version": VERSION,
                       "manifest_path": str(root / "Cargo.toml"),
                       "source": "registry+https://github.com/rust-lang/crates.io-index"}
            result = Mock(stdout=json.dumps({"packages": [package]}))
            with patch.object(FETCH.subprocess, "run", return_value=result) as run:
                self.assertEqual(FETCH.pinned_archive(TARGET, root), (VERSION, NAME, SHA256))
                self.assertIn("--locked", run.call_args.args[0])
                self.assertIn("--filter-platform", run.call_args.args[0])
                for value in (f"{VERSION} {TARGET} {SHA256}\n" * 2,
                              f"0.0.0 {TARGET} {SHA256}\n", f"{VERSION} {TARGET} invalid\n"):
                    manifest.write_text(value, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "Invalid immutable"):
                        FETCH.pinned_archive(TARGET, root)
                manifest.write_text(f"{VERSION} other-target {SHA256}\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "No pinned.*archive"):
                    FETCH.pinned_archive(TARGET, root)
                package["source"] = None
                result.stdout = json.dumps({"packages": [package]})
                with self.assertRaisesRegex(ValueError, "immutable registry"):
                    FETCH.pinned_archive(TARGET, root)


class VectorscanWorkflowTests(unittest.TestCase):
    def test_all_native_ci_jobs_prefetch_before_builds(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for name, build in {
            "packaging": "make linux-x64", "lint": "cargo clippy --locked --workspace",
            "latest-stable": "cargo check --locked --workspace", "library-contract": "cargo test --locked",
            "linux-x64": "run: make tests", "linux-arm64": "run: make tests",
            "macos": "run: make tests", "windows": "run: WINDOWS_ONLY_DEPS=1 make windows-",
        }.items():
            with self.subTest(job=name):
                body = job(workflow, name)
                self.assertLess(body.index(ACTION), body.index(build))
        self.assertIn("target: x86_64-unknown-linux-musl", job(workflow, "packaging"))
        windows = job(workflow, "windows")
        self.assertIn("x86_64-pc-windows-gnu", windows)
        self.assertIn("aarch64-pc-windows-gnullvm", windows)

    def test_sdk_and_optional_wizard_builds_use_the_same_prefetch(self):
        node = (ROOT / ".github/workflows/node-sdk.yml").read_text(encoding="utf-8")
        build = job(node, "build")
        self.assertLess(build.index(ACTION), build.index("cargo clippy --locked"))
        self.assertIn("target: ${{ matrix.target }}", build)
        triggers = node.split("\npermissions:", 1)[0]
        for path in (".github/actions/vectorscan-prebuilt/**", "scripts/fetch-vectorscan.py",
                     "scripts/tests/test_fetch_vectorscan.py"):
            self.assertEqual(triggers.count(f"'{path}'"), 2)
        python = (ROOT / ".github/workflows/python-sdk.yml").read_text(encoding="utf-8")
        self.assertIn(ACTION, job(python, "source"))
        wheels = job(python, "wheels")
        prefetch = wheels[wheels.index(ACTION):].split("      - name:", 1)[0]
        self.assertIn("if: runner.os != 'Linux'", prefetch)
        self.assertIn("target: ${{ matrix.target }}", prefetch)
        self.assertIn("-e VECTORSCAN_BUILD_FROM_SOURCE=1", wheels)
        wizard = (ROOT / ".github/workflows/wizard.yml").read_text(encoding="utf-8")
        self.assertLess(wizard.index(ACTION), wizard.index("cargo test --locked"))

    def test_release_prefetch_uses_musl_not_the_linux_host_triple(self):
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        for arch, target in (("x64", "x86_64"), ("arm64", "aarch64")):
            self.assertIn(f"target: {target}-unknown-linux-musl", job(release, f"linux-{arch}"))
        for name in ("macos-x64", "macos-arm64", "windows"):
            self.assertIn(ACTION, job(release, name))

    def test_composite_action_uses_pinned_python_and_exports_only_verified_directory(self):
        action = (ROOT / ".github/actions/vectorscan-prebuilt/action.yml").read_text(encoding="utf-8")
        self.assertRegex(action, r"actions/setup-python@[0-9a-f]{40}")
        self.assertIn("GH_TOKEN: ${{ github.token }}", action)
        self.assertIn('python scripts/fetch-vectorscan.py --target "$PREFETCH_TARGET" --github-env', action)
        self.assertIn("working-directory: ${{ github.workspace }}", action)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("make"), "Bash and Make are required")
    def test_optional_docker_mount_preserves_space_paths_and_unset_environment(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        recipe = makefile.split("linux-x64 linux-arm64: ", 1)[1].split("\n\t$(MAKE) list-archives", 1)[0]
        recipe = recipe.split("\n\t@set --; \\\n", 1)[1]
        recipe = "set --; \\\n" + recipe.split("\n          -e VECTORSCAN_BUILD_FROM_SOURCE", 1)[0] + "\n"
        recipe = recipe.replace("$$", "$").replace("$(DOCKER_PLATFORM)", "linux/amd64")
        # Only exercise the argument construction; replace Docker with a shell function.
        wrapper = 'set -euo pipefail\ndocker() { printf "%s\\0" "$@"; }\n'
        for directory in (None, "/fixture/native archives"):
            with self.subTest(directory=directory):
                env = os.environ.copy()
                env.pop("VECTORSCAN_PREBUILT_DIR", None)
                if directory:
                    env["VECTORSCAN_PREBUILT_DIR"] = directory
                result = subprocess.run([shutil.which("bash"), "-c", wrapper + recipe], env=env,
                                        cwd=ROOT, capture_output=True, check=True)
                args = result.stdout.decode().rstrip("\0").split("\0")
                if directory:
                    self.assertIn(directory + ":/vectorscan-prebuilt:ro", args)
                    self.assertIn("VECTORSCAN_PREBUILT_DIR=/vectorscan-prebuilt", args)
                else:
                    self.assertFalse(any("vectorscan-prebuilt" in arg for arg in args))


if __name__ == "__main__":
    unittest.main()
