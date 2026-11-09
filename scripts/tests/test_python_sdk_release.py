"""Check main-merge SDK publishing without performing any registry writes."""
import importlib.util
import io
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sdk_publisher", ROOT / "scripts/plan-python-sdk-publish.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PythonSdkReleaseTests(unittest.TestCase):
    def test_main_pushes_publish_tested_artifacts_only_in_upstream(self):
        workflow = (ROOT / ".github/workflows/python-sdk.yml").read_text(encoding="utf-8")
        triggers = workflow.split("permissions:", 1)[0]
        self.assertIn("branches: [main]", triggers)
        publish = workflow.split("  publish:\n", 1)[1]
        plan = workflow.split("  plan-publish:\n", 1)[1].split("  publish:\n", 1)[0]
        condition = next(line for line in plan.splitlines() if line.strip().startswith("if:"))
        for guard in ("github.repository == 'mongodb/kingfisher'",
                      "github.event_name == 'push'", "github.ref == 'refs/heads/main'"):
            self.assertIn(guard, condition)
        # Accept flow/block lists, quoting, whitespace and any dependency order.
        needs = re.search(r"(?m)^    needs:[ \t]*(\[[^\]]*\]|(?:\n[ \t]{6,}-[^\n]+)+)", plan)
        self.assertIsNotNone(needs)
        dependency_list = re.sub(r"#[^\n]*", "", needs.group(1))
        dependencies = set(re.findall(r"[\w-]+", dependency_list))
        for required in ("wheels", "source", "cache-portability"):
            self.assertIn(required, dependencies)
        self.assertIn("name: pypi-sdk", publish)
        self.assertIn("group: pypi-sdk-publish-${{ github.run_id }}", publish)
        self.assertIn("skip-existing: true", publish)
        self.assertIn("pattern: python-*", plan)
        self.assertIn("if: needs.plan-publish.outputs.pending == 'true'", publish)
        self.assertIn("needs: [plan-publish]", publish)
        self.assertIn("name: python-sdk-pending", publish)
        self.assertNotIn("id-token: write", plan)
        self.assertNotIn("environment:", plan)

    def test_release_builds_do_not_replace_other_pending_releases(self):
        workflow = (ROOT / ".github/workflows/python-sdk.yml").read_text(encoding="utf-8")
        concurrency = workflow.split("concurrency:\n", 1)[1].split("env:\n", 1)[0]
        self.assertIn(
            "group: python-sdk-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
            concurrency,
        )
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", concurrency)

    def test_plan_includes_only_missing_artifacts(self):
        names = ["kingfisher_secret_scanner-1.3.0-cp310-abi3-win_amd64.whl",
                 "kingfisher_secret_scanner-1.3.0.tar.gz"]
        for existing in (set(), {names[0]}, set(names)):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temporary:
                dist = Path(temporary)
                for name in names:
                    (dist / name).write_bytes(b"built artifact")
                with patch.object(publisher, "published_filenames", return_value=existing) as query, \
                     patch("builtins.print"):
                    pending = publisher.plan(dist, "1.3.0")
                query.assert_called_once_with("1.3.0")
                self.assertEqual({path.name for path in pending}, set(names) - existing)
                self.assertEqual({path.name for path in dist.iterdir()}, set(names))

    def test_upload_staging_contains_only_missing_distributions(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary) / "dist"
            staged = Path(temporary) / "pending"
            dist.mkdir()
            for name in ["existing.whl", "missing.whl", "sdk.tar.gz"]:
                (dist / name).write_bytes(name.encode())
            with patch.object(publisher, "published_filenames", return_value={"existing.whl"}), \
                 patch("sys.argv", ["plan", "--dist", str(dist), "--pending-dir", str(staged)]), \
                 patch.dict(publisher.os.environ, {}, clear=True), patch("builtins.print"):
                self.assertEqual(publisher.main(), 0)
            self.assertEqual({path.name for path in staged.iterdir()}, {"missing.whl", "sdk.tar.gz"})
            self.assertEqual({path.name for path in dist.iterdir()}, {"existing.whl", "missing.whl", "sdk.tar.gz"})

    def test_registry_errors_preserve_artifacts_and_fail_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            artifact = dist / "sdk.whl"
            artifact.write_bytes(b"built artifact")
            with patch.object(publisher, "published_filenames", side_effect=urllib.error.URLError("offline")):
                with self.assertRaises(urllib.error.URLError):
                    publisher.plan(dist, "1.3.0")
            self.assertEqual(artifact.read_bytes(), b"built artifact")

    def test_empty_artifacts_are_not_a_successful_noop(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(publisher, "published_filenames") as fetch:
            with self.assertRaisesRegex(ValueError, "No SDK distributions"):
                publisher.plan(Path(temporary), "1.3.0")
            fetch.assert_not_called()

    def test_registry_returns_published_filenames(self):
        for files in ([], [{"filename": "sdk.whl"}]):
            response = json.dumps({"urls": files}).encode()
            with self.subTest(files=files), \
                 patch.object(publisher.urllib.request, "urlopen", return_value=io.BytesIO(response)) as fetch:
                self.assertEqual(publisher.published_filenames("1.3.0"), {item["filename"] for item in files})
                self.assertEqual(fetch.call_args.args[0].full_url,
                                 "https://pypi.org/pypi/kingfisher-secret-scanner/1.3.0/json")

    def test_only_404_means_unpublished(self):
        for code in (404, 403, 503):
            error = urllib.error.HTTPError("https://pypi.org", code, "error", {}, None)
            with self.subTest(code=code), \
                 patch.object(publisher.urllib.request, "urlopen", side_effect=error), \
                 patch.object(publisher.time, "sleep"):
                if code == 404:
                    self.assertEqual(publisher.published_filenames("1.3.0"), set())
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        publisher.published_filenames("1.3.0")

    def test_transient_registry_failure_retries(self):
        with patch.object(publisher.urllib.request, "urlopen", side_effect=[
            urllib.error.URLError("offline"), io.BytesIO(b'{"urls": []}')
        ]), patch.object(publisher.time, "sleep") as sleep:
            self.assertEqual(publisher.published_filenames("1.3.0"), set())
            sleep.assert_called_once_with(1)


class MaturinDownloadTests(unittest.TestCase):
    def container_environment(self, workspace):
        workflow = (ROOT / ".github/workflows/python-sdk.yml").read_text(encoding="utf-8")
        build = workflow.split("      - name: Build portable Linux wheel\n", 1)[1]
        build = build.split("      # manylinux builds", 1)[0]
        self.assertIn("if: runner.os == 'Linux'", build)
        self.assertIn("PyO3/maturin-action@e83996d129638aa358a18fbd1dfb82f0b0fb5d3b", build)
        self.assertIn("manylinux: '2_28'", build)
        self.assertIn("maturin-version: 'v1.16.0'", build)
        self.assertNotIn("CURL_HOME", workflow.split("jobs:\n", 1)[0])
        folded = re.search(r"(?m)^          docker-options: >-\n((?:            .+\n)+)", build)
        self.assertIsNotNone(folded)
        options = " ".join(line.strip() for line in folded.group(1).splitlines())
        options = shlex.split(options.replace("${{ github.workspace }}", workspace.as_posix()))
        self.assertEqual(options[::2], ["-e"] * 4)
        environment = dict(option.split("=", 1) for option in options[1::2])
        self.assertEqual(environment, {
            "VECTORSCAN_BUILD_FROM_SOURCE": "1",
            "CARGO_PROFILE_RELEASE_PANIC": "unwind",
            "CARGO_PROFILE_RELEASE_LTO": "false",
            "CURL_HOME": (workspace / ".github/maturin-curl").as_posix(),
        })
        return environment

    def download(self, statuses):
        curl = shutil.which("curl")
        self.assertIsNotNone(curl, "curl is required to exercise the container download configuration")
        archive = io.BytesIO()
        payload = b"fixture maturin binary\n"
        with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
            entry = tarfile.TarInfo("maturin")
            entry.size = len(payload)
            bundle.addfile(entry, io.BytesIO(payload))
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                status = statuses[min(len(requests), len(statuses) - 1)]
                requests.append(status)
                body = archive.getvalue() if status == 200 else b"upstream gateway error\n"
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory(prefix="kingfisher maturin downloads ") as temporary:
            workspace = Path(temporary)
            config_dir = workspace / ".github/maturin-curl"
            config_dir.mkdir(parents=True)
            config = (ROOT / ".github/maturin-curl/.curlrc").read_bytes()
            (config_dir / ".curlrc").write_bytes(config)
            environment = {**os.environ, **self.container_environment(workspace)}
            with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                thread = threading.Thread(
                    target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True,
                )
                thread.start()
                try:
                    # Match the action's curl -L download; keep test requests local,
                    # even when the developer or runner has proxy variables set.
                    result = subprocess.run(
                        [curl, "-L", "--noproxy", "*", f"http://127.0.0.1:{server.server_port}/maturin.tar.gz"],
                        env=environment, capture_output=True, timeout=30, check=False,
                    )
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
        return result, requests, payload

    def test_gateway_timeout_retries_without_piping_error_page_into_tar(self):
        result, requests, payload = self.download([504, 200])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(requests, [504, 200])
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:gz") as bundle:
            with bundle.extractfile("maturin") as binary:
                self.assertEqual(binary.read(), payload)

    def test_permanent_http_error_fails_without_retry_or_error_body(self):
        result, requests, _ = self.download([404])
        self.assertEqual(result.returncode, 22, result.stderr.decode())
        self.assertEqual(requests, [404])
        self.assertEqual(result.stdout, b"")

    def test_persistent_outage_exhausts_bounded_retries_and_still_fails(self):
        result, requests, _ = self.download([503])
        self.assertEqual(result.returncode, 22, result.stderr.decode())
        self.assertEqual(requests, [503] * 5)
        self.assertEqual(result.stdout, b"")

    def test_download_attempts_and_connection_time_are_bounded(self):
        config = (ROOT / ".github/maturin-curl/.curlrc").read_text(encoding="utf-8")
        for setting in ("retry-max-time", "connect-timeout", "max-time"):
            with self.subTest(setting=setting):
                value = re.search(rf"(?m)^{setting}\s*=\s*(\d+)\s*$", config)
                self.assertIsNotNone(value)
                self.assertGreater(int(value.group(1)), 0)
                self.assertLessEqual(int(value.group(1)), 300)


if __name__ == "__main__":
    unittest.main()
