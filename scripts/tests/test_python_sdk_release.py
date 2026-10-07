"""Check main-merge SDK publishing without performing any registry writes."""
import importlib.util
import io
import json
import re
from pathlib import Path
import tempfile
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

    def test_existing_sdk_version_never_enters_upload_plan(self):
        names = ["kingfisher_secret_scanner-1.3.0-cp310-abi3-win_amd64.whl",
                 "kingfisher_secret_scanner-1.3.0.tar.gz"]
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temporary:
                dist = Path(temporary)
                for name in names:
                    (dist / name).write_bytes(b"built artifact")
                with patch.object(publisher, "version_exists", return_value=existing) as query, \
                     patch("builtins.print"):
                    pending = publisher.plan(dist, "1.3.0")
                query.assert_called_once_with("1.3.0")
                self.assertEqual({path.name for path in pending}, set() if existing else set(names))
                self.assertEqual({path.name for path in dist.iterdir()}, set(names))

    def test_registry_errors_preserve_artifacts_and_fail_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            artifact = dist / "sdk.whl"
            artifact.write_bytes(b"built artifact")
            with patch.object(publisher, "version_exists", side_effect=urllib.error.URLError("offline")):
                with self.assertRaises(urllib.error.URLError):
                    publisher.plan(dist, "1.3.0")
            self.assertEqual(artifact.read_bytes(), b"built artifact")

    def test_empty_artifacts_are_not_a_successful_noop(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(publisher, "version_exists") as fetch:
            with self.assertRaisesRegex(ValueError, "No SDK distributions"):
                publisher.plan(Path(temporary), "1.3.0")
            fetch.assert_not_called()

    def test_existing_version_is_skipped_even_with_missing_files(self):
        for files in ([], [{"filename": "sdk.whl"}]):
            response = json.dumps({"urls": files}).encode()
            with self.subTest(files=files), \
                 patch.object(publisher.urllib.request, "urlopen", return_value=io.BytesIO(response)) as fetch:
                self.assertTrue(publisher.version_exists("1.3.0"))
                self.assertEqual(fetch.call_args.args[0].full_url,
                                 "https://pypi.org/pypi/kingfisher-secret-scanner/1.3.0/json")

    def test_only_404_means_unpublished(self):
        for code in (404, 403, 503):
            error = urllib.error.HTTPError("https://pypi.org", code, "error", {}, None)
            with self.subTest(code=code), \
                 patch.object(publisher.urllib.request, "urlopen", side_effect=error), \
                 patch.object(publisher.time, "sleep"):
                if code == 404:
                    self.assertFalse(publisher.version_exists("1.3.0"))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        publisher.version_exists("1.3.0")

    def test_transient_registry_failure_retries(self):
        with patch.object(publisher.urllib.request, "urlopen", side_effect=[
            urllib.error.URLError("offline"), io.BytesIO(b'{"urls": []}')
        ]), patch.object(publisher.time, "sleep") as sleep:
            self.assertTrue(publisher.version_exists("1.3.0"))
            sleep.assert_called_once_with(1)


if __name__ == "__main__":
    unittest.main()
