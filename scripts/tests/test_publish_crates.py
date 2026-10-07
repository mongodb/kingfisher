import hashlib
import importlib.util
import io
import json
import shlex
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location("publish_crates", Path(__file__).parents[1] / "publish-crates.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def crate(name="kingfisher-core", version="1.0.0", **changes):
    files = {"Cargo.toml": f'[package]\nname = "{name}"\nversion = "{version}"\n'.encode(),
             "src/lib.rs": b"pub fn example() {}", "Cargo.lock": b"lockfile",
             ".cargo_vcs_info.json": b"old git commit", "Cargo.toml.orig": b"original"}
    files.update(changes)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for path, value in files.items():
            if value is None:
                continue
            info = tarfile.TarInfo(f"{name}-{version}/{path}")
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


class PublishTests(unittest.TestCase):
    def test_release_preflight_packages_only_registry_release_crates(self):
        workflow = (publisher.ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        commands = [shlex.split(line.strip()) for line in workflow.splitlines()
                    if line.strip().startswith("cargo package ")]
        self.assertEqual(len(commands), 1)
        command = commands[0]
        selected = [command[index + 1] for index, arg in enumerate(command) if arg == "-p"]
        self.assertEqual(tuple(selected), publisher.PACKAGES)
        self.assertIn("--locked", command)
        self.assertNotIn("--no-verify", command)
        self.assertNotIn("--workspace", command)

    def test_fetch_retries_transient_errors(self):
        errors = [urllib.error.HTTPError("https://crates.io", code, "retry", {}, None)
                  for code in (408, 429, 500, 503)]
        errors.extend([urllib.error.URLError("connection reset"), TimeoutError("timed out")])
        for error in errors:
            with self.subTest(error=error), \
                 patch.object(publisher.urllib.request, "urlopen", side_effect=[error, io.BytesIO(b"ok")]) as request, \
                 patch.object(publisher.time, "sleep") as sleep:
                self.assertEqual(publisher.fetch("https://crates.io"), b"ok")
                self.assertEqual(request.call_count, 2)
                sleep.assert_called_once_with(1)

    def test_fetch_stops_after_second_network_failure(self):
        with patch.object(publisher.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline")) as request, \
             patch.object(publisher.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.URLError):
                publisher.fetch("https://crates.io")
            self.assertEqual(request.call_count, 2)
            sleep.assert_called_once_with(1)

    def test_fetch_does_not_retry_missing_or_permanent_errors(self):
        for code in (400, 401, 403, 404):
            response = io.BytesIO(b"error body")
            error = urllib.error.HTTPError("https://crates.io", code, "error", {}, response)
            self.addCleanup(error.close)
            with self.subTest(code=code), \
                 patch.object(publisher.urllib.request, "urlopen", side_effect=error) as request, \
                 patch.object(publisher.time, "sleep") as sleep:
                if code == 404:
                    self.assertIsNone(publisher.fetch("https://crates.io", missing_ok=True))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        publisher.fetch("https://crates.io", missing_ok=True)
                self.assertEqual(request.call_count, 1)
                self.assertTrue(response.closed)
                sleep.assert_not_called()

    def test_missing_archive_manifest_is_a_clean_error(self):
        with self.assertRaisesRegex(ValueError, "missing Cargo.toml"):
            publisher.archive_contents(crate(**{"Cargo.toml": None}), "kingfisher-core", "1.0.0")

    def test_incomplete_archive_manifest_is_a_clean_error(self):
        for manifest in [b"", b'[package]\nname = "kingfisher-core"\n']:
            with self.subTest(manifest=manifest), self.assertRaisesRegex(ValueError, "manifest does not match"):
                publisher.archive_contents(crate(**{"Cargo.toml": manifest}), "kingfisher-core", "1.0.0")

    def test_library_bookkeeping_does_not_force_new_release(self):
        before = crate()
        after = crate(**{"Cargo.lock": b"new dependencies", ".cargo_vcs_info.json": b"new commit",
                         "Cargo.toml.orig": b"new workspace spelling"})
        self.assertEqual(publisher.archive_contents(before, "kingfisher-core", "1.0.0"),
                         publisher.archive_contents(after, "kingfisher-core", "1.0.0"))

    def test_cli_lockfile_is_part_of_release(self):
        before = publisher.archive_contents(crate("kingfisher-bin"), "kingfisher-bin", "1.0.0")
        after = publisher.archive_contents(crate("kingfisher-bin", **{"Cargo.lock": b"new"}), "kingfisher-bin", "1.0.0")
        self.assertNotEqual(before, after)

    def test_changed_source_requires_version_bump(self):
        remote = crate()
        local = crate(**{"src/lib.rs": b"pub fn changed() {}"})
        with patch.object(publisher, "fetch", return_value=remote):
            with self.assertRaisesRegex(ValueError, "Bump its version"):
                publisher.verify_existing(local, "kingfisher-core", "1.0.0", {"checksum": hashlib.sha256(remote).hexdigest()})

    def test_provenance_exception_is_limited_to_workspace_manifest_hashes(self):
        def rules(root_hash, source_hash, bundle):
            provenance = {"generator_input_sha256": {"Cargo.toml": root_hash, "Cargo.lock": root_hash,
                                                      "importer.rs": source_hash}, "bundle_sha256": bundle}
            return publisher.archive_contents(crate("kingfisher-rules", **{
                "generated/provenance.json": json.dumps(provenance).encode()
            }), "kingfisher-rules", "1.0.0")
        self.assertEqual(rules("old", "same", "same"), rules("new", "same", "same"))
        self.assertNotEqual(rules("old", "same", "same"), rules("new", "changed", "same"))
        self.assertNotEqual(rules("old", "same", "same"), rules("new", "same", "changed"))

    def test_registry_failure_is_not_treated_as_missing_version(self):
        error = urllib.error.HTTPError("https://crates.io", 403, "forbidden", {}, None)
        with patch.object(publisher.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                publisher.published_version("kingfisher-core", "1.0.0")

    def test_missing_and_yanked_versions_are_distinct(self):
        with patch.object(publisher, "fetch", return_value=None):
            self.assertIsNone(publisher.published_version("kingfisher-core", "1.0.0"))
        body = json.dumps({"version": {"crate": "kingfisher-core", "num": "1.0.0", "yanked": True}}).encode()
        with patch.object(publisher, "fetch", return_value=body):
            with self.assertRaisesRegex(ValueError, "yanked"):
                publisher.published_version("kingfisher-core", "1.0.0")

    def test_plan_checks_all_packages_before_upload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            packages = []
            for name in publisher.PACKAGES:
                (root / f"{name}-1.0.0.crate").write_bytes(crate(name))
                packages.append({"name": name, "version": "1.0.0", "publish": ["crates-io"]})
            with patch.object(publisher, "published_version", side_effect=[None, None, None, ValueError("binary changed")]):
                with self.assertRaisesRegex(ValueError, "binary changed"):
                    publisher.make_plan({"packages": packages}, root)

    def test_resumes_in_dependency_order_and_waits_between_uploads(self):
        events = []
        plan = [{"name": name, "version": "1.0.0", "publish": name != "kingfisher-core"}
                for name in publisher.PACKAGES]
        publisher.publish_plan(plan,
            run=lambda args, **kwargs: events.append(("publish", args[-1])),
            wait=lambda name, version: events.append(("wait", name)))
        self.assertEqual(events, [(action, name) for name in publisher.PACKAGES[1:]
                                  for action in ["publish", "wait"]])

    def test_unchanged_published_crates_do_not_upload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            packages = []
            for name in publisher.PACKAGES:
                (root / f"{name}-1.0.0.crate").write_bytes(crate(name))
                packages.append({"name": name, "version": "1.0.0", "publish": ["crates-io"]})

            def published(name, version):
                return {"checksum": hashlib.sha256(crate(name, version)).hexdigest()}

            def download(url):
                name = url.split("/")[-2]
                return crate(name)

            with patch.object(publisher, "published_version", side_effect=published), \
                 patch.object(publisher, "fetch", side_effect=download):
                plan = publisher.make_plan({"packages": packages}, root)
            self.assertFalse(any(item["publish"] for item in plan))
            with patch.object(publisher.subprocess, "run") as upload, \
                 patch.object(publisher, "wait_for_index") as wait:
                publisher.publish_plan(plan, run=upload, wait=wait)
                upload.assert_not_called()
                wait.assert_not_called()

    def test_index_propagation_retries_until_exact_version_is_visible(self):
        with patch.object(publisher, "fetch", side_effect=[None, b'{"vers":"1.0.0","yanked":false}\n']), \
             patch.object(publisher.time, "sleep") as sleep:
            publisher.wait_for_index("kingfisher-core", "1.0.0")
            sleep.assert_called_once_with(5)

    def test_index_retries_transient_errors(self):
        errors = [urllib.error.HTTPError("https://index.crates.io", code, "retry", {}, None)
                  for code in (408, 429, 500, 503)]
        errors.extend([urllib.error.URLError("connection reset"), TimeoutError("timed out")])
        for error in errors:
            if isinstance(error, urllib.error.HTTPError):
                self.addCleanup(error.close)
            with self.subTest(error=error), \
                 patch.object(publisher, "fetch", side_effect=[error, b'{"vers":"1.0.0","yanked":false}\n']), \
                 patch.object(publisher.time, "sleep") as sleep:
                publisher.wait_for_index("kingfisher-core", "1.0.0")
                sleep.assert_called_once_with(5)

    def test_index_does_not_retry_permanent_errors(self):
        for code in (400, 401, 403):
            error = urllib.error.HTTPError("https://index.crates.io", code, "forbidden", {}, None)
            self.addCleanup(error.close)
            with self.subTest(code=code), patch.object(publisher, "fetch", side_effect=error), \
                 patch.object(publisher.time, "sleep") as sleep:
                with self.assertRaises(urllib.error.HTTPError):
                    publisher.wait_for_index("kingfisher-core", "1.0.0")
                sleep.assert_not_called()

    def test_index_retries_respect_deadline(self):
        error = urllib.error.URLError("connection reset")
        with patch.object(publisher, "fetch", side_effect=error) as fetch, \
             patch.object(publisher.time, "monotonic", side_effect=[0, 0, 2, 3]), \
             patch.object(publisher.time, "sleep") as sleep:
            with self.assertRaisesRegex(TimeoutError, "retry workflow"):
                publisher.wait_for_index("kingfisher-core", "1.0.0", timeout=3)
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(fetch.call_args.kwargs["timeout"], 3)
            sleep.assert_called_once_with(1)

    def test_index_rejects_yanked_version(self):
        with patch.object(publisher, "fetch", return_value=b'{"vers":"1.0.0","yanked":true}\n'), \
             patch.object(publisher.time, "sleep") as sleep:
            with self.assertRaisesRegex(ValueError, "yanked during publication"):
                publisher.wait_for_index("kingfisher-core", "1.0.0")
            sleep.assert_not_called()

    def test_download_checksum_is_verified(self):
        with patch.object(publisher, "fetch", return_value=crate()):
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                publisher.verify_existing(crate(), "kingfisher-core", "1.0.0", {"checksum": "wrong"})


if __name__ == "__main__":
    unittest.main()
