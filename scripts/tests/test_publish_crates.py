import hashlib
import importlib.util
import io
import json
import shlex
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, call, patch
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
    def test_binary_root_documents_are_anchored_to_avoid_sdk_duplicates(self):
        manifest = tomllib.loads((publisher.ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        includes = manifest["package"]["include"]
        # Cargo treats an unanchored basename as a match at any depth, including
        # javascript/THIRD_PARTY_NOTICES as well as the canonical root copy.
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES", "README.md", "Cargo.lock"):
            with self.subTest(name=name):
                self.assertIn(f"/{name}", includes)
                self.assertNotIn(name, includes)

    def test_release_preflight_uses_registry_aware_read_only_packaging(self):
        workflow = (publisher.ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        lines = [line.strip().removeprefix("run: ") for line in workflow.splitlines()]
        commands = [shlex.split(line) for line in lines
                    if line.startswith("python3 scripts/publish-crates.py ")]
        packaging = [command for command in commands if "--package" in command]
        self.assertEqual(len(packaging), 1)
        self.assertIn("--tag", packaging[0])
        self.assertNotIn("--publish", packaging[0])
        self.assertFalse(any(line.startswith("cargo package ") for line in lines))

    def package_metadata(self):
        return {"packages": [{"name": name, "version": "1.0.0", "publish": ["crates-io"]}
                             for name in publisher.PACKAGES] +
                            [{"name": "kingfisher-python", "version": "9.0.0", "publish": []}],
                "target_directory": str(publisher.ROOT / "target")}

    def assert_package_groups(self, existing, groups):
        metadata = self.package_metadata()
        queries = []

        def status(name, version):
            self.assertEqual(version, "1.0.0")
            queries.append(name)
            return {"checksum": "a" * 64} if name in existing else None

        def verify_queries(command, **kwargs):
            self.assertEqual(tuple(queries), publisher.PACKAGES)

        run = Mock(side_effect=verify_queries)
        with patch.object(publisher, "published_version", side_effect=status):
            publisher.package_crates(metadata, run=run)
        expected = []
        for group in groups:
            command = ["cargo", "package", "--locked"]
            for name in group:
                command.extend(["-p", name])
            expected.append(call(command, cwd=publisher.ROOT, check=True))
        # Exact argv also forbids --no-verify, --allow-dirty, --workspace, publishing,
        # authentication commands, and accidentally selecting the private SDK crate.
        self.assertEqual(run.call_args_list, expected)

    def test_packages_all_new_versions_in_one_dependency_ordered_batch(self):
        self.assert_package_groups(set(), [publisher.PACKAGES])

    def test_packages_all_published_versions_separately(self):
        self.assert_package_groups(set(publisher.PACKAGES), [(name,) for name in publisher.PACKAGES])

    def test_packages_mixed_versions_without_shadowing_published_libraries(self):
        core, rules, scanner, binary = publisher.PACKAGES
        self.assert_package_groups({core, rules}, [(core,), (rules,), (scanner, binary)])

    def test_packages_a_single_pending_binary_without_an_overlay_of_published_libraries(self):
        self.assert_package_groups(set(publisher.PACKAGES[:-1]), [(name,) for name in publisher.PACKAGES])

    def test_validates_all_publish_configurations_before_queries_or_packaging(self):
        for invalid in (None, [], ["another-registry"], ["crates-io", "another-registry"]):
            metadata = self.package_metadata()
            metadata["packages"][3]["publish"] = invalid
            run = Mock()
            with self.subTest(publish=invalid), patch.object(publisher, "published_version") as query:
                with self.assertRaisesRegex(ValueError, "must be configured for crates-io"):
                    publisher.package_crates(metadata, run=run)
                query.assert_not_called()
                run.assert_not_called()

    def test_missing_release_member_stops_before_queries_or_packaging(self):
        metadata = self.package_metadata()
        metadata["packages"].pop(3)
        run = Mock()
        with patch.object(publisher, "published_version") as query:
            with self.assertRaisesRegex(ValueError, "Missing release package"):
                publisher.package_crates(metadata, run=run)
            query.assert_not_called()
            run.assert_not_called()

    def test_registry_failure_or_malformed_response_stops_before_any_packaging(self):
        def info(name):
            return {"crate": name, "num": "1.0.0", "yanked": False, "checksum": "a" * 64}

        def body(value):
            return json.dumps({"version": value}).encode()

        binary = info(publisher.PACKAGES[-1])
        invalid = [b"not JSON", b"[]", b"{}", body(None), body([]),
                   body({**binary, "crate": "another-crate"}), body({**binary, "num": "2.0.0"}),
                   body({**binary, "yanked": True}), body({**binary, "yanked": "false"}),
                   body({key: value for key, value in binary.items() if key != "yanked"}),
                   body({key: value for key, value in binary.items() if key != "checksum"}),
                   body({**binary, "checksum": "invalid"}), body({**binary, "checksum": "g" * 64}),
                   body({**binary, "checksum": 123}),
                   urllib.error.HTTPError("https://crates.io", 403, "forbidden", {}, None),
                   urllib.error.URLError("registry unavailable"), TimeoutError("registry timed out")]
        for bad in invalid:
            responses = [body(info(name)) for name in publisher.PACKAGES[:-1]] + [bad]
            run = Mock()
            with self.subTest(response=bad), patch.object(publisher, "fetch", side_effect=responses) as fetch:
                with self.assertRaises((ValueError, urllib.error.URLError, TimeoutError)):
                    publisher.package_crates(self.package_metadata(), run=run)
                self.assertEqual(fetch.call_count, 4)
                run.assert_not_called()

    def test_cargo_package_failure_propagates_and_stops_later_groups(self):
        error = subprocess.CalledProcessError(101, ["cargo", "package", "--locked"])
        run = Mock(side_effect=error)
        with patch.object(publisher, "published_version", return_value={"checksum": "a" * 64}):
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                publisher.package_crates(self.package_metadata(), run=run)
        self.assertIs(failure.exception, error)
        self.assertEqual(run.call_count, 1)

    def test_package_flag_stages_then_plans_without_token_or_upload(self):
        metadata = self.package_metadata()
        plan = [{"name": name, "version": "1.0.0", "publish": True} for name in publisher.PACKAGES]
        events = []
        with patch.object(sys, "argv", ["publish-crates.py", "--package", "--tag", "v1.0.0"]), \
             patch.dict(publisher.os.environ, {}, clear=True), \
             patch.object(publisher.subprocess, "check_output", return_value=json.dumps(metadata).encode()), \
             patch.object(publisher, "package_crates", side_effect=lambda data: events.append("package")) as package, \
             patch.object(publisher, "make_plan", side_effect=lambda *args: events.append("plan") or plan) as make_plan, \
             patch.object(publisher, "publish_plan") as publish, patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(publisher.main(), 0)
            package.assert_called_once_with(metadata)
            make_plan.assert_called_once_with(metadata, Path(metadata["target_directory"]) / "package")
            publish.assert_not_called()
        self.assertEqual(events, ["package", "plan"])

    def test_default_planning_and_publish_do_not_repackage(self):
        metadata = self.package_metadata()
        plan = [{"name": "kingfisher-bin", "version": "1.0.0", "publish": True}]
        for args in ([], ["--publish"]):
            with self.subTest(args=args), patch.object(sys, "argv", ["publish-crates.py", *args]), \
                 patch.dict(publisher.os.environ, {"CARGO_REGISTRY_TOKEN": "test-token"}, clear=True), \
                 patch.object(publisher.subprocess, "check_output", return_value=json.dumps(metadata).encode()), \
                 patch.object(publisher, "package_crates") as package, \
                 patch.object(publisher, "make_plan", return_value=plan), \
                 patch.object(publisher, "publish_plan") as publish, patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(publisher.main(), 0)
                package.assert_not_called()
                if args:
                    publish.assert_called_once_with(plan)
                else:
                    publish.assert_not_called()

    def test_package_and_publish_flags_are_mutually_exclusive(self):
        with patch.object(sys, "argv", ["publish-crates.py", "--package", "--publish"]), \
             patch.object(publisher.subprocess, "check_output") as metadata, \
             patch.object(publisher, "package_crates") as package, \
             patch.object(publisher, "publish_plan") as publish, patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as failure:
                publisher.main()
            self.assertEqual(failure.exception.code, 2)
            metadata.assert_not_called()
            package.assert_not_called()
            publish.assert_not_called()

    def test_package_mode_keeps_strict_plan_failure_before_any_upload(self):
        metadata = self.package_metadata()
        with patch.object(sys, "argv", ["publish-crates.py", "--package"]), \
             patch.dict(publisher.os.environ, {}, clear=True), \
             patch.object(publisher.subprocess, "check_output", return_value=json.dumps(metadata).encode()), \
             patch.object(publisher, "package_crates") as package, \
             patch.object(publisher, "make_plan", side_effect=ValueError("Cargo.lock changed")), \
             patch.object(publisher, "publish_plan") as publish:
            with self.assertRaisesRegex(ValueError, "Cargo.lock changed"):
                publisher.main()
            package.assert_called_once_with(metadata)
            publish.assert_not_called()

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

    def test_cli_dependency_checksum_drift_still_requires_version_bump(self):
        lock = b'[[package]]\nname = "kingfisher-core"\nchecksum = "registry-checksum"\n'
        remote = crate("kingfisher-bin", **{"Cargo.lock": lock})
        local = crate("kingfisher-bin", **{
            "Cargo.lock": lock.replace(b"registry-checksum", b"rebuilt-archive-checksum")})
        with patch.object(publisher, "fetch", return_value=remote):
            with self.assertRaisesRegex(ValueError, r"Cargo\.lock.*Bump its version"):
                publisher.verify_existing(local, "kingfisher-bin", "1.0.0",
                                          {"checksum": hashlib.sha256(remote).hexdigest()})

    def test_changed_source_requires_version_bump(self):
        remote = crate()
        local = crate(**{"src/lib.rs": b"pub fn changed() {}"})
        with patch.object(publisher, "fetch", return_value=remote):
            with self.assertRaisesRegex(ValueError, "Bump its version"):
                publisher.verify_existing(local, "kingfisher-core", "1.0.0", {"checksum": hashlib.sha256(remote).hexdigest()})

    def test_added_packaged_regression_tests_require_version_bump(self):
        remote = crate()
        local = crate(**{"src/blob/identity_tests.rs": b"#[test] fn identity_is_stable() {}"})
        with patch.object(publisher, "fetch", return_value=remote):
            with self.assertRaisesRegex(ValueError, r"src/blob/identity_tests\.rs.*Bump its version"):
                publisher.verify_existing(local, "kingfisher-core", "1.0.0",
                                          {"checksum": hashlib.sha256(remote).hexdigest()})

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
