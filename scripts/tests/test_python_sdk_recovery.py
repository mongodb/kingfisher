"""Offline artifact-only SDK recovery: authorization, immutable inputs and metadata."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("python_sdk_recovery", ROOT / "scripts/check-python-sdk-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
HEAD, PRODUCER = "a" * 40, "b" * 40
VERSION = "1.6.4"
NOW = datetime(2026, 11, 16, 23, tzinfo=timezone.utc)
REPOSITORY = {"id": 42, "full_name": recovery.UPSTREAM}


def stamp(seconds):
    return (NOW - timedelta(minutes=1) + timedelta(seconds=seconds)).isoformat()


def environment(**updates):
    return {"GITHUB_REPOSITORY": recovery.UPSTREAM, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": HEAD, "GITHUB_WORKFLOW_SHA": HEAD,
            "GITHUB_WORKFLOW_REF": f"{recovery.UPSTREAM}/{recovery.WORKFLOW}@refs/heads/main",
            "GITHUB_RUN_ID": "99", "GH_TOKEN": "mock-read-only-token", **updates}


def event(**updates):
    return {"repository": copy.deepcopy(REPOSITORY), "inputs": {
        "publish": "true", "sdk_only": "true", "crates_only": "false", "release_run_id": "71",
        "release_run_attempt": "1", "artifact_id": "222", "producer_sha": PRODUCER,
        "expected_sha": HEAD, "expected_version": VERSION, **updates}}


class GitHub:
    def __init__(self):
        self.workflow = {"id": 17, "path": recovery.WORKFLOW}
        self.run = {"id": 71, "run_attempt": 1, "workflow_id": 17, "path": recovery.WORKFLOW,
                    "head_sha": PRODUCER, "head_branch": "main", "repository": dict(REPOSITORY),
                    "head_repository": dict(REPOSITORY), "status": "completed", "conclusion": "failure",
                    "event": "push"}
        names = (*recovery.REQUIRED_JOBS, "publish-python-sdk / publish")
        self.jobs = []
        for index, name in enumerate(names):
            start = 2 if name in recovery.SDK_BUILDS else 4 if name in recovery.SDK_CACHES else {
                recovery.PLAN: 6, recovery.BUILD_GATE: 8, recovery.PUBLISH_GATE: 10,
                "publish-python-sdk / publish": 12}.get(name, 0)
            self.jobs.append({"id": index + 1, "name": name, "run_id": 71, "run_attempt": 1,
                              "status": "completed", "conclusion": "failure" if index == len(names) - 1 else "success",
                              "started_at": stamp(start), "completed_at": stamp(start + 1)})
        self.history = {}
        self.artifact = {"id": 222, "name": recovery.ARTIFACT_NAME, "expired": False,
                         "digest": "sha256:" + "d" * 64, "size_in_bytes": 100,
                         "created_at": stamp(6), "expires_at": (NOW + timedelta(days=30)).isoformat(),
                         "workflow_run": {"id": 71, "head_sha": PRODUCER, "head_branch": "main",
                                          "repository_id": 42, "head_repository_id": 42}}
        self.calls = []

    def __call__(self, path, token):
        self.calls.append((path, token))
        prefix = f"/repos/{recovery.UPSTREAM}/actions"
        if "/jobs?" in path:
            attempt = int(path.split("/attempts/")[1].split("/")[0])
            page = int(path.rsplit("page=", 1)[1])
            jobs = self.jobs if attempt == self.run["run_attempt"] else self.history.get(attempt, [])
            return {"jobs": copy.deepcopy(jobs[(page - 1) * 100:page * 100])}
        return copy.deepcopy({f"{prefix}/workflows/release.yml": self.workflow,
                              f"{prefix}/runs/71": self.run, f"{prefix}/artifacts/222": self.artifact}[path])

    def job(self, name):
        return next(job for job in self.jobs if job["name"] == name)


class Git:
    def __init__(self):
        self.head, self.main, self.dirty = HEAD, HEAD, ""
        self.changed = [".github/workflows/release.yml", "scripts/check-python-sdk-recovery.py",
                        "scripts/check-release-source.py", "scripts/tests/test_python_sdk_recovery.py",
                        "docs/PYPI.md", "docs-site/docs/reference/python-bindings.md"]
        self.mode, self.previous_mode, self.version, self.failure = "100644", "100644", VERSION, None
        self.calls = []

    def __call__(self, _root, *args):
        self.calls.append(args)
        if self.failure == args[0]:
            raise subprocess.CalledProcessError(1, ["git", *args])
        if args == ("rev-parse", "HEAD"):
            return self.head
        if args == ("rev-parse", "refs/remotes/origin/main"):
            return self.main
        if args[0] == "status":
            return self.dirty
        if args[0] == "diff":
            return "\0".join(self.changed) + "\0"
        if args[0] == "ls-tree":
            return f"{self.mode if args[1] == HEAD else self.previous_mode} blob {'c' * 40}\t{args[-1]}"
        if args[0] == "show":
            revision, path = args[1].split(":", 1)
            if path == "crates/kingfisher-python/Cargo.toml":
                return f'[package]\nname = "kingfisher-python"\nversion = "{self.version}"\n'
            if path == "Cargo.toml":
                return '[package]\nname = "kingfisher-bin"\nversion = "2.19.1"\n'
            if path == "javascript/package.json":
                return json.dumps({"name": recovery.PACKAGE, "version": "1.0.2"})
        if args[0] in {"fetch", "merge-base"}:
            return ""
        raise AssertionError(f"Unexpected Git operation: {args}")


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.api = GitHub()

    def validate(self, **updates):
        args = dict(run_id="71", attempt="1", sha=PRODUCER, artifact_id="222", token="mock-token",
                    api=self.api, now=NOW)
        args.update(updates)
        return recovery.validate_producer(**args)

    def test_failed_upload_does_not_discard_successful_original_cohort(self):
        result = self.validate()
        self.assertEqual(result["artifact_digest"], self.api.artifact["digest"])
        self.assertEqual(result["producer_ref"], "refs/heads/main")
        self.assertTrue(all(path.startswith(f"/repos/{recovery.UPSTREAM}/actions/") for path, _ in self.api.calls))
        self.api.run["conclusion"] = "success"
        self.api.jobs[-1]["conclusion"] = "success"
        self.assertEqual(self.validate()["artifact_id"], "222")

    def test_new_direct_publisher_name_is_supported(self):
        self.api.jobs[-1]["name"] = "Publish Python SDK to PyPI"
        self.validate()

    def test_every_required_gate_build_source_cache_and_plan_is_mandatory(self):
        for name in recovery.REQUIRED_JOBS:
            for conclusion in ("failure", "cancelled", "skipped", None):
                with self.subTest(name=name, conclusion=conclusion):
                    self.api = GitHub()
                    self.api.job(name)["conclusion"] = conclusion
                    with self.assertRaisesRegex(ValueError, "successful gate"):
                        self.validate()
            self.api = GitHub()
            self.api.jobs.remove(self.api.job(name))
            with self.assertRaisesRegex(ValueError, "successful gate"):
                self.validate()

    def test_duplicate_and_pending_jobs_fail_closed(self):
        for status in ("queued", "in_progress", "waiting"):
            with self.subTest(status=status):
                self.api = GitHub()
                self.api.job(recovery.BUILD_GATE)["status"] = status
                with self.assertRaisesRegex(ValueError, "successful gate"):
                    self.validate()
        self.api = GitHub()
        duplicate = dict(self.api.job(recovery.PLAN), id=333)
        self.api.jobs.append(duplicate)
        with self.assertRaisesRegex(ValueError, "successful gate"):
            self.validate()

    def test_skipped_cancelled_or_missing_upload_does_not_authorize_recovery(self):
        for conclusion in ("skipped", "cancelled", None):
            with self.subTest(conclusion=conclusion):
                self.api.jobs[-1]["conclusion"] = conclusion
                with self.assertRaisesRegex(ValueError, "authorized upload"):
                    self.validate()
        self.api.jobs.pop()
        with self.assertRaisesRegex(ValueError, "authorized upload"):
            self.validate()

    def test_producer_identity_and_completion_are_pinned(self):
        invalid = {"id": 72, "workflow_id": 99, "path": ".github/workflows/python-sdk.yml",
                   "head_sha": HEAD, "run_attempt": 2, "head_branch": "development", "event": "pull_request",
                   "status": "in_progress", "conclusion": "cancelled",
                   "repository": {"full_name": "fork/kingfisher", "id": 42},
                   "head_repository": {"full_name": recovery.UPSTREAM, "id": 43}}
        for key, value in invalid.items():
            with self.subTest(key=key):
                self.api = GitHub()
                self.api.run[key] = value
                with self.assertRaises(ValueError):
                    self.validate()
        self.api = GitHub()
        self.api.workflow["path"] = ".github/workflows/python-sdk.yml"
        with self.assertRaises(ValueError):
            self.validate()

    def test_ids_and_attempt_count_are_bounded(self):
        for key in ("run_id", "attempt", "artifact_id"):
            for value in (None, "", "0", "-1", " 71", "71\n", True, [], "9" * 21):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.validate(**{key: value})
        with self.assertRaisesRegex(ValueError, "at most 20"):
            self.validate(attempt="21")
        for sha in ("", PRODUCER[:7], "0" * 40):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                self.validate(sha=sha)

    def test_effective_prerequisites_may_come_from_earlier_attempts(self):
        self.api.history[1] = copy.deepcopy(self.api.jobs[:-1])
        self.api.jobs = [dict(self.api.jobs[-1], run_attempt=2)]
        self.api.run["run_attempt"] = 2
        self.validate(attempt="2")
        self.api.jobs.append(dict(self.api.history[1][0], run_attempt=2, conclusion="failure"))
        with self.assertRaisesRegex(ValueError, "successful gate"):
            self.validate(attempt="2")

    def test_newer_rerun_cannot_use_old_staging_after_new_test_results(self):
        self.api.history[1] = copy.deepcopy(self.api.jobs)
        self.api.jobs = [dict(self.api.jobs[-1], run_attempt=2),
                         dict(self.api.job(recovery.SDK_BUILDS[0]), run_attempt=2,
                              started_at=stamp(20), completed_at=stamp(21))]
        self.api.run["run_attempt"] = 2
        with self.assertRaisesRegex(ValueError, "out of order"):
            self.validate(attempt="2")

    def test_job_origin_ids_pagination_and_timestamps_are_checked(self):
        for key, value in (("run_id", 72), ("run_attempt", 2), ("id", 0),
                           ("completed_at", "bad"), ("started_at", stamp(20)),
                           ("completed_at", (NOW + timedelta(seconds=1)).isoformat())):
            with self.subTest(key=key, value=value):
                self.api = GitHub()
                self.api.job(recovery.PLAN)[key] = value
                with self.assertRaises(ValueError):
                    self.validate()
        self.api = GitHub()
        self.api.jobs.append(copy.deepcopy(self.api.jobs[0]))
        with self.assertRaisesRegex(ValueError, "Duplicate producer job ID"):
            self.validate()
        self.api = GitHub()
        self.api.jobs = [dict(self.api.jobs[0], id=1000 + index, name=f"extra {index}")
                         for index in range(100)] + self.api.jobs
        self.validate()
        self.assertTrue(any("page=2" in path for path, _ in self.api.calls))

    def test_artifact_identity_digest_expiry_size_and_staging_interval(self):
        invalid = {"id": 223, "name": "python-sdk-pending-other", "expired": True,
                   "digest": "sha256:" + "0" * 64, "size_in_bytes": 0,
                   "created_at": stamp(8), "expires_at": NOW.isoformat()}
        for key, value in invalid.items():
            with self.subTest(key=key):
                self.api = GitHub()
                self.api.artifact[key] = value
                with self.assertRaises(ValueError):
                    self.validate()
        for digest in (None, "", "d" * 64, "sha256:" + "G" * 64):
            self.api = GitHub()
            self.api.artifact["digest"] = digest
            with self.assertRaises(ValueError):
                self.validate()
        for key, value in (("id", 72), ("head_sha", HEAD), ("head_branch", "development"),
                           ("repository_id", 43), ("head_repository_id", 43)):
            self.api = GitHub()
            self.api.artifact["workflow_run"][key] = value
            with self.assertRaisesRegex(ValueError, "pending artifact"):
                self.validate()


class RecoveryContextTests(unittest.TestCase):
    def setUp(self):
        self.api, self.git = GitHub(), Git()

    def validate(self, env=None, payload=None):
        return recovery.validate_recovery(ROOT, env or environment(), payload or event(),
                                          api=self.api, git_fn=self.git, now=NOW)

    def test_reviewed_current_main_and_distinct_original_source_are_preserved(self):
        self.assertEqual(self.validate(), {"run_id": "71", "artifact_id": "222",
                                         "artifact_digest": "sha256:" + "d" * 64, "version": VERSION})
        self.assertIn(("merge-base", "--is-ancestor", PRODUCER, HEAD), self.git.calls)
        self.assertFalse({"push", "commit", "tag", "checkout", "reset"} & {args[0] for args in self.git.calls})

    def test_unchanged_current_main_can_recover_its_own_separately_pinned_producer(self):
        self.api.run["head_sha"] = HEAD
        self.api.artifact["workflow_run"]["head_sha"] = HEAD
        self.git.changed = []
        self.assertEqual(self.validate(payload=event(producer_sha=HEAD))["version"], VERSION)

    def test_manual_opt_in_repository_ref_and_workflow_identity(self):
        for key, value in (("GITHUB_REPOSITORY", "fork/kingfisher"), ("GITHUB_EVENT_NAME", "push"),
                           ("GITHUB_REF", "refs/tags/python-v1.6.4"), ("GITHUB_WORKFLOW_SHA", PRODUCER),
                           ("GITHUB_WORKFLOW_REF", f"{recovery.UPSTREAM}/.github/workflows/python-sdk.yml@refs/heads/main")):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "upstream current-main"):
                self.validate(env=environment(**{key: value}))
        for updates in ({"publish": False}, {"sdk_only": False}, {"crates_only": "true"},
                        {"publish": "false"}, {"sdk_only": "false"}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.validate(payload=event(**updates))

    def test_pins_checkout_cleanliness_current_main_and_ancestry(self):
        for updates in ({"producer_sha": ""}, {"producer_sha": PRODUCER[:7]},
                        {"expected_sha": PRODUCER}, {"expected_version": "1.6.5"}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.validate(payload=event(**updates))
        for attribute, value in (("head", PRODUCER), ("main", PRODUCER), ("dirty", " M pyproject.toml"),
                                 ("version", "1.6.5")):
            self.git = Git()
            setattr(self.git, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                self.validate()
        for command in ("fetch", "merge-base"):
            self.git = Git()
            self.git.failure = command
            with self.subTest(command=command), self.assertRaises(subprocess.CalledProcessError):
                self.validate()

    def test_no_token_self_producer_and_event_repo_mismatch(self):
        with self.assertRaisesRegex(ValueError, "authentication"):
            self.validate(env=environment(GH_TOKEN=""))
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.validate(env=environment(GITHUB_RUN_ID="71"))
        payload = event()
        payload["repository"]["id"] = 43
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.validate(payload=payload)

    def test_registry_staging_repair_does_not_change_original_sdk_build_inputs(self):
        self.git.changed = ["scripts/publish-crates.py"]
        self.assertEqual(self.validate()["artifact_id"], "222")

    def test_runtime_lock_manifest_and_unapproved_changes_are_never_recovery(self):
        for path in ("src/main.rs", "Cargo.lock", "Cargo.toml", "pyproject.toml", "python/README.md",
                     "python/tests/test_sdk.py", "crates/kingfisher-python/Cargo.toml", "Makefile",
                     "crates/kingfisher-rules/generated/provenance.json", "scripts/build-pypi-wheel.sh",
                     "scripts/release-packages.py",
                     "../docs/PYPI.md", "docs/../pyproject.toml", "docs\\PYPI.md"):
            self.git.changed = [path]
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unapproved package inputs"):
                self.validate()

    def test_deletions_symlinks_and_file_mode_changes_are_not_metadata_repairs(self):
        for current, previous in (("120000", "100644"), ("", "100644"), ("100755", "100644")):
            self.git.mode, self.git.previous_mode = current, previous
            with self.subTest(mode=current), self.assertRaisesRegex(ValueError, "regular files"):
                self.validate()

    def test_matching_independent_cli_python_and_npm_tag_producers(self):
        for tag in ("v2.19.1", "python-v1.6.4", "npm-v1.0.2"):
            self.api = GitHub()
            self.api.run["head_branch"] = tag
            self.api.artifact["workflow_run"]["head_branch"] = tag
            self.assertEqual(self.validate()["version"], VERSION)
        self.api.run["head_branch"] = "npm-v9.9.9"
        self.api.artifact["workflow_run"]["head_branch"] = "npm-v9.9.9"
        with self.assertRaisesRegex(ValueError, "manifest version"):
            self.validate()


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="SDK recovery artifacts ")
        self.addCleanup(self.temporary.cleanup)
        self.dist = Path(self.temporary.name) / "dist"
        self.dist.mkdir()
        self.registry = Mock(return_value={})

    def wheel(self, platform="win_amd64", *, version=VERSION, metadata_version=VERSION,
              metadata_name=recovery.PACKAGE, wheel_tags=None, pure="false", extra_metadata=""):
        prefix = f"{recovery.DIST_NAME}-{version}"
        path = self.dist / f"{prefix}-cp310-abi3-{platform}.whl"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(f"{prefix}.dist-info/METADATA", f"Metadata-Version: 2.4\nName: {metadata_name}\nVersion: {metadata_version}\n{extra_metadata}\n")
            tags = wheel_tags if wheel_tags is not None else [f"cp310-abi3-{tag}" for tag in platform.split(".")]
            archive.writestr(f"{prefix}.dist-info/WHEEL", f"Wheel-Version: 1.0\nRoot-Is-Purelib: {pure}\n" + "".join(f"Tag: {tag}\n" for tag in tags))
            archive.writestr("kingfisher_sdk/_native.pyd", b"never loaded or executed")
        return path

    def sdist(self, *, metadata_version=VERSION, member_name=None):
        prefix = f"{recovery.DIST_NAME}-{VERSION}"
        path = self.dist / f"{prefix}.tar.gz"
        payload = f"Metadata-Version: 2.4\nName: {recovery.PACKAGE}\nVersion: {metadata_version}\n\n".encode()
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo(member_name or f"{prefix}/PKG-INFO")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return path

    def validate(self):
        return recovery.verify_distributions(self.dist, VERSION, registry=self.registry)

    def test_six_native_targets_and_source_validate_without_executing_any_content(self):
        for platform in ("win_amd64", "win_arm64", "manylinux_2_28_x86_64", "manylinux_2_28_aarch64",
                         "macosx_11_0_x86_64", "macosx_11_0_arm64"):
            self.wheel(platform)
        self.sdist()
        digests = self.validate()
        self.assertEqual(len(digests), 7)
        self.registry.assert_called_once_with(VERSION)
        for path in self.dist.iterdir():
            self.assertEqual(digests[path.name], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_partial_staging_is_valid_and_existing_files_must_match_exact_hashes(self):
        path = self.wheel()
        digest = self.validate()[path.name]
        self.registry.return_value = {path.name: digest, "previously-published-other-wheel.whl": "e" * 64}
        self.validate()
        self.registry.return_value[path.name] = "e" * 64
        with self.assertRaisesRegex(ValueError, "immutable PyPI file differs"):
            self.validate()

    def test_wrong_project_version_duplicate_metadata_and_native_tags_are_rejected(self):
        for updates in ({"metadata_name": "kingfisher-bin"}, {"metadata_version": "1.6.5"},
                        {"extra_metadata": f"Name: {recovery.PACKAGE}\n"}, {"pure": "true"},
                        {"wheel_tags": ["cp311-cp311-win_amd64"]}):
            with self.subTest(updates=updates):
                self.wheel(**updates)
                with self.assertRaises(ValueError):
                    self.validate()
        self.registry.assert_not_called()

    def test_wrong_filename_version_architecture_abi_or_extra_artifacts_are_rejected(self):
        for platform in ("linux_x86_64", "musllinux_1_2_x86_64", "macosx_11_0_universal2",
                         "win32", "win_amd64.win_arm64"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                original = self.dist
                self.dist = Path(temporary)
                self.wheel(platform)
                with self.assertRaises(ValueError):
                    self.validate()
                self.dist = original
        self.wheel(version="1.6.5")
        with self.assertRaisesRegex(ValueError, "Unexpected file"):
            self.validate()
        with tempfile.TemporaryDirectory() as temporary:
            self.dist = Path(temporary)
            (self.dist / "attestation.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unexpected file"):
                self.validate()

    def test_no_files_directories_empty_files_and_duplicate_architectures_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "one to seven"):
            self.validate()
        path = self.wheel("manylinux_2_28_x86_64")
        self.wheel("manylinux_2_17_x86_64.manylinux2014_x86_64")
        with self.assertRaisesRegex(ValueError, "duplicate distributions"):
            self.validate()
        with tempfile.TemporaryDirectory() as temporary:
            self.dist = Path(temporary)
            (self.dist / path.name).mkdir()
            with self.assertRaisesRegex(ValueError, "regular files"):
                self.validate()
        with tempfile.TemporaryDirectory() as temporary:
            self.dist = Path(temporary)
            (self.dist / path.name).touch()
            with self.assertRaisesRegex(ValueError, "nonempty regular files"):
                self.validate()

    def test_sdist_requires_exact_matching_regular_pkg_info(self):
        self.sdist(metadata_version="1.6.5")
        with self.assertRaisesRegex(ValueError, "exact SDK project and version"):
            self.validate()
        self.sdist(member_name="different-project/PKG-INFO")
        with self.assertRaisesRegex(ValueError, "missing its exact PKG-INFO"):
            self.validate()
        self.sdist()
        self.assertEqual(len(self.validate()), 1)

    def test_metadata_is_size_bounded(self):
        self.wheel()
        with patch.object(recovery, "MAX_METADATA", 10), self.assertRaisesRegex(ValueError, "size limit"):
            self.validate()

    def test_post_upload_accepts_only_exact_action_generated_attestation_sidecars(self):
        for platform in ("win_amd64", "win_arm64", "manylinux_2_28_x86_64", "manylinux_2_28_aarch64",
                         "macosx_11_0_x86_64", "macosx_11_0_arm64"):
            self.wheel(platform)
        self.sdist()
        hashes = self.validate()
        self.registry.return_value = hashes
        for name in hashes:
            (self.dist / f"{name}.publish.attestation").write_text('{"version": 1}', encoding="utf-8")
        self.assertEqual(recovery.verify_distributions(
            self.dist, VERSION, registry=self.registry, require_published=True), hashes)
        with self.assertRaises(ValueError):
            self.validate()  # Sidecars are forbidden before upload.
        (self.dist / "not-a-tested-distribution.whl.publish.attestation").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "exact regular attestation sidecars"):
            recovery.verify_distributions(self.dist, VERSION, registry=self.registry, require_published=True)


class RegistryAndOutputTests(unittest.TestCase):
    def test_pypi_404_only_means_unused_and_other_errors_are_not_ignored(self):
        for code in (404, 403, 429, 500):
            error = urllib.error.HTTPError("https://pypi.org", code, "failure", {}, None)
            with patch.object(recovery.urllib.request, "urlopen", side_effect=error):
                if code == 404:
                    self.assertEqual(recovery.published_digests(VERSION), {})
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        recovery.published_digests(VERSION)

    def test_pypi_identity_empty_reserved_release_and_digest_schema(self):
        payload = {"info": {"name": recovery.PACKAGE, "version": VERSION},
                   "urls": [{"filename": "sdk.whl", "digests": {"sha256": "d" * 64}}]}
        for value, valid in ((payload, True), ({**payload, "urls": []}, False),
                             ({**payload, "info": {"name": "kingfisher-bin", "version": VERSION}}, False),
                             ({**payload, "urls": payload["urls"] * 2}, False)):
            with patch.object(recovery.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(value).encode())):
                if valid:
                    self.assertEqual(recovery.published_digests(VERSION), {"sdk.whl": "d" * 64})
                else:
                    with self.assertRaises(ValueError):
                        recovery.published_digests(VERSION)

    def test_post_upload_waits_for_visibility_and_verifies_every_original_digest(self):
        digests = {"sdk.whl": "d" * 64, "sdk.tar.gz": "e" * 64}
        registry = Mock(side_effect=[{}, {"sdk.whl": "d" * 64}, digests])
        with patch.object(recovery.time, "sleep") as sleep:
            recovery.verify_registry(digests, VERSION, registry=registry, require_published=True)
        self.assertEqual(registry.call_count, 3)
        self.assertEqual([call.args for call in sleep.call_args_list], [(1,), (2,)])
        registry = Mock(return_value={})
        with patch.object(recovery.time, "sleep"), self.assertRaisesRegex(ValueError, "Not all original artifact files"):
            recovery.verify_registry(digests, VERSION, registry=registry, require_published=True)
        self.assertEqual(registry.call_count, 5)

    def test_racing_conflicting_upload_is_not_hidden_by_skip_existing_or_retries(self):
        registry = Mock(return_value={"sdk.whl": "e" * 64})
        with patch.object(recovery.time, "sleep") as sleep, self.assertRaisesRegex(ValueError, "immutable PyPI file differs"):
            recovery.verify_registry({"sdk.whl": "d" * 64}, VERSION, registry=registry, require_published=True)
        sleep.assert_not_called()
        self.assertEqual(registry.call_count, 1)

    def test_post_upload_retries_only_bounded_transient_registry_errors(self):
        for code in (429, 500, 403):
            error = urllib.error.HTTPError("https://pypi.org", code, "failure", {}, None)
            registry = Mock(side_effect=[error, {"sdk.whl": "d" * 64}])
            with patch.object(recovery.time, "sleep"):
                if code == 403:
                    with self.assertRaises(urllib.error.HTTPError):
                        recovery.verify_registry({"sdk.whl": "d" * 64}, VERSION, registry=registry, require_published=True)
                    self.assertEqual(registry.call_count, 1)
                else:
                    recovery.verify_registry({"sdk.whl": "d" * 64}, VERSION, registry=registry, require_published=True)
                    self.assertEqual(registry.call_count, 2)

    def test_outputs_are_written_only_after_all_validation_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            event_path, output = Path(temporary) / "event.json", Path(temporary) / "outputs"
            event_path.write_text(json.dumps(event()), encoding="utf-8")
            plan = {"run_id": "71", "artifact_id": "222", "artifact_digest": "sha256:" + "d" * 64, "version": VERSION}
            env = environment(GITHUB_EVENT_PATH=str(event_path), GITHUB_OUTPUT=str(output))
            with patch.dict(os.environ, env, clear=True), patch.object(recovery, "validate_recovery", return_value=plan), \
                    patch.object(recovery, "verify_distributions", side_effect=ValueError("bad distribution")):
                with self.assertRaisesRegex(ValueError, "bad distribution"):
                    recovery.main(["--dist", temporary])
                self.assertFalse(output.exists())
            with patch.dict(os.environ, env, clear=True), patch.object(recovery, "validate_recovery", return_value=plan), \
                    patch("builtins.print"):
                self.assertEqual(recovery.main([]), 0)
            self.assertIn("artifact_id=222\n", output.read_text(encoding="utf-8"))
            self.assertNotIn("producer_ref", output.read_text(encoding="utf-8"))


class RealGitRecoveryTests(unittest.TestCase):
    def test_real_git_requires_ancestor_current_main_clean_checkout_and_config_only_drift(self):
        with tempfile.TemporaryDirectory(prefix="SDK recovery git ") as temporary, patch.dict(os.environ, {
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_COUNT": "0"}):
            root = Path(temporary) / "source checkout"
            root.mkdir()
            def git(*args):
                return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                                      text=True, encoding="utf-8").stdout.strip()
            git("init", "-b", "main")
            for key, value in (("user.name", "SDK Recovery Test"), ("user.email", "test@example.com"),
                               ("commit.gpgsign", "false"), ("tag.gpgsign", "false"), ("core.autocrlf", "false")):
                git("config", key, value)
            manifest = root / "crates/kingfisher-python/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(f'[package]\nname = "kingfisher-python"\nversion = "{VERSION}"\n', encoding="utf-8")
            guide = root / "docs/PYPI.md"
            guide.parent.mkdir()
            guide.write_text("Original publishing guidance\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-m", "Original tested source")
            producer = git("rev-parse", "HEAD")
            guide.write_text("Corrected publishing guidance\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-m", "Publishing-only correction")
            head = git("rev-parse", "HEAD")
            remote = Path(temporary) / "upstream repository.git"
            git("clone", "--bare", root.as_posix(), remote.as_posix())
            git("remote", "add", "origin", remote.as_posix())
            api = GitHub()
            api.run["head_sha"] = producer
            api.artifact["workflow_run"]["head_sha"] = producer
            env = environment(GITHUB_SHA=head, GITHUB_WORKFLOW_SHA=head)
            payload = event(producer_sha=producer, expected_sha=head)
            validate = lambda: recovery.validate_recovery(root, env, payload, api=api, now=NOW)
            self.assertEqual(validate()["version"], VERSION)
            (root / "untracked-distributions").mkdir()
            self.assertEqual(validate()["version"], VERSION)
            guide.write_text("Uncommitted change\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unchanged checkout"):
                validate()
            git("checkout", "--", "docs/PYPI.md")
            runtime = root / "runtime.rs"
            runtime.write_text("// New runtime source is not a publication-only correction\n", encoding="utf-8")
            git("add", "runtime.rs")
            git("commit", "-m", "Runtime drift")
            git("push", "origin", "main")
            with self.assertRaisesRegex(ValueError, "unchanged checkout"):
                validate()
            new_head = git("rev-parse", "HEAD")
            env.update(GITHUB_SHA=new_head, GITHUB_WORKFLOW_SHA=new_head)
            payload["inputs"]["expected_sha"] = new_head
            with self.assertRaisesRegex(ValueError, "unapproved package inputs"):
                validate()
            git("checkout", "--detach", head)
            env.update(GITHUB_SHA=head, GITHUB_WORKFLOW_SHA=head)
            payload["inputs"]["expected_sha"] = head
            with self.assertRaisesRegex(ValueError, "no longer the current upstream main"):
                validate()


if __name__ == "__main__":
    unittest.main()
