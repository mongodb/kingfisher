"""Exercise registry-only recovery with local Git and mocked, read-only GitHub calls."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("crates_recovery", ROOT / "scripts/check-crates-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "recovery tree"
        self.root.mkdir()
        self.empty_git = Path(self.temporary.name) / "empty git configuration"
        self.empty_git.mkdir()
        self.git("init", "-b", "main")
        for key, value in (("user.name", "Recovery Test"), ("user.email", "recovery@example.com"),
                           ("commit.gpgsign", "false"), ("tag.gpgsign", "false"), ("core.autocrlf", "false")):
            self.git("config", key, value)
        self.write("crates/kingfisher-core/src/encoding.rs", "// released implementation\n")
        self.write("README.md", "Release documentation\n")
        self.write_metadata("1.0.3")
        self.commit()
        self.base = self.git("rev-parse", "HEAD")
        self.git("tag", "v2.14.0")
        self.write_metadata("1.0.4")
        self.commit()
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.repo = {"full_name": recovery.REPOSITORY, "private": False}
        self.release = {"tag_name": "v2.14.0", "target_commitish": self.base,
                        "draft": False, "prerelease": False, "published_at": "2026-10-20T02:05:43Z"}
        self.run = {"repository": self.repo, "path": ".github/workflows/release.yml",
                    "head_sha": self.base, "head_branch": "v2.14.0", "status": "completed",
                    "event": "push", "conclusion": "failure"}
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                     for name in sorted(recovery.REQUIRED_JOBS | {"tests / Stable API"})]
        self.jobs.append({"name": "Publish crates.io packages", "status": "completed", "conclusion": "failure"})
        self.calls = []

    def git(self, *args):
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.check_output(["git", "-c", f"core.hooksPath={self.empty_git}",
                                        "-c", f"init.templateDir={self.empty_git}", *args],
                                       cwd=self.root, stderr=subprocess.PIPE, env=env).decode().strip()

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8", newline="\n")

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-m", "Fixture metadata")

    def write_metadata(self, version):
        self.write(recovery.CORE, f'[package]\nname = "kingfisher-core"\nversion = "{version}"\n')
        for path in recovery.DEPENDENTS:
            name = {"Cargo.toml": "kingfisher-bin", recovery.DEPENDENTS[1]: "kingfisher-rules",
                    recovery.DEPENDENTS[2]: "kingfisher-scanner"}[path]
            package_version = "2.14.0" if name == "kingfisher-bin" else "2.0.0"
            self.write(path, f'[package]\nname = "{name}"\nversion = "{package_version}"\n'
                       f'[dependencies]\nkingfisher-core = {{version = "{version}", path = "core"}}\n'
                       '[features]\ndefault = []\n')
        self.write(recovery.SDK, '[package]\nname = "kingfisher-python"\nversion = "1.4.0"\n'
                   '[dependencies]\npyo3 = "0.29"\n')
        self.write("Cargo.lock", 'version = 4\n[[package]]\nname = "kingfisher-core"\n'
                   f'version = "{version}"\n[[package]]\nname = "kingfisher-python"\nversion = "1.4.0"\n'
                   '[[package]]\nname = "dependency"\nversion = "1.0.0"\n'
                   'source = "registry+https://example.com"\nchecksum = "unchanged"\n')
        self.regenerate_provenance()

    def regenerate_provenance(self):
        provenance = {"generator_input_sha256": {
            path: hashlib.sha256((self.root / path).read_bytes()).hexdigest()
            for path in recovery.PROVENANCE_INPUTS},
            "artifact_sha256": {"builtin-rules.gz": "unchanged"}, "rules": {"unchanged": True}}
        self.write(recovery.PROVENANCE, json.dumps(provenance))

    def api(self, path, token):
        self.calls.append(path)
        prefix = f"/repos/{recovery.REPOSITORY}"
        responses = {prefix: self.repo, f"{prefix}/releases/tags/v2.14.0": self.release,
                     f"{prefix}/actions/runs/123": self.run}
        if "/jobs?" in path:
            page = int(path.rsplit("page=", 1)[1])
            return {"jobs": copy.deepcopy(self.jobs[(page - 1) * 100:page * 100])}
        return copy.deepcopy(responses[path])

    def validate(self, **kwargs):
        args = {"repository": recovery.REPOSITORY, "ref": "refs/heads/main",
                "event": "workflow_dispatch", "sha": self.git("rev-parse", "HEAD"),
                "run_id": "123", "token": "fixture-token", "api": self.api,
                "expected_sha": self.git("rev-parse", "HEAD")}
        args.update(kwargs)
        return recovery.validate_recovery(self.root, **args)

    def test_metadata_only_recovery_accepts_failed_downstream_run(self):
        self.write("README.md", "Updated crate version documentation\n")
        self.commit()
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.assertEqual(self.validate(), "v2.14.0")
        self.assertEqual(self.git("rev-parse", "v2.14.0"), self.base)

    def sdk_version_change(self, version="1.5.0", lock_version=None):
        self.write(recovery.SDK, (self.root / recovery.SDK).read_text(encoding="utf-8").replace("1.4.0", version))
        lock = (self.root / "Cargo.lock").read_text(encoding="utf-8")
        self.write("Cargo.lock", lock.replace('name = "kingfisher-python"\nversion = "1.4.0"',
                                              f'name = "kingfisher-python"\nversion = "{lock_version or version}"'))
        self.regenerate_provenance()
        self.commit()

    def test_accepts_optional_sdk_version_change_and_matching_lock_entry(self):
        self.sdk_version_change()
        recovery.check_metadata(self.root, self.base)

    def test_rejects_sdk_lock_mismatch(self):
        self.sdk_version_change(lock_version="1.4.0")
        with self.assertRaisesRegex(ValueError, "matching workspace SDK"):
            recovery.check_metadata(self.root, self.base)

    def test_rejects_sdk_version_drift_beyond_exact_optional_correction(self):
        for version in ("1.4.1", "1.4.2", "1.5.1", "1.6.0", "2.0.0", "1.5.0-rc.1"):
            with self.subTest(version=version):
                self.write_metadata("1.0.4")
                self.sdk_version_change(version)
                with self.assertRaisesRegex(ValueError, "SDK metadata version correction"):
                    recovery.check_metadata(self.root, self.base)

    def test_rejects_other_sdk_manifest_and_lock_fields(self):
        self.sdk_version_change()
        path = recovery.SDK
        self.write(path, (self.root / path).read_text(encoding="utf-8").replace('pyo3 = "0.29"', 'pyo3 = "0.30"'))
        self.commit()
        with self.assertRaisesRegex(ValueError, "SDK manifest fields"):
            recovery.check_metadata(self.root, self.base)
        self.write_metadata("1.0.4")
        self.sdk_version_change()
        lock = (self.root / "Cargo.lock").read_text(encoding="utf-8")
        self.write("Cargo.lock", lock.replace('name = "kingfisher-python"', 'dependencies = ["injected"]\nname = "kingfisher-python"'))
        self.regenerate_provenance()
        self.commit()
        with self.assertRaisesRegex(ValueError, "unrelated lockfile"):
            recovery.check_metadata(self.root, self.base)

    def test_release_maintenance_allowlist_is_explicit(self):
        for path in ("Makefile", "scripts/release-packages.py", "scripts/check-sdk-release.py",
                     "scripts/tests/test_release_packages.py", "scripts/tests/test_release_makefile.py",
                     "scripts/tests/test_sdk_preflight.py", "scripts/tests/test_python_sdk_release.py",
                     ".github/workflows/python-sdk.yml", "docs/PYPI.md", "python/README.md",
                     "docs-site/docs/reference/python-bindings.md"):
            self.write(path, "reviewed release maintenance\n")
        self.commit()
        recovery.check_metadata(self.root, self.base)
        self.write("python/kingfisher_sdk/__init__.py", "runtime change\n")
        self.commit()
        with self.assertRaisesRegex(ValueError, "runtime or unapproved"):
            recovery.check_metadata(self.root, self.base)

    def test_rejects_missing_invalid_or_stale_expected_main_sha(self):
        for expected in ("", "main", self.base, "0" * 40):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, "expected_sha"):
                self.validate(expected_sha=expected)
        self.assertEqual(self.calls, [])

    def test_rejects_wrong_repository_ref_event_or_checkout(self):
        for args in ({"repository": "private/kingfisher"}, {"ref": "refs/tags/v2.14.0"},
                     {"ref": "refs/heads/topic"}, {"event": "push"}, {"sha": self.base}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.validate(**args)
        self.assertEqual(self.calls, [])

    def test_rejects_unmerged_commit(self):
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        with self.assertRaises(subprocess.CalledProcessError):
            self.validate()
        self.assertEqual(self.calls, [])

    def test_rejects_dirty_checkout(self):
        self.write("README.md", "uncommitted\n")
        with self.assertRaisesRegex(ValueError, "clean checkout"):
            self.validate()

    def test_rejects_runtime_source_change(self):
        self.write("crates/kingfisher-core/src/encoding.rs", "// changed implementation\n")
        self.commit()
        with self.assertRaisesRegex(ValueError, "runtime or unapproved"):
            recovery.check_metadata(self.root, self.base)

    def test_rejects_example_viewer_bundle_and_build_changes(self):
        for path in ("examples/example.rs", "docs/viewer/index.html", "build.rs",
                     "crates/kingfisher-rules/generated/builtin-rules.gz"):
            with self.subTest(path=path):
                self.write(path, "changed\n")
                self.commit()
                with self.assertRaisesRegex(ValueError, "runtime or unapproved"):
                    recovery.check_metadata(self.root, self.base)

    def test_rejects_manifest_feature_or_unrelated_dependency_change(self):
        for path in (recovery.CORE, *recovery.DEPENDENTS):
            with self.subTest(path=path):
                self.write_metadata("1.0.4")
                original = (self.root / path).read_text(encoding="utf-8")
                self.write(path, original + '\n[build-dependencies]\nnew-dependency = "1"\n')
                self.regenerate_provenance()
                self.commit()
                with self.assertRaisesRegex(ValueError, "manifest|core version"):
                    recovery.check_metadata(self.root, self.base)

    def test_rejects_missing_minimum_requirement(self):
        path = recovery.DEPENDENTS[1]
        self.write(path, (self.root / path).read_text(encoding="utf-8").replace("1.0.4", "1.0.3"))
        self.commit()
        with self.assertRaisesRegex(ValueError, "minimum requirement"):
            recovery.check_metadata(self.root, self.base)

    def test_rejects_non_patch_or_unchanged_core_version(self):
        for version in ("1.0.3", "1.0.5", "1.1.0", "2.0.0", "1.0.4-rc.1"):
            with self.subTest(version=version):
                self.write_metadata(version)
                self.commit()
                with self.assertRaisesRegex(ValueError, "patch"):
                    recovery.check_metadata(self.root, self.base)

    def test_rejects_lockfile_dependency_or_checksum_drift(self):
        lock = (self.root / "Cargo.lock").read_text(encoding="utf-8")
        for changed in (lock.replace('checksum = "unchanged"', 'checksum = "changed"'),
                        lock.replace('version = "1.0.0"', 'version = "1.0.1"')):
            with self.subTest(lock=changed):
                self.write("Cargo.lock", changed)
                self.regenerate_provenance()
                self.commit()
                with self.assertRaisesRegex(ValueError, "lockfile dependencies"):
                    recovery.check_metadata(self.root, self.base)

    def test_rejects_stale_or_unrelated_provenance_changes(self):
        original = json.loads((self.root / recovery.PROVENANCE).read_text(encoding="utf-8"))
        for field in ("input", "artifact"):
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                if field == "input":
                    changed["generator_input_sha256"]["Cargo.toml"] = "stale"
                else:
                    changed["artifact_sha256"]["builtin-rules.gz"] = "changed"
                self.write(recovery.PROVENANCE, json.dumps(changed))
                self.commit()
                with self.assertRaisesRegex(ValueError, "provenance"):
                    recovery.check_metadata(self.root, self.base)

    def test_rejects_private_or_wrong_public_repository(self):
        for key, value in (("private", True), ("full_name", "fork/kingfisher")):
            with self.subTest(key=key):
                original = copy.deepcopy(self.repo)
                self.repo[key] = value
                with self.assertRaisesRegex(ValueError, "public mongodb/kingfisher"):
                    recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "", self.api)
                self.repo = original

    def test_rejects_missing_draft_prerelease_or_mismatched_release(self):
        for key, value in (("draft", True), ("prerelease", True), ("published_at", None),
                           ("target_commitish", "main"), ("tag_name", "v2.13.0")):
            with self.subTest(key=key):
                original = copy.deepcopy(self.release)
                self.release[key] = value
                with self.assertRaisesRegex(ValueError, "existing public stable release"):
                    recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "", self.api)
                self.release = original
        error = urllib.error.HTTPError("https://api.github.com", 404, "not found", {}, None)
        self.addCleanup(error.close)
        with self.assertRaises(urllib.error.HTTPError):
            recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "",
                                  api=lambda *args: (_ for _ in ()).throw(error))

    def test_rejects_wrong_original_workflow_commit_tag_or_status(self):
        for key, value in (("path", ".github/workflows/other.yml"), ("head_sha", "wrong"),
                           ("head_branch", "main"), ("status", "in_progress"), ("event", "pull_request"),
                           ("repository", {"full_name": "fork/kingfisher"})):
            with self.subTest(key=key):
                original = copy.deepcopy(self.run)
                self.run[key] = value
                with self.assertRaisesRegex(ValueError, "Original release run"):
                    recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "", self.api)
                self.run = original

    def test_rejects_missing_or_non_green_public_release_job(self):
        for jobs in ([], [{"name": "Public GitHub Release", "status": "completed", "conclusion": "failure"}],
                     [{"name": "Public GitHub Release", "status": "completed", "conclusion": "skipped"}],
                     [{"name": "Public GitHub Release", "status": "in_progress", "conclusion": None}]):
            with self.subTest(jobs=jobs):
                self.jobs = jobs
                with self.assertRaisesRegex(ValueError, "must have succeeded"):
                    recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "", self.api)

    def test_rejects_missing_or_failed_prerequisites_even_with_green_release_job(self):
        original = copy.deepcopy(self.jobs)
        for name in sorted(recovery.REQUIRED_JOBS):
            with self.subTest(missing=name):
                self.jobs = [job for job in copy.deepcopy(original) if job["name"] != name]
                with self.assertRaisesRegex(ValueError, "must have succeeded"):
                    recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "", self.api)
        for name in sorted(recovery.REQUIRED_JOBS | {"tests / Stable API"}):
            with self.subTest(failed=name):
                self.jobs = copy.deepcopy(original)
                next(job for job in self.jobs if job["name"] == name)["conclusion"] = "failure"
                with self.assertRaisesRegex(ValueError, "must have succeeded"):
                    recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "", self.api)

    def test_rejects_manifest_feature_change(self):
        path = "Cargo.toml"
        original = (self.root / path).read_text(encoding="utf-8")
        self.write(path, original.replace("default = []", 'default = ["new-feature"]'))
        self.regenerate_provenance()
        self.commit()
        with self.assertRaisesRegex(ValueError, "unrelated manifest fields"):
            recovery.check_metadata(self.root, self.base)

    def test_requires_numeric_original_run_id(self):
        for run_id in ("", "0", "-1", "123/../jobs", "123\n"):
            with self.subTest(run_id=run_id), self.assertRaisesRegex(ValueError, "release-run-id"):
                recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, run_id, "", self.api)
        self.assertEqual(self.calls, [])

    def test_follows_job_pagination(self):
        self.jobs = [{"name": "other", "status": "completed", "conclusion": "success"}] * 100 + self.jobs
        recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "", self.api)
        self.assertTrue(any(path.endswith("page=2") for path in self.calls))

    def test_lookup_errors_are_not_treated_as_missing_or_successful(self):
        for status in (403, 404, 500):
            error = urllib.error.HTTPError("https://api.github.com", status, "error", {}, None)
            self.addCleanup(error.close)
            with self.subTest(status=status), self.assertRaises(urllib.error.HTTPError):
                recovery.check_github(recovery.REPOSITORY, "v2.14.0", self.base, "123", "",
                                      api=lambda *args: (_ for _ in ()).throw(error))


class RecoveryWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    def job(self, name, following=None):
        result = self.workflow.split(f"  {name}:\n", 1)[1]
        return result.split(f"  {following}:\n", 1)[0] if following else result

    def test_normal_tag_guards_remain_default_and_recovery_is_separate(self):
        self.assertIn("type: boolean\n        default: false", self.workflow)
        normal = self.job("validate-release", "validate-crates-recovery")
        self.assertIn("if: ${{ !inputs.crates_only }}", normal)
        self.assertIn('git merge-base --is-ancestor "$GITHUB_SHA" origin/main', normal)
        self.assertIn('os.environ["GITHUB_REF"] != f"refs/tags/{tag}"', normal)
        self.assertIn("scripts/check-release-target.py", normal)
        recovery_job = self.job("validate-crates-recovery", "tests")
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.crates_only", recovery_job)
        self.assertIn("ref: ${{ github.sha }}", recovery_job)
        self.assertIn("tag: ${{ steps.recovery.outputs.tag }}", recovery_job)
        self.assertIn("EXPECTED_SHA: ${{ inputs.expected_sha }}", recovery_job)
        self.assertIn("      expected_sha:", self.workflow)
        self.assertLess(recovery_job.index("scripts/check-crates-recovery.py"),
                        self.workflow.index("      - name: Test libraries for registry-only recovery"))
        self.assertIn('run: python3 scripts/check-crates-recovery.py --release-run-id "$RELEASE_RUN_ID"', recovery_job)
        self.assertNotIn("${{ inputs.release_run_id }}", recovery_job.split("        run:", 1)[1])

    def test_full_builds_and_release_remain_behind_normal_validation(self):
        for name, following in (("tests", "linux-x64"), ("linux-x64", "linux-arm64"),
                                ("linux-arm64", "macos-x64"), ("macos-x64", "macos-arm64"),
                                ("macos-arm64", "windows"), ("windows", "release")):
            with self.subTest(job=name):
                self.assertIn("needs: [validate-release]", self.job(name, following))
        release_job = self.job("release", "publish-docker")
        self.assertIn("needs: [validate-release, tests, linux-x64, linux-arm64, windows, macos-x64, macos-arm64]", release_job)
        self.assertIn("skipIfReleaseExists: true", release_job)
        for name, following in (("publish-docker", "publish-pypi"), ("publish-pypi", "publish-crates")):
            self.assertIn("needs: [release]", self.job(name, following))

    def test_publication_requires_successful_explicit_path_and_keeps_auth_order(self):
        publish = self.job("publish-crates")
        self.assertIn("needs: [release, validate-crates-recovery]", publish)
        self.assertIn("always() && !cancelled() && github.repository == 'mongodb/kingfisher'", publish)
        self.assertIn("!inputs.crates_only && needs.release.result == 'success'", publish)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.crates_only &&", publish)
        self.assertIn("needs.validate-crates-recovery.result == 'success'", publish)
        self.assertIn("environment: crates-io", publish)
        self.assertIn("group: crates-io-publish\n      cancel-in-progress: false", publish)
        self.assertIn("needs.release.outputs.tag || needs.validate-crates-recovery.outputs.tag", publish)
        self.assertIn('if: ${{ !inputs.crates_only }}\n        run: test "$(git rev-parse "refs/tags/$RELEASE_TAG^{commit}")" = "$(git rev-parse HEAD)"', publish)
        self.assertIn("cargo test --locked -p kingfisher-core -p kingfisher-rules -p kingfisher-scanner", publish)
        for command in ("cargo run --locked -p kingfisher-rule-bundle -- --check", "cargo package --locked",
                        "scripts/check-crates-recovery.py", 'scripts/publish-crates.py --tag "$RELEASE_TAG"'):
            with self.subTest(command=command):
                self.assertLess(publish.index(command), publish.index("Select bootstrap-token"))
        self.assertNotIn("--no-verify", publish)
        self.assertNotIn("--allow-dirty", publish)
        self.assertEqual(publish.count("if: steps.plan.outputs.pending == 'true'"), 3)


if __name__ == "__main__":
    unittest.main()
