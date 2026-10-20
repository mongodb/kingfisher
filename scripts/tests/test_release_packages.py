"""Guard launcher behavior using isolated Git fixtures and mocked remote services.

No GitHub/registry writes or host Git hooks are used. Cargo's output is modeled as
fresh archives; the production immutable-package planner still checks them.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_packages", ROOT / "scripts/release-packages.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def archive(name, version, source=b"unchanged runtime"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for path, data in {"Cargo.toml": f'[package]\nname = "{name}"\nversion = "{version}"\n'.encode(),
                           "src/lib.rs": source}.items():
            member = tarfile.TarInfo(f"{name}-{version}/{path}")
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return output.getvalue()


class PackageLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.empty_git = self.directory / "empty Git configuration"
        self.empty_git.mkdir()
        self.root = self.directory / "working tree"
        self.root.mkdir()
        self.remote = self.directory / "remote repository.git"
        self.environment = patch.dict(os.environ, {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                                                 "GIT_CONFIG_COUNT": "0"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.git("init", "-b", "main")
        for key, value in (("user.name", "Package Release Test"), ("user.email", "release@example.com"),
                           ("commit.gpgsign", "false"), ("tag.gpgsign", "false"), ("core.autocrlf", "false")):
            self.git("config", key, value)
        self.write_metadata("1.0.3", "1.4.0")
        for workflow, inputs in (("release.yml", ("crates_only", "release_run_id", "expected_sha")),
                                 ("python-sdk.yml", ("publish", "expected_sha", "expected_version"))):
            text = "name: Release fixture\non:\n  workflow_dispatch:\n    inputs:\n"
            for name in inputs:
                text += f"      {name}:\n        type: string\n"
            self.write(f".github/workflows/{workflow}", text + "# ── release metadata — café 🐟\njobs: {}\n")
        self.write("README.md", "release fixture\n")
        self.write(".gitignore", "target/\n")
        self.commit()
        self.base = self.git("rev-parse", "HEAD")
        self.git("tag", "-a", "v2.14.0", "-m", "Public stable CLI")
        self.git("init", "--bare", self.remote.as_posix())
        self.git("remote", "add", "origin", "https://github.com/mongodb/kingfisher.git")
        self.git("push", self.remote.as_posix(), "main", "refs/tags/v2.14.0")
        self.write_metadata("1.0.4", "1.5.0")
        self.commit()
        self.push_main()
        self.repo = {"full_name": launcher.REPOSITORY, "private": False, "fork": False,
                     "default_branch": "main", "permissions": {"push": True}}
        self.jobs = [{"id": index + 1, "name": name, "status": "completed", "conclusion": "success"}
                     for index, name in enumerate(sorted(launcher.recovery.REQUIRED_JOBS))]
        self.jobs += [{"id": 999, "name": launcher.CRATES_JOB, "status": "completed", "conclusion": "failure"}]
        self.run = {"id": 123, "repository": self.repo, "path": ".github/workflows/release.yml",
                    "head_sha": self.base, "head_branch": "v2.14.0", "status": "completed", "event": "push"}
        self.run_candidates = [self.run]
        self.published = {}
        self.remote_crates = {}
        self.package_sources = {}
        self.api_calls = []
        self.commands = []
        self.actions = []
        self.sdk_checks = []
        self.cargo_commands = []
        self.fail_api = set()
        self.inactive = set()
        self.sdk_error = None
        self.sdk_result = None
        self.auth_error = None
        self.package_error = None
        self.after_sdk_check = None
        self.after_package = None
        self.main_override = None
        self.package_dirs = []
        self.real_command = launcher.command
        self.addCleanup(patch.stopall)
        patch.object(launcher, "command", side_effect=self.command).start()
        patch.object(launcher.shutil, "which", return_value="mock-gh").start()
        patch.object(launcher.publisher, "published_version", side_effect=self.published_version).start()
        patch.object(launcher.publisher, "fetch", side_effect=self.download).start()
        patch("builtins.print").start()

    def git(self, *args):
        return subprocess.check_output(["git", "-c", f"core.hooksPath={self.empty_git}",
                                        "-c", f"init.templateDir={self.empty_git}", *args],
                                       cwd=self.root, stderr=subprocess.PIPE).decode().strip()

    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8", newline="\n")

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-m", "Release metadata fixture")

    def push_main(self):
        self.git("push", self.remote.as_posix(), "HEAD:refs/heads/main")

    def write_metadata(self, core, sdk):
        versions = {"kingfisher-core": core, "kingfisher-rules": "2.0.0",
                    "kingfisher-scanner": "2.0.0", "kingfisher-bin": "2.14.0"}
        for name, path in launcher.MANIFESTS.items():
            prefix = '[workspace.package]\npublish = ["crates-io"]\n' if name == "kingfisher-bin" else ""
            dependency = (f'[dependencies]\nkingfisher-core = {{version = "{core}", path = "core"}}\n'
                          if name != "kingfisher-core" else "")
            self.write(path, prefix + f'[package]\nname = "{name}"\nversion = "{versions[name]}"\n'
                       'publish.workspace = true\n' + dependency)
        self.write(launcher.SDK_MANIFEST, '[package]\nname = "kingfisher-python"\n'
                   f'version = "{sdk}"\npublish = false\n')
        self.write("Cargo.lock", "version = 4\n" + "".join(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
            for name, version in {**versions, "kingfisher-python": sdk}.items()))
        self.write("pyproject.toml", '[project]\nname = "kingfisher-secret-scanner"\ndynamic = ["version"]\n'
                   f'[tool.maturin]\nmanifest-path = "{launcher.SDK_MANIFEST}"\n')
        self.provenance()

    def provenance(self):
        self.write(launcher.recovery.PROVENANCE, json.dumps({"generator_input_sha256": {
            path: hashlib.sha256((self.root / path).read_bytes()).hexdigest()
            for path in launcher.recovery.PROVENANCE_INPUTS}, "bundle": "unchanged"}))

    def published_version(self, name, version):
        return self.published.get(name)

    def publish_existing(self, name, version=None, source=b"unchanged runtime"):
        version = version or self.inferred()[name]
        data = archive(name, version, source)
        self.published[name] = {"checksum": hashlib.sha256(data).hexdigest()}
        self.remote_crates[name] = data

    def download(self, url):
        self.assertTrue(url.startswith("https://static.crates.io/crates/"))
        return self.remote_crates[url.split("/")[-2]]

    def inferred(self):
        return launcher.versions(self.root, self.git("rev-parse", "HEAD"))

    def api(self, path):
        self.api_calls.append(path)
        if path in self.fail_api:
            raise launcher.CommandError("mock GitHub network/permission failure")
        if path == "":
            return self.repo
        if path == "/commits/main":
            return {"sha": self.main_override or self.git("--git-dir", self.remote.as_posix(), "rev-parse", "refs/heads/main")}
        if path.startswith("/actions/workflows/") and "/runs?" not in path:
            workflow = path.rsplit("/", 1)[1]
            return {"state": "disabled_manually" if workflow in self.inactive else "active",
                    "path": f".github/workflows/{workflow}"}
        if path.startswith("/contents/"):
            file, sha = path.removeprefix("/contents/").split("?ref=")
            data = self.git("show", f"{sha}:{file}") + "\n"
            return {"encoding": "base64", "content": base64.b64encode(data.encode()).decode()}
        if path == "/releases/tags/v2.14.0":
            return {"tag_name": "v2.14.0", "target_commitish": self.base, "draft": False,
                    "prerelease": False, "published_at": "2026-10-20T02:05:43Z"}
        if "/actions/workflows/release.yml/runs?" in path:
            return {"workflow_runs": self.run_candidates if path.endswith("page=1") else []}
        if path == "/actions/runs/123":
            return self.run
        if path.startswith("/actions/runs/123/jobs?"):
            page = int(path.rsplit("page=", 1)[1])
            return {"jobs": self.jobs[(page - 1) * 100:page * 100]}
        raise AssertionError(f"Unexpected read-only API path: {path}")

    def command(self, args, root, *, check=True):
        self.commands.append(args)
        if args[0] == "git":
            args = list(args)
            if args[1] in {"fetch", "ls-remote"}:
                args = [self.remote.as_posix() if arg == "origin" else arg for arg in args]
            args = ["git", "-c", f"core.hooksPath={self.empty_git}", "-c", f"init.templateDir={self.empty_git}", *args[1:]]
            return self.real_command(args, root, check=check)
        if args[:2] == ["gh", "auth"]:
            if self.auth_error:
                raise self.auth_error
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ["gh", "api"]:
            prefix = f"repos/{launcher.REPOSITORY}"
            self.assertTrue(args[-1].startswith(prefix))
            return subprocess.CompletedProcess(args, 0, json.dumps(self.api(args[-1][len(prefix):])), "")
        if args[:3] in (["gh", "workflow", "run"], ["gh", "run", "rerun"]):
            self.actions.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == [sys.executable, "scripts/check-sdk-release.py"]:
            self.sdk_checks.append(args)
            if self.sdk_error:
                raise self.sdk_error
            if self.after_sdk_check:
                self.after_sdk_check()
            return self.sdk_result or subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "cargo":
            self.cargo_commands.append(args)
            versions = self.inferred()
            if args[1] == "metadata":
                packages = [{"name": name, "version": version, "source": None,
                             "publish": ["crates-io"],
                             "manifest_path": str(self.root / (launcher.SDK_MANIFEST if name == "kingfisher-python" else launcher.MANIFESTS[name]))}
                            for name, version in versions.items()]
                return subprocess.CompletedProcess(args, 0, json.dumps({"packages": packages}), "")
            if args[1] == "package":
                if self.package_error:
                    raise self.package_error
                directory = Path(args[args.index("--target-dir") + 1])
                self.assertEqual(list(directory.iterdir()), [])
                self.package_dirs.append(directory)
                package_dir = directory / "package"
                package_dir.mkdir()
                for name in launcher.publisher.PACKAGES:
                    (package_dir / f"{name}-{versions[name]}.crate").write_bytes(
                        archive(name, versions[name], self.package_sources.get(name, b"unchanged runtime")))
                if self.after_package:
                    self.after_package()
                return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"Unexpected command (no remote mutation permitted): {args}")

    def release(self, package="crates"):
        launcher.release(package, root=self.root)

    def test_sdk_new_version_dispatches_exact_committed_version_and_sha(self):
        sha = self.git("rev-parse", "HEAD")
        self.release("kingfisher-secret-scanner")
        self.assertEqual(self.sdk_checks, [[sys.executable, "scripts/check-sdk-release.py", "--require-new",
                                          "--expected-version", "1.5.0"]])
        self.assertEqual(self.actions, [["gh", "workflow", "run", "python-sdk.yml", "--repo", launcher.REPOSITORY,
                                        "--ref", "main", "-f", "publish=true", "-f", f"expected_sha={sha}",
                                        "-f", "expected_version=1.5.0"]])
        self.assertEqual(self.git("rev-parse", "v2.14.0^{commit}"), self.base)
        self.assertEqual(self.cargo_commands, [])

    def test_sdk_existing_version_or_bad_registry_network_stops_before_dispatch(self):
        for error in (ValueError("SDK version already exists"), urllib.error.URLError("registry unavailable")):
            with self.subTest(error=error):
                self.sdk_error = error
                with self.assertRaises((ValueError, urllib.error.URLError)):
                    self.release("kingfisher-secret-scanner")
                self.assertEqual(self.actions, [])

    def test_existing_sdk_subprocess_diagnostic_is_actionable_and_sanitized(self):
        self.sdk_result = subprocess.CompletedProcess([], 1, "",
            "SDK release preflight failed: SDK 1.5.0 already exists on PyPI; bump SDK version\n"
            "token=do-not-leak")
        with self.assertRaisesRegex(ValueError, "SDK 1.5.0 already exists on PyPI; bump SDK version") as error:
            self.release("kingfisher-secret-scanner")
        self.assertNotIn("do-not-leak", str(error.exception))
        self.assertEqual(self.actions, [])

    def test_sdk_preflight_network_diagnostics_are_not_exposed(self):
        self.sdk_result = subprocess.CompletedProcess([], 1, "", "https://private:token@example.com failed")
        with self.assertRaisesRegex(ValueError, "cannot verify a new PyPI version/source") as error:
            self.release("kingfisher-secret-scanner")
        self.assertNotIn("private:token", str(error.exception))
        self.assertEqual(self.actions, [])

    def test_cargo_package_failure_stops_before_any_remote_action(self):
        self.package_error = launcher.CommandError("cargo package failed")
        with self.assertRaisesRegex(launcher.CommandError, "cargo package failed"):
            self.release()
        self.assertEqual(self.actions, [])

    def test_crates_infers_versions_and_automatically_dispatches_pinned_recovery(self):
        sha = self.git("rev-parse", "HEAD")
        self.release()
        self.assertEqual(self.actions, [["gh", "workflow", "run", "release.yml", "--repo", launcher.REPOSITORY,
                                        "--ref", "main", "-f", "crates_only=true", "-f", "release_run_id=123",
                                        "-f", f"expected_sha={sha}"]])
        lookups = [path for path in self.api_calls if "/actions/workflows/release.yml/runs?" in path]
        self.assertTrue(lookups)
        self.assertIn(f"head_sha={self.base}&branch=v2.14.0", lookups[0])
        package = next(args for args in self.cargo_commands if args[1] == "package")
        self.assertIn("--locked", package)
        self.assertIn("--no-verify", package)
        self.assertNotIn("--allow-dirty", package)
        self.assertEqual(tuple(package[index + 1] for index, arg in enumerate(package) if arg == "-p"), launcher.publisher.PACKAGES)
        self.assertTrue(all(not path.exists() for path in self.package_dirs))

    def test_original_tested_commit_reruns_only_existing_failed_crates_job(self):
        self.git("checkout", "--detach", self.base)
        self.git("push", self.remote.as_posix(), f"{self.base}:refs/heads/main", "--force")
        self.release()
        self.assertEqual(self.actions, [["gh", "run", "rerun", "123", "--repo", launcher.REPOSITORY, "--job", "999"]])
        self.assertFalse(any("--failed" in command for command in self.actions))

    def test_original_tested_commit_does_not_rerun_successful_crates_job(self):
        self.git("checkout", "--detach", self.base)
        self.git("push", self.remote.as_posix(), f"{self.base}:refs/heads/main", "--force")
        self.jobs[-1]["conclusion"] = "success"
        with self.assertRaisesRegex(ValueError, "existing failed crates job"):
            self.release()
        self.assertEqual(self.actions, [])
        self.assertEqual(self.cargo_commands, [])

    def test_failed_job_becoming_successful_during_plan_is_not_rerun(self):
        self.git("checkout", "--detach", self.base)
        self.git("push", self.remote.as_posix(), f"{self.base}:refs/heads/main", "--force")
        self.after_package = lambda: self.jobs[-1].update(conclusion="success")
        with self.assertRaisesRegex(ValueError, "failed crates job changed"):
            self.release()
        self.assertEqual(self.actions, [])

    def test_follows_automatic_original_release_run_pagination(self):
        self.run_candidates = [self.run] * 100
        self.release()
        self.assertTrue(any("/actions/workflows/release.yml/runs?" in path and path.endswith("page=2")
                            for path in self.api_calls))
        self.assertEqual(len(self.actions), 1)

    def test_main_recovery_run_is_not_an_original_tested_tag_run(self):
        self.run["head_branch"] = "main"
        with self.assertRaisesRegex(ValueError, "No original public tag release run"):
            self.release()
        self.assertEqual(self.actions, [])

    def test_local_conflicting_tag_is_never_retargeted(self):
        self.git("tag", "-f", "v2.14.0", "HEAD")
        conflicting = self.git("rev-parse", "v2.14.0")
        with self.assertRaisesRegex(ValueError, "conflicts with the public tag"):
            self.release()
        self.assertEqual(self.git("rev-parse", "v2.14.0"), conflicting)
        self.assertEqual(self.actions, [])

    def test_missing_public_cli_tag_is_not_a_generic_crates_bypass(self):
        self.git("push", self.remote.as_posix(), ":refs/tags/v2.14.0")
        with self.assertRaisesRegex(ValueError, "public CLI tag.*normal CLI release first"):
            self.release()
        self.assertEqual(self.actions, [])

    def test_all_published_versions_stop_before_any_cargo(self):
        for name in launcher.publisher.PACKAGES:
            self.publish_existing(name)
        with self.assertRaisesRegex(ValueError, "already exist"):
            self.release()
        self.assertEqual(self.cargo_commands, [])
        self.assertEqual(self.actions, [])

    def test_unchanged_published_library_is_allowed_and_skipped(self):
        self.publish_existing("kingfisher-core")
        self.release()
        self.assertEqual(len(self.actions), 1)

    def test_same_version_changed_source_fails_before_remote_action(self):
        self.publish_existing("kingfisher-core")
        self.package_sources["kingfisher-core"] = b"changed runtime"
        with self.assertRaisesRegex(ValueError, "packaged files changed"):
            self.release()
        self.assertEqual(self.actions, [])

    def test_published_binary_conflict_is_also_fatal(self):
        self.publish_existing("kingfisher-bin")
        self.package_sources["kingfisher-bin"] = b"changed executable source"
        with self.assertRaisesRegex(ValueError, "kingfisher-bin.*packaged files changed"):
            self.release()
        self.assertEqual(self.actions, [])

    def test_registry_network_failure_is_not_treated_as_unpublished(self):
        with patch.object(launcher.publisher, "published_version", side_effect=urllib.error.URLError("offline")):
            with self.assertRaises(urllib.error.URLError):
                self.release()
        self.assertEqual(self.cargo_commands, [])
        self.assertEqual(self.actions, [])

    def test_fresh_archives_ignore_stale_workspace_package_directory(self):
        self.write("target/package/kingfisher-core-1.0.4.crate", "stale invalid archive")
        self.release()
        self.assertEqual(len(self.actions), 1)
        self.assertTrue(all(path.parent != self.root for path in self.package_dirs))

    def test_dirty_tracked_and_untracked_files_fail_before_network(self):
        self.write("README.md", "dirty tracked")
        with self.assertRaisesRegex(ValueError, "clean checkout"):
            self.release("kingfisher-secret-scanner")
        self.git("restore", "README.md")
        self.write("untracked.txt", "dirty untracked")
        self.git("config", "status.showUntrackedFiles", "no")
        # The launcher's explicit status must override a display-only user setting.
        with self.assertRaisesRegex(ValueError, "clean checkout"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.api_calls, [])
        self.assertEqual(self.actions, [])

    def test_remote_fetch_failure_never_dispatches_or_checks_registry(self):
        self.remote = self.directory / "unavailable remote.git"
        with self.assertRaisesRegex(launcher.CommandError, "git -c failed"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.sdk_checks, [])
        self.assertEqual(self.api_calls, [])
        self.assertEqual(self.actions, [])

    def test_unmerged_head_fails_before_preflight(self):
        self.git("commit", "--allow-empty", "-m", "unmerged")
        with self.assertRaisesRegex(ValueError, "merged"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.sdk_checks, [])
        self.assertEqual(self.actions, [])

    def test_stale_main_checkout_is_not_latest_main_release(self):
        selected = self.git("rev-parse", "HEAD")
        self.git("commit", "--allow-empty", "-m", "main advanced")
        self.push_main()
        self.git("checkout", "--detach", selected)
        with self.assertRaisesRegex(ValueError, "Stale checkout"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.sdk_checks, [])
        self.assertEqual(self.actions, [])

    def test_main_race_seen_through_github_stops_before_sdk_check(self):
        self.main_override = "0" * 40
        with self.assertRaisesRegex(ValueError, "main advanced"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.sdk_checks, [])
        self.assertEqual(self.actions, [])

    def test_main_advancing_during_sdk_preflight_stops_dispatch(self):
        def advance():
            self.main_override = "0" * 40
        self.after_sdk_check = advance
        with self.assertRaisesRegex(ValueError, "main advanced"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(len(self.sdk_checks), 1)
        self.assertEqual(self.actions, [])

    def test_fork_private_or_nonmain_default_repository_fails_closed(self):
        for key, value in (("full_name", "fork/kingfisher"), ("private", True), ("fork", True),
                           ("default_branch", "master")):
            original = self.repo[key]
            with self.subTest(key=key):
                self.repo[key] = value
                with self.assertRaisesRegex(ValueError, "public mongodb/kingfisher"):
                    self.release("kingfisher-secret-scanner")
                self.repo[key] = original
        self.assertEqual(self.sdk_checks, [])
        self.assertEqual(self.actions, [])

    def test_incorrect_fetch_or_push_remote_is_rejected(self):
        for key in ("remote.origin.url", "remote.origin.pushurl"):
            with self.subTest(key=key):
                self.git("config", key, "https://github.com/fork/kingfisher.git")
                with self.assertRaisesRegex(ValueError, "not a fork"):
                    self.release("kingfisher-secret-scanner")
                self.git("config", "--unset", key)
                self.git("config", "remote.origin.url", "https://github.com/mongodb/kingfisher.git")
        self.assertEqual(self.api_calls, [])
        self.assertEqual(self.actions, [])

    def test_missing_gh_or_authentication_or_permission_stops_dispatch(self):
        with patch.object(launcher.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "Install GitHub CLI"):
                self.release("kingfisher-secret-scanner")
        self.auth_error = launcher.CommandError("gh auth status failed")
        with self.assertRaisesRegex(launcher.CommandError, "gh auth status failed"):
            self.release("kingfisher-secret-scanner")
        self.auth_error = None
        self.repo["permissions"] = {"pull": True}
        with self.assertRaisesRegex(ValueError, "Actions permission"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.actions, [])

    def test_inactive_workflow_or_missing_inputs_fail_before_sdk_check(self):
        self.inactive.add("python-sdk.yml")
        with self.assertRaisesRegex(ValueError, "must be active"):
            self.release("kingfisher-secret-scanner")
        self.inactive.clear()
        path = ".github/workflows/python-sdk.yml"
        self.write(path, (self.root / path).read_text(encoding="utf-8").replace("      expected_sha:\n", "      unrelated:\n"))
        self.commit()
        self.push_main()
        with self.assertRaisesRegex(ValueError, "lacks guarded dispatch inputs.*expected_sha"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.sdk_checks, [])
        self.assertEqual(self.actions, [])

    def test_github_lookup_failure_is_fatal_not_empty_state(self):
        self.fail_api.add("/commits/main")
        with self.assertRaisesRegex(launcher.CommandError, "network/permission failure"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.actions, [])

    def test_wrong_sdk_lock_version_or_stale_provenance_stops_before_network(self):
        original = (self.root / "Cargo.lock").read_text(encoding="utf-8")
        self.write("Cargo.lock", original.replace('version = "1.5.0"', 'version = "1.4.0"'))
        self.provenance()
        self.commit()
        self.push_main()
        with self.assertRaisesRegex(ValueError, "Cargo.lock.*kingfisher-python"):
            self.release("kingfisher-secret-scanner")
        self.write("Cargo.lock", original)
        self.commit()
        self.push_main()
        with self.assertRaisesRegex(ValueError, "Stale rule-bundle provenance"):
            self.release("kingfisher-secret-scanner")
        self.assertEqual(self.api_calls, [])

    def test_runtime_recovery_change_fails_before_packaging(self):
        self.write("crates/kingfisher-core/src/lib.rs", "runtime drift")
        self.commit()
        self.push_main()
        with self.assertRaisesRegex(ValueError, "runtime or unapproved"):
            self.release()
        self.assertEqual(self.cargo_commands, [])
        self.assertEqual(self.actions, [])

    def test_missing_green_original_prerequisites_prevent_recovery(self):
        self.jobs = [job for job in self.jobs if job["name"] != "Linux x64"]
        with self.assertRaisesRegex(ValueError, "No original public tag release run"):
            self.release()
        self.assertEqual(self.cargo_commands, [])
        self.assertEqual(self.actions, [])

    def test_original_run_lookup_network_error_is_not_skipped(self):
        self.fail_api.add("/actions/runs/123")
        with self.assertRaisesRegex(launcher.CommandError, "network/permission failure"):
            self.release()
        self.assertEqual(self.actions, [])

    def test_no_pending_plan_does_not_dispatch(self):
        with patch.object(launcher.publisher, "make_plan", return_value=[{"publish": False}]):
            with self.assertRaisesRegex(ValueError, "No crate publication is pending"):
                self.release()
        self.assertEqual(self.actions, [])

    def test_cli_does_not_require_version_or_accept_manual_run_id(self):
        with patch.object(launcher, "release") as release, \
             patch.object(sys, "argv", ["release-packages.py", "crates", "--remote", "upstream"]):
            self.assertEqual(launcher.main(), 0)
            release.assert_called_once_with("crates", "upstream")
        with patch.object(sys, "argv", ["release-packages.py", "crates", "--release-run-id", "123"]), \
             patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                launcher.main()


class CommandSafetyTests(unittest.TestCase):
    def test_subprocess_output_is_explicit_utf8_not_host_codepage(self):
        result = subprocess.CompletedProcess([], 0, "# ── release metadata — café 🐟\n", "")
        with patch.object(launcher.subprocess, "run", return_value=result) as run:
            self.assertEqual(launcher.command(["git", "show", "HEAD:workflow"], ROOT).stdout, result.stdout)
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")

    def test_command_errors_never_echo_credentials(self):
        result = subprocess.CompletedProcess(["gh", "auth", "status"], 1, "", "token=credential-must-not-leak")
        with patch.object(launcher.subprocess, "run", return_value=result):
            with self.assertRaises(launcher.CommandError) as error:
                launcher.command(["gh", "auth", "status"], ROOT)
        self.assertNotIn("credential-must-not-leak", str(error.exception))


if __name__ == "__main__":
    unittest.main()
