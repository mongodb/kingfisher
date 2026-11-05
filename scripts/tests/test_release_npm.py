"""Exercise npm release tagging locally; no registry, GitHub, or publishing writes."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_packages_npm", ROOT / "scripts/release-packages.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
PACKAGE = "kingfisher-secret-scanner"
PLATFORMS = ("darwin-x64", "darwin-arm64", "linux-x64-gnu", "linux-arm64-gnu",
             "win32-x64-msvc", "win32-arm64-msvc")


class NpmReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        self.root = directory / "working tree"
        self.root.mkdir()
        self.remote = directory / "remote repository.git"
        self.empty_git = directory / "empty Git configuration"
        self.empty_git.mkdir()
        isolated_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        isolated_env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_COUNT="0")
        environment = patch.dict(os.environ, isolated_env, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.git("init", "-b", "main")
        for key, value in (("user.name", "Npm Release Test"), ("user.email", "release@example.com"),
                           ("commit.gpgsign", "false"), ("tag.gpgsign", "false"),
                           ("core.autocrlf", "false")):
            self.git("config", key, value)
        self.write_metadata("0.1.0")
        self.write(".github/workflows/node-sdk.yml", "name: Node SDK\non:\n  workflow_dispatch:\njobs: {}\n")
        self.write("README.md", "npm release fixture\n")
        self.commit()
        self.git("init", "--bare", self.remote.as_posix())
        self.git("remote", "add", "origin", "https://github.com/mongodb/kingfisher.git")
        self.push_main()
        self.commands = []
        self.fail_push = False
        self.after_tag = None
        self.after_readiness = None
        self.real_command = launcher.command
        command = patch.object(launcher, "command", side_effect=self.command)
        command.start()
        self.addCleanup(command.stop)
        readiness = patch.object(launcher, "readiness", side_effect=self.readiness)
        self.readiness_mock = readiness.start()
        self.addCleanup(readiness.stop)
        versions = patch.object(launcher, "versions", side_effect=AssertionError("npm must not read CLI/Python versions"))
        versions.start()
        self.addCleanup(versions.stop)
        printing = patch("builtins.print")
        printing.start()
        self.addCleanup(printing.stop)

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-c", f"core.hooksPath={self.empty_git.as_posix()}",
             "-c", f"init.templateDir={self.empty_git.as_posix()}", *args],
            cwd=self.root, stderr=subprocess.PIPE,
        ).decode("utf-8").strip()

    def write(self, name, text):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")

    def write_json(self, name, value):
        self.write(name, json.dumps(value, indent=2) + "\n")

    def write_metadata(self, version):
        dependencies = {f"{PACKAGE}-{suffix}": f"file:./npm/{suffix}" for suffix in PLATFORMS}
        manifest = {"name": PACKAGE, "version": version, "private": True,
                    "optionalDependencies": dependencies}
        self.write_json("javascript/package.json", manifest)
        packages = {"": {"name": PACKAGE, "version": version, "optionalDependencies": dependencies}}
        for suffix in PLATFORMS:
            name = f"{PACKAGE}-{suffix}"
            self.write_json(f"javascript/npm/{suffix}/package.json",
                            {"name": name, "version": version, "private": True})
            packages[f"npm/{suffix}"] = {"name": name, "version": version}
            packages[f"node_modules/{name}"] = {"resolved": f"npm/{suffix}", "link": True}
        self.write_json("javascript/package-lock.json", {"name": PACKAGE, "version": version,
                                                         "lockfileVersion": 3, "packages": packages})
        self.write("crates/kingfisher-node/Cargo.toml", '[package]\nname = "kingfisher-node"\n'
                   f'version = "{version}"\npublish = false\n')
        self.write("Cargo.lock", 'version = 4\n[[package]]\nname = "kingfisher-node"\n'
                   f'version = "{version}"\n')

    def commit(self):
        self.git("add", ".")
        self.git("commit", "--allow-empty", "-m", "Prepare npm release")
        return self.git("rev-parse", "HEAD")

    def push_main(self):
        self.git("push", self.remote.as_posix(), "HEAD:refs/heads/main")

    def command(self, args, root, *, check=True):
        args = list(args)
        self.commands.append(args)
        self.assertEqual(args[0], "git", f"Unexpected command; no network/publication allowed: {args}")
        if args[1] == "push" and self.fail_push:
            raise launcher.CommandError("simulated push failure")
        rewritten = list(args)
        if args[1] in {"fetch", "push", "ls-remote"}:
            rewritten = [self.remote.as_posix() if arg in {"origin", "upstream"} else arg for arg in args]
        result = self.real_command(
            ["git", "-c", f"core.hooksPath={self.empty_git.as_posix()}",
             "-c", f"init.templateDir={self.empty_git.as_posix()}", *rewritten[1:]], root, check=check,
        )
        if args[1] == "tag" and any(flag in args for flag in ("-a", "--annotate")) and self.after_tag:
            self.after_tag()
        return result

    def readiness(self, root, sha, workflow, inputs):
        self.assertEqual(Path(root), self.root)
        self.assertEqual(workflow, "node-sdk.yml")
        self.assertEqual(inputs, set())
        if self.after_readiness:
            self.after_readiness()

    def release(self, remote="origin"):
        launcher.release("npm", remote, root=self.root)

    def assert_no_remote_tags(self):
        self.assertEqual(self.git("ls-remote", "--tags", self.remote.as_posix()), "")

    def assert_no_tags(self):
        self.assertEqual(self.git("tag", "--list"), "")
        self.assert_no_remote_tags()

    def update_json(self, name, change):
        data = json.loads((self.root / name).read_text(encoding="utf-8"))
        change(data)
        self.write_json(name, data)

    def test_pushes_only_annotated_npm_tag_at_selected_committed_sha(self):
        sha = self.git("rev-parse", "HEAD")
        self.release()
        ref = "refs/tags/npm-v0.1.0"
        self.assertEqual(self.git("cat-file", "-t", ref), "tag")
        self.assertEqual(self.git("rev-parse", f"{ref}^{{commit}}"), sha)
        self.assertEqual(self.git("ls-remote", "--tags", self.remote.as_posix(), ref).split()[0],
                         self.git("rev-parse", ref))
        pushes = [args for args in self.commands if args[1] == "push"]
        self.assertEqual(len(pushes), 1)
        self.assertIn("origin", pushes[0])
        self.assertIn(f"{ref}:{ref}", pushes[0])
        self.assertFalse(any("force" in arg or arg.startswith("+") for arg in pushes[0]))
        self.assertGreaterEqual(self.readiness_mock.call_count, 2)

    def test_npm_version_is_independent_and_supports_prerelease_and_build(self):
        for version in ("0.2.0-rc.1", "1.2.3+build.5", "2.0.0-beta.2+sha.abc"):
            with self.subTest(version=version):
                self.write_metadata(version)
                self.commit()
                self.push_main()
                self.release()
                self.assertEqual(self.git("rev-parse", f"npm-v{version}^{{commit}}"), self.git("rev-parse", "HEAD"))

    def test_rejects_invalid_semver_before_creating_tags(self):
        for version in ("01.2.3", "1.2", "1.2.3-01", "1.2.3-", "1.2.3+", "v1.2.3"):
            with self.subTest(version=version):
                self.write_metadata(version)
                self.commit()
                self.push_main()
                with self.assertRaises(ValueError):
                    self.release()
                self.assert_no_tags()

    def test_rejects_dirty_or_untracked_source(self):
        for name in ("README.md", "untracked.txt"):
            with self.subTest(name=name):
                self.write(name, "uncommitted\n")
                with self.assertRaisesRegex(ValueError, "Commit or stash"):
                    self.release()
                self.assert_no_tags()
                # Commit the fixture change to restore a clean current main without deleting files.
                self.commit()
                self.push_main()

    def test_rejects_unmerged_source(self):
        self.commit()
        with self.assertRaisesRegex(ValueError, "merged"):
            self.release()
        self.assert_no_tags()

    def test_rejects_stale_checkout(self):
        sha = self.git("rev-parse", "HEAD")
        self.commit()
        self.push_main()
        self.git("checkout", "--detach", sha)
        with self.assertRaisesRegex(ValueError, "Stale|current"):
            self.release()
        self.assert_no_tags()

    def test_rejects_fork_fetch_or_push_url(self):
        for push_only in (False, True):
            with self.subTest(push_only=push_only):
                args = ["remote", "set-url"] + (["--push"] if push_only else [])
                self.git(*args, "origin", "https://github.com/someone/kingfisher.git")
                with self.assertRaisesRegex(ValueError, "public mongodb/kingfisher"):
                    self.release()
                self.assert_no_tags()
                self.git(*args, "origin", "https://github.com/mongodb/kingfisher.git")

    def test_uses_selected_upstream_not_fork_origin(self):
        self.git("remote", "set-url", "origin", "https://github.com/someone/kingfisher.git")
        self.git("remote", "add", "upstream", "https://github.com/mongodb/kingfisher.git")
        self.release("upstream")
        for args in self.commands:
            if args[1] in {"fetch", "push", "ls-remote"}:
                self.assertIn("upstream", args)
                self.assertNotIn("origin", args)

    def test_rejects_manifest_and_lock_mismatches(self):
        cases = [
            ("javascript/package.json", lambda p: p.update(name="another-package")),
            ("javascript/package.json", lambda p: p.update(private=False)),
            ("javascript/package.json", lambda p: p["optionalDependencies"].pop(f"{PACKAGE}-darwin-x64")),
            ("javascript/package.json", lambda p: p["optionalDependencies"].update({f"{PACKAGE}-darwin-x64": "0.1.0"})),
            ("javascript/package-lock.json", lambda p: p.update(version="9.0.0")),
            ("javascript/package-lock.json", lambda p: p["packages"][""].update(version="9.0.0")),
            ("javascript/package-lock.json", lambda p: p["packages"][""].update(name="another-package")),
            ("javascript/package-lock.json", lambda p: p["packages"]["npm/darwin-x64"].update(version="9.0.0")),
            ("javascript/package-lock.json", lambda p: p["packages"][""].update(optionalDependencies={})),
        ]
        for index, (name, change) in enumerate(cases):
            with self.subTest(path=name, change=index):
                self.write_metadata("0.1.0")
                self.update_json(name, change)
                self.commit()
                self.push_main()
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.release()
                self.assert_no_tags()

    def test_rejects_each_native_manifest_name_private_and_version_mismatch(self):
        for suffix in PLATFORMS:
            for change in ({"name": "another-package"}, {"private": False}, {"version": "0.2.0"}):
                with self.subTest(platform=suffix, change=change):
                    self.write_metadata("0.1.0")
                    self.update_json(f"javascript/npm/{suffix}/package.json", lambda p: p.update(change))
                    self.commit()
                    self.push_main()
                    with self.assertRaises(ValueError):
                        self.release()
                    self.assert_no_tags()

    def test_rejects_node_binding_or_cargo_lock_version_mismatch(self):
        for name in ("crates/kingfisher-node/Cargo.toml", "Cargo.lock"):
            with self.subTest(path=name):
                self.write_metadata("0.1.0")
                text = (self.root / name).read_text(encoding="utf-8").replace('"0.1.0"', '"9.0.0"')
                self.write(name, text)
                self.commit()
                self.push_main()
                with self.assertRaises(ValueError):
                    self.release()
                self.assert_no_tags()

    def test_rejects_existing_remote_tag_with_rerun_guidance(self):
        self.git("tag", "-a", "npm-v0.1.0", "-m", "Existing release")
        self.git("push", self.remote.as_posix(), "refs/tags/npm-v0.1.0")
        original = self.git("rev-parse", "npm-v0.1.0")
        with self.assertRaisesRegex(ValueError, "(?i)rerun|re-run"):
            self.release()
        self.assertEqual(self.git("rev-parse", "npm-v0.1.0"), original)
        self.assertFalse(any(args[1] == "push" for args in self.commands))

    def test_rejects_lightweight_local_tag(self):
        self.git("tag", "npm-v0.1.0")
        with self.assertRaisesRegex(ValueError, "annotated"):
            self.release()
        self.assertEqual(self.git("cat-file", "-t", "npm-v0.1.0"), "commit")
        self.assert_no_remote_tags()

    def test_rejects_annotated_local_tag_on_another_commit(self):
        self.git("tag", "-a", "npm-v0.1.0", "-m", "Old source")
        original = self.git("rev-parse", "npm-v0.1.0")
        self.commit()
        self.push_main()
        with self.assertRaisesRegex(ValueError, "commit"):
            self.release()
        self.assertEqual(self.git("rev-parse", "npm-v0.1.0"), original)
        self.assert_no_remote_tags()

    def test_failed_push_retries_same_annotated_local_tag(self):
        self.fail_push = True
        with self.assertRaises(launcher.CommandError):
            self.release()
        original = self.git("rev-parse", "npm-v0.1.0")
        self.assert_no_remote_tags()
        self.fail_push = False
        self.release()
        self.assertEqual(self.git("rev-parse", "npm-v0.1.0"), original)
        creates = [args for args in self.commands if args[1] == "tag" and "-a" in args]
        self.assertEqual(len(creates), 1)

    def test_dirty_source_during_readiness_stops_before_tag_creation(self):
        self.after_readiness = lambda: self.write("README.md", "changed during preflight\n")
        with self.assertRaises(ValueError):
            self.release()
        self.assert_no_tags()

    def test_remote_main_advancing_during_preflight_stops_before_tag_creation(self):
        def advance():
            if self.readiness_mock.call_count == 1:
                sha = self.git("commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "New public main")
                self.git("push", self.remote.as_posix(), f"{sha}:refs/heads/main")
        self.after_readiness = advance
        with self.assertRaisesRegex(ValueError, "Stale|advanced|current"):
            self.release()
        self.assert_no_tags()

    def test_dirty_source_after_tag_creation_stops_before_push(self):
        self.after_tag = lambda: self.write("README.md", "changed before push\n")
        with self.assertRaises(ValueError):
            self.release()
        self.assert_no_remote_tags()
        self.assertFalse(any(args[1] == "push" for args in self.commands))

    def test_head_changed_after_tag_creation_stops_before_push(self):
        self.after_tag = self.commit
        with self.assertRaisesRegex(ValueError, "changed"):
            self.release()
        self.assert_no_remote_tags()
        self.assertFalse(any(args[1] == "push" for args in self.commands))

    def test_local_retry_tag_replaced_during_preflight_is_not_pushed(self):
        self.git("tag", "-a", "npm-v0.1.0", "-m", "Original retry tag")
        original = self.git("rev-parse", "npm-v0.1.0")

        def replace_tag():
            if self.readiness_mock.call_count == 2:
                self.git("tag", "-a", "-f", "npm-v0.1.0", "-m", "Replaced retry tag")

        self.after_readiness = replace_tag
        with self.assertRaisesRegex(ValueError, "tag changed"):
            self.release()
        self.assertNotEqual(self.git("rev-parse", "npm-v0.1.0"), original)
        self.assert_no_remote_tags()
        self.assertFalse(any(args[1] == "push" for args in self.commands))


class NpmCliTests(unittest.TestCase):
    def test_cli_accepts_npm_selector_and_selected_remote(self):
        with patch.object(launcher, "release") as release, patch(
                "sys.argv", ["release-packages.py", "npm", "--remote", "upstream"]):
            self.assertEqual(launcher.main(), 0)
        release.assert_called_once_with("npm", "upstream")


if __name__ == "__main__":
    unittest.main()
