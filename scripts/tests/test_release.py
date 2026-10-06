"""Exercise release tagging against local repositories without publishing anything."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("release", Path(__file__).parents[1] / "release.py")
releaser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(releaser)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        self.root = directory / "working tree"
        self.remote = directory / "remote repo.git"
        self.root.mkdir()
        self.git("init", "-b", "main")
        for key, value in (("user.name", "Release Test"), ("user.email", "release@example.com"),
                           ("commit.gpgsign", "false"), ("tag.gpgsign", "false")):
            self.git("config", key, value)
        (self.root / "Cargo.toml").write_text('[package]\nversion = "2.11.0"\n', encoding="utf-8")
        self.git("add", "Cargo.toml")
        self.git("commit", "-m", "Prepare release")
        self.git("init", "--bare", str(self.remote))
        # Absolute paths with forward slashes also work with Git for Windows/MSYS2.
        self.git("remote", "add", "origin", self.remote.as_posix())
        self.git("push", "origin", "main")

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout.strip()

    def release(self, version="2.11.0", remote="origin"):
        with patch("builtins.print"):
            releaser.release(version, remote, root=self.root)

    def assert_no_tags(self):
        self.assertEqual(self.git("tag", "--list"), "")
        self.assertEqual(self.git("ls-remote", "--tags", "origin"), "")

    def test_pushes_annotated_tag_at_committed_version(self):
        self.release()
        self.assertEqual(self.git("cat-file", "-t", "refs/tags/v2.11.0"), "tag")
        self.assertEqual(self.git("rev-parse", "v2.11.0^{commit}"), self.git("rev-parse", "HEAD"))
        self.assertEqual(
            self.git("ls-remote", "--tags", "origin", "refs/tags/v2.11.0").split()[0],
            self.git("rev-parse", "v2.11.0"),
        )

    def test_accepts_prefixed_version_and_explicit_remote_path(self):
        self.release("v2.11.0", self.remote.as_posix())
        self.assertIn("refs/tags/v2.11.0", self.git("ls-remote", "--tags", "origin"))

    def test_rejects_missing_or_wrong_version(self):
        for version in ("", "2.10.0", "vv2.11.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.release(version)
            self.assert_no_tags()

    def test_rejects_dirty_checkout(self):
        for path in ("Cargo.toml", "untracked.txt"):
            with self.subTest(path=path):
                target = self.root / path
                original = target.read_bytes() if target.exists() else None
                target.write_text("uncommitted changes", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Commit or stash"):
                    self.release()
                self.assert_no_tags()
                if original is None:
                    target.unlink()
                else:
                    target.write_bytes(original)

    def test_rejects_commit_not_on_remote_main(self):
        self.git("commit", "--allow-empty", "-m", "Unmerged change")
        with self.assertRaisesRegex(ValueError, "merged"):
            self.release()
        self.assert_no_tags()

    def test_can_release_merged_commit_after_main_advances(self):
        commit = self.git("rev-parse", "HEAD")
        self.git("commit", "--allow-empty", "-m", "Later main change")
        self.git("push", "origin", "main")
        self.git("checkout", "--detach", commit)
        self.release()
        self.assertEqual(self.git("rev-parse", "v2.11.0^{commit}"), commit)

    def test_rejects_local_tag_on_another_commit(self):
        self.git("tag", "v2.11.0")
        previous = self.git("rev-parse", "v2.11.0")
        self.git("commit", "--allow-empty", "-m", "New release commit")
        with self.assertRaisesRegex(ValueError, "another commit"):
            self.release()
        self.assertEqual(self.git("rev-parse", "v2.11.0"), previous)
        self.assertEqual(self.git("ls-remote", "--tags", "origin"), "")

    def test_rejects_existing_remote_tag(self):
        self.release()
        tag = self.git("rev-parse", "v2.11.0")
        with self.assertRaisesRegex(ValueError, "Remote tag .* already exists"):
            self.release()
        self.assertEqual(self.git("rev-parse", "v2.11.0"), tag)

    def test_fetch_failure_does_not_create_tag(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.release(remote=(self.remote.parent / "missing.git").as_posix())
        self.assert_no_tags()

    def test_push_failure_can_retry_same_local_tag(self):
        real_git = releaser.git

        def fail_push(*args, **kwargs):
            if args[0] == "push":
                raise subprocess.CalledProcessError(1, ["git", *args], stderr="push failed")
            return real_git(*args, **kwargs)

        with patch.object(releaser, "git", side_effect=fail_push):
            with self.assertRaises(subprocess.CalledProcessError):
                self.release()
        tag = self.git("rev-parse", "v2.11.0")
        self.assertEqual(self.git("ls-remote", "--tags", "origin"), "")
        self.release()
        self.assertEqual(self.git("rev-parse", "v2.11.0"), tag)


if __name__ == "__main__":
    unittest.main()
