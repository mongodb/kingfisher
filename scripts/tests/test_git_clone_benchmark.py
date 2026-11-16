"""Regression tests for clone benchmark parity checks (Git is the benchmark oracle)."""
import argparse
import contextlib
import importlib.util
import io
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("clone_benchmark", ROOT / "scripts/benchmark-git-clone.py")
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


@unittest.skipUnless(shutil.which("git"), "the comparative benchmark requires native Git")
class CloneBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kingfisher-clone-benchmark-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.git = shutil.which("git")
        self.first = self.root / "first.git"
        self.command("init", "--bare", "--quiet", self.first)
        blob = self.command("-C", self.first, "hash-object", "-w", "--stdin", data=b"fixture\n").strip()
        tree = self.command("-C", self.first, "mktree", data=b"100644 blob " + blob + b"\tfile with spaces.txt\n").strip()
        commit = self.command("-C", self.first, "commit-tree", tree.decode(), "-m", "fixture").strip()
        self.command("-C", self.first, "update-ref", "refs/heads/main", commit.decode())
        self.command("-C", self.first, "symbolic-ref", "HEAD", "refs/heads/main")
        self.second = self.root / "second.git"
        self.command("clone", "--mirror", "--quiet", self.first, self.second)
        self.commit = commit.decode()

    def command(self, *args, data=None):
        return subprocess.check_output(
            [self.git, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *map(str, args)],
            input=data, env=BENCHMARK.isolated_env(), stderr=subprocess.PIPE,
        )

    def verify(self, output):
        args = argparse.Namespace(repo=[f"git={self.first}", f"gix={self.second}"],
                                  output=self.root / output, fsck=False)
        with contextlib.redirect_stdout(io.StringIO()):
            BENCHMARK.verify(args)
        return json.loads(args.output.read_text(encoding="utf-8"))

    def test_identical_content_matches_despite_origin_aliases(self):
        self.command("-C", self.second, "update-ref", "refs/remotes/origin/heads/main", self.commit)
        result = self.verify("matched.json")
        self.assertTrue(result["parity"])
        second = result["repositories"][1]
        self.assertEqual(second["extra_origin_aliases"], 1)
        self.assertEqual(second["head_files"], 1)
        self.assertEqual(second["object_counts"], {"blob": 1, "tree": 1, "commit": 1})

    def test_extra_unreachable_blob_is_not_hidden_by_matching_head(self):
        self.command("-C", self.second, "hash-object", "-w", "--stdin", data=b"extra blob\n")
        with self.assertRaisesRegex(RuntimeError, "clone parity failed"):
            self.verify("extra.json")
        result = json.loads((self.root / "extra.json").read_text(encoding="utf-8"))
        self.assertIn("all_objects_sha256", result["mismatches"])
        self.assertIn("object_counts", result["mismatches"])
        self.assertNotIn("reachable_objects_sha256", result["mismatches"])
        self.assertNotIn("head_tree_sha256", result["mismatches"])

    def test_different_blob_ids_fail_even_with_equal_object_and_file_counts(self):
        self.command("-C", self.first, "hash-object", "-w", "--stdin", data=b"extra one\n")
        self.command("-C", self.second, "hash-object", "-w", "--stdin", data=b"extra two\n")
        with self.assertRaisesRegex(RuntimeError, "clone parity failed"):
            self.verify("different.json")
        result = json.loads((self.root / "different.json").read_text(encoding="utf-8"))
        self.assertIn("all_objects_sha256", result["mismatches"])
        self.assertNotIn("object_counts", result["mismatches"])
        self.assertNotIn("head_files", result["mismatches"])

    def test_shallow_clone_is_rejected(self):
        (self.second / "shallow").write_text(self.commit + "\n", encoding="ascii")
        with self.assertRaisesRegex(RuntimeError, "is shallow"):
            self.verify("shallow.json")

    def test_alternate_object_database_is_rejected(self):
        (self.second / "objects/info/alternates").write_text(str(self.first / "objects") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "has alternates"):
            self.verify("alternates.json")

    def test_single_repository_cannot_claim_parity(self):
        args = argparse.Namespace(repo=[f"only={self.first}"], output=self.root / "single.json", fsck=False)
        with self.assertRaisesRegex(ValueError, "at least two repositories"):
            BENCHMARK.verify(args)
        self.assertFalse(args.output.exists())

    def test_duplicate_engines_are_rejected_without_creating_output(self):
        args = argparse.Namespace(engines="git,git", output=self.root / "invalid-run")
        with self.assertRaisesRegex(ValueError, "without duplicates"):
            BENCHMARK.run(args)
        self.assertFalse(args.output.exists())

    def test_real_origin_namespaced_oracle_ref_cannot_be_normalized_away(self):
        self.command("-C", self.first, "update-ref", "refs/remotes/origin/heads/main", self.commit)
        with self.assertRaisesRegex(RuntimeError, "clone parity failed"):
            self.verify("real-origin.json")
        result = json.loads((self.root / "real-origin.json").read_text(encoding="utf-8"))
        self.assertEqual(result["repositories"][0]["extra_origin_aliases"], 0)
        self.assertIn("refs/remotes/origin/heads/main", result["repositories"][0]["refs"])
        self.assertIn("refs", result["mismatches"])

    def test_unmapped_extra_ref_is_not_ignored(self):
        self.command("-C", self.second, "update-ref", "refs/remotes/origin/custom/extra", self.commit)
        with self.assertRaisesRegex(RuntimeError, "clone parity failed"):
            self.verify("refs.json")
        result = json.loads((self.root / "refs.json").read_text(encoding="utf-8"))
        self.assertIn("refs", result["mismatches"])

    def test_repeated_repository_path_cannot_claim_parity(self):
        args = argparse.Namespace(repo=[f"first={self.first}", f"again={self.first}"],
                                  output=self.root / "repeated.json", fsck=False)
        with self.assertRaisesRegex(ValueError, "not repeated paths"):
            BENCHMARK.verify(args)
        self.assertFalse(args.output.exists())

    def test_local_clone_shortcuts_are_rejected_without_creating_output(self):
        args = argparse.Namespace(engines="git,gix", url=str(self.first), output=self.root / "local-run")
        with self.assertRaisesRegex(ValueError, "requires an HTTP"):
            BENCHMARK.run(args)
        self.assertFalse(args.output.exists())

    def test_existing_verification_report_is_never_overwritten(self):
        output = self.root / "keep.json"
        output.write_text("keep", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            self.verify("keep.json")
        self.assertEqual(output.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()


class BenchmarkArgumentTests(unittest.TestCase):
    """Argument handling that needs no native Git."""

    def test_repo_arguments_require_name_and_path(self):
        self.assertEqual(BENCHMARK.parse_repositories(["a=one", "b=two=x"]),
                         [("a", "one"), ("b", "two=x")])
        for value in ["no-separator", "=path", "name="]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "NAME=PATH"):
                BENCHMARK.parse_repositories([value])

    def test_native_engine_path_keeps_windows_system_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            system = root / "System32"
            git = root / "Git" / "cmd"
            system.mkdir()
            git.mkdir(parents=True)
            (git / "git.exe").write_bytes(b"")
            path = BENCHMARK.os.pathsep.join([str(system), str(git), ""])
            self.assertEqual(BENCHMARK.path_without_git(path, windows=True), str(system))
            self.assertEqual(BENCHMARK.path_without_git(path, windows=False), "")
