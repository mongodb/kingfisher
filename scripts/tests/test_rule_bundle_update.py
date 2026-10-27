"""Fast rule-bundle integrity checks and portable Git checkout contracts."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("rule_bundle_update", ROOT / "scripts/update-rule-bundle.py")
UPDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATE)


class RuleBundleHashTests(unittest.TestCase):
    def fixture(self, root):
        files = {"input.txt": b"source\n", "artifact.bin": b"\x00\xff\n"}
        for name, data in files.items():
            (root / name).write_bytes(data)
        manifest = root / UPDATE.MANIFEST_RELATIVE
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({
            "generator_input_sha256": {"input.txt": hashlib.sha256(files["input.txt"]).hexdigest()},
            "artifact_sha256": {"artifact.bin": hashlib.sha256(files["artifact.bin"]).hexdigest()},
        }), encoding="utf-8")

    def test_hash_preflight_requires_neither_cargo_nor_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            with patch.object(UPDATE, "ROOT", root), patch.object(UPDATE.shutil, "which", return_value=None), \
                    patch.object(UPDATE.subprocess, "run", side_effect=AssertionError("no subprocesses")), \
                    patch("sys.argv", ["update-rule-bundle.py", "--check-hashes"]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(UPDATE.main(), 0)
            self.assertIn("Verified 2 recorded", output.getvalue())

    def test_hash_preflight_rejects_crlf_missing_and_corrupt_bytes_without_repair(self):
        for name, data in [("input.txt", b"source\r\n"), ("artifact.bin", b"corrupt"), ("artifact.bin", None)]:
            with self.subTest(name=name, data=data), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root)
                path = root / name
                if data is None:
                    path.unlink()
                else:
                    path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, name):
                    UPDATE.verify_recorded_hashes(root)
                self.assertEqual(path.read_bytes() if path.exists() else None, data)

    def test_all_recorded_bytes_survive_a_windows_style_git_checkout(self):
        manifest = json.loads((ROOT / UPDATE.MANIFEST_RELATIVE).read_text(encoding="utf-8"))
        names = set(manifest["generator_input_sha256"]) | set(manifest["artifact_sha256"])
        names.add(UPDATE.MANIFEST_RELATIVE.as_posix())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repository"
            checkout = root / "checkout"
            repo.mkdir()
            checkout.mkdir()
            shutil.copyfile(ROOT / ".gitattributes", repo / ".gitattributes")
            for name in names:
                target = repo / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            git = ["git", "-c", "core.autocrlf=true", "-C", str(repo)]
            subprocess.run([*git, "init", "--quiet"], check=True, capture_output=True)
            subprocess.run([*git, "add", "--all"], check=True, capture_output=True)
            subprocess.run(
                [*git, "checkout-index", "--all", f"--prefix={checkout.as_posix()}/"],
                check=True, capture_output=True,
            )
            for name in sorted(names):
                with self.subTest(path=name):
                    self.assertEqual((checkout / name).read_bytes(), (ROOT / name).read_bytes())
            self.assertGreater(UPDATE.verify_recorded_hashes(checkout), 0)


if __name__ == "__main__":
    unittest.main()
