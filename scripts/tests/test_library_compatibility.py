import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "library_compatibility", Path(__file__).parents[1] / "check-library-compatibility.py"
)
compatibility = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compatibility)


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class LibraryCompatibilityTests(unittest.TestCase):
    def test_failed_check_restores_lockfile_and_removes_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            write(repo, "Cargo.lock", "original lockfile\n")
            calls = []

            def run(command, **kwargs):
                calls.append(command)
                if command[:3] == ["git", "worktree", "add"]:
                    write(Path(command[4]), "Cargo.toml", "[workspace]\n")
                elif command[:2] == ["cargo", "semver-checks"]:
                    (repo / "Cargo.lock").write_text("temporary patches\n", encoding="utf-8")
                    raise subprocess.CalledProcessError(1, command)

            with patch.object(compatibility, "__file__", str(repo / "scripts/check.py")), \
                 patch("sys.argv", ["check.py", "--baseline-rev", "HEAD", "--features", "all-features"]), \
                 patch.object(compatibility.subprocess, "run", side_effect=run):
                with self.assertRaises(subprocess.CalledProcessError):
                    compatibility.main()
            self.assertEqual((repo / "Cargo.lock").read_text(encoding="utf-8"), "original lockfile\n")
            self.assertEqual(calls[-1][:4], ["git", "worktree", "remove", "--force"])

    def test_baseline_without_legacy_patches_needs_no_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write(root, "baseline/Cargo.toml", "[workspace]\n")
            compatibility.write_baseline_config(root / "baseline", root)
            self.assertFalse((root / ".cargo").exists())

    def test_external_consumer_uses_baseline_transitive_patch(self):
        # Reproduce the checker's separate workspace, with a transitive
        # dependency that needs an API available only in the vendored crate.
        with tempfile.TemporaryDirectory(prefix="semver fixture ") as temporary:
            root = Path(temporary)
            baseline = root / "baseline"
            write(baseline, "Cargo.toml", '''[workspace]
members = ["rules", "scanner", "vendor/vectorscan-rs"]
resolver = "2"
[patch.crates-io]
vectorscan-rs = { path = "vendor/vectorscan-rs" }
''')
            write(baseline, "vendor/vectorscan-rs/Cargo.toml", '''[package]
name = "vectorscan-rs"
version = "0.0.6"
edition = "2021"
''')
            write(baseline, "vendor/vectorscan-rs/src/lib.rs", 'pub fn vendored_api() {}\n')
            write(baseline, "rules/Cargo.toml", '''[package]
name = "fixture-rules"
version = "0.1.0"
edition = "2021"
[dependencies]
vectorscan-rs = "=0.0.6"
''')
            write(baseline, "rules/src/lib.rs", 'pub fn scan() { vectorscan_rs::vendored_api(); }\n')
            write(baseline, "scanner/Cargo.toml", '''[package]
name = "fixture-scanner"
version = "0.1.0"
edition = "2021"
[dependencies]
fixture-rules = { path = "../rules" }
''')
            write(baseline, "scanner/src/lib.rs", 'pub fn scan() { fixture_rules::scan(); }\n')
            scanner_path = json.dumps(str(baseline / "scanner"))
            write(root, "consumer/Cargo.toml", f'''[package]
name = "fixture-consumer"
version = "0.1.0"
edition = "2021"
[workspace]
[dependencies]
fixture-scanner = {{ path = {scanner_path} }}
''')
            write(root, "consumer/src/lib.rs", 'pub fn scan() { fixture_scanner::scan(); }\n')
            compatibility.write_baseline_config(baseline, root)
            config = tomllib.loads((root / ".cargo/config.toml").read_text(encoding="utf-8"))
            self.assertEqual(
                Path(config["patch"]["crates-io"]["vectorscan-rs"]["path"]),
                (baseline / "vendor/vectorscan-rs").resolve(),
            )
            result = subprocess.run([
                "cargo", "check", "--offline", "--manifest-path",
                str(root / "consumer/Cargo.toml"),
            ], cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
