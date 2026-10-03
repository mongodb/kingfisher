"""Build and execute the published library examples with checked output.

Run with: python3 -m unittest discover -s scripts/tests -p test_library_examples.py -v
Cargo's artifact messages supply executable paths, including cross-target layouts
and Windows suffixes. Set CARGO_BUILD_TARGET when testing a non-host toolchain.
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOKEN = "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"


class LibraryExamplesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = subprocess.run(
            [
                "cargo", "build", "--locked", "--examples",
                "-p", "kingfisher-core", "-p", "kingfisher-rules",
                "-p", "kingfisher-scanner",
                "--features", "kingfisher-scanner/validation",
                "--message-format=json",
            ],
            cwd=ROOT, capture_output=True, text=True,
        )
        if build.returncode:
            raise AssertionError(f"Example build failed:\n{build.stderr}\n{build.stdout}")
        cls.executables = {}
        for line in build.stdout.splitlines():
            message = json.loads(line)
            if (message.get("reason") == "compiler-artifact"
                    and "example" in message["target"]["kind"]
                    and message.get("executable")):
                cls.executables[message["target"]["name"]] = message["executable"]

    def run_example(self, name, *args, succeeds=True):
        result = subprocess.run(
            [self.executables[name], *map(str, args)],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        diagnostic = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        if succeeds:
            self.assertEqual(result.returncode, 0, diagnostic)
        else:
            self.assertNotEqual(result.returncode, 0, diagnostic)
            self.assertTrue(result.stderr.strip(), diagnostic)
        return result.stdout

    def test_blob_locations(self):
        self.assertRegex(
            self.run_example("blob_locations"),
            r"^blob=[0-9a-f]+ bytes=30 line=2 column=6\n$",
        )

    def test_builtin_rules_load(self):
        self.assertRegex(self.run_example("load_rules"), r"^Compiled [1-9][0-9]* rules\n$")

    def test_rule_inspection_catalog_and_details(self):
        rows = [json.loads(line) for line in self.run_example(
            "inspect_rules", "--with-validation", "--with-revocation").splitlines()]
        self.assertTrue(rows)
        self.assertTrue(all(row["validation"] and row["revocation"] for row in rows))
        prefixed = [json.loads(line) for line in self.run_example(
            "inspect_rules", "--id-prefix", "betterleaks.aws").splitlines()]
        self.assertTrue(prefixed)
        self.assertTrue(all(row["id"].startswith("betterleaks.aws") for row in prefixed))
        detail = json.loads(self.run_example(
            "inspect_rules", "betterleaks.aws-access-token"))
        self.assertTrue(detail["pattern"])
        self.assertTrue(detail["detection_regex"])
        self.assertIsNotNone(detail["validation"])
        self.assertIsNotNone(detail["revocation"])
        selected = json.loads(self.run_example(
            "inspect_rules", "betterleaks.aws-access-token", "--field", "pattern",
            "--field", "validation", "--field", "revocation"))
        self.assertEqual(set(selected), {"id", "pattern", "validation", "revocation"})
        self.run_example("inspect_rules", "unknown.rule", succeeds=False)
        self.run_example("inspect_rules", "--field", "pattern", succeeds=False)

    def test_custom_rule_inspection_without_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom rules.yml"
            path.write_text("""rules:
  - id: acme.inspect
    name: Inspection fixture
    pattern: '(?#example)(demo_[a-z0-9]{16})'
""", encoding="utf-8")
            detail = json.loads(self.run_example(
                "inspect_rules", "acme.inspect", "--rules-path", path, "--no-builtins"))
            self.assertIn("(?#example)", detail["pattern"])
            self.assertNotIn("(?#example)", detail["detection_regex"])
            self.assertIsNone(detail["validation"])
            self.assertIsNone(detail["revocation"])

    def test_custom_rules_load_in_both_formats(self):
        fixtures = {
            "toml": """[[rules]]
id = "acme.example"
description = "Synthetic example token"
regex = '(demo_[a-z0-9]{16})'
""",
            "yml": """rules:
  - id: acme.example
    name: Synthetic example token
    pattern: '(demo_[a-z0-9]{16})'
""",
        }
        with tempfile.TemporaryDirectory() as directory:
            for suffix, contents in fixtures.items():
                with self.subTest(format=suffix):
                    path = Path(directory) / f"custom rules.{suffix}"
                    path.write_text(contents, encoding="utf-8")
                    self.assertEqual(self.run_example("load_rules", path), "Compiled 1 rules\n")

    def test_invalid_and_missing_rule_files_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            for suffix in ("toml", "yml"):
                with self.subTest(format=suffix):
                    path = Path(directory) / f"invalid rules.{suffix}"
                    self.run_example("load_rules", path, succeeds=False)
                    path.write_text("rules = [", encoding="utf-8")
                    self.run_example("load_rules", path, succeeds=False)

    def test_synthetic_scan_detects_and_redacts(self):
        self.assertEqual(
            self.run_example("scan_content"), "acme.demo at 1:6: [REDACTED]\n",
        )

    def test_file_scan_detects_redacts_and_accepts_clean_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input with spaces.env"
            for newline in ("\n", "\r\n"):
                with self.subTest(newline=repr(newline)):
                    path.write_bytes(f'name=example{newline}token = "{TOKEN}"{newline}'.encode())
                    output = self.run_example("scan_content", path)
                    self.assertIn("betterleaks.github-pat at 2:9: [REDACTED]\n", output)
                    self.assertNotIn(TOKEN, output)
            path.write_text("ordinary content\n", encoding="utf-8")
            self.assertEqual(self.run_example("scan_content", path), "")
            path.unlink()
            self.run_example("scan_content", path, succeeds=False)

    def test_local_validation_rejects_invalid_material(self):
        self.assertEqual(
            self.run_example("local_validation"), "Validation outcome: InvalidMaterial\n",
        )

    def test_async_scan(self):
        self.assertEqual(
            self.run_example("scan_async"), "visible findings=0\nvisible findings=1\n",
        )

    def test_http_validation_outcomes_without_secret_output(self):
        output = self.run_example("http_validation")
        rows = [json.loads(line) for line in output.splitlines()]
        self.assertEqual([row["outcome"] for row in rows], [
            "verified_active", "verified_inactive", "unavailable", "unavailable",
        ])
        self.assertTrue(all(row["rule_id"] == "acme.demo" for row in rows))
        self.assertNotIn("demo_abcd1234efgh5678", output)

    def test_file_batch_reports_each_path_and_propagates_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ("one.env", "two with spaces.env")]
            for path in paths:
                path.write_text(f'token = "{TOKEN}"\n', encoding="utf-8")
            output = self.run_example("scan_files", *paths)
            rows = [json.loads(line) for line in output.splitlines()]
            self.assertEqual({row["path"] for row in rows}, {str(path) for path in paths})
            self.assertTrue(all(row["validation_outcome"] == "not_attempted" for row in rows))
            self.assertNotIn(TOKEN, output)
            paths[0].unlink()
            self.run_example("scan_files", paths[0], succeeds=False)
        self.run_example("scan_files", succeeds=False)

    def test_custom_scan_yaml_and_toml(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input with spaces.env"
            source.write_text("token=demo_abcd1234efgh5678\n", encoding="utf-8")
            yaml = ROOT / "crates/kingfisher-scanner/examples/fixtures/acme-http.yml"
            self.assertEqual(self.run_example("scan_custom_rules", yaml, source), "acme.demo at 1:6\n")
            toml = Path(directory) / "rules.toml"
            toml.write_text(
                '[[rules]]\nid = "acme.demo"\ndescription = "Demo"\n'
                "regex = '(demo_[a-z0-9]{16})'\n", encoding="utf-8",
            )
            self.assertEqual(
                self.run_example("scan_custom_rules", toml, source), "custom.acme.demo at 1:6\n",
            )
            source.write_text("ordinary content", encoding="utf-8")
            self.assertEqual(self.run_example("scan_custom_rules", yaml, source), "")
            self.run_example("scan_custom_rules", toml.with_suffix(".missing"), source, succeeds=False)

    def test_validation_file_example_accepts_clean_input_without_provider_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clean file.txt"
            path.write_text("ordinary content", encoding="utf-8")
            self.assertEqual(self.run_example("validate_file", path), "")
            path.unlink()
            self.run_example("validate_file", path, succeeds=False)
        self.run_example("validate_file", succeeds=False)
