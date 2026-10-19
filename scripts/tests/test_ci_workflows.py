"""Keep optional native wizard coverage separate from headless CI and releases.

These are focused text contracts, not a YAML parser; actionlint validates syntax.
Run with: python3 -m unittest discover -s scripts/tests -p test_ci_workflows.py -v
"""
from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]


def section(workflow, key):
    match = re.search(rf"(?ms)^{re.escape(key)}:\n(.*?)(?=^\S|\Z)", workflow)
    if match is None:
        raise AssertionError(f"Missing workflow section: {key}")
    return match.group(1)


def job(workflow, name):
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)",
        section(workflow, "jobs"),
    )
    if match is None:
        raise AssertionError(f"Missing workflow job: {name}")
    return match.group(1)


class CiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflows = ROOT / ".github/workflows"
        cls.ci = (workflows / "ci.yml").read_text(encoding="utf-8")
        cls.wizard = (workflows / "wizard.yml").read_text(encoding="utf-8")
        cls.release = (workflows / "release.yml").read_text(encoding="utf-8")

    def test_gui_remains_opt_in_with_explicit_headless_ui_test_support(self):
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        features = manifest["features"]
        self.assertNotIn("gui", features["default"])
        self.assertNotIn("gui-tests", features["default"])
        self.assertIn("gui", features["gui-tests"])
        self.assertIn("gpui-kit/test-support", features["gui-tests"])
        self.assertIn("dep:gpui-kit", features["gui"])
        self.assertTrue(manifest["dependencies"]["gpui-kit"]["optional"])

    def test_default_macos_ci_keeps_both_architectures_without_gui_builds(self):
        macos = job(self.ci, "macos")
        for contract in ("arch: arm64", "runs_on: macos-14", "arch: x64",
                         "runs_on: macos-15-intel", "run: make tests"):
            with self.subTest(contract=contract):
                self.assertIn(contract, macos)
        self.assertNotIn("Run wizard regressions", self.ci)
        self.assertNotIn("--features gui", self.ci)
        self.assertNotIn("workflows/wizard.yml", self.ci)

    def test_optional_wizard_has_manual_and_path_filtered_pr_triggers(self):
        triggers = section(self.wizard, "on")
        self.assertRegex(triggers, r"(?m)^  workflow_dispatch:\s*$")
        self.assertRegex(triggers, r"(?m)^  pull_request:\s*$")
        self.assertIn("branches: [main]", triggers)
        self.assertNotIn("workflow_call:", triggers)
        self.assertNotRegex(triggers, r"(?m)^  (push|pull_request_target):")
        paths = re.findall(r"(?m)^      - ['\"]([^'\"]+)['\"]\s*$", triggers)
        # The wizard links the application and workspace crates, not just src/wizard.
        # Its logo and report fixtures are embedded from docs/viewer.
        required = {
            "src/**", "crates/**", "Cargo.*", "build*.rs", ".cargo/**",
            "rust-toolchain*", "docs/viewer/**", "tests/wizard_cli.rs",
            ".github/workflows/wizard.yml", ".github/workflows/ci.yml",
            ".github/workflows/release.yml", "scripts/tests/test_ci_workflows.py",
        }
        self.assertEqual(set(paths), required)
        self.assertEqual(len(paths), len(required))

    def test_optional_wizard_runs_once_with_all_existing_native_regressions(self):
        jobs = section(self.wizard, "jobs")
        self.assertEqual(re.findall(r"(?m)^  ([\w-]+):$", jobs), ["wizard"])
        wizard = job(self.wizard, "wizard")
        self.assertIn("runs-on: macos-14", wizard)
        self.assertNotIn("matrix:", wizard)
        self.assertIn(
            "cargo test --locked -p kingfisher-bin --features gui-tests --lib wizard::",
            wizard,
        )
        self.assertIn("brew list cmake", wizard)
        self.assertIn("brew list pkg-config", wizard)
        self.assertIn("contents: read", section(self.wizard, "permissions"))

    def test_optional_wizard_reuses_pinned_tools_with_an_isolated_cache(self):
        for action in ("actions/checkout", "dtolnay/rust-toolchain", "swatinem/rust-cache"):
            with self.subTest(action=action):
                pin = re.search(rf"uses: {re.escape(action)}@([0-9a-f]{{40}})", self.ci)
                self.assertIsNotNone(pin)
                self.assertIn(pin.group(0), self.wizard)
        self.assertIn('RUST_TOOLCHAIN: "1.99.0"', self.wizard)
        cache_key = "kingfisher-wizard-v1-${{ runner.os }}-${{ runner.arch }}"
        self.assertIn(f"shared-key: {cache_key}", self.wizard)
        self.assertNotIn(cache_key, self.ci)

    def test_reusable_release_ci_remains_headless_and_still_gates_publication(self):
        self.assertIn("workflow_call:", section(self.ci, "on"))
        self.assertIn("uses: ./.github/workflows/ci.yml", job(self.release, "tests"))
        release = job(self.release, "release")
        needs = re.search(r"(?m)^    needs: \[([^\]]+)\]", release)
        self.assertIsNotNone(needs)
        self.assertIn("tests", {name.strip() for name in needs.group(1).split(",")})
        self.assertNotIn("workflows/wizard.yml", self.release)


if __name__ == "__main__":
    unittest.main()
