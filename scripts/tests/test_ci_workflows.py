"""Keep build and release wiring headless after removal of the desktop feature.

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
        cls.release = (workflows / "release.yml").read_text(encoding="utf-8")

    def test_removed_desktop_features_and_dependencies_are_not_available(self):
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        features = manifest["features"]
        for name in ("gui", "gui-tests"):
            with self.subTest(feature=name):
                self.assertNotIn(name, features)
                self.assertNotIn(name, features["default"])
        self.assertFalse(any(name.startswith("gpui") for name in manifest["dependencies"]))

    def test_removed_desktop_build_target_and_workflow_are_not_available(self):
        self.assertFalse((ROOT / ".github/workflows/wizard.yml").exists())
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertNotRegex(makefile, r"(?i)\bwizard(?:-gui)?\b|\bgui(?:-tests)?\b")

    def test_default_macos_ci_keeps_both_architectures_without_gui_builds(self):
        macos = job(self.ci, "macos")
        for contract in ("arch: arm64", "runs_on: macos-15", "arch: x64",
                         "runs_on: macos-15-intel", "run: make tests"):
            with self.subTest(contract=contract):
                self.assertIn(contract, macos)
        self.assertNotIn("Run wizard regressions", self.ci)
        self.assertNotIn("--features gui", self.ci)
        self.assertNotIn("workflows/wizard.yml", self.ci)

    def test_native_workflows_do_not_reference_removed_desktop_features(self):
        for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
            with self.subTest(workflow=workflow.name):
                contents = workflow.read_text(encoding="utf-8")
                self.assertNotRegex(contents, r"(?i)\bwizard\b|\bgui-tests\b|--features[= ]gui\b")

    def test_headless_ci_retains_pinned_tools(self):
        for action in ("actions/checkout", "dtolnay/rust-toolchain", "swatinem/rust-cache"):
            with self.subTest(action=action):
                self.assertRegex(self.ci, rf"uses: {re.escape(action)}@[0-9a-f]{{40}}\b")
        self.assertIn('RUST_TOOLCHAIN: "1.99.0"', self.ci)

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
