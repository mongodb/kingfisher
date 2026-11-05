"""Keep Node SDK examples and npm setup instructions executable and consistent.

No npm authentication, trust changes, tags, or registry writes are performed.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NodeSdkDocsTests(unittest.TestCase):
    def test_npm_sdk_is_documented_as_0_1_preview(self):
        for name in (
            "README.md", "CONTRIBUTING.md", "javascript/README.md",
            "javascript/PUBLISHING.md", "docs/JAVASCRIPT.md", "docs/ARCHITECTURE.md",
            "docs/DEPLOYMENT.md", "docs/PROJECT.md",
            "llms.txt", "docs-site/overrides/home.html",
        ):
            with self.subTest(document=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("0.1.0", text)
                self.assertIn("preview", text.lower())
                self.assertNotRegex(
                    text.lower(), r"unpublished|not[- ](?:yet[- ])?published|not yet on npm"
                )
        manifest = json.loads((ROOT / "javascript/package.json").read_text())
        self.assertEqual(manifest["version"], "0.1.0")
        release = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").split("## [", 2)[1]
        self.assertIn("0.1.0", release)
        self.assertIn("preview of npm support", release)
        self.assertNotIn("not yet published", release)

    def test_publishing_runbook_covers_all_steps_packages_and_safe_identity(self):
        guide = (ROOT / "javascript/PUBLISHING.md").read_text(encoding="utf-8")
        steps = re.findall(r"(?m)^## (\d+)\. ", guide)
        self.assertEqual(steps, [str(number) for number in range(1, 10)])
        manifest = json.loads((ROOT / "javascript/package.json").read_text())
        for name in [manifest["name"], *manifest["optionalDependencies"]]:
            self.assertIn(f"`{name}`", guide)
        for required in ("account-level 2FA", "48 hours", "node-sdk.yml", "npm-v0.1.0",
                         "Prevent self-review", "unapproved", "never approve", "npm audit signatures",
                         "private development remote", "same tested artifact", "disallow tokens"):
            self.assertIn(required, guide)

    def test_documented_bootstrap_generator_writes_only_seven_dummy_packages(self):
        guide = (ROOT / "javascript/PUBLISHING.md").read_text(encoding="utf-8")
        generator = re.search(r"node - <<'NODE'\n(.*?)\nNODE", guide, re.DOTALL).group(1)
        manifest = json.loads((ROOT / "javascript/package.json").read_text())
        expected = {manifest["name"], *manifest["optionalDependencies"]}
        source_file = ROOT / "javascript/package.json"
        original = source_file.read_bytes()
        with tempfile.TemporaryDirectory(prefix="npm docs bootstrap ") as directory:
            result = subprocess.run(
                ["node", "-"], input=generator, text=True, capture_output=True,
                cwd=ROOT, env={**os.environ, "NPM_BOOTSTRAP_DIR": directory}, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            output = Path(directory)
            self.assertEqual({item.name for item in output.iterdir()}, expected)
            for name in expected:
                package = json.loads((output / name / "package.json").read_text())
                self.assertEqual(package["version"], "0.0.0-bootstrap")
                self.assertEqual(package["name"], name)
                self.assertFalse(package["private"])
                self.assertEqual(package["repository"], manifest["repository"])
                self.assertEqual(package["files"], ["README.md"])
                self.assertNotIn("scripts", package)
                self.assertIn("Do not approve", (output / name / "README.md").read_text())
        self.assertEqual(source_file.read_bytes(), original)

    def test_cargo_publishing_guide_documents_npm_trusted_publishing_setup(self):
        guide = (ROOT / "docs/PUBLISHING.md").read_text(encoding="utf-8")
        setup = guide.split("## npm publishing with GitHub Actions\n", 1)[1]
        setup = setup.split("## Independent terminal commands\n", 1)[0]
        manifest = json.loads((ROOT / "javascript/package.json").read_text())
        for name in [manifest["name"], *manifest["optionalDependencies"]]:
            self.assertIn(f"`{name}`", setup)
        for required in ("`mongodb`", "`kingfisher`", "`node-sdk.yml`", "`npm`",
                         "Allow npm publish", "48 hours", "id-token: write",
                         "npm-v0.1.0", "same tested artifact", "disallow tokens",
                         "Never approve", "../javascript/PUBLISHING.md"):
            self.assertIn(required, setup)

    def test_examples_walkthrough_links_every_new_recipe_and_states_effects(self):
        guide = (ROOT / "javascript/examples/README.md").read_text(encoding="utf-8")
        for name in ("quickstart.mjs", "custom-rules.mjs", "controlled-scan.mjs", "scan-project.mjs",
                     "archive-content.mjs", "git-scopes.mjs", "local-workflow.mjs", "typed-scan.mts"):
            self.assertIn(f"]({name})", guide)
            self.assertTrue((ROOT / "javascript/examples" / name).is_file())
        for contract in ("Working directory", "Side effects", "Success signal", "JSONL",
                         "original", "zero revocations", "byte offsets", "first-ever introduction"):
            self.assertIn(contract, guide)


if __name__ == "__main__":
    unittest.main()
