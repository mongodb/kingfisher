"""Keep Node SDK examples and npm setup instructions executable and consistent.

No npm authentication, trust changes, tags, or registry writes are performed.
"""
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NodeSdkDocsTests(unittest.TestCase):
    def test_npm_sdk_is_documented_as_0_1_preview(self):
        for name in (
            "README.md", "CONTRIBUTING.md", "javascript/README.md",
            "docs/JAVASCRIPT.md", "docs/ARCHITECTURE.md",
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

    def test_sdk_docs_link_to_supported_npm_publishing_guidance(self):
        # The separate javascript publishing guide was intentionally removed.
        # Retain one canonical setup guide rather than recreating its bootstrap script.
        target = "PUBLISHING.md#npm-publishing-with-github-actions"
        for name in ("README.md", "CONTRIBUTING.md", ".github/RELEASING.md",
                     "javascript/AGENTS.md", "javascript/README.md",
                     "javascript/examples/README.md", "docs/INDEX.md", "docs/JAVASCRIPT.md",
                     "llms.txt", "docs-site/docs/llms.txt",
                     "docs-site/docs/reference/documentation-index.md",
                     "docs-site/docs/reference/javascript-bindings.md"):
            with self.subTest(document=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn(target, text)
                self.assertNotIn("javascript/PUBLISHING.md", text)
        self.assertIn("## npm publishing with GitHub Actions\n",
                      (ROOT / "docs/PUBLISHING.md").read_text(encoding="utf-8"))

    def test_cargo_publishing_guide_documents_npm_trusted_publishing_setup(self):
        guide = (ROOT / "docs/PUBLISHING.md").read_text(encoding="utf-8")
        setup = guide.split("## npm publishing with GitHub Actions\n", 1)[1]
        setup = setup.split("## Independent terminal commands\n", 1)[0]
        manifest = json.loads((ROOT / "javascript/package.json").read_text())
        for name in [manifest["name"], *manifest["optionalDependencies"]]:
            self.assertIn(f"`{name}`", setup)
        normalized = " ".join(setup.split())
        for required in ("`mongodb`", "`kingfisher`", "`node-sdk.yml`", "`npm`",
                         "Allow npm publish", "48 hours", "id-token: write",
                         "npm-v0.1.0", "same tested artifact", "disallow tokens",
                         "account-level 2FA", "Prevent self-review", "unapproved",
                         "Never approve", "npm audit signatures", "private development remote",
                         "GitHub-hosted runner", "Do not add an npm write-token secret"):
            self.assertIn(required, normalized)
        self.assertNotIn("javascript/PUBLISHING.md", guide)

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
