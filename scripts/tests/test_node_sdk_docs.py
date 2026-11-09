"""Keep Node SDK examples and npm setup instructions executable and consistent.

No npm authentication, trust changes, tags, or registry writes are performed.
"""
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class NodeSdkDocsTests(unittest.TestCase):
    def test_current_npm_sdk_is_documented_as_1_0_1_stable(self):
        # The root README ships in the independently versioned CLI crate. SDK-only
        # releases update the canonical SDK guides without rewriting that package.
        for name in (
            "CONTRIBUTING.md", "javascript/README.md",
            "docs/JAVASCRIPT.md", "docs/ARCHITECTURE.md",
            "docs/DEPLOYMENT.md", "docs/PROJECT.md",
            "llms.txt", "docs-site/overrides/home.html",
            "docs-site/docs/llms.txt", "docs-site/docs/reference/javascript-bindings.md",
        ):
            with self.subTest(document=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("1.0.1", text)
                self.assertIn("stable", text.lower())
                self.assertNotIn("0.1.0", text)
                self.assertNotRegex(
                    text.lower(), r"unpublished|not[- ](?:yet[- ])?published|not yet on npm"
                )
        manifest = json.loads((ROOT / "javascript/package.json").read_text())
        self.assertEqual(manifest["version"], "1.0.1")

    def test_workbench_dependency_matches_current_sdk_version(self):
        sdk = json.loads((ROOT / "javascript/package.json").read_text())
        directory = ROOT / "javascript/examples/kingfisher-workbench"
        example = json.loads((directory / "package.json").read_text())
        self.assertEqual(example["dependencies"][sdk["name"]], sdk["version"])
        self.assertIn(f'"{sdk["name"]}": "{sdk["version"]}"',
                      (directory / "README.md").read_text(encoding="utf-8"))

    def test_v2_17_release_retains_original_npm_preview_history(self):
        # Stable SDK docs must not rewrite the earlier CLI release's preview entry.
        for name in ("CHANGELOG.md", "docs-site/docs/changelog.md"):
            with self.subTest(document=name):
                changelog = (ROOT / name).read_text(encoding="utf-8")
                release = changelog.split("## [v2.17.0]", 1)[1].split("## [", 1)[0]
                self.assertIn("SDK 0.1.0 as a\n  preview of npm support", release)
                self.assertNotIn("not yet published", release)
                self.assertEqual(changelog.count("preview of npm support"), 1)
                self.assertNotIn("preview of npm support", changelog.split("## [v2.17.0]", 1)[0])

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
                         "npm-v1.0.0", "npm-v1.0.1", "tag unchanged", "original commit",
                         "same tested artifact", "disallow tokens",
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
