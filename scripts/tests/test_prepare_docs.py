"""Keep repository documentation links valid in generated MkDocs pages."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "prepare_docs", ROOT / "docs-site/scripts/prepare-docs.py"
)
prepare_docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_docs)


class PrepareDocsTests(unittest.TestCase):
    def test_javascript_guide_and_source_links_are_mapped(self):
        self.assertIn("JAVASCRIPT.md", prepare_docs.DOC_MAP)
        self.assertEqual(
            prepare_docs.rewrite_links("[guide](JAVASCRIPT.md#scan-content)"),
            "[guide](../reference/javascript-bindings.md#scan-content)",
        )
        self.assertEqual(
            prepare_docs.rewrite_links("[source](../javascript) [example](../javascript/examples/content.cjs)"),
            "[source](https://github.com/mongodb/kingfisher/tree/main/javascript) "
            "[example](https://github.com/mongodb/kingfisher/blob/main/javascript/examples/content.cjs)",
        )

    def test_source_images_use_raw_bytes_but_normal_links_use_blob_viewer(self):
        path = "javascript/examples/kingfisher-workbench/screenshots/report-overview.png"
        raw_url = f"https://raw.githubusercontent.com/mongodb/kingfisher/main/{path}"
        blob_url = f"https://github.com/mongodb/kingfisher/blob/main/{path}"
        for root_level in (False, True):
            for prefix in ("", "../"):
                with self.subTest(root_level=root_level, prefix=prefix):
                    self.assertEqual(
                        prepare_docs.rewrite_links(
                            f'![synthetic findings]({prefix}{path} "Workbench") '
                            f"[screenshot]({prefix}{path}#preview)",
                            root_level=root_level,
                        ),
                        f'![synthetic findings]({raw_url} "Workbench") '
                        f"[screenshot]({blob_url}#preview)",
                    )

    def test_javascript_frontmatter_is_stable_when_regenerated(self):
        destination, title, description = prepare_docs.DOC_MAP["JAVASCRIPT.md"]
        with tempfile.TemporaryDirectory(prefix="SDK docs fixture ") as temporary:
            root = Path(temporary)
            source = root / "JAVASCRIPT.md"
            source.write_text(
                "# SDK\n\n![showcase](../javascript/examples/workbench/report.png)\n",
                encoding="utf-8",
            )
            target = root / destination
            with patch.object(prepare_docs, "DOCS_DST", str(root)):
                prepare_docs.process_file(str(source), str(target), title, description)
            generated = target.read_text(encoding="utf-8")
            frontmatter = generated.split("---", 2)[1]
            self.assertIn('title: "JavaScript and TypeScript SDK"', frontmatter)
            self.assertIn("stable Node SDK (1.0.0)", frontmatter)
            self.assertNotIn("preview", frontmatter)
            self.assertNotIn("0.1.0", frontmatter)
            self.assertIn(
                "![showcase](https://raw.githubusercontent.com/mongodb/kingfisher/main/"
                "javascript/examples/workbench/report.png)",
                generated,
            )

    def test_nested_pages_keep_existing_relative_links(self):
        for source, destination in prepare_docs.LINK_REWRITES.items():
            with self.subTest(source=source):
                self.assertEqual(
                    prepare_docs.rewrite_links(f"[guide]({source}#section)"),
                    f"[guide]({destination}#section)",
                )

    def test_root_pages_rewrite_mapped_docs_without_parent_prefix(self):
        for source, destination in prepare_docs.LINK_REWRITES.items():
            with self.subTest(source=source):
                self.assertEqual(
                    prepare_docs.rewrite_links(f"[guide]({source}#section)", root_level=True),
                    f"[guide]({destination.removeprefix('../')}#section)",
                )

    def test_root_links_preserve_migration_anchor(self):
        for source in ("LIBRARY.md", "./LIBRARY.md", "docs/LIBRARY.md"):
            with self.subTest(source=source):
                self.assertEqual(
                    prepare_docs.rewrite_links(
                        f"[Rust migration guide]({source}#migrating-to-rules-and-scanner-20)",
                        root_level=True,
                    ),
                    "[Rust migration guide](reference/library.md#migrating-to-rules-and-scanner-20)",
                )

    def test_root_special_links_use_root_relative_destinations(self):
        content = (
            "[README](../README.md) [changelog](../CHANGELOG.md) "
            "![chart](./runtime-comparison.png)"
        )
        self.assertEqual(
            prepare_docs.rewrite_links(content, root_level=True),
            "[README](getting-started/quick-start.md) [changelog](changelog.md) "
            "![chart](assets/images/runtime-comparison.png)",
        )

    def test_root_source_documents_preserve_anchors(self):
        content = (
            "[notices](../CONTRIBUTING.md#third-party-license-notices) "
            "[build](../CONTRIBUTING.md#javascripttypescript-sdk-development) "
            "[guidance](../AGENTS.md#scope) [security](../SECURITY.md) [license](../LICENSE)"
        )
        for root_level in (False, True):
            with self.subTest(root_level=root_level):
                self.assertEqual(
                    prepare_docs.rewrite_links(content, root_level=root_level),
                    content.replace("](../", "](https://github.com/mongodb/kingfisher/blob/main/"),
                )

    def test_provider_contract_links_resolve_to_repository_sources(self):
        path = "crates/kingfisher-rules/data/revocation-sources.md#provider-contracts"
        expected = f"[sources](https://github.com/mongodb/kingfisher/blob/main/{path})"
        for target in ("revocation-sources.md#provider-contracts", "../" + path, path):
            for root_level in (False, True):
                with self.subTest(target=target, root_level=root_level):
                    self.assertEqual(
                        prepare_docs.rewrite_links(f"[sources]({target})", root_level=root_level),
                        expected,
                    )

    def test_external_links_and_inline_source_paths_remain_unchanged(self):
        content = (
            "[source](https://github.com/mongodb/kingfisher/blob/main/docs/LIBRARY.md#section) "
            "`docs/LIBRARY.md`"
        )
        self.assertEqual(prepare_docs.rewrite_links(content, root_level=True), content)

    def test_copy_changelog_rewrites_links_without_modifying_source(self):
        with tempfile.TemporaryDirectory(prefix="docs fixture ") as temporary:
            root = Path(temporary)
            destination = root / "site-docs"
            destination.mkdir()
            source = root / "CHANGELOG.md"
            content = (
                "# Changelog\n\n"
                "[Rust migration guide](docs/LIBRARY.md#migrating-to-rules-and-scanner-20)\n"
            )
            source.write_text(content, encoding="utf-8")
            with patch.object(prepare_docs, "REPO_ROOT", str(root)), \
                 patch.object(prepare_docs, "DOCS_DST", str(destination)):
                prepare_docs.copy_changelog()
            generated = (destination / "changelog.md").read_text(encoding="utf-8")
            self.assertIn('title: "Changelog"', generated)
            self.assertIn(
                "[Rust migration guide](reference/library.md#migrating-to-rules-and-scanner-20)",
                generated,
            )
            self.assertNotIn("](docs/LIBRARY.md", generated)
            self.assertEqual(source.read_text(encoding="utf-8"), content)


if __name__ == "__main__":
    unittest.main()
