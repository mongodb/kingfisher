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
