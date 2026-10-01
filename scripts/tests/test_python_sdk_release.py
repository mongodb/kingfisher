"""Check main-merge SDK publishing without performing any registry writes."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PythonSdkReleaseTests(unittest.TestCase):
    def test_main_pushes_publish_tested_artifacts_only_in_upstream(self):
        workflow = (ROOT / ".github/workflows/python-sdk.yml").read_text(encoding="utf-8")
        triggers = workflow.split("permissions:", 1)[0]
        self.assertIn("branches: [main]", triggers)
        publish = workflow.split("  publish:\n", 1)[1]
        condition = next(line for line in publish.splitlines() if line.strip().startswith("if:"))
        for guard in ("github.repository == 'mongodb/kingfisher'",
                      "github.event_name == 'push'", "github.ref == 'refs/heads/main'"):
            self.assertIn(guard, condition)
        self.assertIn("needs: [wheels, source-and-msrv]", publish)
        self.assertIn("name: pypi-sdk", publish)
        self.assertIn("group: pypi-sdk-publish-${{ github.run_id }}", publish)
        self.assertIn("skip-existing: true", publish)
        self.assertIn("pattern: python-*", publish)

    def test_release_builds_do_not_replace_other_pending_releases(self):
        workflow = (ROOT / ".github/workflows/python-sdk.yml").read_text(encoding="utf-8")
        concurrency = workflow.split("concurrency:\n", 1)[1].split("env:\n", 1)[0]
        self.assertIn(
            "group: python-sdk-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
            concurrency,
        )
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", concurrency)


if __name__ == "__main__":
    unittest.main()
