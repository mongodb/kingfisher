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
        self.assertIn("group: pypi-sdk-publish", publish)
        self.assertIn("skip-existing: true", publish)
        self.assertIn("pattern: python-*", publish)


if __name__ == "__main__":
    unittest.main()
