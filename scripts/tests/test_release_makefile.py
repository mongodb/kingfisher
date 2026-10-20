"""Check release subcommand routing without running release scripts or GitHub writes."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAKE = shutil.which("make")


@unittest.skipUnless(MAKE, "GNU Make is required to exercise Makefile routing")
class ReleaseMakefileTests(unittest.TestCase):
    def run_make(self, *args):
        env = os.environ.copy()
        for name in ("VERSION", "MAKEFLAGS", "MAKEOVERRIDES", "RELEASE_PACKAGE"):
            env.pop(name, None)
        return subprocess.run(
            [MAKE, "--no-print-directory", "--dry-run", *args],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=30,
        )

    def test_cli_release_keeps_existing_versioned_entrypoint(self):
        result = self.run_make("release", "VERSION=2.14.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('python3 scripts/release.py --version "$KINGFISHER_RELEASE_VERSION"', result.stdout)
        self.assertNotIn("scripts/release-packages.py", result.stdout)

    def test_package_selectors_infer_versions_and_execute_only_once_in_parallel(self):
        for package in ("crates", "kingfisher-secret-scanner"):
            for goals in (("release", package), (package, "release")):
                with self.subTest(goals=goals):
                    result = self.run_make("--jobs=2", *goals)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    command = f"python3 scripts/release-packages.py {package}"
                    self.assertEqual(result.stdout.count(command), 1, result.stdout)
                    self.assertIn('--remote "$KINGFISHER_RELEASE_REMOTE"', result.stdout)
                    self.assertNotIn("scripts/release.py", result.stdout)
                    self.assertNotIn("--version", result.stdout)

    def test_ambiguous_or_unknown_goals_fail_before_release_commands(self):
        for args in (
            ("crates",),
            ("kingfisher-secret-scanner",),
            ("release", "crates", "kingfisher-secret-scanner"),
            ("release", "crates", "tests"),
            ("release", "kingfisher-secret-scanner", "VERSION=1.5.0"),
            ("release", "crates", "VERSION=2.14.0"),
            ("release", "unknown-package", "VERSION=2.14.0"),
            ("release", "help", "VERSION=2.14.0"),
        ):
            with self.subTest(args=args):
                result = self.run_make(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("python3 scripts/release", result.stdout)
                self.assertIn("release", result.stderr)


if __name__ == "__main__":
    unittest.main()
