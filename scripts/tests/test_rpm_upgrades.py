"""Exercise disposable RPM upgrade test orchestration with mocked tools."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "rpm_upgrades", Path(__file__).parents[1] / "test-rpm-upgrades.py"
)
upgrades = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrades)


class RpmUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rpm upgrade fixture ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "Cargo.toml").write_text('[package]\nversion = "2.12.0"\n', encoding="utf-8")
        self.artifacts = self.root / "built packages"
        self.artifacts.mkdir()
        for arch in ("x64", "arm64"):
            (self.artifacts / f"kingfisher-linux-{arch}.rpm").write_bytes(b"corrected fixture")

    def invoke(self, arch, run):
        with patch.object(upgrades, "ROOT", self.root), \
             patch("sys.argv", ["test-rpm-upgrades.py", "--arch", arch,
                                "--package-dir", str(self.artifacts)]), \
             patch.object(upgrades.subprocess, "run", side_effect=run), patch("builtins.print"):
            upgrades.main()

    def test_both_historical_fixtures_and_architectures(self):
        for arch, target, platform in (
            ("x64", "x86_64-unknown-linux-musl", "linux/amd64"),
            ("arm64", "aarch64-unknown-linux-musl", "linux/arm64"),
        ):
            with self.subTest(arch=arch):
                identities = []
                commands = []
                fixture_directories = []

                def run(command, **kwargs):
                    commands.append(command)
                    self.assertTrue(kwargs["check"])
                    self.assertNotIn("shell", kwargs)
                    if command[0] == "cargo":
                        directory = kwargs["cwd"]
                        fixture_directories.append(directory)
                        self.assertEqual((directory / "corrected.rpm").read_bytes(), b"corrected fixture")
                        with (directory / "Cargo.toml").open("rb") as source:
                            fixture = tomllib.load(source)
                        identities.append((fixture["package"]["name"], fixture["package"]["version"]))
                        metadata = fixture["package"]["metadata"]["generate-rpm"]
                        self.assertEqual(metadata["name"], fixture["package"]["name"])
                        self.assertEqual(metadata["release"], "1")
                        self.assertEqual({asset["dest"] for asset in metadata["assets"]}, {
                            "/usr/bin/kingfisher", "/usr/share/doc/kingfisher/NOTICE",
                            "/usr/share/doc/kingfisher/THIRD_PARTY_NOTICES",
                        })
                        self.assertEqual(command[command.index("--target") + 1], target)
                        self.assertEqual(command[command.index("--auto-req") + 1], "disabled")
                    else:
                        self.assertEqual(command[:3], ["docker", "run", "--rm"])
                        self.assertEqual(command[command.index("--platform") + 1], platform)
                        self.assertIn("amazonlinux:2023", command)
                        self.assertTrue(command[command.index("--mount") + 1].endswith("readonly"))
                        shell = command[command.index("-c") + 1]
                        self.assertIn("dnf install -y /packages/legacy.rpm", shell)
                        self.assertIn("dnf install -y /packages/corrected.rpm", shell)
                        self.assertIn("Legacy package was not removed", shell)
                        self.assertIn("kingfisher --version", shell)
                        self.assertEqual(command[-1], "2.12.0")

                self.invoke(arch, run)
                self.assertEqual(identities, [("kingfisher", "2.7.0"), ("kingfisher-bin", "2.11.0")])
                self.assertEqual([command[0] for command in commands], ["cargo", "docker", "cargo", "docker"])
                self.assertTrue(all(not directory.exists() for directory in fixture_directories))

    def test_failed_packaging_or_transaction_stops_and_cleans_fixtures(self):
        for failed_tool in ("cargo", "docker"):
            with self.subTest(failed_tool=failed_tool):
                commands = []
                fixture_directories = []

                def run(command, **kwargs):
                    commands.append(command)
                    if "cwd" in kwargs:
                        fixture_directories.append(kwargs["cwd"])
                    if command[0] == failed_tool:
                        raise subprocess.CalledProcessError(1, command)

                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke("x64", run)
                self.assertEqual([command[0] for command in commands],
                                 ["cargo"] if failed_tool == "cargo" else ["cargo", "docker"])
                self.assertTrue(all(not directory.exists() for directory in fixture_directories))


if __name__ == "__main__":
    unittest.main()
