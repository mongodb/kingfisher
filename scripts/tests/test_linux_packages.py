"""Check native Linux packages without requiring RPM/DPKG or installing anything."""

import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "linux_packages", Path(__file__).parents[1] / "check-linux-packages.py"
)
packages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packages)


def manifest(version="2.11.0"):
    assets = dict(packages.REQUIRED_ASSETS)
    return {
        "package": {
            "name": "kingfisher-bin", "version": version,
            "metadata": {
                "deb": {
                    "name": "kingfisher",
                    "assets": [[source, dest, "755" if source.startswith("target/") else "644"]
                               for source, dest in assets.items()],
                },
                "generate-rpm": {
                    "name": "kingfisher", "release": "1",
                    "obsoletes": {"kingfisher-bin": "<= 2.11.0-1"},
                    "provides": {"kingfisher-bin": "= 2.11.0-1"},
                    "assets": [{"source": source, "dest": dest,
                                "mode": "755" if source.startswith("target/") else "644"}
                               for source, dest in assets.items()],
                },
            },
        },
    }


class ManifestTests(unittest.TestCase):
    def test_accepts_canonical_names_independent_of_cargo_name(self):
        self.assertEqual(packages.validate_manifest(manifest()), "2.11.0")

    def test_future_releases_keep_fixed_legacy_alias(self):
        self.assertEqual(packages.validate_manifest(manifest("2.12.0")), "2.12.0")

    def test_rejects_original_package_key_bug(self):
        data = manifest()
        rpm = data["package"]["metadata"]["generate-rpm"]
        rpm["package"] = rpm.pop("name")
        with self.assertRaisesRegex(ValueError, r"generate-rpm\.package is invalid"):
            packages.validate_manifest(data)

    def test_rejects_invalid_package_key_even_with_correct_name(self):
        data = manifest()
        data["package"]["metadata"]["generate-rpm"]["package"] = "kingfisher"
        with self.assertRaisesRegex(ValueError, r"generate-rpm\.package is invalid"):
            packages.validate_manifest(data)

    def test_rejects_wrong_or_missing_native_name(self):
        for kind in ("deb", "generate-rpm"):
            for name in ("kingfisher-bin", None):
                with self.subTest(kind=kind, name=name):
                    data = manifest()
                    config = data["package"]["metadata"][kind]
                    if name is None:
                        del config["name"]
                    else:
                        config["name"] = name
                    with self.assertRaisesRegex(ValueError, "name must be kingfisher"):
                        packages.validate_manifest(data)

    def test_rejects_missing_or_changed_migration(self):
        for field, expected in (("obsoletes", "<="), ("provides", "=")):
            for value in (None, "*", f"{expected} 2.12.0-1", "< 2.11.0-1"):
                with self.subTest(field=field, value=value):
                    data = manifest("2.12.0")
                    rpm = data["package"]["metadata"]["generate-rpm"]
                    rpm[field] = {} if value is None else {"kingfisher-bin": value}
                    with self.assertRaisesRegex(ValueError, field):
                        packages.validate_manifest(data)

    def test_rejects_missing_or_wrong_rpm_release(self):
        for release in (None, "2", 1):
            with self.subTest(release=release):
                data = manifest()
                rpm = data["package"]["metadata"]["generate-rpm"]
                if release is None:
                    del rpm["release"]
                else:
                    rpm["release"] = release
                with self.assertRaisesRegex(ValueError, "release"):
                    packages.validate_manifest(data)

    def test_rejects_version_overrides_and_deb_revision(self):
        for kind in ("deb", "generate-rpm"):
            with self.subTest(kind=kind):
                data = manifest()
                data["package"]["metadata"][kind]["version"] = "2.7.0"
                with self.assertRaisesRegex(ValueError, "version must match"):
                    packages.validate_manifest(data)
        data = manifest()
        data["package"]["metadata"]["deb"]["revision"] = "2"
        with self.assertRaisesRegex(ValueError, "revision"):
            packages.validate_manifest(data)

    def test_rejects_missing_cargo_version(self):
        data = manifest()
        del data["package"]["version"]
        with self.assertRaisesRegex(ValueError, r"package\.version"):
            packages.validate_manifest(data)

    def test_rejects_missing_or_wrong_executable_and_notice_assets(self):
        for kind in ("deb", "generate-rpm"):
            for index in range(len(packages.REQUIRED_ASSETS)):
                for missing in (True, False):
                    with self.subTest(kind=kind, index=index, missing=missing):
                        data = manifest()
                        assets = data["package"]["metadata"][kind]["assets"]
                        if missing:
                            assets.pop(index)
                        elif kind == "deb":
                            assets[index][1] = "/wrong/path"
                        else:
                            assets[index]["dest"] = "/wrong/path"
                        with self.assertRaisesRegex(ValueError, "must install"):
                            packages.validate_manifest(data)

    def test_repository_keeps_cargo_library_and_binary_identities(self):
        root = Path(__file__).resolve().parents[2]
        with (root / "Cargo.toml").open("rb") as source:
            data = tomllib.load(source)
        self.assertEqual(data["package"]["name"], "kingfisher-bin")
        self.assertEqual(data["lib"]["name"], "kingfisher")
        self.assertIn("kingfisher", [binary["name"] for binary in data["bin"]])
        packages.validate_manifest(data)

    def test_rejects_wrong_executable_or_notice_permissions(self):
        for kind in ("deb", "generate-rpm"):
            for index in range(len(packages.REQUIRED_ASSETS)):
                with self.subTest(kind=kind, index=index):
                    data = manifest()
                    asset = data["package"]["metadata"][kind]["assets"][index]
                    if kind == "deb":
                        asset[2] = "600"
                    else:
                        asset["mode"] = "600"
                    with self.assertRaisesRegex(ValueError, "mode for"):
                        packages.validate_manifest(data)

    def test_rejects_duplicate_assets(self):
        for kind in ("deb", "generate-rpm"):
            with self.subTest(kind=kind):
                data = manifest()
                assets = data["package"]["metadata"][kind]["assets"]
                assets.append(copy.deepcopy(assets[0]))
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    packages.validate_manifest(data)

    def test_rejects_unaligned_extra_assets(self):
        data = manifest()
        data["package"]["metadata"]["deb"]["assets"].append(
            ["README.md", "/usr/share/doc/kingfisher/README.md", "644"]
        )
        with self.assertRaisesRegex(ValueError, "aligned"):
            packages.validate_manifest(data)

    def test_manifest_only_needs_no_artifacts_or_query_tools(self):
        for arch in ("x64", "arm64"):
            with self.subTest(arch=arch), \
                 patch.object(packages, "validate_manifest", return_value="2.11.0"), \
                 patch.object(packages.subprocess, "run") as run, patch("builtins.print"):
                self.assertEqual(packages.main(["--arch", arch, "--manifest-only"]), 0)
                run.assert_not_called()

    def test_manifest_only_accepts_no_architecture(self):
        with patch.object(packages, "validate_manifest", return_value="2.11.0"), \
             patch.object(packages.subprocess, "run") as run, patch("builtins.print"):
            self.assertEqual(packages.main(["--manifest-only"]), 0)
            run.assert_not_called()

    def test_full_check_requires_architecture(self):
        with patch("sys.stderr"), patch.object(packages.subprocess, "run") as run:
            with self.assertRaises(SystemExit) as error:
                packages.main([])
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()

    def test_cli_reports_manifest_failure(self):
        with patch.object(packages, "validate_manifest", side_effect=ValueError("invalid name")), \
             patch.object(packages.subprocess, "run") as run, patch("builtins.print") as output:
            self.assertEqual(packages.main(["--arch", "x64", "--manifest-only"]), 1)
            self.assertIn("invalid name", output.call_args.args[0])
            run.assert_not_called()

    def test_cli_default_and_explicit_package_directory(self):
        root = Path(packages.__file__).resolve().parents[1]
        for directory in (None, Path("custom packages")):
            argv = ["--arch", "arm64"]
            if directory is not None:
                argv.extend(["--package-dir", str(directory)])
            with self.subTest(directory=directory), \
                 patch.object(packages, "validate_manifest", return_value="2.11.0"), \
                 patch.object(packages, "check_packages") as check, patch("builtins.print"):
                self.assertEqual(packages.main(argv), 0)
                check.assert_called_once_with(directory or root / "target/release", "arm64", "2.11.0")


class WorkflowTests(unittest.TestCase):
    def test_release_notes_skip_unreleased_section(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn(r"/^## \[Unreleased\]/ { next }", workflow)

    def test_release_checks_headers_and_upgrades_for_both_architectures(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
        for arch in ("x64", "arm64"):
            with self.subTest(arch=arch):
                remainder = workflow.split(f"\n  linux-{arch}:\n", 1)[1]
                lines = []
                for line in remainder.splitlines():
                    if line.startswith("  ") and not line.startswith("   ") and line.strip():
                        break
                    lines.append(line)
                job = "\n".join(lines)
                # A job's nested keys have at least four spaces, whereas the
                # next job starts at two; avoid adding a YAML dependency.
                self.assertIn(f"scripts/check-linux-packages.py --arch {arch}", job)
                self.assertIn(f"scripts/test-rpm-upgrades.py --arch {arch}", job)
                self.assertLess(job.index("scripts/check-linux-packages.py"),
                                job.index("name: Move artifact to dist"))
                self.assertLess(job.index("scripts/test-rpm-upgrades.py"),
                                job.index("name: Move artifact to dist"))


class PackageHeaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="linux packages ")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        for arch in ("x64", "arm64"):
            for suffix in ("deb", "rpm"):
                (self.directory / f"kingfisher-linux-{arch}.{suffix}").touch()

    def outputs(self, arch="x64", version="2.11.0"):
        deb_arch, rpm_arch = packages.ARCHITECTURES[arch]
        return [
            f"kingfisher\t{version}-1\t{deb_arch}\n",
            f"kingfisher\t{version}\t1\t{rpm_arch}\n",
            "kingfisher-bin <= 2.11.0-1\n",
            f"kingfisher = {version}-1\nkingfisher({rpm_arch}) = {version}-1\n"
            "kingfisher-bin = 2.11.0-1\n",
        ]

    def check(self, outputs, arch="x64", version="2.11.0"):
        replies = [subprocess.CompletedProcess([], 0, stdout=output, stderr="") for output in outputs]
        with patch.object(packages.subprocess, "run", side_effect=replies) as run:
            packages.check_packages(self.directory, arch, version)
        return run

    def test_accepts_both_architectures_and_queries_only_headers(self):
        for arch in ("x64", "arm64"):
            with self.subTest(arch=arch):
                run = self.check(self.outputs(arch), arch)
                commands = [call.args[0] for call in run.call_args_list]
                self.assertEqual(len(commands), 4)
                self.assertEqual(commands[0][:2], ["dpkg-deb", "--show"])
                for command in commands[1:]:
                    self.assertEqual(command[:2], ["rpm", "-qp"])
                self.assertEqual(commands[2][2], "--obsoletes")
                self.assertEqual(commands[3][2], "--provides")
                for command in commands:
                    self.assertEqual(Path(command[-1]).parent, self.directory)
                    self.assertIn(f"linux-{arch}.", command[-1])
                for call in run.call_args_list:
                    self.assertTrue(call.kwargs["check"])
                    self.assertTrue(call.kwargs["text"])
                    self.assertNotIn("shell", call.kwargs)

    def test_future_release_headers_keep_fixed_migration_alias(self):
        self.check(self.outputs(version="2.12.0"), version="2.12.0")

    def test_rejects_bad_deb_headers(self):
        for header in (
            "kingfisher-bin\t2.11.0-1\tamd64", "kingfisher\t2.7.0-1\tamd64",
            "kingfisher\t2.11.0-1\tarm64", "kingfisher\t2.11.0\tamd64", "malformed",
        ):
            with self.subTest(header=header):
                outputs = self.outputs()
                outputs[0] = header
                with self.assertRaisesRegex(ValueError, "DEB header mismatch"):
                    self.check(outputs)

    def test_rejects_bad_rpm_headers(self):
        for header in (
            "kingfisher-bin\t2.11.0\t1\tx86_64", "kingfisher\t2.7.0\t1\tx86_64",
            "kingfisher\t2.11.0\t2\tx86_64", "kingfisher\t2.11.0\t1\taarch64", "malformed",
        ):
            with self.subTest(header=header):
                outputs = self.outputs()
                outputs[1] = header
                with self.assertRaisesRegex(ValueError, "RPM header mismatch"):
                    self.check(outputs)

    def test_rejects_missing_unbounded_or_wrong_migration_headers(self):
        for index, label, operator in ((2, "Obsoletes", "<="), (3, "Provides", "=")):
            valid = f"kingfisher-bin {operator} 2.11.0-1\n"
            for output in (
                "", "kingfisher = 2.11.0-1", "kingfisher-bin", valid + valid,
                f"kingfisher-bin {operator} 2.12.0-1", "kingfisher-bin < 2.11.0-1",
            ):
                with self.subTest(label=label, output=output):
                    outputs = self.outputs()
                    outputs[index] = output
                    with self.assertRaisesRegex(ValueError, label):
                        self.check(outputs)

    def test_missing_artifact_fails_before_any_query(self):
        with patch.object(packages.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "Missing Linux package"):
                packages.check_packages(self.directory / "missing", "x64", "2.11.0")
            run.assert_not_called()

    def test_reports_missing_query_tool(self):
        with patch.object(packages.subprocess, "run", side_effect=FileNotFoundError("dpkg-deb")):
            with self.assertRaisesRegex(ValueError, "tool not found: dpkg-deb"):
                packages.check_packages(self.directory, "x64", "2.11.0")

    def test_reports_nonzero_query_exit(self):
        error = subprocess.CalledProcessError(1, ["dpkg-deb"], stderr="invalid package")
        with patch.object(packages.subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(ValueError, "query failed: invalid package"):
                packages.check_packages(self.directory, "x64", "2.11.0")


if __name__ == "__main__":
    unittest.main()
