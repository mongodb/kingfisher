"""Guard Windows harness discovery and Python setup without compiling native code.

These are source/wiring contracts; actionlint checks YAML and Windows CI executes
both architectures. Run with unittest discovery from the repository root.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


def job(workflow, name):
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow,
    )
    if match is None:
        raise AssertionError(f"Missing workflow job: {name}")
    return match.group(1)


def step(body, name):
    match = re.search(
        rf"(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - |\Z)", body,
    )
    if match is None:
        raise AssertionError(f"Missing workflow step: {name}")
    return match.group(1)


class WindowsWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflows = ROOT / ".github/workflows"
        cls.windows = job((workflows / "ci.yml").read_text(encoding="utf-8"), "windows")
        cls.oracle = step(
            cls.windows, "Test native Git and Git for Windows oracle from PowerShell",
        )
        cls.wheels = job(
            (workflows / "python-sdk.yml").read_text(encoding="utf-8"), "wheels",
        )

    def test_harness_discovery_markers_name_existing_rust_tests(self):
        markers = re.findall(r"-match '\^([\w:]+): test\$'", self.oracle)
        self.assertEqual(markers, [
            "git_binary::tests::native_options_never_probe_a_git_installation_or_load_global_config",
            "scan_audit::tests::audit_counts_unique_reachable_commits_and_peels_packed_tags",
            "staged_scan_does_not_require_a_git_executable",
        ])
        for marker in markers:
            with self.subTest(marker=marker):
                parts = marker.split("::")
                source = (ROOT / "src" / f"{parts[0]}.rs" if len(parts) > 1
                          else ROOT / "tests/smoke_branch.rs")
                self.assertRegex(
                    source.read_text(encoding="utf-8"),
                    rf"#\[test\]\s+fn {re.escape(parts[-1])}\(",
                )
        self.assertNotIn("git_executable_override_is_literal_and_shared", self.oracle)

    def test_native_tests_and_git_oracle_both_run_without_skips(self):
        self.assertIn("if ($nativeTests -and $auditTests)", self.oracle)
        commands = re.findall(r"(?m)^\s+& \$harness\.FullName (\S+)$", self.oracle)
        self.assertEqual(commands, ["git_binary::tests::", "scan_audit::tests::"])
        for family, error in (
            ("git_binary::tests::", "Native Git regressions failed"),
            ("scan_audit::tests::", "Audit regressions against Git for Windows failed"),
        ):
            with self.subTest(family=family):
                self.assertRegex(
                    self.oracle,
                    rf"& \$harness\.FullName {re.escape(family)}\n"
                    rf"\s+if \(\$LASTEXITCODE -ne 0\) {{ throw '{re.escape(error)}' }}",
                )
        self.assertIn("if (-not $gitHarness) { throw", self.oracle)
        self.assertNotIn("--skip", self.oracle)
        self.assertNotIn("--ignored", self.oracle)
        self.assertNotIn("continue-on-error:", self.windows)

    def test_git_for_windows_is_selected_on_path_for_literal_git_oracles(self):
        self.assertIn("$version -match '\\.windows\\.'", self.oracle)
        self.assertIn("if (-not $gitBinary) { throw", self.oracle)
        path_selection = '$env:PATH = "$(Split-Path -Parent $gitBinary);$env:PATH"'
        self.assertIn(path_selection, self.oracle)
        self.assertLess(self.oracle.index(path_selection),
                        self.oracle.index("& $harness.FullName scan_audit::tests::"))
        self.assertNotRegex(self.oracle, r"\$env:KF_GIT_BINARY\s*=")
        audit_source = (ROOT / "src/scan_audit.rs").read_text(encoding="utf-8")
        self.assertIn('std::process::Command::new("git")', audit_source)

    def test_branch_and_staged_suite_is_validated_and_run_in_full(self):
        self.assertIn('$stagedCases = & $stagedHarness.FullName --list', self.oracle)
        self.assertIn("if ($LASTEXITCODE -ne 0 -or -not ($stagedCases -match", self.oracle)
        self.assertIn("if (-not $stagedHarness) { throw", self.oracle)
        self.assertRegex(
            self.oracle,
            r"(?m)^\s+& \$stagedHarness\.FullName\n"
            r"\s+if \(\$LASTEXITCODE -ne 0\) { throw 'Branch/staged scans with Git for Windows failed' }",
        )
        for target in ("x86_64-pc-windows-gnu", "aarch64-pc-windows-gnullvm"):
            self.assertIn(target, self.oracle)
        self.assertIn("make windows-test-${{ matrix.arch }}", self.windows)

    def test_python_arm64_bypasses_only_optional_msys2_package_cache(self):
        setup = re.search(
            r"(?ms)^      - uses: msys2/setup-msys2@[0-9a-f]{40}\n.*?(?=^      - |\Z)",
            self.wheels,
        )
        self.assertIsNotNone(setup)
        setup = setup.group()
        self.assertIn("if: runner.os == 'Windows'", setup)
        self.assertIn("          update: true", setup)
        self.assertIn("          path-type: inherit", setup)
        self.assertIn("          install: ${{ matrix.packages }} make git perl", setup)
        self.assertEqual(re.findall(r"(?m)^          cache: (.+)$", setup), [
            "${{ matrix.target != 'aarch64-pc-windows-gnullvm' }}",
        ])
        self.assertNotIn("continue-on-error:", self.wheels)
        build = step(self.wheels, "Build Windows wheel")
        self.assertIn("if: runner.os == 'Windows'", build)
        self.assertIn('maturin build --profile python-release --locked --target "$SDK_TARGET"', build)
        installed_tests = step(self.wheels, "Test installed wheel (no editable source imports)")
        self.assertIn("python -m pytest python/tests -q", installed_tests)
        self.assertNotIn("if:", installed_tests)


if __name__ == "__main__":
    unittest.main()
