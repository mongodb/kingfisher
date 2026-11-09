"""Check native SDK release guards without GitHub or npm registry writes."""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]


def job(workflow, name):
    match = re.search(rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", workflow)
    if match is None:
        raise AssertionError(f"Missing workflow job {name}")
    return match.group(1)


def needed_jobs(body):
    match = re.search(r"(?m)^    needs: (.+)$", body)
    if match is None:
        raise AssertionError("Missing job dependencies")
    return {name.strip() for name in match.group(1).strip("[]").split(",")}


class NodeSdkReleaseTests(unittest.TestCase):
    def test_only_upstream_sdk_tag_pushes_publish(self):
        workflow = (ROOT / ".github/workflows/node-sdk.yml").read_text()
        triggers = workflow.split("permissions:", 1)[0]
        self.assertIn("tags: ['npm-v*']", triggers)
        publish = job(workflow, "publish")
        condition = next(line for line in publish.splitlines() if line.strip().startswith("if:"))
        for guard in ("github.repository == 'mongodb/kingfisher'", "github.event_name == 'push'",
                      "startsWith(github.ref, 'refs/tags/npm-v')"):
            self.assertIn(guard, condition)
        self.assertTrue({"package", "verify"}.issubset(needed_jobs(publish)))
        self.assertIn("git merge-base --is-ancestor HEAD origin/main", publish)
        self.assertIn("run: npm run publish:registry", publish)

    def test_publisher_downloads_tested_artifacts_and_uses_oidc_only(self):
        workflow = (ROOT / ".github/workflows/node-sdk.yml").read_text()
        publish = job(workflow, "publish")
        self.assertIn("environment: npm", publish)
        self.assertIn("id-token: write", publish)
        self.assertIn("npm@11.21.1", publish)
        self.assertIn("node-version: '24.22.2'", publish)
        self.assertIn("package-manager-cache: false", publish)
        self.assertIn("name: node-sdk-registry-staging", publish)
        self.assertIn("path: javascript/release", publish)
        self.assertNotIn("NPM_TOKEN", publish)
        self.assertNotIn("NODE_AUTH_TOKEN", publish)
        self.assertNotIn("npm run build", publish)
        self.assertIn("cancel-in-progress: false", publish)
        for name in ("source", "build", "package", "verify"):
            self.assertNotIn("id-token: write", job(workflow, name))
            self.assertNotIn("environment: npm", job(workflow, name))

    def test_source_and_all_target_checks_gate_package_staging(self):
        workflow = (ROOT / ".github/workflows/node-sdk.yml").read_text()
        source = job(workflow, "source")
        build = job(workflow, "build")
        package = job(workflow, "package")
        self.assertIn("crates/kingfisher-node/Cargo.toml", source)
        self.assertIn("npm-v${sdk.version}", source)
        self.assertIn("git merge-base --is-ancestor HEAD origin/main", source)
        self.assertIn("needs: source", build)
        self.assertIn("needs: build", package)
        self.assertIn("npm run check:release", package)
        self.assertIn("npm run test:package", package)
        for target in ("x86_64-apple-darwin", "aarch64-apple-darwin",
                       "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                       "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"):
            self.assertIn(target, build)
        self.assertIn("windows-11-vs2026-arm", build)
        self.assertNotIn("windows-native.ps1", workflow)
        self.assertNotIn("HYPERSCAN_ROOT", build)

    def test_all_hosts_consume_the_same_sealed_archives_before_publication(self):
        workflow = (ROOT / ".github/workflows/node-sdk.yml").read_text()
        source = job(workflow, "source")
        package = job(workflow, "package")
        verify = job(workflow, "verify")
        self.assertIn("make check-notices", source)
        self.assertEqual(needed_jobs(verify), {"package"})
        self.assertLess(package.index("npm run pack:release"), package.index("npm run test:package"))
        self.assertLess(package.index("npm run test:package"), package.index("actions/upload-artifact@"))
        for host in ("macos-15-intel", "macos-15", "ubuntu-22.04", "ubuntu-22.04-arm",
                     "windows-2022", "windows-11-vs2026-arm"):
            self.assertRegex(verify, rf"(?<![\w-]){re.escape(host)}(?![\w-])")
        self.assertIn("name: node-sdk-registry-staging", verify)
        self.assertIn("path: javascript/release", verify)
        self.assertLess(verify.index("actions/download-artifact@"), verify.index("npm run test:package"))
        for runtime in ("22.13.0", "22.23.4", "24.0.0", "24.22.2", "26.0.0", "26.13.0"):
            self.assertIn(f"node-version: '{runtime}'", verify)
            self.assertIn(f"node-version: '{runtime}'", job(workflow, "build"))
        self.assertEqual(verify.count("run: npm run test:package"), 6)
        for body in (verify, job(workflow, "publish")):
            self.assertNotIn("npm run pack:release", body)
            self.assertNotRegex(body, r"\bnpm\s+pack\b")
            self.assertNotIn("npm run build", body)

    def test_release_native_runtime_baselines_are_explicit_and_audited(self):
        build = job((ROOT / ".github/workflows/node-sdk.yml").read_text(), "build")
        for host, target in (("ubuntu-22.04", "x86_64-unknown-linux-gnu"),
                             ("ubuntu-22.04-arm", "aarch64-unknown-linux-gnu")):
            self.assertIn(f"os: {host}, target: {target}", build)
        self.assertIn("node scripts/check-linux-abi.cjs kingfisher_sdk.*.node", build)
        self.assertIn("NATIVE_TARGET: ${{ matrix.target }}", build)
        self.assertIn("$env:NATIVE_TARGET.StartsWith('aarch64')", build)
        self.assertNotIn("'${{ matrix.target }}'.StartsWith", build)
        self.assertIn("-vcvars_ver=14.44", build)
        self.assertIn("Expected MSVC 14.44", build)
        self.assertIn("node-version: '22.13.0'", build)
        minimum = build[build.index("node-version: '22.13.0'"):].split("      - uses:", 1)[0]
        self.assertIn("npm test", minimum)
        self.assertIn("npm run test:types", minimum)

    def test_all_native_and_sealed_runtime_installs_use_the_safe_wrapper(self):
        workflow = (ROOT / ".github/workflows/node-sdk.yml").read_text()
        for name in ("build", "verify"):
            with self.subTest(job=name):
                body = job(workflow, name)
                self.assertEqual(body.count("uses: ./.github/actions/setup-node"), 6)
                self.assertNotIn("uses: actions/setup-node@", body)
                self.assertEqual(re.findall(r"node-version: '([^']+)'", body), [
                    "22.23.4", "24.22.2", "22.13.0", "24.0.0", "26.0.0", "26.13.0",
                ])
        for name in ("source", "package", "publish"):
            self.assertIn("actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
                          job(workflow, name))
        self.assertIn("cache: npm", job(workflow, "build"))
        self.assertIn("cache-dependency-path: javascript/package-lock.json", job(workflow, "build"))
        self.assertIn("if: runner.os == 'Windows'\n        working-directory: .\n"
                      "        run: python -X utf8 -m unittest discover -s scripts/tests "
                      "-p test_node_sdk_release.py -v", job(workflow, "build"))
        triggers = workflow.split("permissions:", 1)[0]
        self.assertEqual(triggers.count("'.github/actions/setup-node/**'"), 2)

    def test_archive_workaround_is_scoped_to_each_arm64_windows_installer(self):
        action = (ROOT / ".github/actions/setup-node/action.yml").read_text()
        selector, installer = action.split("    - name: Set up the pinned Node runtime\n", 1)
        self.assertIn("if: runner.os == 'Windows' && runner.arch == 'ARM64'", selector)
        self.assertIn("shell: powershell", selector)
        self.assertIn("Get-Command powershell.exe -CommandType Application -ErrorAction Stop", selector)
        self.assertIn("$_.Trim().Trim", selector)
        self.assertIn("Test-Path -LiteralPath (Join-Path $directory 'pwsh.exe')", selector)
        self.assertNotIn("GITHUB_ENV", action)
        self.assertNotIn("GITHUB_PATH", action)
        self.assertNotIn("continue-on-error", action)
        self.assertIn("uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38", installer)
        self.assertIn("env: ${{ fromJSON(steps.extractor.outputs.env || '{}') }}", installer)
        for name in ("node-version", "cache", "cache-dependency-path", "package-manager-cache"):
            self.assertIn(f"{name}: ${{{{ inputs.{name} }}}}", installer)
        self.assertIn("default: 'true'", selector)

    @unittest.skipUnless(os.name == "nt", "The archive selector uses Windows PowerShell")
    def test_windows_selector_preserves_compiler_and_node_paths_and_hides_all_pwsh(self):
        powershell = shutil.which("powershell")
        self.assertIsNotNone(powershell, "Windows PowerShell is required by tool-cache's fallback")
        action = (ROOT / ".github/actions/setup-node/action.yml").read_text()
        script = textwrap.dedent(action.split("      run: |\n", 1)[1].split("    - name:", 1)[0])
        with tempfile.TemporaryDirectory(prefix="kingfisher Node extractor ") as temporary:
            root = Path(temporary)
            compiler, node = root / "VS 14.44", root / "Node 22"
            pwsh_directories = [root / "PowerShell 7", root / "Other PowerShell"]
            for directory in (compiler, node, *pwsh_directories):
                directory.mkdir()
            for directory in pwsh_directories:
                (directory / "pwsh.exe").write_bytes(b"fixture, never executed")
            retained = [str(Path(powershell).parent), str(compiler), str(node)]
            hidden = [str(pwsh_directories[0]) + "\\", str(pwsh_directories[0]).upper(),
                      '"' + str(pwsh_directories[1]) + '\\"']
            for index, entries in enumerate((retained, retained + hidden)):
                with self.subTest(pwsh_present=bool(index)):
                    output = root / f"output-{index}.txt"
                    result = subprocess.run([
                        powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
                        "-ExecutionPolicy", "Bypass", "-Command", script,
                    ], env={**os.environ, "PATH": ";".join(entries), "GITHUB_OUTPUT": str(output)},
                        capture_output=True, timeout=30, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                    line = output.read_text(encoding="utf-8-sig").strip()
                    self.assertTrue(line.startswith("env="))
                    self.assertEqual(json.loads(line.removeprefix("env=")), {"PATH": ";".join(retained)})

    def test_fuzz_lockfile_tracks_workspace_crate_versions(self):
        lock = tomllib.loads((ROOT / "fuzz/Cargo.lock").read_text())
        for crate in ("core", "rules", "scanner"):
            manifest = tomllib.loads((ROOT / f"crates/kingfisher-{crate}/Cargo.toml").read_text())
            package = manifest["package"]
            with self.subTest(crate=package["name"]):
                versions = [entry["version"] for entry in lock["package"]
                            if entry["name"] == package["name"] and "source" not in entry]
                self.assertEqual(versions, [package["version"]])

    def test_native_dependency_and_cache_identity_pins_match_published_release(self):
        root = tomllib.loads((ROOT / "Cargo.toml").read_text())
        rules = tomllib.loads((ROOT / "crates/kingfisher-rules/Cargo.toml").read_text())
        self.assertEqual(root["workspace"]["dependencies"]["kingfisher-vectorscan"], "=0.1.4")
        self.assertEqual(rules["dependencies"]["kingfisher-vectorscan-sys"], "=0.1.4")
        expected = {"kingfisher-vectorscan": "0.1.4", "kingfisher-vectorscan-sys": "0.1.4"}
        for name in ("Cargo.lock", "fuzz/Cargo.lock"):
            lock = tomllib.loads((ROOT / name).read_text())
            versions = {package["name"]: package["version"] for package in lock["package"]
                        if package["name"] in expected}
            self.assertEqual(versions, expected, name)
        cache = (ROOT / "crates/kingfisher-rules/src/rules_database.rs").read_text()
        constants = dict(re.findall(r'^const (CACHE_VECTORSCAN_\w+_VERSION): &str = "([^"]+)";',
                                    cache, flags=re.MULTILINE))
        self.assertEqual(constants, {"CACHE_VECTORSCAN_BINDING_VERSION": expected["kingfisher-vectorscan"],
                                     "CACHE_VECTORSCAN_SYS_VERSION": expected["kingfisher-vectorscan-sys"]})
        self.assertIn('"binding={CACHE_VECTORSCAN_BINDING_VERSION};sys={CACHE_VECTORSCAN_SYS_VERSION};runtime={}"', cache)
        self.assertIn("kingfisher_vectorscan::version()", cache)


if __name__ == "__main__":
    unittest.main()
