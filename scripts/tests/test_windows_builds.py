"""Check Windows native dependency contracts without installing packages or Rust targets."""

from pathlib import Path
import re
import shlex
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]


def windows_recipe(architecture):
    """Read one Windows native build/test recipe without executing it."""
    lines = (ROOT / "Makefile").read_text(encoding="utf-8").splitlines(keepends=True)
    header = f"windows-{architecture}:"
    start = next(index for index, line in enumerate(lines) if line.startswith(header))
    body = []
    for line in lines[start + 1:]:
        if not line.startswith("\t"):
            break
        body.append(line)
    return "".join(body)


def package_installs(recipe):
    """Extract package arguments, not comments or the command-availability check."""
    installs = []
    for match in re.finditer(r"(?m)^[ \t]*pacman[ \t]+([^;]+);", recipe):
        arguments = shlex.split(match.group(1).replace("\\\n", " "))
        installs.append((match.start(), arguments))
    return installs


class WindowsBuildDependenciesTests(unittest.TestCase):
    def test_x64_provisions_nasm_without_vectorscan_source_build(self):
        recipe = windows_recipe("x64")
        installs = package_installs(recipe)
        self.assertTrue(installs, "Windows x64 must provision its native dependencies")
        position, arguments = installs[0]
        self.assertTrue({"--noconfirm", "--needed", "-S"}.issubset(arguments))
        self.assertTrue({
            "mingw-w64-x86_64-toolchain",
            "mingw-w64-x86_64-cmake",
            "mingw-w64-x86_64-lld",
            "mingw-w64-x86_64-nasm",
            "mingw-w64-x86_64-pkgconf",
            "mingw-w64-x86_64-zlib",
            "mingw-w64-x86_64-python",
        }.issubset(arguments))
        # The isolated library consumer lacks rustls's prebuilt-nasm feature.
        # NASM must therefore be installed even with the default Vectorscan archive.
        self.assertLess(position, recipe.index("VECTORSCAN_BUILD_FROM_SOURCE"))
        self.assertLess(position, recipe.index("WINDOWS_ONLY_DEPS"))

    def test_arm64_retains_clang_toolchain_without_x64_nasm(self):
        recipe = windows_recipe("arm64")
        installs = package_installs(recipe)
        self.assertTrue(installs, "Windows ARM64 must provision its native dependencies")
        position, arguments = installs[0]
        self.assertTrue({
            "mingw-w64-clang-aarch64-toolchain",
            "mingw-w64-clang-aarch64-cmake",
            "mingw-w64-clang-aarch64-pkgconf",
            "mingw-w64-clang-aarch64-zlib",
            "mingw-w64-clang-aarch64-python",
        }.issubset(arguments))
        self.assertLess(position, recipe.index("WINDOWS_ONLY_DEPS"))
        for _, arguments in installs:
            self.assertFalse(any("nasm" in argument for argument in arguments))
            self.assertFalse(any(argument.startswith("mingw-w64-x86_64-")
                                 for argument in arguments))

    def test_dependency_only_setup_precedes_build_and_packaging(self):
        for architecture, target in (
            ("x64", "x86_64-pc-windows-gnu"),
            ("arm64", "aarch64-pc-windows-gnullvm"),
        ):
            with self.subTest(architecture=architecture):
                recipe = windows_recipe(architecture)
                guard = re.search(
                    r'if \[ "\$\$\{WINDOWS_ONLY_DEPS:-0\}" = "1" \]; then(.*?)fi;',
                    recipe, re.DOTALL,
                )
                self.assertIsNotNone(guard, "CI dependency setup must skip compilation")
                self.assertIn("exit 0;", guard.group(1))
                self.assertLess(recipe.index(f'"$$RUSTUP_BIN" target add {target}'),
                                guard.start())
                self.assertLess(guard.end(),
                                recipe.index(f'"$$CARGO_BIN" build --release --target {target}'))

    def test_ci_uses_the_shared_dependency_only_recipe(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("WINDOWS_ONLY_DEPS=1 make windows-${{ matrix.arch }}", workflow)
        self.assertIn("make windows-test-${{ matrix.arch }}", workflow)

    def test_ci_reuses_preinstalled_msys2_only_on_x64(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        windows = workflow.split("  windows:", 1)[1]
        matrix = windows.split("      matrix:", 1)[1].split("    steps:", 1)[0]
        # Runner availability and MSYSTEM are coupled: the x64 image has
        # C:\msys64, but the ARM64 image omits MSYS2 and needs a fresh install.
        # Do not migrate MINGW64 to UCRT64 as an installer-download workaround.
        self.assertEqual(re.findall(
            r"(?m)^          - arch: (\S+)\n"
            r"            runs_on: (\S+)\n"
            r"            msystem: (\S+)$", matrix,
        ), [
            ("x64", "windows-latest", "MINGW64"),
            ("arm64", "windows-11-arm", "CLANGARM64"),
        ])
        setup = windows.split("      - name: Set up MSYS2\n", 1)[1].split("\n      - ", 1)[0]
        self.assertIn("          release: ${{ matrix.arch == 'arm64' }}", setup)
        self.assertIn("          msystem: ${{ matrix.msystem }}", setup)

    def test_ci_msys2_setup_keeps_pinned_action_upgrades_and_required_packages(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        windows = workflow.split("  windows:", 1)[1]
        setup = windows.split("      - name: Set up MSYS2\n", 1)[1].split("\n      - ", 1)[0]
        self.assertIn("uses: msys2/setup-msys2@ec48f7c5447b3140e2b088413ae3a55687bccb6e", setup)
        # Reusing the runner installation must not freeze old packages or hide
        # setup failures. ARM64 still uses the action's checksum-verified install.
        self.assertIn("          update: true", setup)
        self.assertRegex(setup,
                         r"(?m)^          install: >-\n"
                         r"            make\n            git\n            perl$")
        self.assertNotRegex(setup, r"(?m)^\s+(?:if|continue-on-error):")
        self.assertNotIn("continue-on-error:", windows)

    def test_windows_test_profile_does_not_optimize_the_entire_sdk_graph(self):
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        profile = manifest["profile"]["ci-test"]
        self.assertEqual(profile["opt-level"], 0)
        self.assertEqual(profile["codegen-units"], 256)
        self.assertFalse(profile["debug"])
        self.assertFalse(profile["incremental"])
        self.assertEqual(profile["lto"], "off")
        self.assertEqual(manifest["profile"]["release"]["opt-level"], 3)

    def test_windows_tests_keep_static_linking_and_use_lld_only_for_x64_tests(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        x64 = makefile.split("windows-test-x64:", 1)[1].split("windows-test-arm64:", 1)[0]
        arm64 = makefile.split("windows-test-arm64:", 1)[1].split("windows-test:", 1)[0]
        for recipe in (x64, arm64):
            self.assertIn("-C target-feature=+crt-static -C link-arg=-static", recipe)
            self.assertIn("cargo test --locked --profile ci-test --workspace --all-targets", recipe)
        self.assertIn("command -v ld.lld", x64)
        self.assertIn("-C link-arg=-fuse-ld=lld", x64)
        self.assertNotIn("-fuse-ld=lld", arm64)
        self.assertNotIn("-fuse-ld=lld", windows_recipe("x64"))

    def test_windows_workspace_tests_exclude_only_the_node_addon_tested_on_msvc(self):
        # napi-build needs libnode.dll on GNU Windows even with dyn-symbols.
        # Keep all other workspace suites here; native Node tests must run on
        # the supported MSVC toolchain, including portable Rust unit tests.
        for architecture in ("x64", "arm64"):
            with self.subTest(architecture=architecture):
                recipe = windows_recipe(f"test-{architecture}")
                commands = re.findall(r"(?m)^\t[ \t]*cargo[ \t]+(test[^;]+);", recipe)
                self.assertEqual(len(commands), 1)
                self.assertEqual(shlex.split(commands[0]), [
                    "test", "--locked", "--profile", "ci-test", "--workspace",
                    "--all-targets", "--exclude", "kingfisher-node",
                    "--target", "$$target_triple",
                ])

    def test_node_addon_retains_native_and_runtime_tests_on_all_supported_targets(self):
        workflow = (ROOT / ".github/workflows/node-sdk.yml").read_text(encoding="utf-8")
        build = workflow.split("  build:", 1)[1].split("  package:", 1)[0]
        for target in ("x86_64-apple-darwin", "aarch64-apple-darwin",
                       "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                       "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"):
            with self.subTest(target=target):
                self.assertIn(f"target: {target}", build)
        self.assertIn("      - name: Rust native unit tests", build)
        native_tests = build.split("      - name: Rust native unit tests", 1)[1].split("      - ", 1)[0]
        # --all-targets is necessary: the addon's test=false disables only
        # automatic selection, not its existing portable Rust unit tests.
        self.assertEqual(re.findall(r"(?m)^\s+run: (.+)$", native_tests), [
            'cargo test --locked -p kingfisher-node --all-targets --target "${{ matrix.target }}"',
        ])
        self.assertNotIn("if:", native_tests)
        self.assertNotIn("continue-on-error:", build)
        self.assertLess(build.index("name: Rust native unit tests"),
                        build.index("name: Build production addon"))
        self.assertIn('npm run build -- --target "${{ matrix.target }}"', build)
        self.assertRegex(build, r"(?m)^\s+npm test$")

    def test_node_windows_compilation_keeps_the_native_shell_and_msvc_linker(self):
        workflow = (ROOT / ".github/workflows/node-sdk.yml").read_text(encoding="utf-8")
        build = workflow.split("  build:", 1)[1].split("  package:", 1)[0]
        # In Git Bash, /usr/bin/link shadows MSVC even after VsDevCmd succeeds.
        # Both Cargo tests and npm's Cargo build must inherit PowerShell on
        # Windows (and Bash on Unix), without a Unix-only environment expansion.
        self.assertNotIn("shell:", workflow.split("jobs:", 1)[0])
        self.assertNotIn("shell:", build.split("    steps:", 1)[0])
        for name in ("Rust native unit tests", "Build production addon"):
            with self.subTest(step=name):
                step = build.split(f"      - name: {name}", 1)[1].split("      - ", 1)[0]
                self.assertNotIn("shell:", step)
                self.assertIn('--target "${{ matrix.target }}"', step)
                self.assertNotIn("$NATIVE_TARGET", step)

    def test_node_windows_abi_selects_an_installation_containing_the_pinned_toolset(self):
        workflow = (ROOT / ".github/workflows/node-sdk.yml").read_text(encoding="utf-8")
        step = workflow.split("      - name: Pin Windows C++ ABI", 1)[1].split("      - name:", 1)[0]
        selection = next(line.strip() for line in step.splitlines()
                         if line.strip().startswith("$installation ="))
        self.assertIn("& $vswhere -all -products '*' -property installationPath", selection)
        self.assertIn("Where-Object { Test-Path (Join-Path $_ 'VC\\Tools\\MSVC\\14.44.*') }", selection)
        self.assertTrue(selection.endswith("| Select-Object -First 1"))
        self.assertNotIn("-latest", step)
        # VS 2026 may contain the legacy pinned toolset, including on ARM64;
        # do not select by a hard-coded Visual Studio product-version range.
        self.assertNotIn("-version ", step)
        guard = "if (-not $installation) { throw 'No Visual Studio installation contains the MSVC 14.44 toolset' }"
        self.assertIn(guard, step)
        self.assertLess(step.index(guard), step.index("$devcmd = Join-Path $installation"))
        self.assertIn("-arch={1} -host_arch={1} -vcvars_ver=14.44", step)
        self.assertIn("if ($LASTEXITCODE -ne 0) { throw 'Could not initialize MSVC 14.44' }", step)
        self.assertIn("if ($version -notmatch '^14\\.44\\.') { throw \"Expected MSVC 14.44, received $version\" }", step)

    def test_windows_hash_preflight_runs_before_expensive_native_setup(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        windows = workflow.split("  windows:", 1)[1]
        preflight = windows.index("python scripts/update-rule-bundle.py --check-hashes")
        self.assertLess(preflight, windows.index("name: Set up MSYS2"))
        self.assertLess(preflight, windows.index("name: Run tests"))

    def test_only_superseded_pull_request_windows_jobs_are_cancelled(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        windows = workflow.split("  windows:", 1)[1]
        self.assertIn("group: windows-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}-${{ matrix.arch }}", windows)
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", windows)
        # Keep the existing memory bound; faster linking is not permission to
        # risk simultaneous giant static links on the hosted Windows runners.
        self.assertIn("CARGO_BUILD_JOBS: 1", windows)


if __name__ == "__main__":
    unittest.main()
