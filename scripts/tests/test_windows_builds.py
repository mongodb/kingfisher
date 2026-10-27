"""Check Windows native dependency contracts without installing packages or Rust targets."""

from pathlib import Path
import re
import shlex
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]


def windows_recipe(architecture):
    """Read just the shared release/CI dependency setup recipe for one architecture."""
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
