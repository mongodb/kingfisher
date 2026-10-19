"""Check Windows native dependency contracts without installing packages or Rust targets."""

from pathlib import Path
import re
import shlex
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


if __name__ == "__main__":
    unittest.main()
