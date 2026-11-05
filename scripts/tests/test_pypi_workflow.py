"""Exercise the exact PyPI workflow permission loop without changing file modes."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PyPIWorkflowTests(unittest.TestCase):
    def run_permission_loop(self, *, include_binaries, chmod_status):
        workflow = (ROOT / ".github/workflows/pypi.yml").read_text(encoding="utf-8")
        marker = "          mkdir -p extracted/bin\n"
        self.assertEqual(workflow.count(marker), 1)
        fragment = textwrap.dedent(
            workflow[workflow.index(marker):].split("\n      - name:", 1)[0]
        )
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "Bash is required to exercise the workflow shell fragment")

        with tempfile.TemporaryDirectory(prefix="kingfisher pypi permissions ") as directory:
            root = Path(directory)
            binaries = [
                "extracted/linux x64 (release)/kingfisher",
                "extracted/windows x64/nested release/kingfisher.exe",
            ] if include_binaries else []
            unrelated = [
                "extracted/linux x64 (release)/kingfisher.txt",
                "extracted/windows x64/nested release/kingfisher.exe.sha256",
                "extracted/other assets/README.md",
            ]
            for name in binaries + unrelated:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")
            # A matching directory is not a binary; -type f must exclude it.
            (root / "extracted/directory only/kingfisher").mkdir(parents=True)
            log = root / "chmod argument log"
            log.write_bytes(b"")
            env = {
                **os.environ,
                "CHMOD_LOG": log.as_posix(),
                "CHMOD_STATUS": str(chmod_status),
            }
            # A shell function avoids native executable/permission-bit assumptions
            # on Windows while recording the exact command arguments as NUL fields.
            wrapper = r'''set -euo pipefail
chmod() {
  printf '%s\0' "$@" >> "$CHMOD_LOG"
  return "$CHMOD_STATUS"
}
'''
            result = subprocess.run(
                [bash, "--noprofile", "--norc", "-c", wrapper + fragment],
                cwd=root, env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((root / "extracted/bin").is_dir())
            fields = log.read_bytes().split(b"\0")
            self.assertEqual(fields.pop(), b"")
            self.assertEqual(len(fields) % 2, 0)
            calls = [tuple(os.fsdecode(arg) for arg in fields[index:index + 2])
                     for index in range(0, len(fields), 2)]
            self.assertCountEqual(calls, [("+x", name) for name in binaries])

    def test_binary_paths_with_spaces_are_passed_as_single_arguments(self):
        self.run_permission_loop(include_binaries=True, chmod_status=0)

    def test_chmod_failure_is_best_effort_for_every_binary(self):
        self.run_permission_loop(include_binaries=True, chmod_status=37)

    def test_no_matching_binaries_succeeds_without_chmod(self):
        self.run_permission_loop(include_binaries=False, chmod_status=37)


if __name__ == "__main__":
    unittest.main()
