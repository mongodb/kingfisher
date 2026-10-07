#!/usr/bin/env python3
"""Test both historical RPM identities against a built RPM in Amazon Linux 2023.

Requires Docker and cargo-generate-rpm. Runs only in disposable containers, never
installs packages on the host. Use the native architecture's release RPM.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", required=True, choices=("x64", "arm64"))
    parser.add_argument("--package-dir", type=Path, default=ROOT / "target" / "release")
    args = parser.parse_args()
    package = (args.package_dir / f"kingfisher-linux-{args.arch}.rpm").resolve(strict=True)
    with (ROOT / "Cargo.toml").open("rb") as source:
        version = tomllib.load(source)["package"]["version"]

    with tempfile.TemporaryDirectory(prefix="kingfisher-rpm-upgrades-") as directory:
        fixtures = Path(directory)
        shutil.copyfile(package, fixtures / "corrected.rpm")
        # cargo-generate-rpm loads Cargo metadata even though the payload is prebuilt.
        (fixtures / "src").mkdir()
        (fixtures / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (fixtures / "kingfisher").write_text("#!/bin/sh\necho legacy-fixture\n", encoding="utf-8")
        (fixtures / "NOTICE").write_text("Legacy package notice\n", encoding="utf-8")
        (fixtures / "THIRD_PARTY_NOTICES").write_text("Legacy third-party notice\n", encoding="utf-8")
        for name, old_version in (("kingfisher", "2.7.0"), ("kingfisher-bin", "2.11.0")):
            # Different payload bytes deliberately reproduce file ownership conflicts.
            (fixtures / "Cargo.toml").write_text(f'''[package]
name = "{name}"
version = "{old_version}"
edition = "2021"
description = "Kingfisher upgrade test fixture"
license = "Apache-2.0"

[package.metadata.generate-rpm]
name = "{name}"
release = "1"
assets = [
    {{ source = "kingfisher", dest = "/usr/bin/kingfisher", mode = "755" }},
    {{ source = "NOTICE", dest = "/usr/share/doc/kingfisher/NOTICE", mode = "644", doc = true }},
    {{ source = "THIRD_PARTY_NOTICES", dest = "/usr/share/doc/kingfisher/THIRD_PARTY_NOTICES", mode = "644", doc = true }},
]
''', encoding="utf-8")
            subprocess.run(
                ["cargo", "generate-rpm", "--auto-req", "disabled", "--target",
                 "x86_64-unknown-linux-musl" if args.arch == "x64" else "aarch64-unknown-linux-musl",
                 "--output", "legacy.rpm"],
                cwd=fixtures, check=True,
            )
            print(f"Testing {name}-{old_version}-1 -> kingfisher-{version} on Amazon Linux 2023", flush=True)
            subprocess.run([
                "docker", "run", "--rm", "--platform",
                "linux/amd64" if args.arch == "x64" else "linux/arm64",
                "--mount", f"type=bind,src={fixtures},dst=/packages,readonly",
                "amazonlinux:2023", "bash", "-euo", "pipefail", "-c",
                'dnf install -y /packages/legacy.rpm\n'
                'dnf install -y /packages/corrected.rpm\n'
                'test "$(rpm -q --qf \'%{NAME}\\n\' kingfisher)" = kingfisher\n'
                'if rpm -q kingfisher-bin; then echo "Legacy package was not removed" >&2; exit 1; fi\n'
                'test "$(rpm -qf --qf \'%{NAME}\\n\' /usr/bin/kingfisher)" = kingfisher\n'
                'test "$(rpm -q --qf \'%{VERSION}\\n\' kingfisher)" = "$1"\n'
                'kingfisher --version\n'
                'for file in /usr/share/doc/kingfisher/NOTICE /usr/share/doc/kingfisher/THIRD_PARTY_NOTICES /usr/share/doc/kingfisher/kingfisher-vectorscan-NOTICE; do\n'
                '  test -s "$file"\n'
                '  test "$(rpm -qf --qf \'%{NAME}\\n\' "$file")" = kingfisher\n'
                'done\n'
                'dnf remove -y kingfisher\n'
                'test ! -e /usr/bin/kingfisher\n'
                'test ! -e /usr/share/doc/kingfisher/NOTICE\n'
                'if rpm -q kingfisher; then echo "Package was not removed" >&2; exit 1; fi\n',
                "rpm-upgrade-test", version,
            ], check=True)


if __name__ == "__main__":
    main()
