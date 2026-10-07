#!/usr/bin/env python3
"""Check Linux package metadata and built DEB/RPM headers (Python 3.11+)."""

import argparse
from pathlib import Path
import subprocess
import sys
import tomllib


# This alias deliberately describes the last incorrectly named release, not the
# current release. Raising it later could incorrectly obsolete unrelated packages.
LEGACY_RPM_VERSION = "2.11.0-1"
ARCHITECTURES = {"x64": ("amd64", "x86_64"), "arm64": ("arm64", "aarch64")}
REQUIRED_ASSETS = {
    "target/release/kingfisher": "/usr/bin/kingfisher",
    "NOTICE": "/usr/share/doc/kingfisher/NOTICE",
    "THIRD_PARTY_NOTICES": "/usr/share/doc/kingfisher/THIRD_PARTY_NOTICES",
    "third-party/kingfisher-vectorscan/NOTICE":
        "/usr/share/doc/kingfisher/kingfisher-vectorscan-NOTICE",
}


def validate_manifest(manifest):
    """Validate Cargo's native packaging metadata and return the release version."""
    package = manifest.get("package", {})
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("Cargo package.version must be a nonempty string")
    metadata = package.get("metadata", {})
    deb = metadata.get("deb", {})
    rpm = metadata.get("generate-rpm", {})
    if "package" in rpm:
        raise ValueError("generate-rpm.package is invalid; use generate-rpm.name")
    for label, config in (("deb", deb), ("generate-rpm", rpm)):
        if config.get("name") != "kingfisher":
            raise ValueError(f"{label}.name must be kingfisher")
        if config.get("version", version) != version:
            raise ValueError(f"{label}.version must match Cargo package.version {version}")
    if rpm.get("release") != "1":
        raise ValueError("generate-rpm.release must be '1'")
    if deb.get("revision", "1") != "1":
        raise ValueError("deb.revision must be '1'")
    for field, operator in (("obsoletes", "<="), ("provides", "=")):
        expected = f"{operator} {LEGACY_RPM_VERSION}"
        if rpm.get(field, {}).get("kingfisher-bin") != expected:
            raise ValueError(f"generate-rpm.{field}.kingfisher-bin must be '{expected}'")

    assets = {}
    for label, config in (("deb", deb), ("generate-rpm", rpm)):
        mapping = {}
        modes = {}
        destinations = set()
        for asset in config.get("assets", []):
            if label == "deb":
                if not isinstance(asset, list) or len(asset) != 3:
                    raise ValueError("deb.assets entries must contain source, destination, mode")
                source, destination = asset[:2]
            else:
                if not isinstance(asset, dict):
                    raise ValueError("generate-rpm.assets entries must be tables")
                source, destination = asset.get("source"), asset.get("dest")
            if not isinstance(source, str) or not isinstance(destination, str):
                raise ValueError(f"{label}.assets must have string sources and destinations")
            if source in mapping or destination in destinations:
                raise ValueError(f"{label}.assets contains duplicate source or destination")
            mapping[source] = destination
            modes[source] = asset[2] if label == "deb" else asset.get("mode")
            destinations.add(destination)
        for source, destination in REQUIRED_ASSETS.items():
            if mapping.get(source) != destination:
                raise ValueError(f"{label}.assets must install {source} at {destination}")
            expected_mode = "755" if source == "target/release/kingfisher" else "644"
            if modes.get(source) != expected_mode:
                raise ValueError(f"{label}.assets mode for {source} must be {expected_mode}")
        assets[label] = mapping
    if assets["deb"] != assets["generate-rpm"]:
        raise ValueError("DEB and RPM asset sources and destinations must be aligned")
    return version


def query(command):
    """Query headers without executing package scripts or installing anything."""
    try:
        return subprocess.run(
            command, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout.strip()
    except FileNotFoundError as error:
        raise ValueError(f"Required package query tool not found: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()
        raise ValueError(f"{command[0]} package query failed: {detail or error}") from error


def require_header(label, output, expected):
    actual = tuple(output.split("\t"))
    if actual != expected:
        raise ValueError(f"{label} header mismatch: expected {expected!r}, got {actual!r}")


def require_legacy_dependency(label, output, operator):
    expected = ("kingfisher-bin", operator, LEGACY_RPM_VERSION)
    entries = [tuple(line.split()) for line in output.splitlines()]
    legacy = [entry for entry in entries if entry and entry[0] == "kingfisher-bin"]
    if legacy != [expected]:
        raise ValueError(
            f"RPM {label} must contain exactly 'kingfisher-bin {operator} "
            f"{LEGACY_RPM_VERSION}', got {legacy!r}"
        )


def check_packages(package_dir, arch, version):
    """Check named release artifacts for the requested architecture."""
    deb_arch, rpm_arch = ARCHITECTURES[arch]
    deb = Path(package_dir) / f"kingfisher-linux-{arch}.deb"
    rpm = Path(package_dir) / f"kingfisher-linux-{arch}.rpm"
    for artifact in (deb, rpm):
        if not artifact.is_file():
            raise ValueError(f"Missing Linux package: {artifact}")
    deb_header = query([
        "dpkg-deb", "--show", "--showformat=${Package}\t${Version}\t${Architecture}\n", str(deb),
    ])
    require_header("DEB", deb_header, ("kingfisher", f"{version}-1", deb_arch))
    rpm_header = query([
        "rpm", "-qp", "--queryformat", "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", str(rpm),
    ])
    require_header("RPM", rpm_header, ("kingfisher", version, "1", rpm_arch))
    require_legacy_dependency("Obsoletes", query(["rpm", "-qp", "--obsoletes", str(rpm)]), "<=")
    require_legacy_dependency("Provides", query(["rpm", "-qp", "--provides", str(rpm)]), "=")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=tuple(ARCHITECTURES), help="Required unless --manifest-only")
    parser.add_argument("--package-dir", type=Path, help="Artifact directory (default: target/release)")
    parser.add_argument("--manifest-only", action="store_true", help="Skip artifact and tool queries")
    args = parser.parse_args(argv)
    if not args.manifest_only and args.arch is None:
        parser.error("--arch is required unless --manifest-only is specified")
    root = Path(__file__).resolve().parents[1]
    try:
        with (root / "Cargo.toml").open("rb") as stream:
            version = validate_manifest(tomllib.load(stream))
        if not args.manifest_only:
            check_packages(args.package_dir or root / "target/release", args.arch, version)
    except (ValueError, OSError) as error:
        print(f"Linux package check failed: {error}", file=sys.stderr)
        return 1
    scope = "manifest" if args.manifest_only else "manifest and DEB/RPM headers"
    architecture = f", {args.arch}" if args.arch else ""
    print(f"Linux package {scope} OK: kingfisher {version}{architecture}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
