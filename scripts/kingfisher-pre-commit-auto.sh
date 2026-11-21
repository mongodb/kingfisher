#!/usr/bin/env bash
# Kingfisher pre-commit hook with automatic binary download
# This script downloads the appropriate kingfisher binary if not already cached,
# then scans staged changes or files selected by the hook runner.
set -euo pipefail

REPO="mongodb/kingfisher"
CACHE_DIR="${KINGFISHER_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/kingfisher}"
SCAN_ARGS=(scan . --staged --quiet --no-update-check)
if [[ "${1:-}" == "--pre-commit-files" ]]; then
  shift
  SCAN_ARGS=(scan --pre-commit-files --quiet --no-update-check)
  # The staged hook's cached binary may predate file selection support.
  CACHE_DIR="$CACHE_DIR/pre-commit-files"
fi
KINGFISHER_BIN="$CACHE_DIR/kingfisher"
VERSION_FILE="$CACHE_DIR/.version"

# Determine the expected version from the pre-commit rev (passed as env var or default to latest)
EXPECTED_VERSION="${KINGFISHER_VERSION:-latest}"

get_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)  platform="linux" ;;
    Darwin) platform="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) platform="windows" ;;
    *) echo "Error: Unsupported OS '$os'" >&2; exit 1 ;;
  esac

  case "$arch" in
    x86_64|amd64)  arch_suffix="x64" ;;
    arm64|aarch64) arch_suffix="arm64" ;;
    *) echo "Error: Unsupported architecture '$arch'" >&2; exit 1 ;;
  esac

  echo "${platform}-${arch_suffix}"
}

download_kingfisher() {
  local platform="$1"
  local version="$2"
  local ext="tgz"

  if [[ "$platform" == windows-* ]]; then
    ext="zip"
  fi

  local asset_name="kingfisher-${platform}.${ext}"
  local download_url

  if [[ "$version" == "latest" ]]; then
    download_url="https://github.com/${REPO}/releases/latest/download/${asset_name}"
  else
    # Support both "v1.76.0" and "1.76.0" formats
    if [[ "$version" != v* ]]; then
      version="v${version}"
    fi
    download_url="https://github.com/${REPO}/releases/download/${version}/${asset_name}"
  fi

  mkdir -p "$CACHE_DIR"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  echo "Downloading kingfisher ($version) for $platform..." >&2

  if ! curl -fLsS "$download_url" -o "$tmpdir/$asset_name"; then
    echo "Error: Failed to download $download_url" >&2
    exit 1
  fi

  if [[ "$ext" == "zip" ]]; then
    unzip -q "$tmpdir/$asset_name" -d "$tmpdir"
    local binary_name="kingfisher.exe"
  else
    tar -C "$tmpdir" -xzf "$tmpdir/$asset_name"
    local binary_name="kingfisher"
  fi

  if [[ ! -f "$tmpdir/$binary_name" ]]; then
    echo "Error: Binary not found in downloaded archive" >&2
    exit 1
  fi

  mv "$tmpdir/$binary_name" "$KINGFISHER_BIN"
  chmod +x "$KINGFISHER_BIN"

  # Store the version we downloaded
  if [[ "$version" == "latest" ]]; then
    "$KINGFISHER_BIN" --version 2>/dev/null | head -1 > "$VERSION_FILE" || echo "latest" > "$VERSION_FILE"
  else
    echo "$version" > "$VERSION_FILE"
  fi

  echo "Kingfisher installed to $KINGFISHER_BIN" >&2
}

needs_download() {
  # Binary doesn't exist
  if [[ ! -x "$KINGFISHER_BIN" ]]; then
    return 0
  fi

  # No version tracking - always use existing binary for 'latest'
  if [[ "$EXPECTED_VERSION" == "latest" ]]; then
    return 1
  fi

  # Check if version matches
  if [[ -f "$VERSION_FILE" ]]; then
    local installed_version
    installed_version="$(cat "$VERSION_FILE")"
    # Normalize version format for comparison
    local expected_normalized="$EXPECTED_VERSION"
    if [[ "$expected_normalized" != v* ]]; then
      expected_normalized="v${expected_normalized}"
    fi
    if [[ "$installed_version" == *"$expected_normalized"* ]] || [[ "$installed_version" == "$EXPECTED_VERSION" ]]; then
      return 1
    fi
  fi

  return 0
}

main() {
  local platform
  platform="$(get_platform)"

  if needs_download; then
    download_kingfisher "$platform" "$EXPECTED_VERSION"
  fi

  exec "$KINGFISHER_BIN" "${SCAN_ARGS[@]}" "$@"
}

main "$@"
