#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/sync-public-mirror.sh [OPTIONS]

Copies the current development worktree to the local public mirror without
committing or pushing. Tracked files and untracked, non-ignored files are
included; ignored files and this script are excluded.

Options:
  --destination DIR  Public mirror checkout (default: ~/src/kingfisher)
  --dry-run          Show the changes without modifying the mirror
  -h, --help         Show this help message

Safety checks:
  - Both repositories must be checked out on development.
  - The destination worktree must be clean before the sync.
  - Git metadata and ignored destination files are left untouched.
USAGE
}

destination="${PUBLIC_MIRROR_DIR:-$HOME/src/kingfisher}"
dry_run=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --destination)
      if [[ -z "${2-}" ]]; then
        echo "Error: --destination requires a directory." >&2
        exit 1
      fi
      destination="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown option '$1'." >&2
      usage >&2
      exit 1
      ;;
  esac
done

command -v git >/dev/null 2>&1 || {
  echo "Error: git is required." >&2
  exit 1
}
command -v rsync >/dev/null 2>&1 || {
  echo "Error: rsync is required." >&2
  exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
script_path="$script_dir/$(basename "${BASH_SOURCE[0]}")"
source_root="$(git -C "$script_dir" rev-parse --show-toplevel)"
source_root="$(cd "$source_root" && pwd -P)"

case "$script_path" in
  "$source_root"/*) script_relative_path="${script_path#"$source_root"/}" ;;
  *)
    echo "Error: the sync script must be located inside the source repository." >&2
    exit 1
    ;;
esac

source_branch="$(git -C "$source_root" symbolic-ref --quiet --short HEAD || true)"
if [[ "$source_branch" != "development" ]]; then
  echo "Error: source repository must be on development (currently '${source_branch:-detached}')." >&2
  exit 1
fi

if [[ "$(git -C "$source_root" config --bool core.sparseCheckout || true)" == "true" ]]; then
  echo "Error: sparse source checkouts are not supported." >&2
  exit 1
fi

if [[ ! -d "$destination" ]]; then
  echo "Error: destination directory does not exist: $destination" >&2
  exit 1
fi

destination_root="$(git -C "$destination" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$destination_root" ]]; then
  echo "Error: destination is not a Git worktree: $destination" >&2
  exit 1
fi
destination_root="$(cd "$destination_root" && pwd -P)"

if [[ "$source_root" == "$destination_root" ]]; then
  echo "Error: source and destination repositories are the same worktree." >&2
  exit 1
fi

destination_branch="$(git -C "$destination_root" symbolic-ref --quiet --short HEAD || true)"
if [[ "$destination_branch" != "development" ]]; then
  echo "Error: destination must be on development (currently '${destination_branch:-detached}')." >&2
  exit 1
fi

if [[ -n "$(git -C "$destination_root" status --porcelain --untracked-files=normal)" ]]; then
  echo "Error: destination worktree is not clean: $destination_root" >&2
  echo "Commit, stash, or discard its changes before syncing." >&2
  git -C "$destination_root" status --short >&2
  exit 1
fi

has_gitlinks() {
  git -C "$1" ls-files --stage | awk '$1 == "160000" { found = 1 } END { exit !found }'
}

if has_gitlinks "$source_root" || has_gitlinks "$destination_root"; then
  echo "Error: repositories containing Git submodules are not supported." >&2
  exit 1
fi

sync_temp="$(mktemp -d "${TMPDIR:-/tmp}/kingfisher-public-sync.XXXXXX")"
cleanup() {
  rm -rf -- "$sync_temp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

manifest="$sync_temp/manifest"
staging_root="$sync_temp/staging"
mkdir -p "$staging_root"

validate_repo_path() {
  case "$1" in
    ""|/*|..|../*|*/..|*/../*|.git|.git/*|*/.git|*/.git/*)
      echo "Error: unsafe repository path returned by Git: '$1'" >&2
      exit 1
      ;;
  esac
}

file_count=0
while IFS= read -r -d '' path; do
  validate_repo_path "$path"

  # This exclusion is derived from the running script's path, so it continues
  # to work if the script is renamed or moved within the source repository.
  if [[ "$path" == "$script_relative_path" ]]; then
    continue
  fi

  # A tracked file deleted in the source worktree should be deleted from the
  # mirror, not passed to rsync as a missing source file.
  if [[ ! -e "$source_root/$path" && ! -L "$source_root/$path" ]]; then
    continue
  fi

  printf '%s\0' "$path"
  ((file_count += 1))
done > "$manifest" < <(
  git -C "$source_root" ls-files -z --cached --others --exclude-standard
)

if ((file_count == 0)); then
  echo "Error: source manifest is empty; refusing to modify the destination." >&2
  exit 1
fi

rsync --recursive --links --perms --checksum --from0 --files-from="$manifest" \
  "$source_root/" "$staging_root/"

if [[ -e "$staging_root/$script_relative_path" || -L "$staging_root/$script_relative_path" ]]; then
  echo "Error: the sync script unexpectedly entered the staging tree." >&2
  exit 1
fi

# Preflight file-over-directory replacements before modifying the destination.
# A clean worktree can still contain ignored files, and those must not be erased.
while IFS= read -r -d '' path; do
  if [[ -d "$staging_root/$path" && ! -L "$staging_root/$path" ]]; then
    continue
  fi
  if [[ ! -d "$destination_root/$path" || -L "$destination_root/$path" ]]; then
    continue
  fi

  while IFS= read -r -d '' entry; do
    entry_relative_path="${entry#"$destination_root"/}"
    validate_repo_path "$entry_relative_path"
    if ! git -C "$destination_root" ls-files --error-unmatch -- \
      "$entry_relative_path" >/dev/null 2>&1; then
      echo "Error: refusing to replace a destination directory containing ignored data:" >&2
      echo "  $entry" >&2
      exit 1
    fi
  done < <(find "$destination_root/$path" -mindepth 1 ! -type d -print0)
done < "$manifest"

deletion_count=0
while IFS= read -r -d '' path; do
  validate_repo_path "$path"

  # Parent directories exist in staging but are not themselves tracked files.
  if [[ (! -e "$staging_root/$path" && ! -L "$staging_root/$path") || \
        (-d "$staging_root/$path" && ! -L "$staging_root/$path") ]]; then
    ((deletion_count += 1))
    if $dry_run; then
      printf 'delete %s\n' "$path"
    else
      rm -f -- "$destination_root/$path"
    fi
  fi
done < <(git -C "$destination_root" ls-files -z)

# Remove directory trees whose tracked contents were deleted above so a source
# file or symlink can take their place. Ignored contents were rejected during
# preflight.
while IFS= read -r -d '' path; do
  if [[ -d "$staging_root/$path" && ! -L "$staging_root/$path" ]]; then
    continue
  fi
  if [[ ! -d "$destination_root/$path" || -L "$destination_root/$path" ]]; then
    continue
  fi

  if $dry_run; then
    printf 'replace directory with file %s\n' "$path"
  else
    rm -rf -- "${destination_root:?}/$path"
  fi
done < "$manifest"

rsync_args=(
  --recursive
  --links
  --perms
  --checksum
  --from0
  --files-from="$manifest"
)
if $dry_run; then
  rsync_args+=(--dry-run --itemize-changes)
  dry_run_output="$sync_temp/rsync-dry-run-output"
  rsync "${rsync_args[@]}" "$staging_root/" "$destination_root/" > "$dry_run_output"
  while IFS= read -r change; do
    # The macOS rsync bundled with Xcode reports unchanged files with a
    # time-only marker when timestamps are intentionally not synchronized.
    case "$change" in
      ".f..T.... "*|".d..T.... "*|".L..T.... "*) continue ;;
    esac
    printf '%s\n' "$change"
  done < "$dry_run_output"
else
  rsync "${rsync_args[@]}" "$staging_root/" "$destination_root/"
fi

if $dry_run; then
  printf 'Dry run complete: %d source files, %d tracked deletions.\n' \
    "$file_count" "$deletion_count"
else
  printf 'Synced %d source files to %s on development.\n' "$file_count" "$destination_root"
  printf 'Removed %d tracked files that are absent from the source.\n' "$deletion_count"
  echo "The mirror was not committed or pushed."
  git -C "$destination_root" status --short
fi
