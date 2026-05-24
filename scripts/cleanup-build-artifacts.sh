#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: scripts/cleanup-build-artifacts.sh [--dry-run|--apply] [--days N] [--include-private-tmp] [--prune-worktrees] [--show-sizes]

Safely clean old OpenAuth build artifacts.

Defaults:
  --dry-run                 preview only
  --days 14                 only consider artifacts older than N days

Options:
  --apply                   delete matching artifacts
  --include-private-tmp     include /private/tmp/openauth-* target dirs and temp DBs
  --prune-worktrees         run git worktree prune (does not remove existing worktree dirs)
  --show-sizes              run du for matching local directories; can be slow
  -h, --help                show this help
USAGE
}

mode="dry-run"
days="14"
include_private_tmp="false"
prune_worktrees="false"
show_sizes="false"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      mode="dry-run"
      shift
      ;;
    --apply)
      mode="apply"
      shift
      ;;
    --days)
      if [ "$#" -lt 2 ]; then
        echo "--days requires a value" >&2
        exit 2
      fi
      days="$2"
      shift 2
      ;;
    --include-private-tmp)
      include_private_tmp="true"
      shift
      ;;
    --prune-worktrees)
      prune_worktrees="true"
      shift
      ;;
    --show-sizes)
      show_sizes="true"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$days" in
  '' | *[!0-9]*)
    echo "--days must be a non-negative integer" >&2
    exit 2
    ;;
esac

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

echo "mode: $mode"
echo "repo: $repo_root"
echo "age threshold: $days days"

if [ -d target ]; then
  echo
  echo "local target directory: $repo_root/target"

  if [ "$show_sizes" = "true" ]; then
    echo "local target size:"
    du -sh target 2>/dev/null || true
  fi

  if command -v cargo-sweep >/dev/null 2>&1; then
    echo
    if [ "$mode" = "apply" ]; then
      echo "running cargo sweep --time $days"
      cargo sweep --time "$days"
    else
      echo "previewing cargo sweep --time $days"
      cargo sweep --dry-run --time "$days"
    fi
  else
    echo
    echo "cargo-sweep is not installed; skipping age-based local target cleanup."
    echo "install with: cargo install --locked cargo-sweep"
    echo "for a full manual reset, use: cargo clean --dry-run"
  fi
else
  echo
  echo "no local target directory found"
fi

if [ "$include_private_tmp" = "true" ]; then
  echo
  echo "OpenAuth-owned /private/tmp artifacts older than $days days:"
  tmp_matches="$(
    find /private/tmp -maxdepth 1 \
      \( \
        \( -type d -name 'openauth-*-target' \) -o \
        \( -type d -name 'openauth-publish-target*' \) -o \
        \( -type f -name 'openauth_sqlx_*.db' \) \
      \) \
      -mtime +"$days" -print 2>/dev/null || true
  )"

  if [ -z "$tmp_matches" ]; then
    echo "none"
  else
    printf '%s\n' "$tmp_matches"

    if [ "$show_sizes" = "true" ]; then
      printf '%s\n' "$tmp_matches" | while IFS= read -r path; do
        [ -n "$path" ] || continue
        du -sh "$path" 2>/dev/null || true
      done
    fi

    if [ "$mode" = "apply" ]; then
      printf '%s\n' "$tmp_matches" | while IFS= read -r path; do
        [ -n "$path" ] || continue
        rm -rf -- "$path"
      done
    else
      echo "dry-run only; re-run with --apply to delete these paths"
    fi
  fi
fi

if [ "$prune_worktrees" = "true" ]; then
  echo
  if [ "$mode" = "apply" ]; then
    echo "running git worktree prune"
    git worktree prune
  else
    echo "previewing prunable worktrees"
    git worktree prune --dry-run
  fi
fi
