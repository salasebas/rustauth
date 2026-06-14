#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT}/reference/upstream-better-auth/VERSION.md"

default_version() {
	if [[ ! -f "${VERSION_FILE}" ]]; then
		echo "1.6.9"
		return
	fi
	# First backtick-delimited version in VERSION.md table row for Version.
	grep -E '^\| Version \|' "${VERSION_FILE}" | sed -n 's/.*`\([^`]*\)`.*/\1/p' | head -n 1
}

VERSION="${1:-$(default_version)}"
DEST="${ROOT}/reference/upstream-src/${VERSION}/repository"
REPO_URL="https://github.com/better-auth/better-auth.git"
TAG="v${VERSION}"

if [[ -d "${DEST}/.git" ]] || [[ -f "${DEST}/package.json" ]] || [[ -d "${DEST}/packages" ]]; then
	echo "Upstream tree already exists at ${DEST}"
	echo "Remove that directory to re-clone."
	exit 0
fi

mkdir -p "$(dirname "${DEST}")"
echo "Cloning ${REPO_URL} (${TAG}) into ${DEST} ..."
git clone --depth 1 --branch "${TAG}" "${REPO_URL}" "${DEST}"
echo "Done. Parity sources: ${DEST}/packages/"
