#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

rm -rf data migrations
mkdir -p data

echo "Reset complete. Run migrations from a clean slate:"
echo "  cd examples/cli-migrate-playground"
echo "  cp .env.example .env   # if you have not already"
echo "  cargo run -p rustauth-cli --manifest-path ../../Cargo.toml --features full -- db migrate --yes"
