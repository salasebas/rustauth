#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/examples/backend-reference"

export DATABASE_URL="${DATABASE_URL:-postgres://user:password@127.0.0.1:5432/rustauth}"
export RUSTAUTH_SECRET="${RUSTAUTH_SECRET:-RustAuthSecretForCiMigrate-1234567890!}"

cargo build -p rustauth-cli --features full --quiet --manifest-path "$ROOT/Cargo.toml"
"$ROOT/target/debug/rustauth" db migrate --yes
echo "backend-reference migrations applied"
