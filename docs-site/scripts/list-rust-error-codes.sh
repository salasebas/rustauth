#!/usr/bin/env bash
# List stable RustAuth-RS error code strings from Rust sources.
# Read-only helper for docs and release checks. Do not commit secrets.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "| code | crate::module | message |"
echo "| ---- | ------------- | ------- |"

# Core BASE_ERROR_CODES-style constants (SCREAMING_SNAKE)
while IFS= read -r line; do
  file="${line%%:*}"
  rest="${line#*:}"
  code="${rest%%=*}"
  code="${code// /}"
  code="${code//pub const /}"
  module="${file#crates/}"
  module="${module%.rs}"
  module="${module//\//::}"
  echo "| \`$code\` | \`$module\` | (see source) |"
done < <(rg 'pub const [A-Z_]+:' crates/rustauth-core/src/error_codes.rs || true)

# OAuth redirect / user-info codes (snake_case)
while IFS= read -r line; do
  file="${line%%:*}"
  rest="${line#*:}"
  code=$(echo "$rest" | rg -o '"[a-z_]+"' | head -1 | tr -d '"')
  [[ -z "$code" ]] && continue
  module="${file#crates/}"
  module="${module%.rs}"
  module="${module//\//::}"
  msg=$(echo "$rest" | rg -o '=> "[^"]+"' | head -1 | sed 's/=> "//;s/"$//' || echo "")
  echo "| \`$code\` | \`$module\` | ${msg:-(see source)} |"
done < <(rg '=> "[a-z_]+"' crates/rustauth-core/src/auth/oauth/errors.rs crates/rustauth-core/src/auth/oauth/account_linking.rs 2>/dev/null || true)

# ApiErrorCode variants
while IFS= read -r line; do
  file="${line%%:*}"
  variant="${line#*:}"
  variant="${variant// /}"
  variant="${variant//Self::/}"
  variant="${variant//=>/}"
  module="${file#crates/}"
  module="${module%.rs}"
  module="${module//\//::}"
  echo "| (ApiErrorCode) | \`$module\` | variant \`$variant\` |"
done < <(rg 'Self::[A-Za-z]+ =>' crates/rustauth-core/src/api/error.rs 2>/dev/null || true)

# Plugin-registered codes
rg 'PluginErrorCode::new\("[^"]+"' crates/ -g '*.rs' --no-heading 2>/dev/null | while IFS= read -r line; do
  file="${line%%:*}"
  rest="${line#*:}"
  code=$(echo "$rest" | rg -o 'PluginErrorCode::new\("[^"]+"' | rg -o '"[^"]+"' | head -1 | tr -d '"')
  msg=$(echo "$rest" | rg -o ', "[^"]+"' | head -1 | sed 's/, "//;s/"$//' || echo "")
  module="${file#crates/}"
  module="${module%.rs}"
  module="${module//\//::}"
  echo "| \`$code\` | \`$module\` | ${msg:-(plugin)} |"
done
