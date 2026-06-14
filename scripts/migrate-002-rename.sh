#!/usr/bin/env bash
# Plan 002: rename rustauth-* → rustauth-* (delete source crate, no per-crate shims)
set -euo pipefail
cd "$(dirname "$0")/.."

CRATES=(
  social-providers
  core
  stripe
  saml
  i18n
  sqlx
  telemetry
  tokio-postgres
  deadpool-postgres
  redis
  fred
  plugins
  passkey
  sso
  scim
  oauth-provider
  axum
  cli
)

rename_crate() {
  local KEBAB="$1"
  local SNAKE="${KEBAB//-/_}"
  local OA="rustauth-${KEBAB}"
  local RA="rustauth-${KEBAB}"
  local OA_SNAKE="rustauth_${SNAKE}"
  local RA_SNAKE="rustauth_${SNAKE}"

  echo "=== Renaming ${OA} → ${RA} ==="

  if [[ ! -d "crates/${OA}" ]]; then
    echo "SKIP: crates/${OA} not found (already renamed?)"
    return 0
  fi

  # Remove placeholder src
  rm -rf "crates/${RA}/src"
  rm -rf "crates/${RA}/tests"

  # Move implementation
  mv "crates/${OA}/src" "crates/${RA}/src"
  [[ -d "crates/${OA}/tests" ]] && mv "crates/${OA}/tests" "crates/${RA}/tests"
  [[ -d "crates/${OA}/examples" ]] && mv "crates/${OA}/examples" "crates/${RA}/examples"
  [[ -d "crates/${OA}/benches" ]] && mv "crates/${OA}/benches" "crates/${RA}/benches"
  for f in CHANGELOG.md README.md UPSTREAM.md; do
    [[ -f "crates/${OA}/${f}" ]] && cp "crates/${OA}/${f}" "crates/${RA}/${f}"
  done

  # Cargo.toml from source crate
  cp "crates/${OA}/Cargo.toml" "crates/${RA}/Cargo.toml"
  sed -i '' \
    -e "s/name = \"${OA}\"/name = \"${RA}\"/" \
    -e "s|docs.rs/${OA}|docs.rs/${RA}|g" \
    -e 's/for RustAuth\./for RustAuth./g' \
    -e 's/for RustAuth /for RustAuth /g' \
    -e '/^\[workspace\]$/,$d' \
    "crates/${RA}/Cargo.toml"

  # Self-references in moved tree
  if [[ -d "crates/${RA}" ]]; then
    find "crates/${RA}" -name '*.rs' -print0 | xargs -0 sed -i '' "s/${OA_SNAKE}/${RA_SNAKE}/g" 2>/dev/null || true
  fi

  # Global kebab-name update in all Cargo.toml + lock
  find . -name Cargo.toml -not -path './target/*' -print0 | xargs -0 sed -i '' "s/${OA}/${RA}/g"
  [[ -f Cargo.lock ]] && sed -i '' "s/${OA}/${RA}/g" Cargo.lock

  # Remove from exclude only (do NOT delete matching members lines)
  sed -i '' "/exclude =/,/^\]/{ /\"crates\/${RA}\",/d; }" Cargo.toml

  # Global snake_case in Rust sources
  find crates examples tests -name '*.rs' -print0 2>/dev/null | xargs -0 sed -i '' "s/${OA_SNAKE}/${RA_SNAKE}/g" 2>/dev/null || true

  rm -rf "crates/${OA}"
  echo "Done: ${RA}"
}

for c in "${CRATES[@]}"; do
  rename_crate "$c"
done

echo "=== All leaf/mid crates renamed ==="
