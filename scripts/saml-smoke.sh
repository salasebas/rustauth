#!/usr/bin/env bash
# SAML smoke helper for rustauth-sso / rustauth-saml.
#
# Phase 1 (default): offline crypto + integration regression — no network, safe for local/CI skip.
# Phase 2 (optional): live sandbox checks when SAML_SMOKE_LIVE=1 and IdP env vars are set.
#
# See crates/rustauth-sso/SMOKE-SAML.md for the full manual checklist.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_DOC="${ROOT}/crates/rustauth-sso/SMOKE-SAML.md"
ENV_EXAMPLE="${ROOT}/crates/rustauth-sso/.env.saml-smoke.example"

red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }

echo "rustauth SAML smoke"
echo "Runbook: ${SMOKE_DOC}"
echo "Template: ${ENV_EXAMPLE}"
echo

if [[ -f "${ROOT}/.env" ]]; then
  yellow "Loading ${ROOT}/.env"
  # shellcheck disable=SC1091
  set -a && source "${ROOT}/.env" && set +a
fi

echo "=== Phase 1: offline regression (no IdP network) ==="
echo

cd "${ROOT}"

echo "Running rustauth-sso SAML integration tests..."
cargo test -p rustauth-sso --features saml,oidc -- saml
green "rustauth-sso SAML tests passed"

echo
echo "Running rustauth-saml (saml-signed) unit/security tests..."
cargo test -p rustauth-saml --features saml-signed
green "rustauth-saml tests passed"

echo
green "Phase 1 complete — crypto and HTTP SAML flows verified with opensaml + fixtures."

if [[ "${SAML_SMOKE_LIVE:-}" != "1" ]]; then
  echo
  yellow "Phase 2 skipped (set SAML_SMOKE_LIVE=1 for live sandbox checks)."
  yellow "Live smoke requires a running RustAuth server and a real Okta/Azure/Google SAML app."
  exit 0
fi

echo
echo "=== Phase 2: live sandbox preflight ==="
echo

missing=()
check_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    missing+=("$name")
    red "  missing: $name"
  else
    green "  ok: $name"
  fi
}

check_var RUSTAUTH_BASE_URL
check_var RUSTAUTH_SECRET
check_var SAML_SMOKE_PROVIDER_ID
check_var SAML_SMOKE_IDP_VENDOR
check_var SAML_SMOKE_IDP_ENTRY_POINT
check_var SAML_SMOKE_IDP_ENTITY_ID
check_var SAML_SMOKE_IDP_CERT_PEM

if ((${#missing[@]} > 0)); then
  echo
  red "Fix missing live variables (see ${ENV_EXAMPLE}), then re-run with SAML_SMOKE_LIVE=1."
  exit 1
fi

BASE="${RUSTAUTH_BASE_URL%/}"
METADATA_URL="${BASE}/sso/saml2/sp/metadata/${SAML_SMOKE_PROVIDER_ID}"

echo
echo "Checking SP metadata endpoint..."
if curl -fsS "${METADATA_URL}" -o /tmp/rustauth-saml-sp-metadata.xml; then
  green "  SP metadata reachable: ${METADATA_URL}"
  if grep -q "EntityDescriptor" /tmp/rustauth-saml-sp-metadata.xml; then
    green "  metadata contains EntityDescriptor"
  else
    red "  metadata missing EntityDescriptor — register the SAML provider first"
    exit 1
  fi
else
  red "  cannot fetch ${METADATA_URL} — is the server running and provider registered?"
  exit 1
fi

echo
echo "Checking IdP signing certificate..."
cert_path="${SAML_SMOKE_IDP_CERT_PEM}"
if [[ -f "${cert_path}" ]]; then
  cert_path="${cert_path}"
elif [[ "${SAML_SMOKE_IDP_CERT_PEM}" == *"BEGIN CERTIFICATE"* ]]; then
  printf '%s\n' "${SAML_SMOKE_IDP_CERT_PEM}" > /tmp/rustauth-saml-idp-cert.pem
  cert_path="/tmp/rustauth-saml-idp-cert.pem"
else
  red "  SAML_SMOKE_IDP_CERT_PEM is not a file and does not look like PEM"
  exit 1
fi

if openssl x509 -in "${cert_path}" -noout -subject >/dev/null 2>&1; then
  green "  IdP cert parses as X.509"
  openssl x509 -in "${cert_path}" -noout -subject -dates
else
  red "  IdP cert failed openssl parse"
  exit 1
fi

echo
yellow "Live browser steps (manual — cannot be automated without IdP credentials):"
echo "  1. Upload ${METADATA_URL} (or download XML) to your ${SAML_SMOKE_IDP_VENDOR} SAML app"
echo "  2. Set IdP entryPoint=${SAML_SMOKE_IDP_ENTRY_POINT}"
echo "  3. Set IdP entityId=${SAML_SMOKE_IDP_ENTITY_ID}"
echo "  4. POST ${BASE}/sign-in/sso with providerId=${SAML_SMOKE_PROVIDER_ID}"
echo "  5. Complete login at IdP; verify ACS creates session (no /login-error redirect)"
echo
green "Phase 2 preflight complete. Finish sign-in in the browser per SMOKE-SAML.md."
