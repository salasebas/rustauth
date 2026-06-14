#!/usr/bin/env bash
# Stripe test-mode smoke helper for rustauth-stripe.
# Does not start a server or complete checkout (browser/session required).
# See crates/rustauth-stripe/SMOKE.md for the full manual checklist.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_DOC="${ROOT}/crates/rustauth-stripe/SMOKE.md"
ENV_EXAMPLE="${ROOT}/crates/rustauth-stripe/.env.smoke.example"

red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }

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

echo "rustauth-stripe smoke — env checks"
echo "Runbook: ${SMOKE_DOC}"
echo "Template: ${ENV_EXAMPLE}"
echo

if [[ -f "${ROOT}/.env" ]]; then
  yellow "Loading ${ROOT}/.env"
  # shellcheck disable=SC1091
  set -a && source "${ROOT}/.env" && set +a
else
  yellow "No ${ROOT}/.env — export variables in your shell or create from .env.smoke.example"
fi

echo
echo "Required for Stripe API:"
check_var STRIPE_SECRET_KEY

echo
echo "Webhooks (smoke server uses Stripe CLI listen, not STRIPE_WEBHOOK_SECRET from .env):"
if [[ -n "${STRIPE_WEBHOOK_SECRET:-}" ]]; then
  yellow "  STRIPE_WEBHOOK_SECRET is set (ignored by rustauth-example-stripe-smoke)"
else
  green "  ok: STRIPE_WEBHOOK_SECRET not required for smoke server"
fi

echo
echo "Required for your server (typical names):"
check_var RUSTAUTH_SECRET
check_var RUSTAUTH_BASE_URL

echo
echo "Recommended plan price IDs (must match StripeOptions in your app):"
check_var STRIPE_PRICE_PRO_MONTHLY

if ((${#missing[@]} > 0)); then
  echo
  red "Fix missing variables, then re-run this script."
  exit 1
fi

BASE="${RUSTAUTH_BASE_URL%/}"
WEBHOOK_URL="${BASE}/stripe/webhook"

echo
echo "Smoke server (starts stripe listen + picks a free port):"
echo "  set -a && source .env && set +a && cargo run -p rustauth-example-stripe-smoke"
echo
yellow "Manual listen (only if not using the smoke server):"
echo "  stripe listen --forward-to ${WEBHOOK_URL}"
echo
echo "Stripe CLI — trigger test events (after listen is running):"
echo "  stripe trigger checkout.session.completed"
echo "  stripe trigger customer.subscription.created"
echo "  stripe trigger customer.subscription.updated"
echo "  stripe trigger customer.subscription.deleted"
echo

if [[ -n "${RUSTAUTH_SESSION_COOKIE:-}" ]]; then
  echo "Session cookie set — example authenticated upgrade (JSON body):"
  echo "  curl -sS -X POST '${BASE}/subscription/upgrade' \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -H 'Cookie: ${RUSTAUTH_SESSION_COOKIE}' \\"
  echo "    -d '{\"plan\":\"pro\",\"successUrl\":\"http://127.0.0.1:3000/billing/success\",\"cancelUrl\":\"http://127.0.0.1:3000/billing/cancel\",\"disableRedirect\":true}'"
  echo
  echo "List subscriptions:"
  echo "  curl -sS '${BASE}/subscription/list' -H 'Cookie: ${RUSTAUTH_SESSION_COOKIE}'"
else
  yellow "RUSTAUTH_SESSION_COOKIE not set — sign in via your app, copy the session cookie, then re-run."
  echo "  Manual steps: sign-up → upgrade → complete Checkout → verify webhooks and DB (see SMOKE.md)."
fi

echo
echo "Done. Follow the checklist in SMOKE.md for sign-up, org billing, cancel/restore, and seat sync."
