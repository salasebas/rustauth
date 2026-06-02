# Stripe — design differences (intentional and platform)

OpenAuth is **server-only** (Rust). Better Auth 1.6.9 ships the same plugin on npm with a **`/client`** entry for TypeScript client types and helpers. This document classifies each relevant difference.

---

## 1. By OpenAuth design choice

| Topic | Better Auth 1.6.9 | OpenAuth | Why |
| --- | --- | --- | --- |
| Stripe HTTP client | Official Node `stripe` SDK | `StripeClient` + `StripeTransport` trait | Rust, network-free tests, timeout control (30s default) |
| Code layout | Monolithic `routes.ts` | `routes/` per endpoint | Maintainability in Rust |
| Webhook idempotency | No | `stripeWebhookEvent` table by `event.id` | Duplicate Stripe deliveries / retries; rollback if `on_event` fails |
| Deprecated code | `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION` | Only `SUBSCRIPTION_NOT_PENDING_CHANGE` | Avoid dead API surface in Rust |
| `group` on `GET /subscription/list` | On plan type; list does not return it | `group` in JSON when the plan defines it | Small, useful extension for HTTP clients |
| `freeTrial.days == 0` validation | Not explicitly tested | Error on upgrade | Fail fast on invalid configuration |
| Crate status | Part of stable BA ecosystem | README: **experimental beta** | OpenAuth release policy until beta is removed |

---

## 2. Aligned with upstream (same runtime, different implementation)

| Topic | Notes |
| --- | --- |
| DB hooks best-effort | Sign-up and email sync do not fail the primary operation |
| Webhook handlers best-effort | Internal errors logged; HTTP 200 when signature is OK |
| Strict `on_event` | Error → `STRIPE_WEBHOOK_ERROR` |
| Webhook secret | `whsec_` used as HMAC key without transformation |
| Internal metadata wins over user | + filter `__proto__`, `constructor`, `prototype` |
| Plugin id | `"stripe"` |
| Routes and `operationId` | Same names as upstream |
| Plugin schedules | Metadata `source = @better-auth/stripe`; do not touch foreign schedules |

---

## 3. Runtime parity with nuance (review 2026-06-01)

| Topic | Upstream 1.6.9 | OpenAuth | Impact |
| --- | --- | --- | --- |
| **`limits` on subscription row** | `hooks.ts` writes `plan.limits` when the adapter has the column | Optional schema `limits` + webhooks/checkout persist; **GET list** still merges from plan when missing on row | Aligned with upstream when the field exists |
| **`FAILED_TO_FETCH_PLANS`** | In `error-codes.ts`, unused in `src/` | Used in lookup/plan/transport errors | Intentional Rust extension |
| **Init warn `seatPriceId` without org** | Async `plans()` in init | Static + `plans_provider` via `resolve_plans` in spawn | Aligned |
| **Organization hooks** | Chains BA `organizationHooks` | Stripe plugin’s own DB hooks on org models | OpenAuth design (same semantics with org tables) |
| **Block organization delete** | `subscriptions.list` on Stripe | Local **and** Stripe (`limit: 100`, same terminal statuses) | Aligned (G6 closed) |
| **Checkout create errors** | Stripe `code` in body | Same when not mapped to another plugin code | Aligned (G7 closed) |
| **`/subscription/success`** | Only Stripe subs `active` | Includes `trialing` | G8 — OpenAuth more complete |
| **`referenceId` check on success** | No | Yes | G9 |
| **`subscription.updated` without id** | Heuristic by customer | Only unlinked row without `stripe_subscription_id` | G10 |

### OpenAuth hardening (beyond 1.6.9)

| Area | Extra behavior |
| --- | --- |
| Webhooks | `stripeWebhookEvent` idempotency + rollback on failure |
| Upgrade | `reconcile_active_upgrade_record` before `active_upgrade` |
| Checkout webhook | Resolve local row by `client_reference_id` when `subscriptionId` metadata is missing |
| Cancel | Detect `subscription_already_canceled` via JSON code (not substring only) |
| Org seats | `last_member_delete_clamps_organization_seats_to_one` (test) |

---

## 4. Upstream types only (do not implement without a requirement)

| Topic | Upstream | OpenAuth |
| --- | --- | --- |
| `Subscription.groupId` | In `types.ts`, **not** in schema or routes | Not implemented (same as BA 1.6.9 runtime) |
| `group` on plan | TS configuration | Supported on plan; **extra** on list response |

Use distinct **`referenceId`** values for multiple subscriptions per entity — same recommendation as upstream comments.

---

## 5. Server-only vs client-only (ignore for parity)

| Surface | OpenAuth action |
| --- | --- |
| `@better-auth/stripe/client` → `stripeClient()` | Do not port; document equivalent HTTP routes |
| `$InferServerPlugin`, `pathMethods` | Replace with Rust types or OpenAPI |
| Tests `expectTypeOf<MyAuth["api"][...]>` (12 cases) | **Not** a Rust test gap |
| Checkout/portal redirects | Server returns URL/`redirect`; browser follows the link |

---

## 6. Workspace integration (not a Stripe divergence)

| Aspect | Notes |
| --- | --- |
| Single crate `openauth-stripe` vs monorepo `packages/stripe` | Same functional boundary; different packaging |
| `openauth/stripe` feature | Convenience; equivalent to importing the plugin in `better-auth` |
| `examples/stripe-smoke-server` | OpenAuth tool (CLI + `stripe listen`); not in upstream package |
| DB migrations | OpenAuth adapter responsibility, not the npm package |

---

## 7. Documentation drift

| Document | Note |
| --- | --- |
| `SMOKE.md` | Previously said `event.id` idempotency was out of scope; **now implemented** — corrected |
| `ROADMAP.md` / `tests.md` | Current count **174** tests under `crates/openauth-stripe/tests/` |

---

## 8. Parity documented in the crate

Keep in sync with this directory:

- `crates/openauth-stripe/UPSTREAM.md` — short summary
- `crates/openauth-stripe/ROADMAP.md` — closed items and beta/1.0

When adding behavior **beyond** Better Auth 1.6.9, update this file and `UPSTREAM.md` in the same PR.
