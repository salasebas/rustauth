# Stripe — Better Auth ↔ OpenAuth parity

Parity documentation for the **`openauth-stripe`** crate versus Better Auth **`@better-auth/stripe` v1.6.9**.

| Field | Value |
| --- | --- |
| Parity target | Better Auth **1.6.9** (`f484269`) |
| Upstream | `reference/upstream-src/1.6.9/repository/packages/stripe/` |
| OpenAuth | `crates/openauth-stripe/` |
| Facade integration | `openauth` feature `stripe` → `pub use openauth_stripe as stripe` |
| Scope of this analysis | **Server only** (no port of `client.ts`) |

## Index

| Document | Contents |
| --- | --- |
| [package-mapping.md](./package-mapping.md) | How upstream vs OpenAuth is packaged, dependencies, and modules |
| [features.md](./features.md) | Routes, hooks, schema, callbacks, and parity table |
| [api-reference.md](./api-reference.md) | HTTP bodies, defaults, Stripe API calls, DB hooks |
| [design-differences.md](./design-differences.md) | Intentional differences, extensions, and Rust/server-only limits |
| [tests.md](./tests.md) | Test counts, domain matrix, and gaps |
| [upstream-test-catalog.md](./upstream-test-catalog.md) | All 150 upstream `it()` cases mapped; gaps G1–G12 closed |

## References in the repo

| Resource | Path |
| --- | --- |
| Short notes in the crate | `crates/openauth-stripe/UPSTREAM.md` |
| Roadmap / closed gaps | `crates/openauth-stripe/ROADMAP.md` |
| Historical implementation checklist | `docs/superpowers/plans/2026-05-12-upstream-stripe-server-checklist.md` |
| Manual test-mode smoke | `crates/openauth-stripe/SMOKE.md`, `scripts/stripe-smoke.sh` |
| Minimal example | `examples/stripe-smoke-server/` |

## Executive summary

| Dimension | Better Auth 1.6.9 | OpenAuth `openauth-stripe` |
| --- | --- | --- |
| npm/crates packages | 1 plugin + `./client` export | 1 Rust crate (+ optional re-export in `openauth`) |
| HTTP routes (server) | 7 (webhook always; 6 if `subscription.enabled`) | **Same 7 routes** |
| Stripe client | Official Node `stripe` SDK | `StripeClient` + `StripeTransport` (`reqwest`) |
| Plugin id | `stripe` | `stripe` (`UPSTREAM_PLUGIN_ID`) |
| Error codes | 23 (incl. 1 deprecated) | 22 (no deprecated alias) |
| Runtime tests | **150** Vitest `it()` | **174** Rust integration tests |
| Type-only tests | **12** `expectTypeOf` | N/A |
| Product status | Stable in BA ecosystem | **Experimental beta** (crate README) |

**Server behavior parity:** core flows (customers, subscriptions, webhooks, org/seats, scheduling, metered, references) are ported and covered by tests; see [features.md](./features.md) and [tests.md](./tests.md).

**OpenAuth extensions (beyond 1.6.9):** durable webhook idempotency (`stripeWebhookEvent`), `group` on `GET /subscription/list`, explicit rejection of zero-day trials.

**Out of scope by design:** `@better-auth/stripe/client` (`stripeClient()`), TypeScript inference of `auth.api.*`, and any example checkout UI in the browser.

**Deep review (2026-06-01):** catalog of 150 tests + [api-reference.md](./api-reference.md).

**Second pass (2026-06-02):** re-read of `routes.ts` / `hooks.ts` / `index.ts` — gaps **G1–G12** documented in [upstream-test-catalog.md](./upstream-test-catalog.md).

**Gap closure (2026-06-01):** implemented G1, G4, G6, G7, G11, T1/G2 with regression tests; no known open runtime gaps for 1.6.9. G8–G10 remain intentional OpenAuth hardening.
