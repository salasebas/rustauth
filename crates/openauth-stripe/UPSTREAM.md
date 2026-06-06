# openauth-stripe upstream parity

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` |
| Pin file | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| Upstream package/path | `@better-auth/stripe` / `reference/upstream-src/1.6.9/repository/packages/stripe/` |
| Rust crate | `openauth-stripe` |
| Parity level | High server-side billing plugin parity |
| Scope | Server routes, schema, metadata, hooks, webhook handling, Stripe API wrapper |

`openauth-stripe` tracks the Better Auth Stripe server plugin where behavior is
observable over HTTP, database mutations, webhook outcomes, and Stripe request
parameters. This document only covers the server plugin surface.

## Summary

OpenAuth implements the full Better Auth `@better-auth/stripe` server plugin:
seven billing routes, customer linking, webhook lifecycle sync, schema
contributions, metadata protection, and organization hooks. Rust adds durable
webhook idempotency and stricter redirect validation. Remaining risk is mostly
operational: live Stripe smoke testing, route rate limits, and webhook table
migrations.

## Server-Side Inventory

| Category | Upstream files audited | Notes |
| --- | --- | --- |
| Server plugin | `src/index.ts`, `src/routes.ts`, `src/middleware.ts` | Plugin registration, route bodies, auth/reference middleware, init hooks. |
| Data contracts | `src/schema.ts`, `src/types.ts`, `src/metadata.ts`, `src/error-codes.ts` | Runtime options, schema, metadata, and error-code contracts. |
| Runtime helpers | `src/hooks.ts`, `src/utils.ts`, `src/version.ts` | Webhook lifecycle, plan matching, subscription status helpers, package version. |
| Server tests | `test/stripe.test.ts`, `test/stripe-organization.test.ts`, `test/seat-based-billing.test.ts`, `test/metadata.test.ts`, `test/utils.test.ts` | Used as behavioral evidence for server routes/hooks/utilities. |
| Out of scope | `src/client.ts`, `package.json`, `README.md`, `CHANGELOG.md`, `tsconfig.json`, `tsdown.config.ts`, `vitest.config.ts` | Not server runtime behavior; excluded from parity rows below. |

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Plugin entrypoint and exports | ✅ Implemented | `stripe(...)`, options, plans, error codes, and `StripeClient` map to upstream server exports. |
| HTTP route registration | ✅ Implemented | Same seven server routes: upgrade, cancel, restore, list, success, billing portal, webhook. |
| User customer linking | ✅ Implemented | Creates or links Stripe customers by email/metadata and stores `user.stripeCustomerId`. |
| Sign-up customer database hook | ✅ Implemented | Optional `create_customer_on_sign_up` creates or links customers after user sign-up. |
| User email sync on update | ✅ Implemented | Syncs Stripe customer email when the local user record changes. |
| Organization customer linking | ✅ Implemented | Creates, links, and syncs `organization.stripeCustomerId` when organization billing is enabled. |
| Reference authorization | ✅ Implemented | Session required; `authorizeReference` hook; organization active-org fallback. |
| Dynamic plan resolution | ✅ Implemented | Static plan lists or async `get_plans` providers. |
| Email verification gate | ✅ Implemented | Blocks upgrade when `require_email_verification` is enabled and email is unverified. |
| Checkout creation | ✅ Implemented | Plan lookup, annual prices, lookup keys, line items, metered prices, seats, trials, metadata, locale, `disableRedirect`, and `{CHECKOUT_SESSION_ID}` success URLs. |
| Checkout/customer param hooks | ✅ Implemented | `getCheckoutSessionParams`, `getCustomerCreateParams`, and organization customer create callbacks. |
| Free-trial anti-abuse | ✅ Implemented | Skips plan trials for references that already consumed a trial on the plan set. |
| Checkout success reconciliation | ✅ Implemented | `/subscription/success` reconciles checkout when webhooks lag; substitutes callback checkout session IDs. |
| Incomplete subscription reuse | ✅ Implemented | Reuses existing local `incomplete` subscription rows instead of creating duplicates on upgrade. |
| Active subscription upgrades | ✅ Implemented | Updates active subscriptions, supports multi-item changes, seat prices, and schedule release. |
| Scheduled plan changes | ✅ Implemented | Uses Stripe subscription schedules and stores `stripeScheduleId`. |
| Cancel and restore routes | ✅ Implemented | Handles portal cancel flow, pending cancels, and pending schedule release. |
| Billing portal route | ✅ Implemented | Creates portal sessions for user or organization customer references. |
| Active subscription listing | ✅ Implemented | Returns active/trialing records with plan limits and price metadata. |
| Webhook signature verification | ✅ Implemented | Validates `stripe-signature` against the configured webhook secret. |
| Webhook lifecycle sync | ✅ Implemented | Handles checkout completion and subscription created, updated, and deleted events. |
| Database schema | ✅ Implemented | Adds user/org customer IDs, subscription storage, and OpenAuth webhook idempotency table. |
| Metadata protection | ✅ Implemented | Internal metadata wins; unsafe prototype keys and customer ID spoofing are rejected. |
| Organization hooks | ✅ Implemented | Syncs organization name, blocks deletion with active subscriptions, and syncs seat quantities on membership changes. |
| Subscription lifecycle callbacks | ✅ Implemented | `on_subscription_complete`, `on_subscription_created`, `on_subscription_update`, `on_subscription_cancel`, and `on_subscription_deleted`. |
| Trial lifecycle callbacks | ✅ Implemented | `on_trial_start`, `on_trial_end`, and `on_trial_expired` plan hooks. |
| Customer create callbacks | ✅ Implemented | `on_customer_create` for user and organization customers after Stripe customer creation or linking. |
| Raw event hook | ✅ Implemented | `on_event` observes processed events and can fail the webhook response. |
| Durable webhook idempotency | 🎯 Extension | `stripeWebhookEvent` dedupes by Stripe `event.id`; upstream has no persisted dedupe. |
| Subscription `group` response | 🎯 Extension | OpenAuth includes `group` runtime plan metadata on subscription list responses. |

## Test Coverage

| Surface | OpenAuth tests | Upstream tests | Notes |
| --- | ---: | ---: | --- |
| Customers, routes, webhooks, metadata, errors, utilities | 184 `#[test]` / `#[tokio::test]` | 150 Vitest `it(...)` cases | Counted across `crates/openauth-stripe/tests/` and upstream `packages/stripe/test/*.ts`. |
| Upstream package tests | N/A | `stripe.test.ts` 101, `stripe-organization.test.ts` 22, `seat-based-billing.test.ts` 14, `metadata.test.ts` 4, `utils.test.ts` 9 | Upstream total: 150. |
| Rust route coverage | Covered | Mapped to upstream route tests | Includes upgrade, cancel, restore, list, success, billing portal, and cross-reference authorization. |
| Rust webhook coverage | Covered | Mapped to upstream webhook tests plus extensions | Includes signature verification, lifecycle hooks, idempotency, retries, and skip paths. |
| Live Stripe behavior | ⚠️ Smoke only | Upstream uses mocked Stripe clients | Run `SMOKE.md` before production rollout. |
| Verify command | `cargo nextest run -p openauth-stripe` | Upstream package uses `vitest` | Use the Rust command for this crate. |

## Intentional Differences

| Topic | Better Auth | OpenAuth | Why |
| --- | --- | --- | --- |
| Stripe SDK | JavaScript Stripe SDK peer dependency | Injectable Rust `StripeClient` and `StripeTransport` | Idiomatic Rust testing and application-controlled HTTP behavior. |
| Webhook idempotency | Processes accepted deliveries without durable dedupe | Persists `stripeWebhookEvent` by `event.id` | Prevent duplicate side effects on retries, resends, or concurrent delivery. |
| Webhook failure handling | Built-in handlers swallow many errors | Retryable processing failures release idempotency and return an error | Avoid marking partially processed events as complete. |
| Redirect validation | Origin checks in Better Auth middleware | Explicit callback/return URL validation | Fail closed on auth and billing redirects. |
| Metadata merging | Internal fields win; unsafe keys dropped | Same, plus request metadata cannot spoof `stripeCustomerId` | Protect server-owned billing identity. |
| Error aliases | Keeps deprecated `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION` alias | Exposes only `SUBSCRIPTION_NOT_PENDING_CHANGE` | Avoid carrying deprecated aliases in the Rust public API. |
| Subscription grouping | No runtime grouping field in server responses | Runtime `group` included on list responses when configured | Exposes useful plan metadata without changing upstream route ownership rules. |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| STRIPE-S1 | Live Stripe portal/schedule/webhook delivery needs smoke testing | Medium | Fake transports cover contracts; run `SMOKE.md` with Stripe test mode. |
| STRIPE-S2 | Route-level rate limits are not added by this plugin | Medium | Rely on OpenAuth/server middleware, edge limits, and Stripe retry controls. |
| STRIPE-S3 | Webhook idempotency requires migration/table availability | High | Missing `stripeWebhookEvent` can allow duplicate side effects. |
| STRIPE-S4 | Best-effort hooks can leave stale customer/seat data | Medium | Monitor logs and reconcile through webhooks or operational checks. |
| STRIPE-S5 | Stripe and local pagination have safety caps | Low | Caps prevent unbounded loops; extremely large histories may need operational review. |

## Hardening

- Run adapter migrations after enabling the plugin so `stripeWebhookEvent`,
  `subscription`, `user.stripeCustomerId`, and `organization.stripeCustomerId`
  exist before traffic.
- Keep `STRIPE_WEBHOOK_SECRET` configured with the exact `whsec_` signing secret;
  empty secrets fail closed.
- Add deployment-level rate limits around billing routes and webhooks.
- Monitor hook and webhook logs for Stripe API, adapter, and transport failures.
- Run the manual Stripe test-mode smoke flow in [`SMOKE.md`](./SMOKE.md) before
  production rollout or after changing plans, prices, schedules, or webhooks.

## Upstream Lookup

1. Read the pin in
   [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. If the upstream tree is missing, run
   `./scripts/fetch-upstream-better-auth.sh`.
3. Inspect `reference/upstream-src/1.6.9/repository/packages/stripe/`.
4. Include server files: `src/index.ts`, `src/routes.ts`, `src/middleware.ts`,
   `src/hooks.ts`, `src/schema.ts`, `src/metadata.ts`, `src/error-codes.ts`,
   `src/types.ts`, `src/utils.ts`, `src/version.ts`, and `test/*.ts`.
5. Verify OpenAuth behavior with `cargo nextest run -p openauth-stripe`.

| Upstream file | Rust mapping |
| --- | --- |
| `src/index.ts` | `src/lib.rs`, `src/options.rs`, `src/customers.rs`, `src/organization.rs`, `src/logging.rs` |
| `src/routes.ts` | `src/routes/upgrade.rs`, `src/routes/active_upgrade.rs`, `src/routes/manage.rs`, `src/routes/list_portal.rs`, `src/routes/webhook.rs`, `src/routes/reference.rs`, `src/routes/support.rs`, `src/subscription_lookup.rs` |
| `src/schema.ts` | `src/schema.rs` |
| `src/hooks.ts` | `src/hooks/checkout.rs`, `src/hooks/subscriptions.rs`, `src/hooks/support.rs`, `src/organization.rs` |
| `src/middleware.ts` | `src/routes/reference.rs`, `src/routes/support.rs` |
| `src/metadata.ts` | `src/metadata.rs` |
| `src/error-codes.ts` | `src/errors.rs`, `tests/errors/stripe_api_mapping.rs` |
| `src/types.ts` | `src/options.rs`, `src/models.rs` |
| `src/utils.ts` | `src/utils.rs`, `src/subscription_lookup.rs`, `src/stripe_api/paginated_list.rs` |
| `src/version.ts` | `src/lib.rs` `VERSION` |
| `test/*.ts` | `tests/**/*.rs` |
| Rust-only transport | N/A (upstream uses JS Stripe SDK directly) | `src/stripe_api/mod.rs`, `src/stripe_api/paginated_list.rs` | Injectable HTTP transport and pagination helpers for tests and custom deployments. |

## Audit Checklist (server-only)

All 22 upstream package files were reviewed. Runtime server behavior is covered
below; excluded files are inventory-only.

| Upstream file | Audit status |
| --- | --- |
| `src/index.ts` | ✅ Server plugin entrypoint, init validation, database hooks, organization hooks |
| `src/routes.ts` | ✅ All seven HTTP routes and webhook dispatch |
| `src/middleware.ts` | ✅ Session and reference authorization |
| `src/hooks.ts` | ✅ Checkout and subscription webhook lifecycle |
| `src/schema.ts` | ✅ User, organization, and subscription schema |
| `src/metadata.ts` | ✅ Customer and subscription metadata merge rules |
| `src/error-codes.ts` | ✅ Server error codes |
| `src/types.ts` | ✅ Runtime server options, plans, hooks, and models |
| `src/utils.ts` | ✅ Plan lookup, status helpers, quantity/plan resolution |
| `src/version.ts` | ✅ Package version constant |
| `test/stripe.test.ts` | ✅ Primary server route and webhook behavior |
| `test/stripe-organization.test.ts` | ✅ Organization billing behavior |
| `test/seat-based-billing.test.ts` | ✅ Seat quantity sync behavior |
| `test/metadata.test.ts` | ✅ Metadata merge behavior |
| `test/utils.test.ts` | ✅ Utility helper behavior |
| `src/client.ts` | ⛔ Out of scope |
| `package.json` | ⛔ Out of scope |
| `README.md` | ⛔ Out of scope |
| `CHANGELOG.md` | ⛔ Out of scope |
| `tsconfig.json` | ⛔ Out of scope |
| `tsdown.config.ts` | ⛔ Out of scope |
| `vitest.config.ts` | ⛔ Out of scope |

All 25 Rust source files under `src/` and 37 Rust test modules under `tests/`
were mapped to the upstream server surface above. No unaudited server-runtime
upstream files remain for Better Auth `1.6.9` `@better-auth/stripe`.

## Links

- [README](./README.md)
- [Workspace parity index](../../docs/parity/README.md)
