# Better Auth Stripe parity notes

Reference: Better Auth `packages/stripe` at **1.6.9** (`reference/upstream-src/1.6.9/repository/packages/stripe/`).

OpenAuth-stripe is an idiomatic Rust port, not a line-by-line copy. This document records intentional differences and upstream behavior we mirror.

## Aligned with upstream

| Area | Behavior |
|------|----------|
| **Database hooks** (sign-up customer, email sync, org name, seat sync) | Best-effort: failures are logged and do not fail the primary DB operation. |
| **Webhook handlers** (`checkout.session.completed`, subscription lifecycle) | Handler errors are logged; Stripe still receives HTTP 200 when signature and JSON parsing succeed. |
| **`on_event` hook** | If it returns an error, the webhook responds with `STRIPE_WEBHOOK_ERROR` (same as upstream outer `catch`). |
| **Webhook signature** | The endpoint signing secret is used verbatim (including the `whsec_` prefix) as the HMAC key, matching Stripe's official libraries. |
| **HTTP route errors** | Structured `StripeErrorCode` JSON via `respond_stripe_api_error` where Stripe API calls run on subscription endpoints. |
| **Checkout webhook fallback** | Resolves local subscription by `client_reference_id` / metadata `referenceId` when `subscriptionId` metadata is missing. |
| **Logging** | `warn` / `error` messages follow upstream wording where applicable (`ctx.logger` in TS → `AuthContext::logger` or hook fallback logger). |

## Documented in upstream types but not implemented there (1.6.9)

| Item | Upstream | OpenAuth-stripe |
|------|----------|-----------------|
| **`groupId` on subscriptions** | Present on the `Subscription` TypeScript type only; **not** in DB schema or routes. | Not implemented (same). Use distinct `referenceId` values for multiple billing contexts. |
| **`group` on plans** | Type-only for plan configuration. | Optional on `StripePlan`; exposed on **GET** `/subscription/list` when set (small extension; upstream list only adds `limits` and `priceId`). |
| **Webhook idempotency by `event.id`** | Not implemented. | Not implemented. Retries rely on idempotent DB updates / skip-if-exists logic. |
| **`SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION`** | Deprecated alias in `error-codes.ts`; restore uses `SUBSCRIPTION_NOT_PENDING_CHANGE`. | Only `SUBSCRIPTION_NOT_PENDING_CHANGE` is exposed (no deprecated alias). |

## Rust-specific differences

| Item | Notes |
|------|--------|
| **Hook logger on DB paths** | `PluginDatabaseHookContext::logger` is the same application logger as `AuthContext::logger` (upstream: optional request `ctx` with `ctx.context.logger` in `with-hooks.ts`). |
| **Experimental status** | Crate README still marks the integration as experimental beta. |
| **Stripe client** | Custom `StripeClient` + `StripeTransport` instead of the official Stripe Node SDK (server-only, no browser SDK). |

## When adding features

Prefer matching upstream **runtime** behavior and tests over TypeScript types that are unused in 1.6.9. If OpenAuth adds behavior beyond upstream, update this file in the same PR.
