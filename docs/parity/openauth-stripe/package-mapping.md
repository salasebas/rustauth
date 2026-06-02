# Stripe — package and module mapping

## Upstream vs OpenAuth packaging

Better Auth ships **one npm package** with two entry points; OpenAuth ships **one crate** and optionally re-exports it from the meta-crate.

| Layer | Better Auth 1.6.9 | OpenAuth |
| --- | --- | --- |
| Server plugin | `@better-auth/stripe` → `dist/index.mjs` | `openauth-stripe` |
| Client plugin | `@better-auth/stripe/client` → `stripeClient()` | **Not ported** (server-only) |
| Application facade | `better-auth` + plugins on `auth` | `openauth` with feature `stripe` |
| Organization / seats | Depends on `better-auth/plugins/organization` at runtime | Depends on OpenAuth `organization` plugin (separate crate) |
| Core HTTP / schema | `@better-auth/core`, `better-call` | `openauth-core` (`AuthPlugin`, endpoints, adapter) |

We do not split Stripe into multiple crates: all logic lives in **`openauth-stripe`**. The upstream equivalent of “split packages” is **workspace dependencies** (`openauth`, `openauth-core`, organization plugin) instead of a TS monorepo.

## Module tree

### Upstream (`packages/stripe/src/`)

| File | Responsibility |
| --- | --- |
| `index.ts` | `stripe()`, init, user DB hooks, organization hook chaining |
| `routes.ts` | All 7 endpoints (~single large file) |
| `hooks.ts` | Webhook handlers: checkout + subscription lifecycle |
| `middleware.ts` | Session + `referenceMiddleware` |
| `schema.ts` | `getSchema`, user/org/subscription fields |
| `types.ts` | Options, plans, callbacks |
| `metadata.ts` | Metadata merge + anti prototype pollution |
| `utils.ts` | Plans, plan item, pending cancel, search |
| `error-codes.ts` | `STRIPE_ERROR_CODES` |
| `client.ts` | **Client-only** Better Auth |
| `version.ts` | Package version |

### OpenAuth (`crates/openauth-stripe/src/`)

| Module | Upstream equivalent | Notes |
| --- | --- | --- |
| `lib.rs` | `index.ts` | Plugin registration, DB hooks, init warnings |
| `routes/*.rs` | `routes.ts` | Split by endpoint (`upgrade`, `manage`, `list_portal`, `webhook`, `active_upgrade`, …) |
| `hooks/*.rs` | `hooks.ts` | Dispatch + checkout + subscriptions |
| `routes/reference.rs` | `middleware.ts` | Authorization by `referenceId` / org |
| `schema.rs` | `schema.ts` | + `stripeWebhookEvent` table |
| `options.rs` | `types.ts` | Structs + callback type aliases |
| `metadata.rs` | `metadata.ts` | |
| `utils.rs` | `utils.rs` | |
| `errors.rs` | `error-codes.ts` | |
| `customers.rs` | Parts of `index.ts` + `routes.ts` | Customer create / search |
| `organization.rs` | Part of `index.ts` | Org hooks (private) |
| `stripe_api/mod.rs` | Node `stripe` SDK | HTTP client + signature verification |
| `models.rs` | Partial Stripe types in TS | Deserialization DTOs |
| `logging.rs` | `ctx.logger` | |

## External dependencies

| Need | Upstream | OpenAuth |
| --- | --- | --- |
| Stripe API | Peer `stripe` ^18–22 | Custom `StripeClient` (REST form-encoded) |
| Request validation | `zod` + OpenAPI meta | Handler validation + `JsonSchemaType` / OpenAPI on endpoints |
| Client param merge | `defu` | Explicit merge in `customers` / checkout |
| Webhook verify | `constructEvent` / `constructEventAsync` | `verify_webhook_signature` (HMAC, 300s tolerance) |
| Tests | `vitest`, `getTestInstance`, Stripe mocks | `cargo test` + `CaptureTransport` fake |

## Integration in the OpenAuth workspace

```text
openauth (feature "stripe")
  └── re-export: openauth_stripe as stripe

openauth-stripe
  └── openauth-core (AuthPlugin, adapter, endpoints)
  └── reqwest (default transport)

Application
  └── .plugin(openauth::stripe::stripe(...))
  └── adapter migrations → user / subscription / stripe_webhook_event / organization
  └── optional: organization plugin for org billing and seats
```

## Rust public surface

| Export | Use |
| --- | --- |
| `stripe`, `stripe_with_options` | Build `AuthPlugin` |
| `StripeOptions`, `SubscriptionOptions`, `StripePlan`, … | Configuration |
| `StripeClient`, `StripeTransport` | Stripe API and test injection |
| `StripeErrorCode`, `error_codes` | Stable codes |
| `routes::*` | Endpoint factories (advanced) |
| `hooks::handle_stripe_event` | Event processing (tests / extensions) |
| `VERSION`, `UPSTREAM_PLUGIN_ID` | Parity id `stripe` |

## TypeScript client not ported

`packages/stripe/src/client.ts` exports `stripeClient()` with:

- `id: "stripe-client"`
- `$InferServerPlugin` for types
- `pathMethods` for POST `/subscription/billing-portal` and `/subscription/restore`
- Re-export of `STRIPE_ERROR_CODES`

OpenAuth consumers call the same HTTP routes with their HTTP client (fetch, reqwest, etc.). There is no client plugin or `auth.api.upgradeSubscription` inference.

## Organization integration (different design)

| Aspect | Better Auth | OpenAuth |
| --- | --- | --- |
| Wiring | `init` → `ctx.getPlugin("organization")` + merge `organizationHooks` | `PluginDatabaseHook` on `organization`, `member`, `invitation` models (`organization.rs`) |
| Error if org plugin missing | `Organization plugin not found` in log | N/A — does not depend on organization plugin at hook registration time |
| Real requirement | Organization plugin + stripe `organization.enabled` | Org tables/schema on the adapter + `organization.enabled` in Stripe options |

Same observable semantics (seats, delete blocking, name sync) when the adapter exposes organization models.
