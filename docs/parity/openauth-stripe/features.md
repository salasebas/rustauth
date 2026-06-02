# Stripe — feature inventory and parity

Status legend:

| Status | Meaning |
| --- | --- |
| **Parity** | Server behavior aligned with Better Auth 1.6.9 |
| **Extension** | Implemented in OpenAuth but not in upstream 1.6.9 (or stricter) |
| **N/A client** | Exists only in `@better-auth/stripe/client` |
| **N/A upstream** | Upstream types/docs only, no runtime in 1.6.9 |
| **Partial** | Parity with nuances in [design-differences.md](./design-differences.md) |

---

## 1. HTTP routes

Base: OpenAuth prefix (`base_url`, e.g. `/api/auth`).

| Method | Route | `operationId` | Registered | Status |
| --- | --- | --- | --- | --- |
| `POST` | `/stripe/webhook` | `handleStripeWebhook` | Always | **Parity** (hidden from OpenAPI) |
| `POST` | `/subscription/upgrade` | `upgradeSubscription` | If `subscription.enabled` | **Parity** |
| `POST` | `/subscription/cancel` | `cancelSubscription` | If subscriptions | **Parity** |
| `POST` | `/subscription/restore` | `restoreSubscription` | If subscriptions | **Parity** |
| `GET` | `/subscription/list` | `listActiveSubscriptions` | If subscriptions | **Parity** (+ `group` in response, see Extension) |
| `GET` | `/subscription/success` | `handleSubscriptionSuccess` | If subscriptions | **Parity** |
| `POST` | `/subscription/billing-portal` | `createBillingPortal` | If subscriptions | **Parity** |

Equivalent middleware: authenticated session, `referenceMiddleware` per action, origin checks on return/success/cancel URLs.

---

## 2. Webhooks

| Stripe event | Handler | Status |
| --- | --- | --- |
| `checkout.session.completed` | Update local subscription, trials, `onSubscriptionComplete` | **Parity** |
| `customer.subscription.created` | Create row if missing (dashboard), `onSubscriptionCreated` | **Parity** |
| `customer.subscription.updated` | Sync status, pending cancel, schedule, trials | **Parity** |
| `customer.subscription.deleted` | Mark canceled, `onSubscriptionDeleted` | **Parity** |
| Other events | `on_event` only if configured | **Parity** |

| Behavior | Upstream 1.6.9 | OpenAuth | Status |
| --- | --- | --- | --- |
| `stripe-signature` verification | Yes | Yes | **Parity** |
| `whsec_` secret as-is | Yes | Yes | **Parity** |
| Built-in handlers best-effort (log, HTTP 200) | Yes | Yes | **Parity** |
| `on_event` failure → `STRIPE_WEBHOOK_ERROR` | Yes | Yes | **Parity** |
| Idempotency by `event.id` | No | `stripeWebhookEvent` table | **Extension** |
| Rollback idempotency on handler/`on_event` failure | No | Yes | **Extension** |

---

## 3. Schema and storage

| Field / table | Upstream | OpenAuth | Status |
| --- | --- | --- | --- |
| `user.stripeCustomerId` | Yes | Yes | **Parity** |
| `organization.stripeCustomerId` | If `organization.enabled` | Yes | **Parity** |
| `subscription` table (standard fields) | If `subscription.enabled` | Yes | **Parity** |
| Omit `subscription` when subs disabled | Yes | Yes | **Parity** |
| Custom schema merge | Yes | Yes | **Parity** |
| `stripeWebhookEvent` | No | Yes (`id` = Stripe event id) | **Extension** |
| `Subscription.priceId` in DB | No (response only) | No (response only) | **Parity** |
| `Subscription.groupId` | TS type only | No | **N/A upstream** |

Subscription statuses: `active`, `canceled`, `incomplete`, `incomplete_expired`, `past_due`, `paused`, `trialing`, `unpaid` — **Parity**.

---

## 4. Plugin configuration

| Option / callback | Status |
| --- | --- |
| `stripeClient` / `StripeClient` | **Parity** (different implementation) |
| `stripeWebhookSecret` | **Parity** |
| `createCustomerOnSignUp` | **Parity** |
| `onCustomerCreate`, `getCustomerCreateParams` | **Parity** |
| `onEvent` | **Parity** |
| `subscription.enabled`, `plans`, dynamic plans | **Parity** |
| `subscription.requireEmailVerification` | **Parity** |
| Subscription hooks (`onSubscription*`, trials, `getCheckoutSessionParams`) | **Parity** |
| `subscription.authorizeReference` | **Parity** |
| `organization.enabled` + org hooks | **Parity** (requires OpenAuth organization plugin) |
| Init validation `seatPriceId` without org | **Parity** (warn/error log) |
| Plugin version + error codes registered | **Parity** |

### `StripePlan` model

| Field | Status |
| --- | --- |
| `name`, `priceId`, `lookupKey` | **Parity** |
| `annualDiscountPriceId`, `annualDiscountLookupKey` | **Parity** |
| `limits`, `group` | **Parity** (`group` on list: **Extension** in response) |
| `seatPriceId`, `prorationBehavior`, `lineItems` | **Parity** |
| `freeTrial` (+ callbacks) | **Parity** |
| Reject trial `days == 0` on upgrade | Not explicit in upstream tests | **Extension** (`upgrade_trial_validation.rs`) |

---

## 5. Stripe customers

| Flow | Status |
| --- | --- |
| Create customer on sign-up (best-effort) | **Parity** |
| Search by email (`customers.search` + `list` fallback) | **Parity** |
| Exclude `customerType=organization` customers in user search | **Parity** |
| Internal metadata (`userId`, `organizationId`, `customerType`) | **Parity** |
| Anti prototype pollution on metadata | **Parity** |
| Sync user email → Stripe | **Parity** |
| Sync organization name → Stripe | **Parity** |
| Org customer on upgrade / billing portal | **Parity** |
| Block org delete with active subs (non-terminal states) | **Parity** |

---

## 6. Subscriptions — main flows

| Flow | Status |
| --- | --- |
| New checkout (`upgrade` without active sub) | **Parity** |
| Reuse local `incomplete` row | **Parity** |
| Reject same plan + seats + active price | **Parity** |
| Monthly → annual same plan | **Parity** |
| Active sub upgrade via Billing Portal (simple) | **Parity** |
| Multi-item / line items upgrade via `subscriptions.update` | **Parity** |
| Scheduled change at period end (`subscription_schedules`) | **Parity** |
| Schedule metadata `source = @better-auth/stripe` | **Parity** |
| Do not release schedules outside the plugin | **Parity** |
| Cancel via portal `subscription_cancel` | **Parity** |
| Restore: clear cancel / release schedule | **Parity** |
| List: active/trialing only + limits + priceId by interval | **Parity** |
| `GET /subscription/success` redirect + checkout reconcile | **Parity** |
| Free trial: once per `referenceId` | **Parity** |
| Metered: omit `quantity` on checkout/upgrade/schedule | **Parity** |
| Org seats: quantity from members, member/invite hooks | **Parity** |
| `authorizeReference` user vs org | **Parity** |
| Cross-user `subscriptionId` rejected | **Parity** |

---

## 7. Error codes

22 active codes in OpenAuth = 22 from upstream **without** the deprecated one:

| Code | OpenAuth | Upstream |
| --- | --- | --- |
| `SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION` | Not exposed | Deprecated (alias) |
| Rest (`UNAUTHORIZED` … `ORGANIZATION_REFERENCE_ID_REQUIRED`) | Yes | Yes |

Stripe API error → plugin code mapping: **Parity** (tests in `tests/errors/stripe_api_mapping.rs`).

---

## 8. Easy-to-miss behaviors (verified in code)

| Behavior | Status |
| --- | --- |
| `locale` on checkout and billing portal | **Parity** |
| `disableRedirect` on upgrade / cancel / portal | **Parity** |
| `scheduleAtPeriodEnd` + schedule metadata `@better-auth/stripe` | **Parity** |
| Webhook `hide_from_openapi` / raw body | **Parity** |
| `customer_update` name/address auto on checkout | **Parity** |
| `{CHECKOUT_SESSION_ID}` in success URL | **Parity** |
| `checkout.session.completed` ignores `mode=setup` | **Parity** |
| Trial once per `referenceId` (any plan) | **Parity** |
| `reference_has_ever_trialed` with explicit incomplete `subscriptionId` | **Parity** (`trial_abuse.rs`) |
| Cancel `returnUrl` has no default (client must send) | **Parity** |
| Org delete blocks `past_due`, `unpaid`, etc. | **Parity** |
| `limits` persisted on webhook create/update | **Parity** — optional schema + hooks/checkout; list still merges from plan like upstream |
| `FAILED_TO_FETCH_PLANS` at runtime | **Extension** — dead code in upstream TS |
| Org delete: subscription source of truth | Stripe API list + local rows | **Parity** |
| Checkout create: HTTP error code | Stripe `code` in body | Stripe `code`/`message` when unmapped | **Parity** |
| Success with `trialing` sub on Stripe | Lists `active` only | Lists `all`, filters active/trialing | **Extension** (better) |
| Success: validate metadata `referenceId` | No | Yes | **Extension** |

---

## 9. Out of scope / not ported

| Item | Reason |
| --- | --- |
| `stripeClient()` (`client.ts`) | **N/A client** — TypeScript browser helper |
| `expectTypeOf` tests for `auth.api.*` | **N/A client** — TS compiler only |
| Stripe Node SDK (`constructEventAsync` v19+) | **Partial** — equivalent custom verification, no SDK version fork |
| OpenAPI from `zod.meta` | **Partial** — OpenAuth uses `operation_id` + `OpenApiOperation`; not 1:1 with upstream zod pipeline |
| Example checkout UI | Not in upstream package; OpenAuth has smoke server without UI (**roadmap** in ROADMAP.md) |

---

## 10. Dependencies on other plugins

| Integration | Upstream | OpenAuth |
| --- | --- | --- |
| Organization plugin | Required if `organization.enabled` | `organization` plugin on the same server |
| Session `activeOrganizationId` | Yes | Yes (same org reference semantics) |
| Seat sync in org hooks | Yes | Yes |

Without the organization plugin, routes with `customerType=organization` and `seatPriceId` are incomplete — same as upstream.
