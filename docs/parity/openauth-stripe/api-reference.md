# Stripe — server API reference (1.6.9 parity)

HTTP surface and configuration aligned with `packages/stripe/src/routes.ts` and `types.ts`. For tests see [upstream-test-catalog.md](./upstream-test-catalog.md).

---

## Routes

| Method | Path | Session | Origin check | Notes |
| --- | --- | --- | --- | --- |
| `POST` | `/stripe/webhook` | No | No | `hide_from_openapi`, raw body, signature |
| `POST` | `/subscription/upgrade` | Yes | `successUrl`, `cancelUrl` | |
| `POST` | `/subscription/cancel` | Yes | `returnUrl` | |
| `POST` | `/subscription/restore` | Yes | No | |
| `GET` | `/subscription/list` | Yes | No | |
| `GET` | `/subscription/success` | Optional | `callbackURL` | HTTP redirect |
| `POST` | `/subscription/billing-portal` | Yes | `returnUrl` | |

`referenceMiddleware` actions: `upgrade-subscription`, `list-subscription`, `cancel-subscription`, `restore-subscription`, `billing-portal`.

---

## Bodies and query

### `POST /subscription/upgrade`

| Field | Type | Default |
| --- | --- | --- |
| `plan` | string | required |
| `annual` | bool | false |
| `referenceId` | string | session user or active org |
| `subscriptionId` | string | optional |
| `customerType` | `user` \| `organization` | `user` |
| `metadata` | object | optional |
| `seats` | number | 1 if licensed |
| `locale` | string | optional (Stripe checkout) |
| `successUrl` | string | `/` |
| `cancelUrl` | string | `/` |
| `returnUrl` | string | portal/schedule |
| `scheduleAtPeriodEnd` | bool | false |
| `disableRedirect` | bool | false |

**Responses:** new checkout (session JSON + `redirect`); active sub → portal URL, direct update, or schedule (`url` + `redirect`).

### `POST /subscription/cancel`

| Field | Notes |
| --- | --- |
| `returnUrl` | required |
| `referenceId`, `subscriptionId`, `customerType` | optional |
| `disableRedirect` | default false |

Flow: Billing Portal `subscription_cancel`. If Stripe already canceled: sync local `cancelAt*` (fallback for lost webhook).

### `POST /subscription/restore`

No `disableRedirect`. Requires pending cancel or `stripeScheduleId`. Releases plugin schedule or clears `cancel_at` / `cancel_at_period_end`.

### `GET /subscription/list`

Query: `referenceId`, `customerType`. Only `active` / `trialing`. Enriched with `limits`, `priceId`, and in OpenAuth optionally `group` from the plan.

### `GET /subscription/success`

Query: `callbackURL` (default `/`), `checkoutSessionId`. Without session → redirect. Reconciles checkout when possible.

### `POST /subscription/billing-portal`

`locale`, `referenceId`, `customerType`, `returnUrl` (default `/`), `disableRedirect`.

---

## Webhook

| Header / config | Behavior |
| --- | --- |
| `stripe-signature` | Required |
| `stripeWebhookSecret` | Literal HMAC key (`whsec_…`) |
| Built-in events | `checkout.session.completed`, `customer.subscription.*` |
| `on_event` | All events; failure → `STRIPE_WEBHOOK_ERROR` |
| OpenAuth idempotency | `stripeWebhookEvent` table by `event.id` |

Built-in handlers: errors logged; route returns 200 when verification succeeds (except `on_event` failure or OpenAuth handler error that rolls back the claim).

---

## Stripe API used (both sides)

| API | Use |
| --- | --- |
| `customers.search` / `list` / `create` / `retrieve` / `update` | User/org customers |
| `prices.list` / `retrieve` | lookup_key, metered |
| `checkout.sessions.create` / `retrieve` | Sign-up and success |
| `billingPortal.sessions.create` | Portal, cancel, upgrade confirm |
| `subscriptions.list` / `retrieve` / `update` | Status, direct upgrade |
| `subscriptionSchedules.*` | End-of-period change |
| `webhooks.constructEvent*` | Upstream Node only |

---

## Database and organization hooks

| Hook | Model | Effect |
| --- | --- | --- |
| `user.create.after` | user | Stripe customer if `createCustomerOnSignUp` (best-effort) |
| `user.update.after` | user | Email sync (best-effort) |
| `organization.update.after` | organization | Name sync (best-effort) |
| `member.create.after` / delete / invitation accept | member / invitation | Seat sync |
| `organization.delete.before` | organization | Block if non-terminal subs |

**Note (G6 closed):** Better Auth queries Stripe (`subscriptions.list`, `limit: 100`). OpenAuth queries local `subscription` rows by `reference_id` **and** Stripe with the same non-terminal statuses (`active`, `trialing`, `past_due`, `paused`, `unpaid`).

---

## `GET /subscription/success` — important difference

| Step | Better Auth 1.6.9 | OpenAuth |
| --- | --- | --- |
| List Stripe subs | `status: "active"` only | `status: "all"`, first active/trialing |
| Validate metadata | `subscriptionId` in checkout metadata | Also rejects if metadata `referenceId` ≠ local row |

OpenAuth reconciles **trialing** checkouts that upstream may miss (G8).

---

## Plugin schema

| Field / table | When |
| --- | --- |
| `user.stripeCustomerId` | always |
| `organization.stripeCustomerId` | `organization.enabled` |
| `subscription` (full table) | `subscription.enabled` |
| `stripeWebhookEvent` | always (OpenAuth) |
| `subscription.limits` (optional) | OpenAuth schema; webhooks persist `plan.limits` when set |

**Not in default schema:** `priceId`, `groupId` on the row (upstream does not store them; list merges from plan config).

---

## Configurable callbacks

| Callback | Trigger |
| --- | --- |
| `onCustomerCreate` | User customer created/linked |
| `getCustomerCreateParams` | Before user create |
| `organization.onCustomerCreate` / `getCustomerCreateParams` | Org customer |
| `getCheckoutSessionParams` | New checkout |
| `authorizeReference` | Foreign `referenceId` or org |
| `onSubscriptionComplete` | Post checkout webhook |
| `onSubscriptionCreated` | Dashboard sub created |
| `onSubscriptionUpdate` | Sub updated |
| `onSubscriptionCancel` | New pending cancel |
| `onSubscriptionDeleted` | Sub deleted |
| `freeTrial.onTrialStart` / `onTrialEnd` / `onTrialExpired` | Trials |
| `onEvent` | Any webhook |
