# Stripe — upstream test catalog (1.6.9)

Inventory of all **150** `it()` cases in `packages/stripe/test/`, with status against `openauth-stripe`.

Legend:

| Status | Meaning |
| --- | --- |
| **Covered** | Behavior covered by Rust tests (different name OK) |
| **N/A** | TypeScript / Stripe Node SDK only; not applicable to Rust |
| **Partial** | Logic likely aligned; missing dedicated or narrow equivalent test |
| **Extension** | OpenAuth test without upstream counterpart |

---

## Summary

| Metric | Count |
| --- | ---: |
| Upstream `it()` tests | 150 |
| OpenAuth `#[test]` / `#[tokio::test]` | 174 |
| Upstream type-only (`expectTypeOf` inside `it`) | 4 cases in `stripe type` block |
| **N/A** (TS inference + v18 SDK) | 7 |
| **Partial** (documented test gap) | 0 |
| **Extension** (Rust-only) | ~20+ (idempotency, form encoding, plugin_surface, trial 0d, …) |

---

## Runtime parity gaps — closed 2026-06-01

| # | Topic | Status |
| --- | --- | --- |
| G1 | **`limits` on `subscription` row** | **Closed** — optional schema field; webhooks `created`/`updated`/`checkout.completed` persist `plan.limits` |
| G2 / T1 | **Single `customers.create` on signup + upgrade** | **Closed** — `signup_and_upgrade_call_customers_create_only_once` |
| G3 | **`FAILED_TO_FETCH_PLANS`** | **Extension** in Rust (no change) |
| G4 | **Init `seatPriceId` with `plans_provider`** | **Closed** — `tokio::spawn` + `resolve_plans()` in init |
| G5 | **Organization hooks** | **Design** — own DB hooks (documented) |
| G6 | **Org delete with active subs on Stripe** | **Closed** — `list_subscriptions` + test without local row |
| G7 | **Checkout create error** | **Closed** — Stripe `code`/`message` when not mapped to another plugin code |
| G8–G10 | Success / webhook updated | **OpenAuth improvements** (not reverted) |
| G11 | **Member count** | **Closed** — `adapter.count` via `organization_member_count` |
| G12 | **Already-scheduled cancel** | **Parity** (Stripe JSON code) |

No known open runtime gaps for 1.6.9.

### Gap closure (2026-06-01)

Implementation in `crates/openauth-stripe/` + regression tests. Prior re-audit: **G6–G12** identified in second pass (2026-06-02 in historical doc).

---

## N/A tests (7)

| Upstream test | Reason |
| --- | --- |
| should api endpoint exists | `expectTypeOf` → `auth.api.stripeWebhook` |
| should have subscription endpoints | `expectTypeOf` → subscription APIs |
| should infer plugin schema fields on user type | TS inference `stripeCustomerId` |
| should infer plugin schema fields alongside additional user fields | TS inference + schema merge |
| should call constructEventAsync with exactly 3 required parameters | Stripe Node SDK v19+ |
| should support Stripe v18 with sync constructEvent method | Stripe Node SDK v18 |
| should handle constructEventAsync returning null/undefined | Node SDK |

**Rust equivalent:** `plugin_surface.rs`, `stripe_api/webhook_signature.rs` (custom HMAC, not `constructEvent`).

---

## Partial tests (0)

| Upstream test | OpenAuth status | Note |
| --- | --- | --- |
| should only call Stripe customers.create once for signup and upgrade | **Covered** | `customers::signup_and_upgrade_call_customers_create_only_once` |

---

## OpenAuth extensions (tests without upstream counterpart)

| Rust module | Covers |
| --- | --- |
| `webhooks/idempotency.rs` | Durable `event.id`, retry after failure |
| `webhooks/resilience.rs` | Rollback claim when checkout retrieve fails |
| `stripe_api/form_encoding.rs` | Stripe bracket form notation |
| `stripe_api/webhook_signature.rs` | `whsec_`, timestamp, v1 signature |
| `stripe_api/client.rs` | Authenticated transport + schedules |
| `plugin_surface.rs` | Endpoint/schema/callback registration |
| `routes/upgrade_trial_validation.rs` | `freeTrial.days == 0` rejected |
| `routes/list_limits.rs` | Nested `limits` + `group` on list |
| `routes/upgrade_lookup.rs` | `FAILED_TO_FETCH_PLANS` on lookup |
| `errors/stripe_api_mapping.rs` | Stripe code → plugin mapping |
| `organization.rs` | bulk delete, clamp seats, add missing seat item |
| `examples/stripe-smoke-server` | CLI / secret redaction (outside crate) |

---

## By upstream file

### `metadata.test.ts` (4) — **Covered**

- drops __proto__ / constructor / prototype (customer + subscription)
- internal fields always take precedence

→ `tests/metadata.rs`

### `utils.test.ts` (9) — **Covered**

- escapeStripeSearchValue (3)
- resolvePlanItem (6)

→ `tests/utils.rs`

### `seat-based-billing.test.ts` (14) — **Covered**

- checkout base+seat, member count, line items, priceId==seatPriceId
- portal seat swap, prorationBehavior, skip unchanged swap, seat-only upgrade
- invitation accept / member removal seat sync
- webhook seat create/update

→ `upgrade.rs`, `active_upgrade.rs`, `organization.rs`, `webhook_lifecycle.rs`

### `stripe-organization.test.ts` (22) — **Covered**

- org customer create/reuse, portal, cancel, restore, list
- dashboard webhook, cross-org, authorizeReference, user/org separation
- update/cancel/delete webhooks, NOT_FOUND, customer errors, onSubscriptionCreated
- metadata collision, org hooks (name sync, delete block/allow)

→ `organization.rs`, `customers.rs`, `manage.rs`, `reference.rs`, `webhook_lifecycle.rs`

### `stripe.test.ts` (101) — **Covered** (except N/A + Partial above)

Grouped by `describe`:

| Describe block | Tests | Main Rust |
| --- | ---: | --- |
| stripe type | 4 | N/A (3) + plugin_surface |
| stripe - metadata helpers | 4 | metadata.rs |
| stripe (core user subs) | ~30 | upgrade.rs, routes.rs, customers.rs, webhook_* |
| getCustomerCreateParams | 4 | customers.rs |
| Webhook Error Handling (Stripe v19) | 8 | routes.rs webhooks, webhook_signature (N/A v18/async null) |
| Duplicate customer prevention | 2 | customers.rs signup |
| User/Org customer collision | 3 | customers.rs |
| Search API fallback | 2 | customers.rs list fallback |
| webhook cancel_at_period_end | 2 | webhook_lifecycle, webhook_hooks |
| webhook immediate cancellation | 2 | webhook_lifecycle |
| trial abuse prevention | 4 | trial_abuse.rs, upgrade.rs |
| restore subscription | 4 | manage.rs |
| cancel subscription fallback | 1 | cancel_already_canceled.rs |
| referenceMiddleware user/org | 9 | reference.rs, upgrade.rs |
| scheduling + external schedule | 4 | active_upgrade.rs |
| line items replace/add/remove/dedup | 6 | active_upgrade.rs |
| subscriptionSuccess checkoutSessionId | 4 | routes.rs |
| metered usage pricing | 5 | upgrade.rs, active_upgrade.rs |

---

## Alphabetical list (150 upstream names)

<details>
<summary>Click to expand all 150 `it()` titles</summary>

```
customerMetadata.get extracts typed fields
customerMetadata.set protects internal fields
drops __proto__ from user metadata on customerMetadata.set
drops __proto__ from user metadata on subscriptionMetadata.set
drops constructor and prototype from user metadata on customerMetadata.set
internal fields always take precedence over user metadata
should CREATE customer only when user has no stripeCustomerId and none exists in Stripe
should NOT create duplicate customer when email already exists in Stripe
should NOT return organization customer when searching for user customer with same email
should add new line items when upgrading to a plan with more items
should allow another user's referenceId when authorizeReference returns true
should allow organization deletion when no active subscription
should allow seat upgrades for the same plan
should allow upgrade from monthly to annual billing for the same plan
should api endpoint exists
should block organization deletion when active subscription exists
should call constructEventAsync with exactly 3 required parameters
should call getCustomerCreateParams and merge with default params
should call getCustomerCreateParams when creating org customer
should call onSubscriptionCreated callback for organization subscription from dashboard
should cancel subscription for organization
should check all subscriptions for trial history even when processing a specific incomplete subscription
should clear cancelAt when restoring a cancel_at (specific date) subscription
should clear cancelAtPeriodEnd when restoring a cancel_at_period_end subscription
should clear stripeScheduleId from webhook when schedule is removed
should clear stripeScheduleId on subscription deleted webhook
should create a Stripe customer for organization when upgrading subscription
should create a customer on sign up
should create a subscription
should create billing portal for organization
should create billing portal session
should create billing portal session for an existing custom referenceId
should create checkout with both base plan and seat line items
should create organization customer with customerType metadata
should escape double quotes
should escape multiple quotes
should execute subscription event handlers
should fall back to customers.list when customers.search is unavailable (user signup)
should fall back to customers.list when customers.search is unavailable (user upgrade)
should find existing user customer even when organization customer with same email exists
should handle async errors in webhook event processing
should handle constructEventAsync returning null/undefined
should handle customer.subscription.created webhook event
should handle customer.subscription.deleted webhook for organization
should handle customer.subscription.updated webhook for organization
should handle customer.subscription.updated webhook with cancellation for organization
should handle invalid webhook signature with constructEventAsync
should handle strings without quotes
should handle subscription deletion webhook
should handle subscription webhook events
should handle subscription webhook events with trial
should handle webhook for organization subscription created from dashboard
should have subscription endpoints
should include additional line items in checkout
should infer plugin schema fields alongside additional user fields
should infer plugin schema fields on user type
should keep user and organization subscriptions separate
should list active subscriptions
should list subscriptions for organization
should match by lookup key
should not allow cross-organization subscription operations
should not allow cross-user subscriptionId operations (upgrade/cancel/restore)
should not create duplicate subscription if already exists
should not duplicate base price in line_items
should not duplicate line items already present in scheduled phase
should not duplicate line items already present in the subscription (immediate)
should not duplicate subscription item when upgrading between seat-only plans
should not include extra line items when plan has none
should not include quantity for metered base price in checkout session
should not include quantity for metered price during billing portal upgrade
should not include quantity for metered price during direct subscription upgrade
should not include quantity for metered price during scheduled upgrade
should not match user customer with organizationId in metadata during org customer lookup
should not release schedules created outside the plugin
should not update personal subscription when upgrading with a custom referenceId
should only call Stripe customers.create once for signup and upgrade
should pass metadata to subscription when upgrading
should pass when authorizeReference returns true
should pass when no explicit referenceId is provided
should pass when referenceId equals user id
should persist seat count on subscription creation
should prevent duplicate subscriptions with same plan and same seats
should prevent multiple free trials across different plans
should prevent multiple free trials for the same user
should prevent trial abuse after subscription canceled during trial
should propagate trial data from Stripe event on subscription.deleted
should propagate trial data from Stripe event on subscription.updated
should properly merge nested objects using defu
should redirect when checkout session retrieval fails
should redirect without update when checkoutSessionId is missing
should reject another user's referenceId when authorizeReference returns false
should reject organization subscription when authorizeReference is not configured
should reject restore when no pending cancel and no pending schedule
should reject webhook request without stripe-signature header
should reject when authorizeReference is not defined
should reject when authorizeReference is not defined but other referenceId is provided
should reject when authorizeReference returns false
should reject when no referenceId or activeOrganizationId
should release existing schedule before immediate upgrade
should release existing schedule before scheduling a new one
should release schedule and clear stripeScheduleId when restoring a pending schedule
should remove extra line items when downgrading to a plan with fewer items
should replace {CHECKOUT_SESSION_ID} placeholder in callbackURL with actual session ID
should restore subscription for organization
should return ORGANIZATION_NOT_FOUND when upgrading for non-existent organization
should return annualDiscountPriceId when subscription billingInterval is year
should return billingInterval in subscription.list() response
should return error when Stripe customer creation fails for organization
should return error when getCustomerCreateParams callback throws
should return item and plan for single-item subscriptions
should return item without plan for unmatched single-item
should return matching plan item from multi-item subscription
should return undefined for empty items
should return undefined when no plan matches in multi-item
should return updated subscription in onSubscriptionUpdate callback
should schedule plan change at period end when scheduleAtPeriodEnd is true
should set endedAt when cancel_at_period_end subscription reaches period end
should set status=canceled and endedAt when subscription is immediately canceled
should skip creating subscription when metadata.subscriptionId exists
should skip seat item swap when seat pricing is unchanged
should skip subscription creation when plan not found
should skip subscription creation when user not found
should still include quantity for licensed base price in checkout session
should store billingInterval as year for annual subscriptions
should successfully process webhook with valid async signature verification
should support Stripe v18 with sync constructEvent method
should support flexible limits types
should swap line item prices in scheduled phase
should swap line item prices when upgrading immediately
should swap seat item when upgrading to a plan with different seat pricing
should sync cancelAt when subscription is scheduled to cancel at a specific date
should sync cancelAtPeriodEnd and canceledAt when user cancels via Billing Portal (at_period_end mode)
should sync from Stripe when cancel request fails because subscription is already canceled
should sync organization name to Stripe customer on update
should sync seat quantity when a member accepts an invitation
should sync seat quantity when a member is removed
should sync stripeScheduleId from webhook when schedule is present
should update seat count on subscription update
should update stripe customer email when user email changes
should update subscription via checkoutSessionId and redirect
should upgrade existing active subscription even when canceled subscription exists for same referenceId
should upgrade existing subscription instead of creating new one
should use actual member count as seat quantity
should use custom prorationBehavior from plan config
should use custom prorationBehavior on member removal
should use existing Stripe customer ID from organization
should use getCustomerCreateParams to add custom address
should work without getCustomerCreateParams
subscriptionMetadata.get extracts typed fields
subscriptionMetadata.set protects internal fields
```

</details>

---

## Easy-to-forget request fields (verified in code)

| Field | Routes | Upstream / OpenAuth default |
| --- | --- | --- |
| `locale` | upgrade checkout, billing portal | optional |
| `disableRedirect` | upgrade, cancel, portal | `false` → `redirect: true` in JSON |
| `scheduleAtPeriodEnd` | upgrade | `false` |
| `successUrl` / `cancelUrl` | upgrade | `"/"` |
| `returnUrl` | cancel (required), portal, schedule | cancel has no default in upstream zod; OpenAuth validates URL |
| `customer_update` | checkout | user: `name`+`address` auto; org: `address` auto |
| `{CHECKOUT_SESSION_ID}` | success URL | literal placeholder preserved |
| Schedule metadata | subscription schedule | `source = @better-auth/stripe` |

See [features.md](./features.md) and [design-differences.md](./design-differences.md).
