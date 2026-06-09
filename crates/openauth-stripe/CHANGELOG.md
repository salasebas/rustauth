# Changelog

All notable changes to `openauth-stripe` are documented in this file.

## Unreleased

## [0.1.1] - 2026-06-09

### Changed

- **Breaking:** `stripe()` returns `Result<AuthPlugin, StripeConfigError>` and
  rejects an empty `stripe_webhook_secret` at plugin construction time.
- **Breaking:** removed `stripe_with_options`; use `stripe` only.
- **Breaking:** privatized internal modules (`routes`, `customers`, `hooks`,
  `schema`, `metadata`, `utils`, …). Public integration surface is
  `stripe()`, `StripeOptions`, hook input types, `StripeClient`, and
  `stripe_api`.
- **Breaking:** option structs are `#[non_exhaustive]` with `pub(crate)` fields;
  configure through builder methods. Hook setters accept plain `async` closures.
- **Breaking:** removed public `Arc<dyn Fn>` hook type aliases.

## [0.1.0] - 2026-06-08




### Changed

- **Breaking:** Stripe plugin database logical names are now `snake_case`
  (`stripe_webhook_event`, `stripe_customer_id` on user/organization,
  subscription field keys such as `reference_id`, `period_start`, …). HTTP
  subscription JSON and Stripe-facing metadata keys remain camelCase
  (`referenceId`, `stripeCustomerId`, …).

### Added

- Added durable webhook idempotency by Stripe `event.id` (OPE-40). A new
  `stripe_webhook_event` table records processed events: already-processed
  deliveries are skipped with HTTP 200, the event is claimed before side
  effects run, and a failed `on_event` hook removes the claim so Stripe retries
  can recover. On SQL adapters the primary key also blocks concurrent duplicate
  deliveries.

### Fixed

- Customer search now scans up to 100 results per page (and paginates when needed)
  before falling back to customer creation, so a foreign same-email customer in the
  first search slot no longer triggers duplicate customer creation (OPE-156).
- Customer fallback lookups paginate Stripe `customers.list` responses instead of
  scanning only the first page when `customers.search` is unavailable (OPE-138).
- Subscription state reconciliation paginates Stripe list calls instead of
  loading only the first page.
- Releases orphaned subscription schedules when a period-end update fails after
  the schedule was created.
- Fixed `customer.subscription.updated` handling so the customer-id fallback no
  longer overwrites an unrelated local subscription (OPE-81). When the event
  has no trusted mapping (matching `id`, `stripe_subscription_id`, or plugin
  metadata), the handler now adopts a local row only when exactly one row for
  that customer is still unlinked; otherwise it logs a warning and skips instead
  of selecting an arbitrary active/trialing row.
- Fixed checkout success fallback to reconcile trialing subscriptions that were
  not activated by the primary webhook delivery path.
- Fixed organization seat synchronization to clamp Stripe subscription
  quantities to at least one seat when syncing member counts.
- Webhook signature verification now uses the endpoint signing secret verbatim
  (including the `whsec_` prefix) as the HMAC key, matching Stripe's official
  libraries. Previously the `whsec_` prefix was stripped and the suffix
  base64-decoded, which rejected valid Dashboard/CLI webhook deliveries whose
  suffix was valid base64. Removed the `webhook_signing_key` helper.

## [0.0.6] - 2026-05-24

### Added

- Added server-side Stripe plugin registration with customer, subscription,
  billing portal, and webhook endpoints.
- Added a Stripe API client abstraction with injectable transport for tests.
- Added user and organization customer linking, email/name synchronization, and
  customer creation hooks.
- Added subscription plan configuration, checkout upgrade flows, cancel/restore
  flows, active subscription listing, billing portal creation, and free-trial
  hooks.
- Added webhook signature verification and local subscription synchronization
  for checkout and subscription lifecycle events.
- Added plugin schema contributions for Stripe customer IDs and subscription
  storage.
- Added route, webhook, metadata, customer, organization, utility, and Stripe API
  coverage.

## [0.0.5] - 2026-05-19

### Added

- Published the beta Stripe integration release line.
