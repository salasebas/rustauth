# Changelog

All notable changes to `openauth-stripe` are documented in this file.

## [Unreleased]

### Added

- Added durable webhook idempotency by Stripe `event.id` (OPE-40). A new
  `stripeWebhookEvent` table records processed events: already-processed
  deliveries are skipped with HTTP 200, the event is claimed before side
  effects run, and a failed `on_event` hook removes the claim so Stripe retries
  can recover. On SQL adapters the primary key also blocks concurrent duplicate
  deliveries.

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
