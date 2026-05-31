# Changelog

All notable changes to `openauth-stripe` are documented in this file.

## [Unreleased]

### Fixed

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
