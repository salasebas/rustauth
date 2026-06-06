# Changelog

All notable changes to `openauth` are documented in this file.

## [Unreleased]

### Changed

- **Breaking:** Email/password authentication is disabled by default. Enable it
  with `OpenAuthBuilder::email_password(EmailPasswordOptions::new().enabled(true))`.
  `EmailPasswordOptions` is now re-exported from the `openauth` crate.

### Fixed

- SQL/memory/Postgres adapter constructors apply `database_hooks` once instead of
  wrapping the inner adapter on every `new`.
- `open_auth_async` / `OpenAuth::new_async` build without requiring the
  `telemetry` feature.

## [0.0.6] - 2026-05-24

### Added

- Added umbrella feature wiring for `openauth-i18n`.
- Added optional umbrella exports for the split OIDC, SAML, and SCIM crates.
- Added public API and feature-flag coverage for the expanded crate surface.

### Changed

- Kept the top-level crate aligned with the workspace feature split and new
  integration crates.

## [0.0.5] - 2026-05-19

### Added

- Published the beta umbrella crate release line.
