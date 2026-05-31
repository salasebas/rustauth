# Changelog

All notable changes to the OpenAuth workspace are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

## Unreleased

### Fixed

- Fixed `openauth-tokio-postgres` and `openauth-deadpool-postgres` leaving
  connections in open transactions when `transaction()` or rate-limit `consume()`
  is cancelled or panics mid-callback, which could let a later `COMMIT` persist
  aborted auth writes (cross-request transaction bleed).

## [0.0.6] - 2026-05-24

### Added

- Added server-side SCIM provisioning support with users, groups, bulk
  operations, filtering, patching, metadata routes, token handling, and adapter
  conformance coverage.
- Added OAuth 2.1/OpenID Connect provider parity work, including authorization,
  client, consent, token, introspection, metadata, logout, and userinfo
  endpoint modules.
- Added standalone `openauth-oidc` and `openauth-saml` crates split from SSO
  internals.
- Added richer i18n locale responses and the `openauth` umbrella feature for
  re-exporting i18n.
- Added Fred-backed secondary storage support and stronger SQL/Postgres adapter
  conformance coverage.

### Changed

- Hardened core auth flows, sessions, password routes, account linking,
  database schema planning, SQL migrations, and route service boundaries.
- Split large route, storage, adapter, CLI, passkey, plugin, and provider
  modules into smaller focused modules.
- Gated JOSE crypto dependencies behind feature flags where possible.
- Updated Axum integration contracts for routing, request conversion, response
  handling, and error behavior.
- Updated release automation and manual release documentation to include every
  workspace crate in dependency order.
- Updated CI and local test guidance to use `cargo-nextest` for faster test
  execution.
- Added a Docker Compose helper that recreates stale test service containers
  and verifies published ports before integration tests run.

### Fixed

- Fixed request error reporting so body encoding context is preserved.
- Fixed SQL migration checks for unique constraints and table existence.
- Fixed Postgres migration constraint introspection.
- Fixed SCIM resource mutation and filter validation behavior.
- Fixed social provider token authentication method defaults.

## [0.0.5] - 2026-05-19

### Changed

- Published the beta workspace release line to crates.io.
- Updated release automation to continue when a crate version already exists.

## [0.0.3] - 2026-05-15

### Added

- Published an early OpenAuth pre-release.
