# Changelog

All notable changes to `openauth-core` are documented in this file.

## Unreleased

### Fixed

- Fixed session cookie cache authentication so cached session data is only
  returned after the backing session token still exists and is unexpired.

## [0.0.6] - 2026-05-24

### Added

- Added route service modules for email/password, password, session, and user
  behavior.
- Added database adapter harness support, schema builder modules, join support,
  hook pipelines, and ID policy coverage.
- Added typed option modules for email/password, email verification, password,
  and session configuration.
- Added secret handling and JWE secret helpers.

### Changed

- Hardened auth flows, session storage, account linking, password routes,
  session routes, SQL schema planning, migrations, and rate limiting.
- Split large account, password, social, database factory, schema, and hook
  modules into focused units.
- Gated JOSE crypto support behind feature flags where possible.

### Fixed

- Preserved body encoding details in request errors.
- Fixed migration checks for unique constraints and table existence.

## [0.0.5] - 2026-05-19

### Added

- Published the beta core release line.

