# Changelog

All notable changes to `openauth-sqlx` are documented in this file.

## Unreleased


### Fixed

- Fixed rate-limit persistence so negative stored counts are rejected instead
  of wrapping to huge values when decoded as `u64`.

## [0.0.6] - 2026-05-24

### Added

- Added shared migration and rate-limit helpers.
- Added shared test helpers and expanded MySQL, Postgres, and SQLite adapter
  coverage.

### Changed

- Hardened SQL schema planning across MySQL, Postgres, and SQLite adapters.
- Updated dialect-specific error, query, row, schema, and state handling.

### Fixed

- Improved migration behavior around unique constraints and existing tables.

## [0.0.5] - 2026-05-19

### Added

- Published the beta SQLx adapter release line.

