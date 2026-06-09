# Changelog

All notable changes to `openauth-sqlx` are documented in this file.

## Unreleased

## [0.1.1] - 2026-06-09

### Changed

- Postgres migration planning now loads schema snapshots with batched catalog
  queries (`pg_catalog` for constraints and indexes) instead of per-column
  `information_schema` round trips.

### Fixed

- Postgres migration introspection no longer spends tens of seconds in slow
  `constraint_column_usage` lookups on large auth schemas.
- Rate-limit persistence rejects negative stored counts instead of wrapping to
  huge values when decoded as `u64`.

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

