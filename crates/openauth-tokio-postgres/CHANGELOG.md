# Changelog

All notable changes to `openauth-tokio-postgres` are documented in this file.

## Unreleased

## [0.1.1] - 2026-06-09

### Changed

- Postgres migration planning now loads schema snapshots with batched catalog
  queries instead of per-column `information_schema` round trips (shared with
  `openauth-deadpool-postgres`).

### Fixed

- Postgres migration introspection no longer spends tens of seconds in slow
  `constraint_column_usage` lookups on large auth schemas.
- Fixed standalone `TokioPostgresRateLimitStore` construction bypassing the
  adapter transaction gate when both were built from cloned `Client` handles.
  Introduced `TokioPostgresConnection` as the shared client/gate bundle,
  added `TokioPostgresAdapter::rate_limit_store()` /
  `TokioPostgresRateLimitStore::from_connection`, and removed constructors that
  silently created a separate gate on the same physical connection.
- Reject schema migrations whose plan carries non-executable warnings before any
  statement runs, matching the SQLx Postgres preflight. `create_schema` and
  `run_migrations` now fail closed on planner warnings (such as column type
  drift) instead of silently applying the additive parts of the plan.
- Fixed rate-limit persistence so negative stored counts are rejected instead
  of wrapping to huge values when decoded as `u64`.
- Roll back in-flight transactions when `transaction()` or rate-limit `consume()`
  is dropped before explicit `COMMIT`/`ROLLBACK` (cancellation, task abort, or
  panic), holding the shared connection gate until cleanup completes so later
  operations cannot commit orphaned writes.

## [0.0.6] - 2026-05-24

### Added

- Added focused adapter, rate-limit, transaction, query, row, and schema
  handling modules.
- Added expanded Postgres adapter and driver coverage.

### Changed

- Reworked tokio-postgres adapter internals around reusable conformance support.

## [0.0.5] - 2026-05-19

### Added

- Published the beta tokio-postgres adapter release line.

