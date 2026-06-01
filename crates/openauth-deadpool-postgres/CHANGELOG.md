# Changelog

All notable changes to `openauth-deadpool-postgres` are documented in this file.

## Unreleased

### Fixed

- Reject schema migrations whose plan carries non-executable warnings before any
  statement runs, matching the SQLx Postgres preflight. Because the pooled
  adapter reuses the `openauth-tokio-postgres` schema path, `create_schema` and
  `run_migrations` no longer mutate the schema when the planner reports warnings
  such as column type drift.
- Fixed rate-limit persistence so negative stored counts are rejected instead
  of wrapping to huge values when decoded as `u64`.
- Roll back in-flight transactions when `transaction()` or rate-limit `consume()`
  is dropped before explicit `COMMIT`/`ROLLBACK`, keeping the checked-out pool
  connection until cleanup completes so recycled connections cannot commit
  orphaned writes from an aborted request.

## [0.0.6] - 2026-05-24

### Added

- Added focused adapter, configuration, rate-limit, and transaction modules.
- Added expanded Postgres adapter conformance coverage.

### Changed

- Reworked the deadpool-postgres adapter surface around the shared
  tokio-postgres implementation.

## [0.0.5] - 2026-05-19

### Added

- Published the beta deadpool-postgres adapter release line.

