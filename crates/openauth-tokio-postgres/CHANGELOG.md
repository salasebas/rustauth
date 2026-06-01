# Changelog

All notable changes to `openauth-tokio-postgres` are documented in this file.

## Unreleased

### Fixed

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

