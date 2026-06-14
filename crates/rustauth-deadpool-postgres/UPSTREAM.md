# Upstream parity — rustauth-deadpool-postgres

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
RustAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `@better-auth/kysely-adapter` (PostgreSQL) |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/kysely-adapter/`; migrations under `packages/better-auth/src/db/` |
| **Rust crate** | `crates/rustauth-deadpool-postgres/` |
| **Parity level** | **High (~96%)** for observable Postgres adapter semantics |
| **Scope** | Server-side pooled Postgres `DbAdapter`, `RateLimitStore`, and migration execution. SQL planning and dialect logic live in [`rustauth-sqlx`](../rustauth-sqlx/UPSTREAM.md) and [`rustauth-tokio-postgres`](../rustauth-tokio-postgres/README.md). HTTP routes, adapter factory transforms, and client SDKs are out of scope. |

## Summary

`rustauth-deadpool-postgres` is the recommended production Postgres adapter: it wraps
`deadpool-postgres` pooling around shared Postgres SQL planning from `rustauth-sqlx`
and driver helpers from `rustauth-tokio-postgres`. Observable database behavior
(CRUD, filters, joins, transactions, additive migrations, native arrays, and
SQL-backed rate limits) matches the non-pooled Postgres adapters. Remaining gap is
mostly TypeScript API-shape parity, not missing Postgres semantics.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| `DbAdapter` CRUD | ✅ High | `create`, `find_one`, `find_many`, `count`, `update`, `update_many`, `delete`, `delete_many` |
| Filters and sorting | ✅ High | Equality, comparisons, `IN`/`NOT IN`, pattern operators, null checks, `AND`/`OR`, sort, limit, offset |
| Joins | ✅ High | One-to-one, one-to-many, reverse, limited, missing-row, and multi-join reads (including inside transactions) |
| Transactions | ✅ High | Commit, rollback, SQL-error rollback; pool checkout per callback |
| Nested transactions | ❌ Missing | Rejected with adapter error (no savepoints); consistent with other RustAuth Postgres adapters |
| Schema creation | ✅ High | RustAuth and plugin tables from `DbSchema`; optional compiled SQL output |
| Migration planning | ✅ High | Additive tables, columns, indexes, FKs, generated defaults; type-mismatch reporting |
| Migration execution | ✅ High | Each plan runs in a single Postgres transaction; matches `PostgresAdapter` in `rustauth-sqlx` |
| Native Postgres arrays | ✅ High | `StringArray` / `NumberArray` columns; JSONB-backed legacy arrays require manual migration |
| Rate-limit storage | ✅ High | `DeadpoolPostgresRateLimitStore`; atomic consume, denied-request semantics |
| Connection pooling | 🎯 Extension | `deadpool-postgres` pool with `connect_checked` / `validate_connection` fail-fast |
| Physical table names | ✅ High | `AuthSchemaOptions` prefixes and schema-qualified names such as `internal.users` |
| Core auth route flows | ✅ High | Email/password sign-up, additional user fields, password-reset verifications via pooled adapter |
| Public HTTP routes | ➖ N/A | Kysely adapter has no route surface; routes live in `rustauth-core` / `rustauth` |
| Adapter factory transforms | ⚠️ Partial | Defaults, field mappings, and `onUpdate` live in RustAuth core/service layers |
| Non-Postgres dialects | ➖ N/A | SQLite, MySQL, MSSQL, D1, etc. are [`rustauth-sqlx`](../rustauth-sqlx/UPSTREAM.md) scope |

## Test coverage

| Surface | RustAuth (Rust) | Upstream | Notes |
| --- | --- | --- | --- |
| Integration tests | 46 | — | `tests/postgres_adapter.rs`; shared harness in `tests/support/postgres_adapter_conformance.rs` |
| Unit tests | 3 | — | `src/config.rs` (URL/env helpers, error formatting) |
| Pool-specific | 6 | 0 | Checkout validation, missing DB errors, cancelled-tx rollback, concurrent pool ops |
| Upstream Postgres Kysely | — | `adapter.kysely.pg.test.ts`, `adapter.kysely.custom-schema-pg.test.ts`, shared adapter suites | Same behavioral contract as other Postgres adapters |
| Migrations | Covered | 10 `it()` in `get-migration-schema.test.ts` | Transactional plan rollback and warning rejection tested locally |
| Database rate limits | 4 | `rate-limiter.test.ts` | Atomic consume, deny semantics, negative-count rejection |
| **Total (this crate)** | **49** | **Postgres Kysely + shared suites** | `cargo nextest list -p rustauth-deadpool-postgres` |

Verify:

```bash
cargo nextest run -p rustauth-deadpool-postgres
```

Requires reachable Postgres (`RUSTAUTH_TEST_POSTGRES_URL` or Docker Compose defaults on
`postgres://user:password@localhost:5432/rustauth`).

## Intentional differences

| Topic | Better Auth 1.6.9 | RustAuth | Why |
| --- | --- | --- | --- |
| Connection model | Kysely pool via runtime options | `deadpool-postgres` pool; optional owned `Pool` injection | Production pooling without SQLx dependency |
| Nested transactions | Not a first-class Kysely concern | Explicitly rejected | Avoid savepoint complexity across pooled connections |
| Delete semantics | Full `WHERE` passed through `delete` | Single-row `delete`; bulk via `delete_many` | Fail-closed auth boundaries (shared with [`rustauth-sqlx`](../rustauth-sqlx/UPSTREAM.md)) |
| Pattern matching | Kysely `LIKE`/`ILIKE` from raw user values | `%`, `_`, `\` escaped with explicit `ESCAPE` | Treat user input literally |
| Schema creation | Implicit in some migration paths | Postgres schemas not created implicitly for `schema.table` | Caller/migration environment must create schema first |
| Default list limit | Factory defaults `findMany` to 100 | No adapter-level default limit | Explicit limits at HTTP/service layer |
| TypeScript factory ergonomics | Debug logs, dynamic transform hooks | Rust schema + service layers | Idiomatic, typed server boundaries |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| G1 | TypeScript API-shape parity | Low | Observable Postgres semantics match; remaining delta is factory/ergonomics, not SQL |
| G2 | Legacy JSONB-backed array columns | Med | Planner reports type mismatches; manual migration required |
| G3 | Live Postgres required for full test run | Med | No in-memory substitute; CI/local Docker dependency |
| G4 | Shared Better Auth adapter e2e suites not ported 1:1 | Low | `postgres_adapter_conformance` + focused integration tests instead |
| G5 | Postgres custom-schema e2e depth | Low | `current_schema()` introspection tested; upstream also has search-path e2e suites |

## Hardening notes

- Pool checkout per transaction; cancelled transactions roll back and release connections cleanly.
- `connect_checked` / `validate_connection` fail fast when the pool cannot reach Postgres.
- Migration plans with type warnings are rejected before any DDL executes.
- Each migration plan runs inside one Postgres transaction (atomic apply/rollback).
- Rate-limit counters consumed in one transaction; denied requests do not rewrite counters.
- LIKE/ILIKE operators escape SQL wildcard characters from user input.
- Nested transactions return an explicit adapter error instead of creating savepoints.

## Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is missing.
3. Open `reference/upstream-src/1.6.9/repository/packages/kysely-adapter/`.
4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `kysely-adapter.ts` (Postgres paths) | `src/adapter.rs`, `src/transaction.rs` |
| `query-builders.ts` | Shared SQL planner via `rustauth-sqlx` / `rustauth-tokio-postgres` |
| `better-auth/db/get-migration.ts` | `src/migration.rs` (re-exports), adapter `plan_migrations` / `run_migrations` |
| `packages/better-auth/src/api/rate-limiter/` | `src/rate_limit.rs` |
| `adapter.kysely.pg.test.ts`, shared adapter suites | `tests/postgres_adapter.rs`, `tests/support/postgres_adapter_conformance.rs` |

5. Add a failing Rust integration test before behavior changes; match HTTP status, error
   codes, and DB side effects—not TypeScript types.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [rustauth-sqlx UPSTREAM](../rustauth-sqlx/UPSTREAM.md) — shared SQL planning and dialect gaps
- [rustauth-tokio-postgres](../rustauth-tokio-postgres/README.md) — non-pooled Postgres sibling
- [Parity index](../../docs/parity/README.md)
