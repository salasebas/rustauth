# Upstream parity — rustauth-tokio-postgres

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
RustAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `@better-auth/kysely-adapter` (+ `better-auth` DB/migration wiring) |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/kysely-adapter/` |
| **Rust crate** | `crates/rustauth-tokio-postgres/` |
| **Parity level** | **High** (~96% server-only for Postgres semantics this crate owns) |
| **Scope** | Server-side Postgres `DbAdapter`, migrations, and SQL rate-limit storage. Out of scope: HTTP routes (`rustauth`, `rustauth-core`), SQLx adapters (`rustauth-sqlx`), pooling (`rustauth-deadpool-postgres`), non-Postgres dialects, client SDKs |

## Summary

`rustauth-tokio-postgres` implements the Better Auth Kysely Postgres adapter contract on a
single `tokio_postgres::Client`, sharing SQL planning with `rustauth-sqlx`. CRUD, joins,
filters, transactions, additive migrations, schema-qualified tables, native arrays, and
database-backed rate limits match upstream observable behavior. Intentional differences favor
idiomatic Rust (explicit connection ownership, fail-closed migrations, escaped LIKE patterns)
and a transaction gate instead of a pool.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| Adapter CRUD | ✅ High | `create`, `find_one`, `find_many`, `count`, `update`, `update_many`, `delete`, `delete_many` |
| Physical schema names | ✅ High | Tables and fields from `AuthSchemaOptions` / `DbSchema` |
| Generated IDs | ✅ High | Text, UUID, and identity/serial IDs |
| JSON and native arrays | ✅ High | Postgres `StringArray` / `NumberArray`; JSON round-trip |
| Filters and sorting | ✅ High | Scalar and pattern filters, null equality, mixed `AND`/`OR` groups |
| Join reads | ✅ High | One-to-one, one-to-many, reverse, limited, missing-row, and multi-join (with fallback) |
| Transactions | ✅ High | Commit, rollback, SQL errors, cancellation; join reads inside transactions |
| Schema creation & migrations | ✅ High | Additive tables, columns, indexes, unique constraints, FKs, generated defaults; type-mismatch reporting |
| Schema-qualified names | ✅ High | e.g. `internal.users` (caller must create schema) |
| Rate limiting | ✅ High | SQL-backed consume store; atomic with adapter transaction gate |
| Core auth route flows | ✅ High | Email/password and password-reset flows via adapter integration tests |
| Connection pooling | ➖ N/A | Single client by design; use `rustauth-deadpool-postgres` for pools |
| HTTP routes | ➖ N/A | No route surface in this crate |
| Adapter factory ergonomics | ⚠️ Partial | Debug logs and dynamic transform hooks live in RustAuth core/plugins |
| TypeScript API shape | ⚠️ Partial | Rust types differ; database semantics align |

## Test coverage

| Surface | RustAuth (Rust) | Upstream | Notes |
| --- | --- | --- | --- |
| Postgres adapter integration | 39 `#[tokio::test]` in `tests/postgres_adapter.rs` | `adapter.kysely.pg.test.ts`, `adapter.kysely.custom-schema-pg.test.ts`, shared adapter suites, PG e2e | Requires `RUSTAUTH_TEST_POSTGRES_URL` or Docker Compose defaults |
| Driver/param binding | 1 `#[test]` in `tests/driver.rs` | Kysely dialect bind paths | Unit-level bind coverage |
| Migrations | Integration tests in `postgres_adapter.rs` | `get-migration-schema.test.ts` | Transactional plan apply and warning rejection |
| Rate limits | Integration tests in `postgres_adapter.rs` | `rate-limiter.test.ts` | Atomic consume, denied-request semantics, transaction gate |
| Shared adapter contract | `run_adapter_contract` helpers in integration tests | `packages/test-utils/src/adapter/` | Not ported 1:1 |

Verify:

```bash
cargo nextest run -p rustauth-tokio-postgres
```

Quick count: `rg '#\[test\]|#\[tokio::test\]' crates/rustauth-tokio-postgres` → **40** tests.

## Intentional differences

| Topic | Better Auth 1.6.9 | RustAuth | Why |
| --- | --- | --- | --- |
| Connection model | Kysely pool / runtime-selected adapter | Single async `tokio-postgres` client with optional shared `TokioPostgresConnection` | Smallest adapter for apps that own the client; pooling is a sibling crate |
| Concurrent access | Pool hands out connections | Normal queries may pipeline; migrations, schema DDL, transactions, and rate-limit consumes use an exclusive gate | One connection must not interleave transaction state |
| Transaction callback | Generic return value from callback | `Result<(), RustAuthError>` | Idiomatic Rust; DB state transitions preserved |
| LIKE / ILIKE patterns | Kysely wildcard semantics on user input | `%`, `_`, and `\` escaped with explicit `ESCAPE` | Treat user input literally unless an operator adds wildcards |
| Custom Postgres schemas | Implicit schema handling in some paths | Schemas not created implicitly for `schema.table` names | Caller or migration environment creates the schema first |
| Factory transforms | Runtime defaults, field maps, `onUpdate`, fallback joins in adapter factory | Applied in RustAuth core/service layers above the adapter | Keep adapter focused on SQL execution |

## Open gaps and risks

| ID | Gap / risk | Severity | Notes |
| --- | --- | --- | --- |
| TPG-1 | TypeScript API-shape parity | Low | Remaining delta is mostly surface API, not missing Postgres semantics |
| TPG-2 | Shared adapter contract not ported 1:1 | Low | Relies on `run_adapter_contract` and focused integration tests |
| TPG-3 | Live Postgres required for full test run | Medium | CI/Docker needed; no in-memory Postgres substitute in this crate |
| TPG-4 | Further parity needs core contract changes | Low | Gains beyond current ~96% may require shared RustAuth adapter API work |

## Hardening notes

- Migration and `create_schema` plans run inside a single Postgres transaction; failed DDL rolls back.
- Warning plans (e.g. type mismatches) fail closed before applying statements.
- Transaction gate serializes DDL, transactions, and rate-limit consumes on one client.
- Nested transactions are rejected (no savepoints).
- Rate-limit store rejects negative persisted counts; denied requests do not increment counters.
- Shared `TokioPostgresConnection` serializes adapter and rate-limit access; unshared clients bypass the gate.

## Upstream lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is missing.
3. Open `reference/upstream-src/1.6.9/repository/packages/kysely-adapter/`.
4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `packages/kysely-adapter/src/kysely-adapter.ts` | `src/adapter.rs`, `src/query.rs`, `src/row.rs` |
| `packages/kysely-adapter/src/query-builders.ts` | `src/query.rs` (via `rustauth-sqlx` SQL planner) |
| `packages/kysely-adapter/src/dialect.ts` | `src/driver.rs`, `src/connection.rs` |
| `packages/better-auth/src/db/get-migration.ts` | `src/migration.rs`, `src/schema.rs` |
| `packages/better-auth/src/api/rate-limiter/` | `src/rate_limit.rs` |
| `packages/kysely-adapter/src/*.test.ts`, `e2e/adapter/test/kysely-adapter/*.test.ts` | `tests/postgres_adapter.rs`, `tests/driver.rs` |

5. Add a failing Rust integration test before behavior changes; match HTTP status, error codes, and DB side effects—not TypeScript types.

## Related docs

- [Crate README](./README.md) — usage and quick start
- [Parity index](../../docs/parity/README.md)
- [rustauth-sqlx UPSTREAM.md](../rustauth-sqlx/UPSTREAM.md) — shared SQL planner and multi-dialect context
- [rustauth-deadpool-postgres UPSTREAM.md](../rustauth-deadpool-postgres/UPSTREAM.md) — pooled Postgres variant
