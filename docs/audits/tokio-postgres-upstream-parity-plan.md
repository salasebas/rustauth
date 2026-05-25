# Tokio Postgres Upstream Parity Audit Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `openauth-tokio-postgres` closer to Better Auth's server-side SQL adapter behavior while preserving idiomatic Rust, explicit errors, and the existing OpenAuth adapter architecture.

**Architecture:** Upstream does not have a tokio-postgres package, so parity is measured against Better Auth's core adapter factory, Kysely Postgres adapter, and shared adapter test suites. The crate should keep using OpenAuth's shared SQL planner, but remove unnecessary single-client serialization outside transactions and align transaction join behavior with the normal adapter and the deadpool Postgres adapter.

**Tech Stack:** Rust, `tokio-postgres`, `tokio`, OpenAuth `DbAdapter`, Better Auth TypeScript upstream reference.

---

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/factory.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/kysely-adapter/src/kysely-adapter.ts`
- `upstream/better-auth/1.6.9/repository/packages/kysely-adapter/src/query-builders.ts`
- `upstream/better-auth/1.6.9/repository/packages/kysely-adapter/src/kysely-adapter.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/basic.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/case-insensitive.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/joins.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/transactions.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/number-id.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/uuid.ts`
- `upstream/better-auth/1.6.9/repository/e2e/adapter/test/kysely-adapter/adapter.kysely.pg.test.ts`

## OpenAuth Files Inspected

- `crates/openauth-tokio-postgres/src/adapter.rs`
- `crates/openauth-tokio-postgres/src/transaction.rs`
- `crates/openauth-tokio-postgres/src/rate_limit.rs`
- `crates/openauth-tokio-postgres/src/driver.rs`
- `crates/openauth-tokio-postgres/src/query.rs`
- `crates/openauth-tokio-postgres/src/row.rs`
- `crates/openauth-tokio-postgres/src/schema.rs`
- `crates/openauth-tokio-postgres/src/migration.rs`
- `crates/openauth-tokio-postgres/src/errors.rs`
- `crates/openauth-tokio-postgres/src/lib.rs`
- `crates/openauth-tokio-postgres/tests/postgres_adapter.rs`
- `crates/openauth-tokio-postgres/tests/driver.rs`
- `tests/support/postgres_adapter_conformance.rs`
- `crates/openauth-core/src/db/sql/*`
- `crates/openauth-core/src/db/schema.rs`
- `crates/openauth-deadpool-postgres/src/adapter.rs`
- `crates/openauth-deadpool-postgres/src/transaction.rs`
- `crates/openauth-deadpool-postgres/src/rate_limit.rs`

## Confirmed Matches

- The crate exposes the expected server-side adapter capabilities: native JSON, arrays, UUID IDs, joins, and transactions.
- CRUD operations follow the shared OpenAuth SQL planner and cover Better Auth's observable behavior for create, find, count, update, updateMany, delete, deleteMany, selection, physical table/field names, generated UUID IDs, generated serial IDs, and no-result behavior.
- Predicate behavior matches upstream for scalar comparisons, `in`, `not_in`, case-insensitive string matching, null `eq`/`ne`, and literal pattern matching. OpenAuth intentionally escapes SQL LIKE wildcards, which is stricter than the upstream Kysely helper and prevents user input from becoming wildcard syntax.
- Join behavior matches upstream for one-to-many, one-to-one, backwards joins, missing joined rows, join limits, and fallback multi-join reads on the normal adapter.
- Transactions commit successful callbacks, roll back callback errors, roll back after SQL errors, and reject nested transactions.
- Schema creation/migration planning supports additive table, column, index, unique, foreign-key, generated UUID, generated identity, JSON, array, boolean, timestamp, and type-mismatch reporting.
- Database-backed rate limit consumption is transactional and uses physical names from the configured schema.
- Integration smoke tests cover email/password sign-up, sign-in, session lookup, and password reset verification storage.

## Confirmed Differences

- The normal `TokioPostgresAdapter` currently wraps the single `tokio_postgres::Client` in `Arc<Mutex<Client>>`. Because `tokio-postgres` query APIs take `&self`, this serializes all non-transactional adapter calls unnecessarily. Upstream SQL adapters do not impose a process-level query lock, and `openauth-deadpool-postgres` already permits concurrent calls through the pool.
- The transaction adapter does not report join support and does not use the same multi-join fallback as the normal adapter. Better Auth's transaction adapter contract exposes the same adapter methods inside a transaction, and OpenAuth's deadpool Postgres transaction adapter already performs this fallback.
- Existing tests cover null handling indirectly through shared SQL behavior, but the tokio-postgres crate does not have focused upstream-parity regression tests for `IS NULL` / `IS NOT NULL` under mixed `AND` and `OR` groups.
- Better Auth's Kysely Postgres e2e suite includes schema-qualified model names such as `internal.users`. OpenAuth's SQL quoting and tokio-postgres schema snapshot loading treated `schema.table` as one identifier, so schema-qualified tables were rejected and could not be introspected for migration parity.

## Risks

- A single Postgres connection cannot safely interleave a transaction with unrelated adapter calls. Replacing the client mutex must keep an exclusive transaction gate that prevents non-transaction queries while `BEGIN` to `COMMIT`/`ROLLBACK` is active.
- Schema creation and migrations should also be exclusive because they alter database state and may conflict with normal adapter calls on the same client.
- The rate-limit store opens its own transaction and must share the same exclusive gate when created from a `TokioPostgresAdapter`.

## Proposed Fixes

- Replace `Arc<Mutex<Client>>` with `Arc<Client>` in `TokioPostgresAdapter` and use `Arc<RwLock<()>>` as the transaction/schema/rate-limit gate.
- Acquire a read lock for normal CRUD operations so independent non-transaction calls can pipeline through `tokio-postgres`.
- Acquire a write lock for explicit transactions, schema creation, migration planning/execution, and rate-limit consumption.
- Update `TokioPostgresRateLimitStore` to use `Arc<Client>` and the same `RwLock` gate.
- Update `TokioPostgresTxAdapter` to use `Arc<Client>`, report `.with_joins()`, and use `JoinAdapter` fallback for more than one requested join.
- Support schema-qualified SQL identifiers in the shared SQL dialect and make tokio-postgres migration introspection resolve `table_schema`/`table_name` separately for schema-qualified table names.

## Tests To Add Or Update

- Add a transaction regression test proving a direct `tx.find_many` with both `account` and `session` joins returns both joined arrays inside the transaction.
- Add focused null predicate tests for:
  - `eq` with null uses `IS NULL`.
  - `ne` with null uses `IS NOT NULL`.
  - mixed `AND` and `OR` groups combine null predicates correctly.
- Add a tokio-postgres integration test that creates a separate Postgres schema, uses `schema.table` names for all core tables, runs schema creation, inserts linked user/session rows, performs a join, and confirms no migrations remain pending.
- Add focused upstream-parity contract tests for escaped LIKE wildcards, `updateMany` without a `where` clause, returning the updated row when a field used by `where` changes, and joined reads with partial base-field selection.
- Keep the existing conformance, migration, rate-limit, generated-ID, and route-flow tests.
- Verification commands:
  - `cargo fmt --all --check`
  - `cargo clippy -p openauth-tokio-postgres --all-targets -- -D warnings`
  - `cargo nextest run -p openauth-tokio-postgres`

## Items Intentionally Left Unchanged

- Keep the crate's public constructors and re-exports unchanged.
- Do not add dependencies.
- Do not weaken SQL identifier validation or LIKE pattern escaping; this is an intentional Rust security hardening while preserving the intended upstream contract.
- Do not change `openauth-deadpool-postgres`; it is only a reference for the target crate.
- Do not redesign the shared `DbAdapter` transaction callback to return generic callback values; preserving object-safe adapter usage is more important than exact TypeScript API shape parity.
