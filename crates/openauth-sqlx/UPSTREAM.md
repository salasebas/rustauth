# Upstream Parity: openauth-sqlx

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` (`reference/upstream-better-auth/VERSION.md`) |
| Upstream package/path | `@better-auth/kysely-adapter` at `reference/upstream-src/1.6.9/repository/packages/kysely-adapter/`; runtime wiring and migrations under `packages/better-auth/src/db/` |
| Rust crate | `openauth-sqlx` |
| Parity level | High for the Better Auth SQL adapter contract |
| Scope | Server-side SQL database adapter runtime: SQLite, Postgres, MySQL, schema migrations, adapter contract behavior, and SQL-backed rate-limit storage |

`openauth-sqlx` maps Better Auth's Kysely runtime adapter, database wiring, schema/migration helper, shared adapter suites, and database rate-limit storage to concrete SQLx adapters. The crate covers observable server-side database behavior used by OpenAuth core and plugins, while intentionally hardening migration execution, rate-limit updates, and pattern matching where upstream runtime behavior is looser.

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Adapter exports | ✅ | `SqliteAdapter`, `PostgresAdapter`, `MySqlAdapter`, rate-limit stores, and migration re-exports are feature-gated Rust equivalents of the Kysely adapter surface. |
| CRUD operations | ✅ | Implements `create`, `find_one`, `find_many`, `count`, `update`, `update_many`, `delete`, and `delete_many` through `DbAdapter`. |
| Filters and sorting | ✅ | Parameter-bound filters cover equality, inequality, comparisons, `IN`, `NOT IN`, `contains`, `starts_with`, `ends_with`, null checks, sort, limit, and offset. |
| Joins | ✅ | Native one-to-one and one-to-many joins are supported for all three dialects through OpenAuth core SQL planning. |
| Transactions | ✅ | All adapters support transaction callbacks; SQLite enables foreign keys per transaction. |
| Schema creation | ✅ | Creates OpenAuth and plugin tables from `DbSchema`; optional file output returns compiled migration SQL. |
| Migration planning | ✅ | Additive table, column, and index plans are compiled per dialect; warning plans are rejected before execution. |
| Migration atomicity | 🎯 | SQLite/Postgres run each plan in a transaction; MySQL performs best-effort reverse cleanup because MySQL DDL implicitly commits. |
| Rate-limit storage | 🎯 | SQL-backed stores consume in one transaction and denied requests do not rewrite counters. Upstream database rate limits are split read/write through the generic adapter. |
| Server runtime dialect coverage | ⚠️ | SQLite, Postgres, and MySQL are implemented. Upstream Kysely also has server/runtime adapters for MSSQL, Bun SQLite, Node SQLite, and Cloudflare D1. |
| Public HTTP routes | ➖ | The Kysely adapter has no route surface; route-level behavior belongs to `openauth-core`, `openauth`, and plugin crates. |
| Adapter factory runtime transforms | ⚠️ | Better Auth applies defaults, field mappings, `onUpdate`, type conversions, and fallback joins in its adapter factory. OpenAuth handles these through Rust schema, service, and shared SQL layers. |
| Rate-limit table naming | ⚠️ | Upstream stores database rate limits through model `rateLimit`; OpenAuth's default physical table is `rate_limits` for logical model `rate_limit`. |

## Test Coverage

| Surface | OpenAuth tests | Upstream tests | Notes |
| --- | --- | --- | --- |
| SQLite adapter | 37 source-counted tests in `tests/sqlite_adapter.rs` | `adapter.kysely.sqlite.test.ts`, `node-sqlite-dialect.test.ts`, shared adapter suites | Deepest local coverage, including foreign-key pool enforcement and serialized rate-limit concurrency. |
| Postgres adapter | 32 source-counted tests in `tests/postgres_adapter.rs` | `adapter.kysely.pg.test.ts`, `adapter.kysely.custom-schema-pg.test.ts`, schema-reference suites, migration schema tests | Requires reachable `OPENAUTH_TEST_POSTGRES_URL` or local Docker Compose defaults. |
| MySQL adapter | 32 source-counted tests in `tests/mysql_adapter.rs` | `adapter.kysely.mysql.test.ts` and shared adapter suites | Requires reachable `OPENAUTH_TEST_MYSQL_URL` or local Docker Compose defaults. |
| Upstream-only server dialects | None in this crate | `adapter.kysely.mssql.test.ts`, Bun SQLite dialect, D1 dialect | Tracked as unsupported server/runtime coverage. |
| Kysely adapter package | N/A | 1 local smoke test in `packages/kysely-adapter/src/kysely-adapter.test.ts` | Most upstream behavior is exercised outside the package-local test file. |
| Migrations | Dialect integration tests plus shared migration atomicity helpers | 10 tests in `packages/better-auth/src/db/get-migration-schema.test.ts` | OpenAuth adds executable-plan checks and atomic application guarantees. |
| Model/table metadata | Covered indirectly through schema/migration tests | `packages/core/src/db/test/get-tables.test.ts`, `packages/better-auth/src/db/db.test.ts` | Upstream covers custom names, field mapping, verification table inclusion, and database hooks. |
| Database rate limits | Dialect rate-limit store tests in `tests/*_adapter.rs` | `packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts` | Upstream tests HTTP storage behavior; OpenAuth tests dedicated SQL consume stores. |
| Internal adapter consumers | Outside direct SQLx crate scope | `internal-adapter.test.ts`, `secondary-storage.test.ts` | Server-side consumers of the adapter; useful boundary evidence, not raw adapter parity. |
| Shared adapter contract | `run_adapter_contract` plus focused dialect tests | `packages/test-utils/src/adapter/` suites and Kysely e2e files | Upstream suites are not ported 1:1. |
| Verify command | `cargo nextest run -p openauth-sqlx` | Upstream uses Vitest/e2e harnesses | Add `--features postgres,mysql` with live services to exercise every SQLx dialect. |
| Quick count | `rg '#\[test\]|#\[tokio::test\]' crates/openauth-sqlx` | Include `packages/kysely-adapter`, `packages/better-auth/src/db`, `packages/better-auth/src/api/rate-limiter`, `packages/test-utils/src/adapter`, and `e2e/adapter/test/kysely-adapter` | Current OpenAuth source count: 101 tests; upstream e2e suites are generated dynamically. |

## Intentional Differences

| Topic | Better Auth | OpenAuth | Why |
| --- | --- | --- | --- |
| Adapter shape | Runtime-selected Kysely adapter from Better Auth database options | Concrete SQLx adapter types and capability flags | Idiomatic Rust API, explicit feature gates, and explicit dialect selection. |
| Runtime field transforms | Adapter factory applies defaults, mapped field names, date/boolean/json/array conversions, `onUpdate`, and fallback joins | OpenAuth applies schema metadata and service-layer behavior before/around adapter calls, with dialect binding handled in SQLx code | Keep auth behavior explicit and typed without dynamic adapter wrapping. |
| Migration execution | `runMigrations` executes builders sequentially | SQLite/Postgres transactional plans; MySQL best-effort cleanup | Avoid partially applied schemas where the database can support it. |
| Unsafe schema drift | Type mismatches are warned; unsupported drift is not repaired | Warning plans fail closed before applying migrations | Authentication schemas should not silently mutate unsafe changes. |
| Rate limits | Generic adapter `findMany`/`create`/`updateMany` wrapper with split request/response phases | Dedicated SQL stores with shared single-transaction consume logic in `openauth_core::db::sql::rate_limit` | Reduces races and preserves denied-request semantics. |
| Pattern matching | `query-builders.ts` builds LIKE/ILIKE patterns from user values | `%`, `_`, and `\` are escaped with explicit `ESCAPE` clauses | Treat user input literally unless an OpenAuth operator adds the wildcard. |
| Arrays and JSON | Kysely reports `supportsArrays: false`; arrays are generally stringified or JSON-backed | Postgres uses native arrays; SQLite/MySQL bind arrays as JSON text | Use SQLx/dialect-native behavior while preserving serialized values for non-native dialects. |
| MySQL timestamp | Upstream migration helper emits `timestamp(3)` | SQLx schema uses `DATETIME(6)` | Better SQLx compatibility and precision. |
| Delete semantics | Better Auth factory and Kysely adapter pass the full `WHERE` through; matching rows are deleted | OpenAuth's shared SQL planner uses one-row `delete`; `delete_many` is bulk | Avoid accidental bulk deletes at auth boundaries. |
| Default list limit | Better Auth factory defaults top-level `findMany` to 100 when limit is omitted | SQLx adapter has no adapter-level default limit | Callers and HTTP layers should set externally driven limits explicitly. |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| SQLX-1 | MSSQL, Bun SQLite, Node SQLite, and Cloudflare D1 are not implemented | Medium | These are server/runtime upstream surfaces, but outside this crate's supported SQLx dialects. |
| SQLX-2 | Postgres/MySQL test coverage depends on live services | Medium | SQLite-only local runs do not exercise all production dialects. |
| SQLX-3 | Postgres/MySQL do not mirror every SQLite-only hardening test | Medium | Missing equivalents include FK pool enforcement, warning-plan rejection paths, and serialized rate-limit concurrency. |
| SQLX-4 | Direct `with_schema` use can drift from migrations | Medium | The normal OpenAuth builder wires schema, hooks, defaults, and `onUpdate` behavior above the adapter. |
| SQLX-5 | Shared Better Auth adapter/e2e suites are not ported 1:1 | Low | OpenAuth relies on `run_adapter_contract` and focused dialect integration tests. |
| SQLX-6 | `find_many` has no adapter-level default limit | Low | Public list endpoints should pass explicit limits. |
| SQLX-7 | MySQL DDL rollback is best-effort | Medium | Inspect failed MySQL migrations before retrying because DDL implicitly commits. |
| SQLX-8 | Postgres custom-schema parity is shallower than upstream e2e coverage | Low | OpenAuth introspects `current_schema()` and tests prefixed table names; upstream also has schema-reference and search-path e2e suites. |
| SQLX-9 | Upstream dynamic e2e suite count is not statically comparable to OpenAuth's 101 source-counted tests | Low | Better Auth expands tests through `testAdapter` and `createTestSuite`; compare coverage areas, not only raw `it(` counts. |

## Hardening Notes

- SQL identifiers are validated and values are parameter-bound by the shared SQL planner and dialect binders.
- Migration plans fail closed on unsafe warnings before any executable SQL is applied.
- SQLite and Postgres migration plans are transactional; MySQL compensates successful statements in reverse order on failure.
- SQLite enables `PRAGMA foreign_keys = ON` on pooled connections and transactions.
- Rate-limit counters are consumed inside one transaction; SQLite uses `BEGIN IMMEDIATE` to avoid stale reads across pooled connections.
- LIKE pattern operators escape SQL wildcard characters in user input.
- Negative or invalid rate-limit counts are rejected instead of silently coerced.

## Upstream Lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. If needed, run `./scripts/fetch-upstream-better-auth.sh`.
3. Open `reference/upstream-src/1.6.9/repository/`.
4. Compare Kysely adapter behavior by database operation, migration SQL, DB side effects, rate-limit mutations, and error handling.
5. Verify local behavior with `cargo nextest run -p openauth-sqlx`; add `--features postgres,mysql` with reachable database services for all dialect tests.

| Upstream | Rust |
| --- | --- |
| `packages/kysely-adapter/src/index.ts` | `src/lib.rs` public re-exports |
| `packages/kysely-adapter/src/kysely-adapter.ts` | `src/{sqlite,postgres,mysql}/mod.rs`, `state.rs`, `query.rs`, `row.rs` |
| `packages/kysely-adapter/src/query-builders.ts` | Shared SQL planner LIKE/ILIKE behavior and SQLx dialect parameter binding |
| `packages/kysely-adapter/src/dialect.ts` | SQLx connection constructors, feature-gated adapter types, and runtime dialect selection |
| `packages/kysely-adapter/src/{node-sqlite,bun-sqlite,d1-sqlite}-dialect.ts` | Unsupported upstream server/runtime dialects tracked as gaps |
| `better-auth/db/migration` public export | `plan_migrations`, `compile_migrations`, `create_schema`, and `run_migrations` methods |
| `better-auth/db/adapter`, `better-auth/db/adapter/minimal` public exports | OpenAuth builder and direct adapter construction paths |
| `packages/better-auth/src/db/adapter-kysely.ts` | Better Auth Kysely wiring; OpenAuth uses explicit SQLx adapter construction instead |
| `packages/better-auth/src/db/adapter-base.ts` | OpenAuth adapter selection and fallback behavior outside direct SQLx scope |
| `packages/better-auth/src/db/get-schema.ts` | `DbSchema` table and field-name mapping before SQLx schema planning |
| `packages/better-auth/src/db/internal-adapter.ts`, `with-hooks.ts` | Server-side adapter consumer layer; hooks/defaults are applied above direct SQLx adapter calls |
| `packages/better-auth/src/db/verification-token-storage.ts`, `secondary-storage.test.ts` | Secondary/verification storage boundary; not direct SQLx adapter parity unless configured to store in SQL |
| `packages/better-auth/src/db/get-migration.ts` | `src/{sqlite,postgres,mysql}/schema.rs`, `src/migration.rs` |
| `packages/core/src/db/adapter/index.ts` | `openauth_core::db::DbAdapter` trait used by this crate |
| `packages/core/src/db/adapter/factory.ts`, `utils.ts`, and name-resolution helpers | OpenAuth core schema/name resolution, defaults, and service-layer transforms |
| `packages/core/src/db/get-tables.ts`, `packages/core/src/db/schema/*.ts` | `openauth_core::db::auth_schema`, `DbSchema`, `DbField`, and plugin schema inputs |
| `packages/core/src/db/test/get-tables.test.ts`, `packages/better-auth/src/db/db.test.ts` | Schema metadata and custom naming coverage in `tests/*_adapter.rs` and OpenAuth core tests |
| `packages/test-utils/src/adapter/test-adapter.ts`, `create-test-suite.ts`, `suites/*.ts` | `tests/*_adapter.rs` plus `openauth_core::db::adapter_harness` |
| `e2e/adapter/test/adapter-factory/index.ts`, `e2e/adapter/test/kysely-adapter/*.test.ts` | Dialect integration tests in `tests/sqlite_adapter.rs`, `tests/postgres_adapter.rs`, `tests/mysql_adapter.rs` |
| `e2e/adapter/test/kysely-adapter/schema-reference-test-suite.ts` | Postgres schema/search-path parity risks and current-schema introspection |
| `packages/better-auth/src/api/rate-limiter/index.ts`, `rate-limiter.test.ts` | `SqliteRateLimitStore`, `PostgresRateLimitStore`, `MySqlRateLimitStore` |
| `packages/core/src/db/schema/rate-limit.ts`, `packages/core/src/utils/ip.ts` | `openauth_core::db::sql::rate_limit` and OpenAuth rate-limit keying |

Back to [`README.md`](./README.md). See the workspace parity index at [`../../docs/parity/README.md`](../../docs/parity/README.md).
