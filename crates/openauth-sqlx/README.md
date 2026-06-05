# openauth-sqlx

SQLx database adapters for OpenAuth-RS.

## What It Is

`openauth-sqlx` provides OpenAuth `DbAdapter` implementations for SQLite,
Postgres, and MySQL through SQLx. Use it when your application already uses
SQLx or when SQLite is a good fit for local development and small deployments.

For Postgres production deployments that do not otherwise use SQLx,
`openauth-deadpool-postgres` may be a smaller operational fit.

## What It Provides

- `SqliteAdapter` behind the `sqlite` feature.
- `PostgresAdapter` behind the `postgres` feature.
- `MySqlAdapter` behind the `mysql` feature.
- SQL-backed rate-limit stores for supported dialects.
- Schema creation, migration planning, and additive migration execution.
- SQL filter, sort, pagination, and transaction support used by OpenAuth core
  and plugins.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_sqlx::SqliteAdapter;

let adapter = SqliteAdapter::connect("sqlite://openauth.db").await?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .adapter(adapter)
    .build()?;

auth.run_migrations().await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Enable the matching crate feature for your dialect:

```toml
[dependencies]
openauth-sqlx = { version = "0.0.6", features = ["sqlite"] }
```

## Migration Notes

- `run_migrations` applies executable additive plans only.
- Type mismatches, destructive rewrites, renames, and unsafe changes are
  reported as warnings/errors instead of being applied automatically.
- `plan_migrations` and `compile_migrations` let you inspect generated SQL
  before applying it.
- `SqliteAdapter::connect` and [`sqlite_pool_options`](crate::sqlite_pool_options)
  enable `PRAGMA foreign_keys = ON` on every pooled connection. `new(pool)` also
  enforces foreign keys on each checkout even when the caller omitted pool
  options; prefer `sqlite_pool_options()` when building pools yourself.

### Atomic schema application

`create_schema` and `run_migrations` apply each generated plan as one unit so a
mid-plan failure does not leave a partially applied OpenAuth schema:

- **Postgres and SQLite** run the plan inside a single database transaction.
  Failed statements roll back earlier DDL in that plan.
- **MySQL** cannot roll back DDL through a transaction because MySQL performs
  implicit commits for those statements. The adapter instead undoes successful
  statements in reverse order on failure (for example `DROP TABLE` after a
  failed later `CREATE TABLE`). This is best-effort; treat a failed migration as
  requiring inspection before retrying.

Postgres adapters in `openauth-tokio-postgres` and `openauth-deadpool-postgres`
use the same transactional execution model as `PostgresAdapter`.

## Status

Experimental beta. SQLite has the strongest local coverage. Postgres and MySQL
are covered by integration tests and should be validated against your
production schema and privileges before rollout.

## Upstream parity (Better Auth 1.6.9)

Primary upstream: `@better-auth/kysely-adapter` + `getMigrations` in `better-auth`.
Not a port of Drizzle, Prisma, or Mongo adapters. Estimated server-only parity:
**~95%**; remaining gap is mostly intentional Rust design, TypeScript-only factory
behavior, or unsafe upstream patterns we do not copy.

### Status

| Area | Level | Notes |
| --- | --- | --- |
| CRUD, joins, transactions | **High (~95%)** | SQLite, Postgres, MySQL via SQLx |
| Migrations (additive) | **High** | Blocks unsafe plans; missing-index repair beyond upstream |
| Rate limit SQL stores | **High** | Single-tx consume; denied requests do not increment |
| MSSQL / D1 / Bun sqlite | **Gap** | Not implemented in this crate |

CRUD, count, transaction, and migration surfaces match relevant Better Auth adapter
operations. Queries use parameter binding and validated identifiers. WHERE operators
cover equality, inequality, comparison, IN, NOT IN, contains, starts-with, and
ends-with; null equality compiles to `IS NULL` / `IS NOT NULL`. Join behavior matches
one-to-one and one-to-many contracts including default join limits, missing rows as
`null`/empty arrays, and multi-join `find_many` as a single statement when
`supports_native_joins`. Schema planning is additive and refuses unsafe warning plans.
`create_schema(file)` can write compiled migration SQL with `SchemaCreation` metadata.
Postgres and MySQL coverage runs against live Docker Compose database services.

### Intentional differences

- `delete` removes one matching row; use `delete_many` for bulk (upstream Kysely
  `deleteFrom(...).where(...)` can delete every match).
- Default values and `onUpdate` transforms from Better Auth's factory are applied
  explicitly in OpenAuth service layers before adapter calls.
- SQLx Postgres uses native `TEXT[]`/`BIGINT[]`; upstream Kysely stores arrays as
  JSON-like values. MySQL uses `DATETIME(6)` instead of upstream `timestamp(3)`.
- Count queries use `COUNT(*)` instead of counting `id` (equivalent for these schemas).
- Rate-limit counters consume in one transaction (Rust atomic store contract) rather
  than Better Auth's split read/write phases.
- LIKE pattern operators escape `%`, `_`, and `\` with an explicit `ESCAPE` clause.
- `FindMany` defaults to no limit (upstream factory defaults to 100); callers should
  set explicit limits on externally driven list endpoints.

### Open gaps/risks

- Postgres and MySQL runtime coverage requires live database services; CI and
  contributors must provide reachable databases equivalent to local Docker Compose.
- Direct SQLx adapter use expects the schema configured in `with_schema`; the
  OpenAuth builder wraps adapters with schema and hook layers for normal use.
- A configurable default `FindMany` limit would be a core API change, not a SQLx-only
  parity fix.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/<upstream-package>/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-sqlx/src/` to upstream `.ts` by route paths, exported handlers, and `*.test.ts` files.
4. Add a failing Rust integration test before changing behavior; match HTTP status, JSON error codes, and DB side effects—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
