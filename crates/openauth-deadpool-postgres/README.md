# openauth-deadpool-postgres

Pooled Postgres database adapter for OpenAuth-RS.

## What It Is

`openauth-deadpool-postgres` is the recommended Postgres adapter when you want
pooling without taking a SQLx dependency. It uses `deadpool-postgres` for pool
management and reuses OpenAuth's shared Postgres SQL planning.

## What It Provides

- `DeadpoolPostgresAdapter` for OpenAuth primary storage.
- `DeadpoolPostgresRateLimitStore` for SQL-backed rate limiting.
- Connection URL, custom config, schema, and TLS constructors.
- Additive migration planning and execution.
- Native Postgres arrays for OpenAuth array fields.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_deadpool_postgres::DeadpoolPostgresAdapter;

let adapter = DeadpoolPostgresAdapter::connect_checked(
    "postgres://user:password@localhost:5432/openauth",
)
.await?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .adapter(adapter)
    .build()?;

auth.run_migrations().await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `connect_checked` or `validate_connection()` when startup should fail fast
if the pool cannot check out a working database connection. The unchecked
constructors create pools lazily and may report connection errors on the first
operation.

## Notes

- Nested transactions are not supported; attempting one returns an adapter
  error instead of creating a savepoint.
- Existing experimental JSONB-backed array columns should be migrated manually;
  the planner reports those as type mismatches.
- Applications that already own a `deadpool_postgres::Pool` can pass it to
  `DeadpoolPostgresAdapter::new`.

## Status

Beta/release-candidate quality for the OpenAuth Postgres adapter contract, but
public APIs may still evolve before stable 1.0.

## Upstream parity (Better Auth 1.6.9)

Same upstream reference as `openauth-sqlx` and `openauth-tokio-postgres`:
`@better-auth/kysely-adapter` PostgreSQL behavior plus `getMigrations` in
`better-auth`. This crate adds `deadpool-postgres` pooling on top of shared Postgres
SQL planning from `openauth-sqlx` (query compilation, migrations, row mapping, rate
limit stores). Server-only parity is approximately **96%**, matching the non-pooled
Postgres adapters for observable database semantics.

### Status

Pooled `DbAdapter` and `RateLimitStore` implementations cover the same CRUD, join,
filter, transaction, additive migration, schema-qualified table, native array, and
rate-limit contracts as `openauth-tokio-postgres`. Transactional migration execution
matches `PostgresAdapter` in `openauth-sqlx`.

### Intentional differences

- Connection pooling via `deadpool-postgres` instead of a single client or SQLx pool.
- Nested transactions are rejected (no savepoints), consistent with other OpenAuth
  Postgres adapters.
- Shares intentional differences documented for `openauth-tokio-postgres` and
  `openauth-sqlx`: single-row `delete`, escaped LIKE patterns, no implicit schema
  creation, explicit service-layer defaults, and `FindMany` without a default limit.

### Open gaps/risks

- Remaining gap is mostly TypeScript API-shape parity, not missing Postgres semantics.
- Existing experimental JSONB-backed array columns require manual migration; the
  planner reports those as type mismatches.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/<upstream-package>/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-deadpool-postgres/src/` to upstream `.ts` by route paths, exported handlers, and `*.test.ts` files.
4. Add a failing Rust integration test before changing behavior; match HTTP status, JSON error codes, and DB side effects—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
