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

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
