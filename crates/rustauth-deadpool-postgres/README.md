# rustauth-deadpool-postgres

Pooled Postgres database adapter for RustAuth.

## What It Is

`rustauth-deadpool-postgres` is the recommended Postgres adapter when you want
pooling without taking a SQLx dependency. It uses `deadpool-postgres` for pool
management and reuses RustAuth's shared Postgres SQL planning.

## Naming

RustAuth storage backends share one vocabulary:

| Type | Role |
|------|------|
| `DeadpoolPostgresAdapter` | `DbAdapter` implementation |
| `DeadpoolPostgresStores` | Adapter + SQL-backed rate-limit store sharing one pool |
| `DeadpoolPostgresStoresBuilder` or `DeadpoolPostgresStores::builder()` | Configure URL, schema, pool size, TLS, and validation |
| `apply_to_options` | Wire the rate-limit store into [`RustAuthOptions`] |

`DeadpoolPostgresStoresBuilder` is a type alias for `DeadpoolPostgresBuilder`.

## What It Provides

- `DeadpoolPostgresStores`: bundled adapter + SQL-backed rate-limit store
  sharing one pool (recommended entry point).
- `DeadpoolPostgresAdapter` and `DeadpoolPostgresRateLimitStore` for BYO-pool
  setups.
- `DeadpoolPostgresStoresBuilder` (alias `DeadpoolPostgresBuilder`) for
  connection URL, custom config, schema, pool size, TLS, and startup validation.
- Additive migration planning and execution.
- Native Postgres arrays for RustAuth array fields.

Migration planning types live in `rustauth_core::db`.

## Quick Start

```rust
use rustauth::{RustAuth, RustAuthOptions};
use rustauth_core::db::{auth_schema, AuthSchemaOptions, RateLimitStorage};
use rustauth_deadpool_postgres::DeadpoolPostgresStores;

let schema = auth_schema(AuthSchemaOptions {
    rate_limit_storage: RateLimitStorage::Database,
    ..AuthSchemaOptions::default()
})?;

let stores = DeadpoolPostgresStores::connect_with_schema_checked(
    "postgres://user:password@localhost:5432/rustauth",
    schema.clone(),
)
.await?;

let auth = RustAuth::builder()
    .options(stores.apply_to_options(
        RustAuthOptions::new().secret("secret-a-at-least-32-chars-long!!"),
    ))
    .adapter(stores.adapter)
    .build()?;

// Apply schema with `rustauth db migrate` before serving traffic.
# Ok::<(), Box<dyn std::error::Error>>(())
```

Configure `rustauth.toml` with `database.adapter = "deadpool-postgres"`, then run
`rustauth db migrate --yes` before starting the server. See
[docs/database-migrations.md](../../docs/database-migrations.md).

### Builder

```rust
use rustauth_deadpool_postgres::DeadpoolPostgresStoresBuilder;

let adapter = DeadpoolPostgresStoresBuilder::new()
    .database_url("postgres://user:password@localhost:5432/rustauth")
    .schema(schema)
    .checked(true)
    .max_size(16)
    .connect()
    .await?;
```

Use `.checked(true)` or `validate_connection()` when startup should fail fast if
the pool cannot check out a working database connection. Unchecked builds create
pools lazily and may report connection errors on the first operation.

Applications that already own a `deadpool_postgres::Pool` can pass it to
`DeadpoolPostgresAdapter::new(pool)` or `with_schema(pool, schema)`.

## Notes

- Nested transactions are not supported; attempting one returns an adapter
  error instead of creating a savepoint.
- Existing experimental JSONB-backed array columns should be migrated manually;
  the planner reports those as type mismatches.

## Status

Beta/release-candidate quality for the RustAuth Postgres adapter contract, but
public APIs may still evolve before stable 1.0.

## Better Auth compatibility

Server-side pooled Postgres `DbAdapter` and rate-limit storage. Aligned with Better
Auth **1.6.9** where it matters for this crate; RustAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
