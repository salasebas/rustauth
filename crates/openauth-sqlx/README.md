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

## Status

Experimental beta. SQLite has the strongest local coverage. Postgres and MySQL
are covered by integration tests and should be validated against your
production schema and privileges before rollout.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
