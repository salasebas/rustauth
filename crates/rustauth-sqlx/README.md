# rustauth-sqlx

SQLx database adapters for RustAuth.

## What It Is

`rustauth-sqlx` provides RustAuth `DbAdapter` implementations for SQLite,
Postgres, and MySQL through SQLx. Use it when your application already uses
SQLx or when SQLite is a good fit for local development and small deployments.

For Postgres production deployments that do not otherwise use SQLx,
`rustauth-deadpool-postgres` may be a smaller operational fit.

## Naming

RustAuth storage backends share one vocabulary:

| Type | Role |
|------|------|
| `XAdapter` | `DbAdapter` implementation |
| `XStores` | Adapter + SQL-backed rate-limit store sharing one pool |
| `XStoresBuilder` or `XStores::builder()` | Configure schema, pool, and connection |
| `apply_to_options` | Wire the rate-limit store into [`RustAuthOptions`] |

This crate exposes `Sqlite*`, `Postgres*`, and `MySql*` variants behind feature
flags.

## What It Provides

- `SqliteStores`, `PostgresStores`, `MySqlStores`: bundled adapter +
  SQL-backed rate-limit store sharing one pool (recommended entry point).
- `SqliteAdapter`, `PostgresAdapter`, `MySqlAdapter` behind feature flags.
- Matching `*RateLimitStore` types for BYO-pool setups.
- Schema creation, migration planning, and additive migration execution.
- SQL filter, sort, pagination, and transaction support used by RustAuth core
  and plugins.

Migration planning types (`SchemaMigrationPlan`, `MigrationStatementKind`, …)
live in `rustauth_core::db`, not in this crate.

## Quick Start

```rust
use rustauth::{RustAuth, RustAuthOptions};
use rustauth_core::db::{auth_schema, AuthSchemaOptions, RateLimitStorage};
use rustauth_sqlx::SqliteStores;

let schema = auth_schema(AuthSchemaOptions {
    rate_limit_storage: RateLimitStorage::Database,
    ..AuthSchemaOptions::default()
})?;

let stores = SqliteStores::connect_with_schema("sqlite://rustauth.db", schema).await?;

let auth = RustAuth::builder()
    .options(stores.apply_to_options(
        RustAuthOptions::new().secret("secret-a-at-least-32-chars-long!!"),
    ))
    .adapter(stores.adapter)
    .build()?;

// Apply schema with `rustauth db migrate` before serving traffic.
# Ok::<(), Box<dyn std::error::Error>>(())
```

Configure `rustauth.toml` with `database.adapter = "sqlx"` and your provider,
then run `rustauth db migrate --yes` before starting the server. See
[docs/database-migrations.md](../../docs/database-migrations.md).

Enable the matching crate feature for your dialect (no default features):

```toml
[dependencies]
rustauth-sqlx = { version = "0.2.0", default-features = false, features = ["sqlite"] }
```

## Feature Flags

`default = []`. Enable exactly the dialect(s) you need:

- `sqlite`: SQLite adapter and rate-limit store.
- `postgres`: Postgres adapter (includes `sqlx/uuid`).
- `mysql`: MySQL adapter.

### BYO pool

When the application already owns a `SqlitePool` / `PgPool` / `MySqlPool`:

```rust
use rustauth_sqlx::{SqliteAdapter, SqliteRateLimitStore};

let adapter = SqliteAdapter::with_schema(pool, schema);
let rate_limit = SqliteRateLimitStore::from(&adapter);
```

## Migration Notes

Applications should apply schema with `rustauth db migrate` (see
[docs/database-migrations.md](../../docs/database-migrations.md)). At the
adapter layer, `DbAdapter::run_migrations` applies executable additive plans only.
- Type mismatches, destructive rewrites, renames, and unsafe changes are
  reported as warnings/errors instead of being applied automatically.
- `plan_migrations` and `compile_migrations` let you inspect generated SQL
  before applying it.
- `SqliteAdapter::connect` enables `PRAGMA foreign_keys = ON` on every pooled
  connection. `new(pool)` also enforces foreign keys on each checkout.

### Atomic schema application

`create_schema` and `DbAdapter::run_migrations` apply each generated plan as one unit so a
mid-plan failure does not leave a partially applied RustAuth schema:

- **Postgres and SQLite** run the plan inside a single database transaction.
  Failed statements roll back earlier DDL in that plan.
- **MySQL** cannot roll back DDL through a transaction because MySQL performs
  implicit commits for those statements. The adapter instead undoes successful
  statements in reverse order on failure (for example `DROP TABLE` after a
  failed later `CREATE TABLE`). This is best-effort; treat a failed migration as
  requiring inspection before retrying.

Postgres adapters in `rustauth-tokio-postgres` and `rustauth-deadpool-postgres`
use the same transactional execution model as `PostgresAdapter`.

## Status

Experimental beta. SQLite has the strongest local coverage. Postgres and MySQL
are covered by integration tests and should be validated against your
production schema and privileges before rollout.

## Better Auth compatibility

Server-side SQL adapter parity for SQLite, Postgres, and MySQL.
Aligned with Better Auth 1.6.9 where it matters; RustAuth is not a line-by-line port.
For route-level parity, test counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
