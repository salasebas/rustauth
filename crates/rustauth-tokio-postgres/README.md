# rustauth-tokio-postgres

Minimal `tokio-postgres` database adapter for RustAuth.

## What It Is

`rustauth-tokio-postgres` is useful when an application already owns a
`tokio_postgres::Client` or wants the smallest async Postgres adapter. It is
not a pool; production applications that need pooling should usually prefer
`rustauth-deadpool-postgres`.

## Naming

RustAuth storage backends share one vocabulary:

| Type | Role |
|------|------|
| `TokioPostgresAdapter` | `DbAdapter` implementation |
| `TokioPostgresStores` | Adapter + SQL-backed rate-limit store sharing one client |
| `TokioPostgresStoresBuilder` or `TokioPostgresStores::builder()` | Configure schema and connection |
| `apply_to_options` | Wire the rate-limit store into [`RustAuthOptions`] |

## What It Provides

- `TokioPostgresStores`: bundled adapter + SQL-backed rate-limit store sharing
  one client (recommended entry point).
- `TokioPostgresAdapter` for RustAuth primary storage.
- `TokioPostgresConnection` for sharing one client and transaction gate across
  adapters and rate-limit stores.
- `TokioPostgresRateLimitStore` for BYO-client setups.
- Native Postgres arrays for RustAuth `StringArray` and `NumberArray` fields.

Migration planning types live in `rustauth_core::db`. Low-level driver helpers
used by `rustauth-deadpool-postgres` are `#[doc(hidden)]`.

## Quick Start

```rust
use rustauth::{RustAuth, RustAuthOptions};
use rustauth_core::db::{auth_schema, AuthSchemaOptions, RateLimitStorage};
use rustauth_tokio_postgres::TokioPostgresStores;

let schema = auth_schema(AuthSchemaOptions {
    rate_limit_storage: RateLimitStorage::Database,
    ..AuthSchemaOptions::default()
})?;

let stores = TokioPostgresStores::connect_with_schema(
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

Configure `rustauth.toml` with `database.adapter = "tokio-postgres"`, then run
`rustauth db migrate --yes` before starting the server. See
[docs/database-migrations.md](../../docs/database-migrations.md).

### BYO client

When the application owns the `tokio_postgres::Client`, build a
`TokioPostgresConnection` once and share it between the adapter and rate-limit
store:

```rust
use rustauth_tokio_postgres::{
    TokioPostgresAdapter, TokioPostgresConnection, TokioPostgresRateLimitStore,
};

let connection = TokioPostgresConnection::from_client(client);
let adapter = TokioPostgresAdapter::with_connection(connection.clone(), schema.clone());
let rate_limit_store = TokioPostgresRateLimitStore::from_connection(&connection, "rate_limits");
```

`connect()` and `connect_with_schema()` spawn the `tokio-postgres` connection
driver task internally. If you construct the adapter with `new(client)` or
`with_schema(client, schema)`, your application remains responsible for driving
the connection task it created.

## Migrations

Applications should apply schema with `rustauth db migrate` (see
[docs/database-migrations.md](../../docs/database-migrations.md)). At the
adapter layer, `create_schema` and `DbAdapter::run_migrations` apply each generated plan inside a single
Postgres transaction. If a later statement fails, earlier DDL in that plan is
rolled back.

## Status

Experimental beta. Adapter behavior, migration planning, and rate-limit store
contracts may change before stable release.

## Better Auth compatibility

Server-side PostgreSQL database adapter aligned with Better Auth Kysely Postgres
semantics. Aligned with Better Auth **1.6.9** where it matters for this crate;
RustAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
