# openauth-tokio-postgres

Minimal `tokio-postgres` database adapter for OpenAuth-RS.

## What It Is

`openauth-tokio-postgres` is useful when an application already owns a
`tokio_postgres::Client` or wants the smallest async Postgres adapter. It is
not a pool; production applications that need pooling should usually prefer
`openauth-deadpool-postgres`.

## What It Provides

- `TokioPostgresAdapter` for OpenAuth primary storage.
- `TokioPostgresConnection` for sharing one client and transaction gate across
  adapters and rate-limit stores.
- `TokioPostgresRateLimitStore` for SQL-backed rate limiting.
- Shared Postgres schema, query, row, migration, and transaction helpers.
- Native Postgres arrays for OpenAuth `StringArray` and `NumberArray` fields.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_tokio_postgres::TokioPostgresAdapter;

let adapter = TokioPostgresAdapter::connect(
    "postgres://user:password@localhost:5432/openauth",
)
.await?;

let rate_limit_store = adapter.rate_limit_store();
let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .adapter(adapter)
    .build()?;

auth.run_migrations().await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

When the application owns the `tokio_postgres::Client`, build a
`TokioPostgresConnection` once and share it between the adapter and rate-limit
store instead of cloning the client into separate constructors:

```rust
use openauth_tokio_postgres::{
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

## Status

Experimental beta. Adapter behavior, migration planning, and rate-limit store
contracts may change before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
