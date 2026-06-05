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

## Migrations

`create_schema` and `run_migrations` apply each generated plan inside a single
Postgres transaction. If a later statement fails, earlier DDL in that plan is
rolled back.

## Status

Experimental beta. Adapter behavior, migration planning, and rate-limit store
contracts may change before stable release.

## Upstream parity (Better Auth 1.6.9)

Compared against Better Auth's Kysely adapter, core adapter factory, shared adapter
test suites, and PostgreSQL e2e coverage. Target contract is observable server-side
behavior, not a line-by-line TypeScript port. Server-only parity is approximately
**96%** for behavior this crate owns.

### Status

CRUD (create, find, count, update, update many, delete, delete many), physical table
and field names from `AuthSchemaOptions`, generated text/UUID/identity IDs, JSON and
native Postgres arrays, scalar and pattern filters, null equality, mixed `AND`/`OR`
groups, one-to-one/one-to-many/reverse/limited/missing-row/multi-join reads, join
reads inside transactions, transactional commit/rollback, additive schema creation and
migration planning (tables, columns, indexes, unique constraints, foreign keys,
generated defaults, type-mismatch reporting), schema-qualified names such as
`internal.users`, database-backed rate limiting, and core email/password route flows
are implemented.

### Intentional differences

- Uses a single async `tokio-postgres` client, not a pool. Normal queries may pipeline
  concurrently; transactions, migrations, schema creation, and rate-limit consumes acquire
  an exclusive gate so transaction state is not interleaved on one connection.
- Transaction callbacks return `Result<(), OpenAuthError>` instead of a generic value;
  database state transitions are preserved.
- SQL pattern filters escape `%`, `_`, and `\` from user input (stricter than Kysely
  wildcard semantics).
- PostgreSQL schemas are not created implicitly for `schema.table` names; the caller
  or migration environment must create the schema first.
- TypeScript-only factory ergonomics (debug logs, dynamic transform hooks) live in
  OpenAuth core/plugin layers, not in this adapter.

### Open gaps/risks

- Remaining gap is mostly API-shape parity with TypeScript, not missing database
  semantics. Further gains would require shared OpenAuth adapter contract changes.
- For pooling, use `openauth-deadpool-postgres`, which shares Postgres SQL planning
  with this crate and `openauth-sqlx`.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/<upstream-package>/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-tokio-postgres/src/` to upstream `.ts` by route paths, exported handlers, and `*.test.ts` files.
4. Add a failing Rust integration test before changing behavior; match HTTP status, JSON error codes, and DB side effects—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
