# openauth-tokio-postgres

Minimal `tokio-postgres` database adapter for OpenAuth-RS.

## Status

This package is in experimental beta. Adapter behavior, migration planning, and
rate-limit store contracts may change before stable release.

## What It Provides

`openauth-tokio-postgres` is useful when an application already owns a
`tokio_postgres::Client` or wants the smallest async Postgres adapter. It is not
a pool; production applications that need pooling should usually prefer
`openauth-deadpool-postgres`.

`connect()` and `connect_with_schema()` spawn the `tokio-postgres` connection
driver task internally. Applications that use `new()` or `with_schema()` with an
existing `tokio_postgres::Client` remain responsible for driving the connection
they created.

Logical OpenAuth array fields (`StringArray` and `NumberArray`) are stored as
native Postgres arrays (`TEXT[]` and `BIGINT[]`). The adapter reports array
support for this OpenAuth contract; it does not expose a lower-level API for
arbitrary Postgres array types. Existing experimental databases created with
JSONB-backed array columns should be migrated manually; the migration planner
reports those columns as type mismatches instead of rewriting data
automatically.

Nested transactions are not supported. Calling `transaction()` from inside an
adapter transaction returns an adapter error instead of creating a savepoint.

## Example

```rust
use openauth::OpenAuth;
use openauth_tokio_postgres::TokioPostgresAdapter;

let adapter = TokioPostgresAdapter::connect(
    "postgres://user:password@localhost:5432/openauth",
)
.await?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .adapter(adapter)
    .build()?;
```

Use `TokioPostgresRateLimitStore::from(&adapter)` when a single client should
also back rate limiting.

## Local Tests

The integration tests use Postgres from the root `docker-compose.yml`.

```bash
docker compose up -d postgres
OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@localhost:5432/openauth \
  cargo test -p openauth-tokio-postgres --all-targets
```

If your local Docker volume was created with another database name, either
create the `openauth` database or point `OPENAUTH_TEST_POSTGRES_URL` at the
database that exists. Driver errors include SQLSTATE and Postgres detail when
available, which helps distinguish missing database, authentication, schema, and
constraint failures.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
