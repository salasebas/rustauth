# openauth-deadpool-postgres

Pooled Postgres database adapter for OpenAuth-RS.

## Status

This package is release-candidate quality for the OpenAuth Postgres adapter
contract. It is intended for server deployments that want pooling without
taking a SQLx dependency. Public APIs may still evolve before a stable 1.0
release.

## What It Provides

`openauth-deadpool-postgres` is the recommended Postgres adapter for production
deployments that want pooling without taking a SQLx dependency. It uses
`deadpool-postgres` for pooling and reuses OpenAuth-RS shared SQL planning.

Logical OpenAuth array fields use native Postgres arrays: `StringArray` maps to
`TEXT[]` and `NumberArray` maps to `BIGINT[]`. Existing experimental databases
created with JSONB-backed array columns should be migrated manually; the
migration planner reports those columns as type mismatches instead of rewriting
data automatically.

Nested transactions are not supported. Calling `transaction()` from inside an
adapter transaction returns an adapter error instead of creating a savepoint.

## Example

```rust
use openauth::OpenAuth;
use openauth_deadpool_postgres::DeadpoolPostgresAdapter;

let adapter = DeadpoolPostgresAdapter::connect(
    "postgres://user:password@localhost:5432/openauth",
)
.await?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .adapter(adapter)
    .build()?;
```

Use `DeadpoolPostgresRateLimitStore::from(&adapter)` when you want the same
database to provide distributed rate limiting.

`connect`, `connect_with_schema`, and their TLS variants create a pool lazily:
configuration errors that require opening a database connection are reported on
the first operation. Use `connect_checked`, `connect_with_schema_checked`,
`connect_tls_checked`, or call `validate_connection()` when startup should fail
fast if the pool cannot check out a working connection.

## Pool Configuration

Use `from_config` or `from_config_with_schema` when you need to configure
`deadpool-postgres` directly. If `Config::pool` is already set, OpenAuth
preserves it. The `max_size` argument is only used as a default when no pool
configuration is present.

```rust
use deadpool_postgres::{Config, PoolConfig};
use openauth_deadpool_postgres::DeadpoolPostgresAdapter;

let mut config = Config::new();
config.url = Some("postgres://user:password@localhost:5432/openauth".to_owned());
config.pool = Some(PoolConfig::new(32));

let adapter = DeadpoolPostgresAdapter::from_config(config, 16)?;
```

Applications that need TLS can use `from_config_with_schema_tls` and pass any
`tokio-postgres` compatible TLS connector. `connect_tls`,
`connect_with_schema_tls`, and `from_config_tls` are available when you do not
need to pass every setting manually. Applications that already own a
`deadpool_postgres::Pool` can pass it to `DeadpoolPostgresAdapter::new` or
`DeadpoolPostgresAdapter::with_schema`.

```rust
use openauth_deadpool_postgres::DeadpoolPostgresAdapter;

// Replace `tls_connector` with a connector from your application, such as one
// built with postgres-native-tls or postgres-openssl.
let adapter = DeadpoolPostgresAdapter::connect_tls(
    "postgres://user:password@db.example.com:5432/openauth",
    tls_connector,
)
.await?;
```

## Rate Limiting

`DeadpoolPostgresRateLimitStore::from(&adapter)` uses the rate-limit table and
column names from the adapter schema. For standalone pools, use
`DeadpoolPostgresRateLimitStore::new(pool)` for the default `rate_limits` table,
`with_table(pool, table)` for a custom table with default column names, or
`with_names(pool, names)` when both table and column names are customized.

## Local Tests

The integration tests use Postgres from the root `docker-compose.yml`.

```bash
./scripts/ensure-test-services.sh postgres
OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@localhost:5432/openauth \
  cargo nextest run -p openauth-deadpool-postgres --all-targets
```

If your local Docker volume was created with an older database name, either
create the `openauth` database or point `OPENAUTH_TEST_POSTGRES_URL` at the
database that exists. Pool errors include the underlying driver detail to make
missing database, authentication, and connection failures easier to diagnose.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
