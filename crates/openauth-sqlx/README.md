# openauth-sqlx

SQLx database adapters for OpenAuth-RS.

## Status

This package is in experimental beta. SQL planning, migration output, feature
flags, and adapter behavior may change before stable release.

Current practical parity with the Better Auth SQL adapter contract is roughly
95% for CRUD, filtering, joins, migrations, database-backed rate limits, and
transactions. SQLite has the strongest local coverage. Postgres and MySQL are
covered by integration tests, but require a correctly provisioned test database.

| Dialect | Status | Notes |
| --- | --- | --- |
| SQLite | Beta, broadly usable for core flows | `connect` and `connect_with_schema` enable `PRAGMA foreign_keys = ON` for pooled connections. Supports database-generated serial IDs. `new(pool)` assumes the caller already configured the pool. |
| Postgres | Beta, broadly usable for core flows | Supports database-generated serial IDs and native UUID IDs with `pg_catalog.gen_random_uuid()`. |
| MySQL | Beta | Supports database-generated serial IDs. Requires an InnoDB database/user with privileges to create tables, indexes, and foreign keys. |

## What It Provides

`openauth-sqlx` provides SQLite, Postgres, and MySQL adapters for OpenAuth-RS,
plus SQL-backed rate-limit stores. Use the crate feature matching your database:
`sqlite`, `postgres`, or `mysql`.

The SQL filters support case-insensitive string matching for equality,
inequality, array membership, and pattern operators. Empty `IN` predicates are
compiled as no-match predicates, while empty `NOT IN` predicates are compiled as
match-all predicates to avoid invalid SQL.

`create_schema` and `run_migrations` only apply executable additive plans. If
migration planning detects warnings such as column type mismatches, they return
an adapter error before applying statements. Use `plan_migrations` or
`compile_migrations` to inspect warnings and SQL without changing the database.

## Example

```rust
use openauth::OpenAuth;
use openauth_sqlx::SqliteAdapter;
use sqlx::sqlite::SqlitePoolOptions;

let pool = SqlitePoolOptions::new()
    .connect("sqlite://openauth.db")
    .await?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .adapter(SqliteAdapter::new(pool))
    .build()?;
```

For Postgres production deployments that do not otherwise use SQLx,
`openauth-deadpool-postgres` may be the smaller operational fit.

## Testing

SQLite tests can run without Docker:

```sh
CARGO_TARGET_DIR=/private/tmp/openauth-sqlx-target cargo test -p openauth-sqlx --features sqlite --lib --tests
```

Postgres and MySQL tests expect Docker Compose services with an `openauth`
database and a user with DDL permissions:

```sh
CARGO_TARGET_DIR=/private/tmp/openauth-sqlx-target cargo test -p openauth-sqlx --features postgres --test postgres_adapter
CARGO_TARGET_DIR=/private/tmp/openauth-sqlx-target cargo test -p openauth-sqlx --features mysql --test mysql_adapter
```

Defaults:

```text
OPENAUTH_TEST_POSTGRES_URL=postgres://user:password@localhost:5432/openauth
OPENAUTH_TEST_MYSQL_URL=mysql://user:password@localhost:3306/openauth
```

If a service is reachable but the database or grants are missing, the
integration tests fail during preflight with an actionable error.

If MySQL was started previously with a stale Docker volume, recreate the volume
before rerunning the suite:

```sh
docker compose down -v
docker compose up -d --wait mysql
```

Known limits:

- The SQL adapters are beta and should be validated against your production
  dialect before rollout.
- Schema migrations are additive only; destructive rewrites, renames, and type
  changes are intentionally reported as warnings instead of being applied.
- MySQL DDL can cause implicit commits, so migration preflight matters even
  though the planner blocks known warnings before execution.
- `SqliteAdapter::new(pool)` does not mutate caller-owned pool options. Enable
  foreign keys yourself when constructing the pool externally.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
