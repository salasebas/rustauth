# rustauth-diesel

Diesel database adapters for RustAuth.

This crate provides async-only Diesel integrations for Postgres and MySQL. It
builds on [`diesel-async`](https://docs.rs/diesel-async) deadpool pooling and
RustAuth's shared SQL runner in `rustauth-core`. The public crate name is
`rustauth-diesel`; configure CLI migrations with `database.adapter = "diesel"`.

SQLite and sync Diesel are intentionally deferred. Use [`rustauth-sqlx`](../rustauth-sqlx/README.md)
for SQLite.

## Install

Postgres:

```toml
[dependencies]
rustauth-diesel = { version = "0.2", features = ["postgres"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

MySQL:

```toml
[dependencies]
rustauth-diesel = { version = "0.2", features = ["mysql"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Both backends:

```toml
[dependencies]
rustauth-diesel = { version = "0.2", features = ["postgres", "mysql"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Via the [`rustauth`](../rustauth/README.md) facade, enable `diesel-postgres` or
`diesel-mysql` and import types from `rustauth::diesel`.

## Features

| Feature | Backend | Types |
| --- | --- | --- |
| `postgres` | PostgreSQL | `DieselPostgresAdapter`, `DieselPostgresStores`, `DieselPostgresRateLimitStore` |
| `mysql` | MySQL | `DieselMysqlAdapter`, `DieselMysqlStores`, `DieselMysqlRateLimitStore` |

`default = []` — enable the backend(s) you need.

## Postgres adapter

Adapter id: `diesel-postgres`.

```rust
use rustauth_diesel::DieselPostgresAdapter;

let adapter = DieselPostgresAdapter::connect(
    "postgres://user:password@localhost:5432/rustauth",
)
.await?;
```

Bundled adapter + SQL-backed rate-limit store:

```rust
use rustauth_diesel::DieselPostgresStores;

let stores = DieselPostgresStores::connect(
    "postgres://user:password@localhost:5432/rustauth",
)
.await?;
let options = stores.apply_to_options(rustauth_core::options::RustAuthOptions::default());
```

## MySQL adapter

Adapter id: `diesel-mysql`.

```rust
use rustauth_diesel::DieselMysqlAdapter;

let adapter = DieselMysqlAdapter::connect(
    "mysql://user:password@localhost:3306/rustauth",
)
.await?;
```

Bundled adapter + SQL-backed rate-limit store:

```rust
use rustauth_diesel::DieselMysqlStores;

let stores = DieselMysqlStores::connect(
    "mysql://user:password@localhost:3306/rustauth",
)
.await?;
let options = stores.apply_to_options(rustauth_core::options::RustAuthOptions::default());
```

## CLI migrations

Configure `rustauth.toml` with `database.adapter = "diesel"` and the matching
`provider` (`postgres` or `mysql`):

```toml
[database]
adapter = "diesel"
provider = "postgres"
url_env = "DATABASE_URL"
```

```bash
cargo install rustauth-cli --features diesel
rustauth db status
rustauth db migrate --yes
```

Diesel migration support uses RustAuth's SQL migration planner through this
adapter. It does **not** use Diesel's migration CLI as a second source of schema
truth.

Do **not** configure `database.adapter = "diesel-async"`. The adapter string is
`diesel`; `diesel-async` is an internal driver dependency only.

## Behavior notes

- Uses `diesel-async` internally with deadpool connection pooling.
- SQLite is deferred (`diesel-async` SQLite uses a sync connection wrapper).
- Sync Diesel is not exposed; RustAuth's `DbAdapter` contract is async-only.
- MySQL array columns are JSON-backed where the shared SQL planner emits array
  types Postgres handles natively.

## Row decoding

Dynamic query results use backend-specific `QueryableByName` row types
([`DieselPostgresRow`](src/postgres/row.rs), [`DieselMysqlRow`](src/mysql/row.rs))
that capture column values at build time, then decode through the shared
[`SqlRowReader`](https://docs.rs/rustauth-core/latest/rustauth_core/db/trait.SqlRowReader.html)
boundary.

See [NOTES.md](./NOTES.md) for the plan 013 feasibility decision record.

## Tests

```bash
./scripts/ensure-test-services.sh postgres
cargo nextest run -p rustauth-diesel --features postgres --test diesel_feasibility
cargo nextest run -p rustauth-diesel --features postgres --test postgres_adapter

./scripts/ensure-test-services.sh mysql
cargo nextest run -p rustauth-diesel --features mysql --test diesel_feasibility
cargo nextest run -p rustauth-diesel --features mysql --test mysql_adapter
```

For route-level parity, test counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).
