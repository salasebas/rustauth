# rustauth-diesel

Diesel database adapters for RustAuth.

This crate is the async-only Diesel integration for RustAuth. It builds on
[`diesel-async`](https://docs.rs/diesel-async) deadpool pooling and the shared
SQL runner in `rustauth-core`.

## Features

- `postgres` — production Postgres [`DbAdapter`](https://docs.rs/rustauth-core/latest/rustauth_core/db/trait.DbAdapter.html), schema migrations, plugin migrations, SQL-backed rate limits, and `DieselPostgresStores`
- `mysql` — production MySQL `DbAdapter` (`diesel-mysql`), schema migrations, plugin migrations, SQL-backed rate limits, and `DieselMysqlStores`

SQLite and sync Diesel are intentionally out of scope for the first rollout.

## Postgres adapter

```rust
use rustauth_diesel::DieselPostgresAdapter;

let adapter = DieselPostgresAdapter::connect("postgres://user:password@localhost:5432/rustauth").await?;
```

Bundled adapter + rate-limit store:

```rust
use rustauth_diesel::DieselPostgresStores;

let stores = DieselPostgresStores::connect("postgres://user:password@localhost:5432/rustauth").await?;
let options = stores.apply_to_options(rustauth_core::options::RustAuthOptions::default());
```

Adapter id: `diesel-postgres`.

## MySQL adapter

```rust
use rustauth_diesel::DieselMysqlAdapter;

let adapter = DieselMysqlAdapter::connect("mysql://user:password@localhost:3306/rustauth").await?;
```

Bundled adapter + rate-limit store:

```rust
use rustauth_diesel::DieselMysqlStores;

let stores = DieselMysqlStores::connect("mysql://user:password@localhost:3306/rustauth").await?;
let options = stores.apply_to_options(rustauth_core::options::RustAuthOptions::default());
```

Adapter id: `diesel-mysql`.

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
