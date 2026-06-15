# Changelog

All notable changes to `rustauth-diesel` are documented here.

## Unreleased

### Added

- Production Postgres `DbAdapter` (`diesel-postgres`) with full CRUD, joins,
  transactions, schema migrations, plugin migrations, and SQL-backed rate limits.
- Production MySQL `DbAdapter` (`diesel-mysql`) with full CRUD, joins,
  transactions, schema migrations, plugin migrations, and SQL-backed rate limits.
- `DieselPostgresStores` / `DieselPostgresStoresBuilder` bundle.
- `DieselMysqlStores` / `DieselMysqlStoresBuilder` bundle.
- Dynamic `DieselPostgresRow` and `DieselMysqlRow` (`QueryableByName`) for shared SQL runner integration.
- Port of `rustauth-sqlx` Postgres and MySQL adapter integration tests.
