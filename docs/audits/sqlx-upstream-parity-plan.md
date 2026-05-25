# SQLx Upstream Parity Audit Plan

## Goal

Bring `openauth-sqlx` as close as reasonably possible to Better Auth 1.6.9
server-side SQL adapter behavior while preserving OpenAuth's Rust-native
adapter boundaries, explicit errors, typed values, and migration safety.

Current server-only parity estimate after implementation and live database
verification: **95%**.

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/kysely-adapter/src/kysely-adapter.ts`
- `upstream/better-auth/1.6.9/repository/packages/kysely-adapter/src/query-builders.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/adapter-base.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/adapter-kysely.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/get-migration.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/get-schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/db/schema.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/factory.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/adapter/utils.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/basic.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/case-insensitive.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/joins.ts`
- `upstream/better-auth/1.6.9/repository/packages/test-utils/src/adapter/suites/transactions.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/rate-limiter/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/get-tables.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/db/schema/rate-limit.ts`

## OpenAuth Files Inspected

- `crates/openauth-sqlx/src/lib.rs`
- `crates/openauth-sqlx/src/migration.rs`
- `crates/openauth-sqlx/src/rate_limit.rs`
- `crates/openauth-sqlx/src/sqlite/{mod.rs,query.rs,row.rs,schema.rs,state.rs,support.rs,errors.rs}`
- `crates/openauth-sqlx/src/postgres/{mod.rs,query.rs,row.rs,schema.rs,state.rs,support.rs,errors.rs}`
- `crates/openauth-sqlx/src/mysql/{mod.rs,query.rs,row.rs,schema.rs,state.rs,support.rs,errors.rs}`
- `crates/openauth-core/src/db/sql/{dialect.rs,executor.rs,joins.rs,migrations.rs,rate_limit.rs,statements.rs,types.rs}`
- `crates/openauth-core/src/db/{adapter.rs,factory.rs,memory.rs,schema.rs,transform.rs,adapter_harness.rs}`
- `crates/openauth-sqlx/tests/{sqlite_adapter.rs,postgres_adapter.rs,mysql_adapter.rs,common/mod.rs}`
- `crates/openauth-sqlx/UPSTREAM_PARITY.md`
- `crates/openauth/tests/{public_api.rs,feature_flags.rs}`

## Confirmed Matches

- Public adapter surface matches the server-side Better Auth adapter shape:
  create, find-one, find-many, count, update, update-many, delete, delete-many,
  transaction, schema creation, and explicit migration execution.
- SQL statements are parameterized and quote validated identifiers. User values
  are not interpolated into SQL.
- Logical model and field names resolve to physical database names before driver
  execution, matching upstream `getModelName` and `getFieldName` behavior.
- Where operators cover upstream `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`,
  `not_in`, `contains`, `starts_with`, and `ends_with`.
- Null predicates use `IS NULL` and `IS NOT NULL` for equality and inequality.
- Case-insensitive equality, inequality, IN, NOT IN, and string pattern matching
  are supported; Postgres uses `ILIKE` for pattern matching and other dialects
  use `LOWER(...) LIKE LOWER(...)`.
- Find-many supports sort, limit, and offset. Join selection adds required base
  fields internally and trims them from caller-visible output when not selected.
- Native and fallback joins preserve Better Auth's one-to-one vs one-to-many
  behavior, default join limit of 100, explicit join limits, missing one-to-one
  results as null, and missing one-to-many results as empty arrays.
- Transactions are native for SQLite, Postgres, and MySQL and roll back failed
  callbacks.
- Migrations are additive, ordered by table order, create indexes after tables,
  detect missing columns/indexes, and refuse to execute when type, nullability,
  generated-id, primary-key, or foreign-key warnings are present.
- Schema customization covers physical table names, field names, plugin fields,
  plugin tables, optional fields, unique fields, indexes, foreign keys, and
  database-backed rate-limit storage.
- Database-backed rate limiting persists `key`, `count`, and `last_request`,
  respects physical names, resets counts after the window, and does not increment
  denied requests.
- SQLite connection setup enables foreign keys in `connect`, preserving server
  side referential integrity for the pooled connections OpenAuth creates.
- `create_schema(file)` applies the schema as before and, when requested,
  writes compiled migration SQL to the given path with `SchemaCreation`
  metadata.
- SQL LIKE wildcard hardening is covered at the SQL planner level and by a
  SQLite, Postgres, and MySQL integration tests that verify literal `%` and `_`
  handling against real databases.

## Confirmed Differences

- Better Auth's Kysely `delete` delegates to `deleteFrom(...).where(...)`, which
  may delete every matching record. OpenAuth's `delete` intentionally deletes one
  matching row, while `delete_many` deletes all matches. This is consistent with
  OpenAuth's internal adapter contract and safer for single-record lifecycle
  calls.
- Better Auth's adapter factory applies default values and `onUpdate` transforms
  in a generic wrapper. OpenAuth service/store layers set timestamps, ids, and
  generated fields explicitly before adapter calls.
- Better Auth's Kysely adapter reports `supportsArrays: false` and stores arrays
  as JSON for all SQL dialects. OpenAuth stores Postgres arrays as native SQL
  arrays and SQLite/MySQL arrays as text/JSON according to dialect capability.
- Better Auth's Kysely Postgres migration type mapping treats `string[]` and
  `number[]` as JSONB. OpenAuth maps Postgres arrays to `TEXT[]` and `BIGINT[]`.
- Better Auth's MySQL date type uses `timestamp(3)`. OpenAuth uses `DATETIME(6)`
  to avoid timestamp range/time-zone surprises and keep microsecond precision.
- Better Auth's count query counts `id`; OpenAuth counts `*`, which is equivalent
  for these schemas because ids are primary keys and avoids depending on a
  selected id column.
- Better Auth rate limiting performs a request-phase read and response-phase
  write. OpenAuth's SQL rate-limit store performs the check and increment in a
  single locked transaction to satisfy the Rust `RateLimitStore` atomicity
  contract.
- Better Auth's Kysely adapter does not escape `%` and `_` in LIKE patterns.
  OpenAuth escapes `%`, `_`, and `\` and emits an explicit `ESCAPE` clause. This
  is intentionally stricter and prevents user search text from becoming SQL
  wildcards.
- OpenAuth's query builder defaults `FindMany` to no limit. Better Auth's
  adapter factory defaults `findMany` to 100 unless configured otherwise.
  Changing this in SQLx alone would break OpenAuth's current typed query
  contract and internal maintenance queries; externally driven list endpoints
  should set explicit limits.

## Risks

- The direct SQLx adapters bypass the schema/factory wrapper when used by value,
  so callers must build query objects using the adapter schema's logical names or
  pass the same schema into `with_schema`.
- Postgres and MySQL integration tests require live database services and may be
  skipped in local environments without configured URLs.
- SQLx MySQL cannot return updated rows directly, so OpenAuth preselects and
  merges updated data. Existing tests cover updates where the where field is also
  changed.
- The Postgres native-array choice intentionally diverges from Better Auth's
  Kysely JSONB array storage and should remain documented as Rust SQLx behavior,
  not upstream parity drift.
- Before this audit, `create_schema` ignored the optional `file` argument for
  SQLx adapters and only applied schema directly. Better Auth exposes a
  CLI-oriented schema-generation path, and OpenAuth's public API already
  documented adapter-specific schema file metadata.

## Proposed Fixes

- Save this audit plan as the durable parity record.
- Add focused regression coverage that SQL string pattern predicates treat `%`,
  `_`, and `\` as literal input.
- Implement SQLx `create_schema(file)` support by preserving existing database
  schema application behavior, writing the compiled migration SQL to the
  requested path after a successful apply, and returning `SchemaCreation`
  metadata with overwrite intent.

## Tests To Add Or Update

- Add shared SQL planner unit tests in `crates/openauth-core/src/db/sql/dialect.rs`
  for `contains`, `starts_with`, and `ends_with` values containing `%`, `_`, and
  `\`.
- Verify the generated SQL includes a dialect-appropriate `ESCAPE` clause and
  the bound pattern contains escaped wildcard characters.
- Add a SQLite adapter regression test that `create_schema(file)` writes the
  requested SQL file, returns matching `SchemaCreation` metadata, and still
  creates tables in the database.
- Add a SQLite adapter regression test proving `%` and `_` in user pattern
  values are treated literally by executed SQL.
- Add matching Postgres and MySQL live database regression tests for
  `create_schema(file)` and literal LIKE wildcard execution.
- Run scoped verification for `openauth-core` because the first tests target
  shared SQL planner behavior. Run `openauth-sqlx` checks for the modified
  target package surface.

## Items Intentionally Left Unchanged

- Do not change `delete` to delete every matching row; OpenAuth keeps a safer
  single-row delete contract and exposes `delete_many` for bulk deletion.
- Do not change Postgres arrays to JSONB; native arrays are idiomatic for SQLx
  and covered by adapter capabilities.
- Do not change MySQL timestamp storage from `DATETIME(6)` to `timestamp(3)`.
- Do not remove SQL LIKE wildcard escaping; it is a production hardening
  improvement over upstream Kysely behavior while preserving pattern-operator
  intent.
- Do not add a SQLx-local default `FindMany` limit; any future configurable
  default limit belongs in OpenAuth's core query/options layer.
- Do not add new dependencies.
