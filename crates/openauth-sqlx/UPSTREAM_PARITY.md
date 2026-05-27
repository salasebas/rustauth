# SQLx Server-Side Upstream Parity

This document tracks the server-side parity status of `openauth-sqlx` against
the Better Auth SQL/Kysely adapter behavior inspected under
`upstream/better-auth/1.6.9/repository/`.

The Rust adapter is not a line-by-line TypeScript port. Parity means matching
observable server behavior where it matters while preserving OpenAuth's typed
query contract, explicit errors, additive migration safety, and SQLx-native
storage choices.

## Current Assessment

Estimated server-only parity: **95%**.

The remaining gap is mostly intentional Rust/OpenAuth design, TypeScript-only
adapter factory behavior, or behavior that would reduce safety if copied
literally.

## Implemented Parity

- CRUD, count, transaction, and migration surfaces match the relevant Better
  Auth adapter operations.
- Queries use parameter binding and validated SQL identifiers.
- Logical table and field names are resolved to physical names before SQL
  execution.
- WHERE operators cover equality, inequality, comparison, IN, NOT IN,
  contains, starts-with, and ends-with.
- Null equality and inequality compile to `IS NULL` and `IS NOT NULL`.
- Case-insensitive equality, inequality, array predicates, and pattern
  predicates are supported.
- Join behavior matches Better Auth's one-to-one and one-to-many contracts,
  including default join limits, explicit join limits, missing one-to-one
  records as `null`, and missing one-to-many records as empty arrays.
- Native transactions roll back failed callbacks.
- Schema planning and execution are additive, ordered, and refuse unsafe
  warning plans instead of applying destructive changes.
- Schema customization covers custom table names, field names, plugin fields,
  plugin tables, indexes, foreign keys, and database-backed rate-limit storage.
- SQL-backed rate limiting persists counters, respects physical names, resets
  expired windows, and does not increment denied requests.
- `create_schema(file)` now applies the schema as before and, when requested,
  writes the compiled migration SQL to the given path with `SchemaCreation`
  metadata.
- `create_schema(file)` and literal LIKE wildcard behavior are covered for
  SQLite, Postgres, and MySQL. Postgres and MySQL coverage runs against live
  Docker Compose database services.

## Intentional Differences

- `delete` deletes one matching row in OpenAuth. Better Auth's Kysely adapter can
  delete every matching row through `deleteFrom(...).where(...)`. OpenAuth keeps
  the safer single-row contract and exposes `delete_many` for bulk deletion.
- Better Auth's generic adapter factory applies default values and `onUpdate`
  transforms. OpenAuth service layers set generated ids, timestamps, and
  lifecycle fields explicitly before adapter calls.
- Better Auth's Kysely SQL adapter stores array fields as JSON-like values and
  reports array support as false. SQLx Postgres stores native `TEXT[]` and
  `BIGINT[]`; SQLite and MySQL use their dialect-specific JSON/text bindings.
- Better Auth's Postgres Kysely migration map treats arrays as JSONB. SQLx
  Postgres uses native array types because that is the idiomatic SQLx/Postgres
  representation.
- Better Auth's MySQL migration map uses `timestamp(3)`. SQLx MySQL uses
  `DATETIME(6)` to avoid timestamp range/time-zone surprises and preserve
  microsecond precision.
- Better Auth's count query counts `id`. OpenAuth counts `*`, which is
  equivalent for these schemas and does not depend on selecting a specific id
  column.
- Better Auth's rate limiter is split between request-time read and
  response-time write. OpenAuth's SQL stores consume counters in one transaction
  to satisfy the Rust atomic rate-limit store contract.
- OpenAuth escapes `%`, `_`, and `\` in LIKE pattern operators and emits an
  explicit `ESCAPE` clause. Better Auth's Kysely adapter does not escape these
  SQL wildcard characters. OpenAuth keeps the stricter behavior because it
  prevents user input from silently becoming SQL wildcards.
- OpenAuth's query builder defaults `FindMany` to no limit. Better Auth's
  adapter factory defaults `findMany` to 100 unless configured otherwise.
  Changing this at the SQLx adapter layer would break OpenAuth's current typed
  query contract and internal maintenance queries; callers should set explicit
  limits on externally driven list endpoints.

## Remaining Risks

- Postgres and MySQL runtime coverage requires live database services. The repo
  Docker Compose services cover the SQLx adapter suite locally, but CI and
  contributors must provide equivalent reachable databases.
- Direct use of SQLx adapters expects callers to use the schema configured in
  `with_schema`. OpenAuth's builder wraps adapters with schema and hook layers
  for normal application use.
- A future OpenAuth-level database options object could add a configurable
  default `FindMany` limit. That would be a core API change, not a SQLx-only
  parity fix.
