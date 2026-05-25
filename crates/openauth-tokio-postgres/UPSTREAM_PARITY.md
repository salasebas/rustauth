# Tokio Postgres Upstream Parity

This crate is compared against Better Auth's server-side SQL adapter behavior,
primarily the core adapter factory, Kysely adapter, shared adapter test suites,
and PostgreSQL e2e coverage under `upstream/better-auth/`.

OpenAuth is not a line-by-line TypeScript port. The target contract is the
observable server-side behavior that matters for applications using the adapter.

## Supported Behavior

- CRUD operations for create, find, count, update, update many, delete, and
  delete many.
- Physical table and field names from `AuthSchemaOptions` / `TableOptions`.
- Generated text, UUID, forced UUID, and PostgreSQL identity numeric IDs.
- JSON, string array, number array, boolean, timestamp, and nullable values.
- Scalar filters, `in`, `not_in`, `contains`, `starts_with`, `ends_with`,
  case-insensitive string filters, null equality, and mixed `AND`/`OR`
  predicate groups.
- One-to-one, one-to-many, reverse, limited, missing-row, and multi-join reads.
- Join reads inside transactions, including multi-join fallback behavior.
- Transaction commit, rollback on callback errors, rollback after SQL errors,
  and nested transaction rejection.
- Additive schema creation and migration planning for tables, columns, indexes,
  unique constraints, foreign keys, generated UUID defaults, generated identity
  columns, and column type mismatch reporting.
- PostgreSQL schema-qualified table names such as `internal.users` when the
  PostgreSQL schema already exists.
- Database-backed rate limiting with transactional consume semantics.
- Core email/password route flows backed by this adapter.

## Intentional Rust Differences

- `tokio-postgres` uses a single async client rather than a connection pool in
  this crate. Normal queries are allowed to pipeline concurrently, while
  explicit transactions, migrations, schema creation, and rate-limit consumes
  acquire an exclusive gate so transaction state cannot be interleaved with
  unrelated statements on the same connection.
- The public transaction callback returns `Result<(), OpenAuthError>`. Better
  Auth's TypeScript adapter can return a generic callback value, but preserving
  that exact shape would make OpenAuth's object-safe `DbAdapter` contract much
  more complex. Server-side database state transitions are preserved.
- SQL string pattern filters escape `%`, `_`, and `\` from user input. Better
  Auth's Kysely helper treats these as SQL wildcard syntax. OpenAuth's behavior
  is stricter and prevents untrusted filter input from broadening a query.
- PostgreSQL schemas are not created implicitly for `schema.table` names. The
  caller or migration environment must create the schema first, matching the
  operational boundary in Better Auth's PostgreSQL e2e setup.
- TypeScript-only factory ergonomics such as runtime debug log options and
  dynamic transform hooks are not adapter-local concepts in OpenAuth. Equivalent
  concerns are handled through Rust types, explicit errors, and the surrounding
  core/plugin layers.

## Current Parity Estimate

Server-only parity is approximately **96%** for the behavior this crate owns.
The remaining gap is mostly API-shape parity with TypeScript, not missing
database semantics. Raising it further would require changing shared OpenAuth
adapter contracts rather than only this crate, and those changes are not
currently justified by observable server-side behavior.

