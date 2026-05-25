# SQL Adapter Parity Notes

This document records shared SQL behavior that affects adapter parity with
Better Auth. It is intentionally separate from the crate README because these
details are implementation contracts for OpenAuth's Rust SQL adapters.

## Identifier Quoting

`SqlDialect::quote_identifier` supports dotted identifiers by validating and
quoting each segment separately. For PostgreSQL this allows configured table
names such as `internal.users` to compile as `"internal"."users"`, matching
Better Auth's PostgreSQL e2e coverage for schema-qualified model names.

Identifier segments remain strict ASCII SQL identifiers. Empty segments,
multiple dots, spaces, and punctuation are rejected rather than escaped into SQL.

## Pattern Filters

String pattern filters escape `%`, `_`, and `\` before compiling to `LIKE` or
`ILIKE`. Better Auth's Kysely helper allows SQL wildcard semantics from the
input string. OpenAuth intentionally treats adapter input as literal user data
for this path so untrusted filter input cannot broaden a query.

