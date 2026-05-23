# openauth-core

Core types and primitives for OpenAuth-RS.

## Status

This package is in experimental beta. Contracts for adapters, plugins, options,
and HTTP routing may change before stable release.

The current core is usable for prototypes and controlled server-side flows such
as email/password auth, OAuth social sign-in, sessions, cookies, verification
tokens, rate limiting, and SQL/Redis-backed storage paths. It is not yet a
drop-in production-grade replacement for the full Better Auth ecosystem:
larger plugins, some adapter coverage, and final OpenAPI/error contract
hardening are still in progress.

## What It Provides

`openauth-core` contains the shared server contracts used by the rest of the
workspace: API requests and responses, auth context, cookies, crypto helpers,
database adapter traits, schemas, errors, options, plugins, sessions, users,
verification storage, and rate limiting.

## Example

```rust
use openauth_core::db::{auth_schema, AuthSchemaOptions};

let schema = auth_schema(AuthSchemaOptions::default());
let user_table = schema.table_name("user")?;
```

Application code usually depends on `openauth`; adapter, plugin, and
integration crates use `openauth-core` for stable internal contracts.

## Production Notes

- Configure a strong secret and explicit `base_url` in deployed environments.
- Use a persistent adapter such as SQLx/Postgres or SQLx/MySQL for primary
  auth data; `MemoryAdapter` is for tests and local development.
- Use a real distributed rate-limit store for multi-instance deployments.
- Sensitive routes bypass the signed cookie cache and read the backing session
  store directly, but deployments should still use HTTPS-only cookies and
  trusted origins.
- Secondary storage is supported for sessions and verification tokens when a
  `SecondaryStorage` implementation is configured.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
