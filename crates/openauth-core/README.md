# openauth-core

Core contracts and server primitives for OpenAuth-RS.

## What It Is

`openauth-core` contains the framework-neutral pieces shared by the workspace:
API routing, auth context, cookies, crypto helpers, database adapter traits,
schema planning, errors, options, plugin contracts, sessions, users,
verification storage, and rate limiting.

Application code usually starts with `openauth`. Adapter and plugin crates use
`openauth-core` directly.

## What It Provides

- Core email/password, session, account, social sign-in, and verification route
  contracts.
- Database adapter traits and schema/migration metadata.
- `MemoryAdapter` for tests and local prototypes.
- Plugin, endpoint, hook, schema, and rate-limit extension contracts.
- Cookie, JWT/JWE, secret-rotation, and request/response primitives.

## Quick Start

```rust
use openauth_core::db::{auth_schema, AuthSchemaOptions};

let schema = auth_schema(AuthSchemaOptions::default());
let user_table = schema.table_name("user")?;
assert_eq!(user_table, "users");
# Ok::<(), Box<dyn std::error::Error>>(())
```

For a full auth server, prefer the `openauth` builder:

```rust
use openauth::OpenAuth;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Feature Flags

Default features preserve the broad compatibility surface:

- `jose`: JOSE/JWE helpers backed by `josekit`.
- `oauth`: OAuth/social route support and OAuth helper re-exports.
- `social-providers`: social provider re-exports.

Use `default-features = false` for a smaller core build when you do not need
JOSE or social provider support.

## Production Notes

- Configure a strong secret and explicit `base_url`.
- Use a durable adapter such as SQLx, `tokio-postgres`, or
  `deadpool-postgres`; `MemoryAdapter` is not persistent.
- Use distributed rate-limit storage for multi-instance deployments.
- Keep browser/client SDK behavior outside core; core owns server boundaries.

## Status

Experimental beta. Adapter, plugin, option, and route contracts may change
before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
