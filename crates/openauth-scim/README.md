# openauth-scim

Server-side SCIM 2.0 support for OpenAuth.

This crate provides the server-side SCIM plugin, SCIM provider schema
contribution, management endpoints, bearer-token authentication, metadata
endpoints, and SCIM 2.0 resource routes.

Implemented route surface:

- `Users`: create, list, search, get, replace, patch, delete.
- `Groups`: create, list, search, get, replace, patch, delete for
  organization-scoped providers.
- `.search`: users, groups, and combined resource search.
- `Bulk`: per-operation execution for Users and Groups with `bulkId`
  resolution, `failOnErrors`, resource version checks, and scoped mutation
  hardening.
- Metadata: `ServiceProviderConfig`, `Schemas`, and `ResourceTypes`.
- Projections and filters: `attributes`, `excludedAttributes`, filtering,
  sorting, pagination, ETags, and `If-Match`.
- `/Me`: implemented as a SCIM `501` unsupported response because OpenAuth
  SCIM tokens are provider-scoped, not end-user aliases.

## Example

```rust
use openauth_core::options::OpenAuthOptions;
use openauth_scim::{scim, ScimOptions};

let options = OpenAuthOptions {
    plugins: vec![scim(ScimOptions::default())],
    ..OpenAuthOptions::default()
};
```

For the public facade crate, enable the optional `scim` feature and use
`openauth::scim`.

```toml
[dependencies]
openauth = { version = "0.0.5", features = ["scim"] }
```

## Token Storage

Generated SCIM tokens can be stored as plain text, SHA-256 hashes, encrypted
values using OpenAuth secret material, or custom async transformations:

```rust
use openauth_scim::{ScimOptions, ScimTokenStorage};

let options = ScimOptions {
    token_storage: ScimTokenStorage::Hashed,
    ..ScimOptions::default()
};
```

## Scope

SCIM is server-side only. This crate does not ship browser SDKs, dashboard UI,
or client-side SCIM code. It does not require SAML or SSO at runtime. If a token
is scoped to an organization, the OpenAuth organization plugin must be installed
and the caller must have an allowed organization role. Organization-scoped SCIM
tokens are rejected with a controlled SCIM error when the organization plugin is
not installed.

## Database Adapters

The SCIM schema contributes these tables:

- `scim_providers`
- `scim_user_profiles`
- `scim_group_profiles`

Migrations and runtime persistence are tested against these SQL adapters:

- SQLx SQLite
- SQLx Postgres
- SQLx MySQL
- tokio-postgres
- deadpool-postgres

The in-memory adapter is supported for tests and in-memory runtime usage, but it
does not provide durable migrations.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
