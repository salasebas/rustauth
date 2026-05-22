# openauth-scim

Server-side SCIM 2.0 support for OpenAuth.

This crate provides the SCIM plugin, SCIM provider schema contribution,
management endpoints, bearer-token authentication, metadata endpoints, and
User provisioning routes.

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

SCIM is server-side only. It does not require SAML or SSO at runtime. If a
token is scoped to an organization, the OpenAuth organization plugin must be
installed and the caller must have an allowed organization role.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
