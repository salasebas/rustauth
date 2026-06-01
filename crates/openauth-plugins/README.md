# openauth-plugins

Official server-side plugin modules for OpenAuth-RS.

## What It Is

`openauth-plugins` groups Better Auth-inspired server features translated into
OpenAuth's Rust plugin contracts. Use it when you want optional auth behavior
without pulling each feature into `openauth-core`.

The deprecated upstream `oidc-provider` plugin is not implemented here. Use
`openauth-oauth-provider` for OAuth 2.1 and OpenID Connect provider behavior.

## What It Provides

Current modules include access control, additional fields, admin, anonymous
users, API keys, bearer sessions, CAPTCHA hooks, custom sessions, device
authorization, email OTP, generic OAuth, Have I Been Pwned checks, JWT, last
login method, magic links, MCP, multi-session, OAuth proxy, one-tap, one-time
tokens, OpenAPI, organizations, phone number, SIWE, two-factor, and username.

Some plugins are pure helpers. Many require an OpenAuth adapter because they
store users, sessions, keys, organizations, tokens, or verification state.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_plugins::admin::{admin, AdminOptions};
use openauth_plugins::jwt;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(admin(AdminOptions::default()))
    .plugin(jwt::jwt()?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use module-specific options when a plugin needs application callbacks such as
email sending, OTP delivery, CAPTCHA verification, SIWE verification, or custom
authorization policy.

## Operational Notes

- Run adapter migrations after adding plugins that contribute schema.
- Prefer server-side plugins here for server behavior; browser-only upstream
  helpers should live in thin client SDKs instead.
- API key storage can use the database and selected secondary-storage paths.
- In pure `SecondaryStorage` mode (no database fallback) the `api-key:by-ref:*`
  listing index is mutated through an in-process lock, so concurrent
  create/delete on one process stay consistent. Multi-process deployments still
  need a secondary-storage backend with atomic collection semantics, or the
  database fallback, to keep `/api-key/list` from dropping concurrently written
  keys.
- OpenAPI support serves generated auth schemas and optional Scalar reference
  UI.

## Status

Experimental beta. Individual plugin APIs, schemas, endpoints, hooks, and
error codes may change before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
