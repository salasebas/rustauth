# openauth-plugins

Official server-side plugin modules for OpenAuth-RS.

## Status

This package is in experimental beta. Individual plugin APIs, schemas,
endpoints, hooks, and error codes may change before stable release.

`openauth-plugins` intentionally implements the server-side Better Auth plugin
surface that still belongs in this crate. The legacy Better Auth
`oidc-provider` plugin is not ported here because upstream marks it deprecated;
use the dedicated `openauth-oauth-provider` crate instead. That crate tracks the
newer Better Auth `oauth-provider` package and is the supported OAuth 2.1/OIDC
provider path for OpenAuth.

## What It Provides

`openauth-plugins` groups server-side features inspired by Better Auth,
translated into Rust plugin contracts. Current modules include admin,
anonymous, API keys, bearer auth, captcha, custom sessions, device
authorization, email OTP, generic OAuth, haveibeenpwned, JWT, magic links, MCP,
multi-session, OAuth proxy, OpenAPI, organization, phone number, SIWE,
two-factor, username, and related helpers.

## Plugin Status

| Plugin | Status | Notes |
| --- | --- | --- |
| access | Stable-ish | Pure policy helper; no adapter required. |
| additional-fields | Beta | Schema contribution helper. |
| admin | Beta | Requires an adapter for HTTP behavior. |
| anonymous | Beta | Requires an adapter for user/session lifecycle. |
| api-key | Beta | Requires an adapter or secondary storage; database/fallback mode uses optimistic concurrency for usage counters, while secondary-storage-only mode remains best-effort. |
| bearer | Stable-ish | Header/cookie bridge for session tokens. |
| captcha | Beta | Requires an external CAPTCHA provider. |
| custom-session | Beta | Depends on application callback behavior. |
| device-authorization | Beta | Requires an adapter. |
| email-otp | Beta | Requires an adapter and an application sender. |
| generic-oauth | Beta | Requires configured OAuth providers. |
| haveibeenpwned | Stable-ish | Uses k-anonymity range checks; external service by default. |
| jwt | Beta | Requires an adapter for local JWKS storage unless using remote/custom signing. |
| last-login-method | Stable-ish | Cookie-only by default; optional DB persistence. |
| magic-link | Beta | Requires an adapter and an application sender. |
| mcp | Experimental | OAuth-style MCP support; requires an adapter. |
| multi-session | Beta | Requires an adapter. |
| oauth-proxy | Experimental | Preview/deployment proxy behavior. |
| one-tap | Beta | Requires Google provider configuration or client ID. |
| one-time-token | Beta | Requires an adapter. |
| open-api | Stable-ish | Serves generated OpenAPI JSON and optional Scalar reference. |
| organization | Beta | Requires an adapter. |
| phone-number | Beta | Requires an adapter and application OTP sender/verifier. |
| siwe | Beta | Requires an adapter and SIWE verification callback. |
| two-factor | Beta | Requires an adapter and optional OTP sender. |
| username | Beta | Requires an adapter for sign-in/availability endpoints. |
| oidc-provider | Replaced | Deprecated upstream; use `openauth-oauth-provider`. |

## Example

```rust
use openauth::OpenAuth;
use openauth_plugins::admin::{admin, AdminOptions};
use openauth_plugins::jwt;

let jwt_plugin = jwt::jwt()?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(admin(AdminOptions::default()))
    .plugin(jwt_plugin)
    .build()?;
```

Prefer plugin modules here for server behavior. Browser-only upstream behavior
should live in future thin client SDKs instead of this crate.

## Integration Matrix

The default test suite uses `MemoryAdapter` for speed. Opt-in Docker tests cover
the plugin schema and key user-facing flows against Postgres, MySQL, Redis, and
Valkey:

```sh
./scripts/ensure-test-services.sh postgres mysql redis valkey
cargo nextest run -p openauth-plugins integration_matrix --run-ignored ignored-only
```

MongoDB is not part of the plugin matrix yet because this workspace does not
currently expose a MongoDB `DbAdapter` or `SecondaryStorage` implementation.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
