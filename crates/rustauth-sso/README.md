# rustauth-sso

Enterprise single sign-on plugin for RustAuth.

## What It Is

`rustauth-sso` is the plugin-level enterprise SSO surface. It stores SSO
providers, exposes SSO management and login routes, consumes external OIDC
providers, optionally exposes SAML compatibility routes, verifies domains, and
links/provisions users and organizations.

Use `rustauth-oidc` directly only when you need low-level OIDC discovery/config
helpers. Use `rustauth-oauth-provider` when your RustAuth server should issue
OAuth/OIDC tokens.

## What It Provides

- Provider registration, lookup, update, and deletion.
- OIDC sign-in and callback routes with discovery support.
- Optional SAML metadata, ACS, SLO, and logout compatibility routes.
- Domain verification and organization assignment helpers.
- Account linking and profile mapping.
- Audit hooks and rate-limit rules for SSO routes.

## Quick Start

Enable the `sso` feature on the umbrella `rustauth` crate (or depend on
`rustauth-sso` directly):

```toml
[dependencies]
rustauth = { version = "0.2.0", features = ["sso"] }
```

```rust
use rustauth::RustAuth;
use rustauth::sso::{sso, SsoOptions};

let auth = RustAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugin(sso(SsoOptions::default()))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`OidcConfig`, `OidcMapping`, and `TokenEndpointAuthentication` are re-exports of
`rustauth_oidc` types. For low-level discovery helpers, use
`rustauth::sso::oidc` or depend on `rustauth-oidc` directly.

Enable `oidc` and/or `saml` explicitly (`default = []`). For OIDC sign-in routes,
enable `oidc`. For SAML metadata, ACS, SLO, or logout routes, enable `saml` (it
pulls in `saml-signed` for XMLDSig verification and encrypted-assertion
decryption via `opensaml`).

## Feature Flags

- `oidc`: external OIDC IdP login support and HTTP client helpers.
- `saml`: SAML metadata, ACS, SLO, and logout routes (enables `rustauth-saml/saml-signed`).
- `saml-signed`: alias for `saml`; explicit signed/encrypted SAML crypto surface.

```toml
rustauth-sso = { version = "0.2.0", default-features = false, features = ["oidc"] }
```

## OIDC vs SAML

| | OIDC (`oidc` feature) | SAML (`saml` feature) |
| --- | --- | --- |
| Setup | Discovery + `clientId` / `clientSecret` | `entryPoint`, IdP `cert`, SP metadata, optional signing/decryption keys |
| Crypto | JWT / JWKS (built into OIDC) | Requires `saml-signed` (`opensaml`); unsigned IdP messages are rejected by default |
| IdP fixtures | Mock OIDC server (Google, Azure, Okta) | Production-shaped fixtures under `tests/fixtures/saml/idp/` |
| Plug-and-play | Yes — similar to social OAuth providers | No — each enterprise IdP needs explicit SAML config and mapping |

Prefer OIDC when the identity provider supports it. Use SAML for legacy
enterprise IdPs or tenants that require it.

## Status

Experimental beta. OIDC is the recommended path for new integrations. SAML
signed/encrypted flows are covered by `opensaml` and integration tests
(Okta/Azure/Google-shaped fixtures); live IdP smoke remains manual — see
[SMOKE-SAML.md](./SMOKE-SAML.md).

## Better Auth compatibility

Server-side SSO plugin (provider CRUD, OIDC sign-in/callback, optional SAML
routes, domain verification, linking). Aligned with Better Auth **1.6.9** where
it matters for this crate; RustAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [rustauth-oidc](../../crates/rustauth-oidc/README.md) — discovery and OIDC types
- [Repository](https://github.com/salasebas/rustauth)
