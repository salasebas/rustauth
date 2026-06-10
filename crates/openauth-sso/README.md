# openauth-sso

Enterprise single sign-on plugin for OpenAuth-RS.

## What It Is

`openauth-sso` is the plugin-level enterprise SSO surface. It stores SSO
providers, exposes SSO management and login routes, consumes external OIDC
providers, optionally exposes SAML compatibility routes, verifies domains, and
links/provisions users and organizations.

Use `openauth-oidc` directly only when you need low-level OIDC discovery/config
helpers. Use `openauth-oauth-provider` when your OpenAuth server should issue
OAuth/OIDC tokens.

## What It Provides

- Provider registration, lookup, update, and deletion.
- OIDC sign-in and callback routes with discovery support.
- Optional SAML metadata, ACS, SLO, and logout compatibility routes.
- Domain verification and organization assignment helpers.
- Account linking and profile mapping.
- Audit hooks and rate-limit rules for SSO routes.

## Quick Start

Enable the `sso` feature on the umbrella `openauth` crate (or depend on
`openauth-sso` directly):

```toml
[dependencies]
openauth = { version = "0.1.1", features = ["sso"] }
```

```rust
use openauth::OpenAuth;
use openauth::sso::{sso, SsoOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugin(sso(SsoOptions::default()))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`OidcConfig`, `OidcMapping`, and `TokenEndpointAuthentication` are re-exports of
`openauth_oidc` types. For low-level discovery helpers, use
`openauth::sso::oidc` or depend on `openauth-oidc` directly.

The default feature set enables OIDC. Enable the `saml` feature when you need
SAML metadata, ACS, SLO, or logout routes (it pulls in `saml-signed` for
XMLDSig verification and encrypted-assertion decryption via `opensaml`).

## Feature Flags

- `oidc`: external OIDC IdP login support. Enabled by default.
- `saml`: SAML metadata, ACS, SLO, and logout routes (enables `openauth-saml/saml-signed`).
- `saml-signed`: alias for `saml`; explicit signed/encrypted SAML crypto surface.

## OIDC vs SAML

| | OIDC (default) | SAML (`saml` feature) |
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
it matters for this crate; OpenAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [openauth-oidc](../../crates/openauth-oidc/README.md) — discovery and OIDC types
- [Repository](https://github.com/sebasxsala/openauth-rs)
