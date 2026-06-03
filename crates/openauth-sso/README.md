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

```rust
use openauth::OpenAuth;
use openauth_sso::{sso, SsoOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugin(sso(SsoOptions::default()))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The default feature set enables OIDC. Enable the `saml` feature only when you
are testing SAML compatibility and understand the current SAML limitations.

## Feature Flags

- `oidc`: external OIDC IdP login support. Enabled by default.
- `saml`: SAML metadata, ACS, SLO, and logout routes.
- `saml-signed`: forwards the explicit signed-SAML feature surface.

## SAML Status

SAML support is experimental. Unsigned compatibility flows are covered, but
signed responses, signed logout messages, outbound signing, and encrypted
assertions are not a production-ready path yet. Prefer OIDC for new IdP
integrations.

## Status

Experimental beta. OIDC is the recommended path. SAML remains WIP until XML
signature/encryption support is backed by an auditable implementation.

## Links

- [Root README](../../README.md)
- [Better Auth 1.6.9 parity (`openauth-sso` OIDC E2E)](../../docs/parity/openauth-sso/README.md)
- [OIDC discovery crate parity](../../docs/parity/openauth-oidc/README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
