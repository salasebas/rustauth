# openauth-saml

Experimental SAML 2.0 service-provider helpers for OpenAuth enterprise SSO.

## Status

This crate is work in progress. It contains useful SAML service-provider
building blocks, but signed and encrypted SAML production flows are not yet
supported end to end. Signed and encrypted SAML messages fail closed unless a
future auditable XML security backend is added.

Prefer OIDC for new enterprise SSO integrations when the identity provider
supports it.

## What It Provides

- AuthnRequest generation.
- Service-provider metadata helpers.
- ACS response parsing and assertion extraction.
- SAML logout request/response helpers.
- XML hardening, timestamp validation, destination/recipient checks, and replay
  state key helpers.
- Algorithm policy types and a reserved `saml-signed` feature surface for
  future signed-flow support.

The crate does not currently add `xmlsec1`, `samael`, `openssl`, or another XML
signature backend.

## Quick Start

Use `openauth-sso` for the plugin-level SAML routes. Depend on
`openauth-saml` directly only when you need the lower-level SAML helpers.

```rust
use openauth_sso::{sso, SsoOptions};

let plugin = sso(SsoOptions::default());
assert_eq!(plugin.id, "sso");
```

Enable SAML routes through the `openauth-sso` `saml` feature when you are
testing SAML compatibility. Keep production SAML rollout blocked until your
deployment requirements match the supported unsigned/compatibility surface.

## How It Fits

- `openauth-saml`: low-level SAML service-provider helpers.
- `openauth-sso`: enterprise SSO plugin that composes OIDC and optional SAML
  routes.
- `openauth-oidc`: recommended relying-party path for modern enterprise IdPs.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
