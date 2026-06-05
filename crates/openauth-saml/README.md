# openauth-saml

SAML 2.0 service-provider helpers for OpenAuth enterprise SSO.

## Status

This crate provides SAML SP building blocks used by `openauth-sso`. Cryptography
(XMLDSig verification, outbound signing, encrypted assertion decryption) is
delegated to the [`opensaml`](https://github.com/sebasxsala/opensaml-rs) crate
(samlify v2.10.2 parity) when the `saml-signed` feature is enabled.

Builds without `saml-signed` reject signed or encrypted SAML messages
fail-closed.

Prefer OIDC for new enterprise SSO integrations when the identity provider
supports it.

## Features

| Feature | Description |
| --- | --- |
| *(default)* | Unsigned SAML parse/build, metadata, logout helpers, security pre-checks. |
| `saml-signed` | Enables `opensaml/crypto-bergshamra` for XMLDSig and XML-Enc. |

The `openauth-sso` `saml` feature enables `openauth-saml/saml-signed`.

## Dependency

`opensaml` is wired as a workspace path dependency (see root `Cargo.toml`).
For CI or downstream crates, pin a git revision once `opensaml` is published.

SP signing and decryption keys (`privateKey`, `decryptionPvk`) must be PEM
(PKCS#1 or PKCS#8). Passphrases are supported via `spMetadata.privateKeyPass`
and `spMetadata.encPrivateKeyPass`.

## What It Provides

- AuthnRequest generation (unsigned and signed Redirect).
- Service-provider metadata generation and IdP metadata parsing.
- ACS response parsing with optional signature verify and assertion decrypt.
- SAML logout request/response build and parse (Redirect/POST).
- XML hardening, timestamp validation, destination/recipient checks, and replay
  state key helpers.
- Algorithm policy types and stable OpenAuth error codes.

## Quick Start

Use `openauth-sso` for the plugin-level SAML routes. Depend on
`openauth-saml` directly only when you need the lower-level SAML helpers.

```rust
use openauth_sso::{sso, SsoOptions};

let plugin = sso(SsoOptions::default());
assert_eq!(plugin.id, "sso");
```

Enable SAML routes through the `openauth-sso` `saml` feature:

```toml
openauth-sso = { version = "...", features = ["saml"] }
```

## How It Fits

- `openauth-saml`: low-level SAML service-provider helpers + `opensaml` adapter.
- `openauth-sso`: enterprise SSO plugin that composes OIDC and optional SAML
  routes.
- `openauth-oidc`: recommended relying-party path for modern enterprise IdPs.

## Upstream parity (Better Auth 1.6.9)

Reference: `@better-auth/sso@1.6.9` → SAML service-provider helpers under
`packages/sso/src/saml/`. Parity pin:
[`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).

**Scope:** Low-level SAML 2.0 SP primitives (AuthnRequest, metadata, ACS parse,
logout XML). HTTP routes, provider storage, and account linking live in
[`openauth-sso`](../openauth-sso/README.md#upstream-parity-better-auth-169).

| Area | Parity | Notes |
| --- | --- | --- |
| Unsigned parse/build | Partial | Redirect/POST compatibility flows |
| Signed/encrypted SAML | Experimental | `opensaml` via `saml-signed` feature |
| SSO plugin HTTP routes | N/A here | `openauth-sso` `saml` feature |

Cryptography (XMLDSig, XML-Enc) is delegated to
[`opensaml`](https://github.com/sebasxsala/opensaml-rs), not Better Auth's Node
XML stack. Prefer OIDC for new enterprise integrations.

### Upstream lookup

1. Pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. SAML SP sources: `reference/upstream-src/<version>/repository/packages/sso/src/saml/`.
3. HTTP SSO parity: upstream `packages/sso/src/` routes and tests →
   [`openauth-sso`](../openauth-sso/README.md#upstream-lookup).
4. Map `crates/openauth-saml/src/` modules to upstream SAML helpers and `*.test.ts` cases.

## Links

- [Root README](../../README.md)
- [SSO HTTP parity (`openauth-sso`)](../openauth-sso/README.md#upstream-parity-better-auth-169)
- [Repository](https://github.com/sebasxsala/openauth-rs)
