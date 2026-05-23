# openauth-sso

Enterprise single sign-on support for OpenAuth-RS.

## Status

This package is in experimental beta. OIDC is the recommended path for new SSO
integrations. SAML endpoints are available for compatibility testing, but SAML is
not production-ready in the default build: XMLDSig validation, outbound signing,
and encrypted assertion decryption fail closed until OpenAuth has an auditable
XML security backend.

## What It Provides

`openauth-sso` exposes a server-side plugin for enterprise SSO. It adds SSO
provider storage, feature-gated OIDC sign-in, feature-gated SAML
metadata/ACS/SLO scaffolding, domain verification, account linking helpers,
organization provisioning, and audit hooks.

Use `openauth-oidc` directly when you only need OpenAuth to consume external
OIDC IdPs. Use `openauth-saml` directly when you only need SAML. Use this crate
when you want the convenient enterprise SSO plugin that composes those protocol
crates with provider management and domain verification.

## Features

- `default = ["oidc"]` keeps the common OIDC SSO path enabled.
- `oidc` enables external OIDC IdP client routes and helpers.
- `saml` enables SAML metadata, ACS, and SLO routes.
- `saml-signed` enables the explicit signed-SAML feature surface and forwards to
  `openauth-saml/saml-signed`.

OIDC-only builds do not depend on the SAML crate or SAML/XML-specific
dependencies. SCIM provisioning remains in `openauth-scim` and is not part of
this login plugin.

## Current Behavior

- OIDC supports provider CRUD, discovery at registration time, runtime discovery
  for partially stored configs, shared or provider-specific callback URLs,
  custom profile mappings, lowercase email normalization, standard ID-token
  claim validation, stable subject-based account linking, callback state
  mix-up rejection, explicit email-verification trust semantics, and default
  `client_secret_basic` token authentication.
- OIDC manual `skipDiscovery` endpoints can opt into strict trusted-origin
  validation with `SsoOptions::strict_oidc_manual_endpoint_origins(true)`.
  The compatibility default accepts valid HTTP(S) manual endpoints; strict mode
  validates registration, updates, and runtime `default_sso`/stored provider use.
- OIDC compatibility tests cover production-shaped manual endpoint matrices and
  provider-specific UserInfo/ID-token claims for Okta, Azure/Entra ID, and
  Google without making network calls to those IdPs.
- Provider IDs are limited to URL-safe slugs: ASCII letters, digits, `_`, and
  `-`, 1-128 bytes, starting and ending with an alphanumeric character.
- `GET /sso/get-provider` accepts `providerId` in the query string. JSON or
  form bodies remain accepted as a compatibility fallback.
- SAML unsigned test flows can run when policy allows unsigned assertions, but
  signed responses, signed logout messages, outbound signing, and encrypted
  assertions remain unsupported unless a future XML security backend is wired.
- SAML ACS rejects replayed assertions, corrupt AuthnRequest state, invalid
  timestamps, invalid destinations/recipients, mismatched `InResponseTo`, and
  assertion wrapping where `Assertion` or `EncryptedAssertion` is not a direct
  `Response` child.

## Example

```rust
use openauth::OpenAuth;
use openauth_sso::{sso, SsoOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugin(sso(SsoOptions::default()))
    .build()?;
```

Prefer OIDC when the IdP supports it. SAML signed/encrypted flows are not
published as supported in this beta release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
