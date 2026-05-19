# openauth-sso

Enterprise single sign-on support for OpenAuth-RS.

## Status

This package is in experimental beta. OIDC is the recommended path for new SSO
integrations. SAML endpoints are compatibility scaffolding and signed or
encrypted SAML messages currently fail closed until OpenAuth has an auditable XML
signature backend.

## What It Provides

`openauth-sso` exposes a server-side plugin for enterprise SSO. It adds SSO
provider storage, OIDC sign-in, SAML metadata/ACS scaffolding, domain
verification, account linking helpers, organization provisioning, and audit
hooks.

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
