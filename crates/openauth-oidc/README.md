# openauth-oidc

OIDC relying-party helpers for OpenAuth-RS.

## What It Is

`openauth-oidc` is for OpenAuth acting as a client of external OpenID Connect
identity providers such as Okta, Microsoft Entra ID, Auth0, Google Workspace,
or Keycloak.

It is not an OAuth/OIDC authorization server. If you want your OpenAuth
application to issue OAuth access tokens, ID tokens, discovery metadata, JWKS,
userinfo, or client credentials, enable `oauth-provider` on the `openauth` crate
or use `openauth-oauth-provider` directly.

The umbrella `openauth` crate does not re-export `openauth-oidc` at the root.
Enterprise SSO apps typically use `openauth::sso` (which re-exports
`openauth::sso::oidc`) or depend on `openauth-oidc` when building custom
relying-party flows.

## What It Provides

- OIDC provider configuration types.
- Discovery URL calculation and discovery document fetching with a
  caller-supplied `reqwest::Client` (so the relying party owns SSRF hardening,
  timeouts, and proxy configuration).
- Runtime discovery for partially stored provider configs.
- Endpoint origin validation for issuer, authorization, token, userinfo, JWKS,
  revocation, introspection, and end-session endpoints.
- Redirect URI construction for the enterprise SSO callback flow.

This crate intentionally has no SAML, XML signature, XML encryption, `samael`,
`openssl`, or `xmlsec` dependency surface.

## Quick Start

```rust
use openauth_oidc::{
    discover_oidc_config, oidc_redirect_uri, OidcConfig, PartialOidcDiscoveryConfig,
    OidcFlowOptions, SecretString,
};

// Discovery, JWKS, and token requests are issued with a caller-supplied
// `reqwest::Client`, so the relying party controls timeouts, proxies, and SSRF
// hardening. Production callers should pass an SSRF-guarded client (the
// `openauth-sso` plugin wires one in automatically and blocks private/internal
// IPs by default).
let http_client = reqwest::Client::new();

let discovered = discover_oidc_config(
    "https://idp.example.com",
    None,
    PartialOidcDiscoveryConfig {
        issuer: None,
        discovery_endpoint: None,
        authorization_endpoint: None,
        token_endpoint: None,
        user_info_endpoint: None,
        jwks_endpoint: None,
        revocation_endpoint: None,
        end_session_endpoint: None,
        introspection_endpoint: None,
        token_endpoint_authentication: None,
    },
    &http_client,
)
.await?;

let config = OidcConfig {
    issuer: discovered.issuer,
    pkce: true,
    client_id: "client-id".into(),
    client_secret: SecretString::new("client-secret"),
    discovery_endpoint: discovered.discovery_endpoint,
    authorization_endpoint: Some(discovered.authorization_endpoint),
    token_endpoint: Some(discovered.token_endpoint),
    user_info_endpoint: discovered.user_info_endpoint,
    jwks_endpoint: Some(discovered.jwks_endpoint),
    revocation_endpoint: discovered.revocation_endpoint,
    end_session_endpoint: discovered.end_session_endpoint,
    introspection_endpoint: discovered.introspection_endpoint,
    token_endpoint_authentication: Some(discovered.token_endpoint_authentication),
    scopes: Some(vec!["openid".into(), "email".into(), "profile".into()]),
    mapping: None,
    override_user_info: false,
};

struct Flow;
impl OidcFlowOptions for Flow {
    fn redirect_uri(&self) -> Option<&str> {
        None
    }
}

let redirect_uri = oidc_redirect_uri(
    "https://app.example.com/api/auth",
    "example-idp",
    &Flow,
);
# let _ = (config, redirect_uri);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Most applications do not wire this crate directly. Use `openauth-sso` when you
want the full enterprise SSO plugin with provider storage, login routes, domain
verification, and account linking.

## How It Fits

- `openauth-oidc`: low-level relying-party config, discovery, and redirect
  helpers.
- `openauth-sso`: OpenAuth plugin that uses this crate to consume external OIDC
  IdPs.
- `openauth-oauth-provider`: OpenAuth plugin that turns your app into an
  OAuth/OIDC provider.

## Status

Experimental beta. Discovery, validation, and configuration types are usable,
but public API details may change before stable release.

## Better Auth compatibility

Server-side OIDC relying-party helpers for external identity providers. Aligned
with Better Auth 1.6.9 where it matters; OpenAuth is not a line-by-line port.
For route-level parity, test counts, differences, and gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [SSO HTTP flow (`openauth-sso`)](../openauth-sso/README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
