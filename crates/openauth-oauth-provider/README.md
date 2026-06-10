# openauth-oauth-provider

OAuth 2.1 and OpenID Connect provider plugin for OpenAuth-RS.

## What It Is

Use this crate when your OpenAuth server should become the authorization server:
register clients, authorize users, issue tokens, expose metadata, and serve
userinfo.

This is the provider-side crate. For consuming external IdPs, use
`openauth-oidc` through `openauth-sso`.

## What It Provides

- Authorization, token, introspection, metadata, logout, userinfo, client, and
  consent endpoints.
- OAuth client, consent, access-token, and refresh-token schema contributions.
- Authorization code, refresh token, and client credentials grant support.
- Configurable login and consent page redirects.
- Optional JWT/JWKS integration through `openauth-plugins::jwt`.
- Hooks for client privileges, token claims, client references, token hashing,
  refresh-token formatting, and custom token/userinfo fields.

## Quick Start

Enable the `oauth-provider` feature on the umbrella `openauth` crate (or depend
on `openauth-oauth-provider` directly):

```toml
[dependencies]
openauth = { version = "0.1.1", features = ["oauth-provider", "plugins"] }
```

```rust
use openauth::OpenAuth;
use openauth::oauth_provider::{oauth_provider, OAuthProviderOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://auth.example.com/api/auth")
    .plugin(oauth_provider(OAuthProviderOptions {
        login_page: "/login".to_owned(),
        consent_page: "/oauth/consent".to_owned(),
        scopes: vec!["openid".into(), "profile".into(), "email".into()],
        ..OAuthProviderOptions::default()
    })?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run your adapter migration flow after enabling the plugin so the OAuth client,
consent, access-token, and refresh-token tables exist.

## MCP (Model Context Protocol)

MCP is exposed as a profile of the OAuth provider rather than a separate
authorization server. Enable protected-resource metadata with `McpOptions`:

```rust
use openauth::oauth_provider::{oauth_provider, McpOptions, OAuthProviderOptions};

let _plugin = oauth_provider(OAuthProviderOptions {
    login_page: "/login".to_owned(),
    consent_page: "/oauth/consent".to_owned(),
    mcp: Some(McpOptions {
        resource: Some("https://api.example.com/mcp".to_owned()),
        ..McpOptions::default()
    }),
    ..OAuthProviderOptions::default()
})?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

MCP clients discover authorization metadata via
`/.well-known/oauth-authorization-server` and protected-resource metadata via
`/.well-known/oauth-protected-resource`. Authorization, token, registration,
userinfo, introspection, and revocation traffic uses the standard `/oauth2/*`
routes.

Framework-neutral resource-server helpers are available behind the
`mcp-client` feature.

## How It Fits

- `openauth-oauth-provider`: provider-side OAuth/OIDC server behavior.
- `openauth-oauth`: low-level OAuth client primitives and token helpers.
- `openauth-oidc`: relying-party helpers for external IdPs.
- `openauth-sso`: enterprise login plugin that consumes external OIDC/SAML IdPs.

## Status

Experimental beta. The provider is implemented server-side and has focused
coverage, but endpoint behavior, token storage, grant support, and option
validation can still evolve before stable release.

## Better Auth compatibility

Server-side OAuth provider behavior is aligned with Better Auth 1.6.9 where it
matters; OpenAuth is not a line-by-line port. For route-level parity, test
counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
