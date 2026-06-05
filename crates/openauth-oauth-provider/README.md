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

```rust
use openauth::OpenAuth;
use openauth_oauth_provider::{oauth_provider, OAuthProviderOptions};

let provider = oauth_provider(OAuthProviderOptions {
    login_page: "/login".to_owned(),
    consent_page: "/oauth/consent".to_owned(),
    scopes: vec!["openid".into(), "profile".into(), "email".into()],
    ..OAuthProviderOptions::default()
})?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://auth.example.com/api/auth")
    .plugin(provider.into_auth_plugin())
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run your adapter migration flow after enabling the plugin so the OAuth client,
consent, access-token, and refresh-token tables exist.

## How It Fits

- `openauth-oauth-provider`: provider-side OAuth/OIDC server behavior.
- `openauth-oauth`: low-level OAuth client primitives and token helpers.
- `openauth-oidc`: relying-party helpers for external IdPs.
- `openauth-sso`: enterprise login plugin that consumes external OIDC/SAML IdPs.

## Upstream parity (Better Auth 1.6.9)

Reference: `@better-auth/oauth-provider@1.6.9` → `packages/oauth-provider/`.
Parity pin:
[`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).

**Scope:** OAuth 2.1 / OIDC **authorization server** — authorize, token,
introspection, revocation, metadata, userinfo, DCR, and client/consent management.
OAuth **client** primitives are in `openauth-oauth`; JWT/JWKS merge via
`openauth-plugins::jwt`.

| Area | Parity | Notes |
| --- | --- | --- |
| OAuth/OIDC endpoints | High | 25 upstream routes; Rust adds `GET /oauth2/continue` |
| Grants (code, refresh, M2M) | High | PKCE, rotation, replay, `resource` → JWT |
| Introspection / revocation | High | RFC 7662/7009; client auth required |
| Metadata / discovery | High | OIDC metadata when `openid`; `oauth_provider_with_jwt()` |
| DCR + client/consent CRUD | High | Admin + session; `client_privileges` |
| MCP helpers | Partial | `src/mcp.rs` without routes; full MCP in `openauth-plugins::mcp` |
| Browser `client.ts` / resource-client | N/A | Server-only |

June 2026 closeout added UserInfo `given_name`/`family_name`, `no-store` on
token/DCR, SPA JSON redirects, `prompt=none` handling, and advertised JWKS
metadata. **96** Rust tests vs **261** upstream `it`.

```bash
cargo nextest run -p openauth-oauth-provider
```

### Upstream lookup

1. Pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Provider package: `reference/upstream-src/<version>/repository/packages/oauth-provider/`.
3. Map routes and handlers in upstream `src/` to `crates/openauth-oauth-provider/src/`.
4. Test maintainer matrix: [`tests/upstream_mapping.md`](tests/upstream_mapping.md).
5. Verify: `cargo nextest run -p openauth-oauth-provider`.

## Status

Experimental beta. The provider is implemented server-side and has focused
coverage, but endpoint behavior, token storage, grant support, and option
validation can still evolve before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
