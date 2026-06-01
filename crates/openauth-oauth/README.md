# openauth-oauth

OAuth client primitives for OpenAuth-RS.

## What It Is

`openauth-oauth` contains low-level OAuth 2.0 and OIDC client-side helpers used
by OpenAuth core and social provider definitions. Most applications consume it
indirectly through `openauth` or `openauth-social-providers`.

It does not turn your server into an OAuth provider. Use
`openauth-oauth-provider` for authorization-server behavior.

## What It Provides

- Authorization URL construction.
- Authorization-code, refresh-token, and client-credentials request helpers.
- OAuth token parsing and validation helpers.
- PKCE code challenge generation.
- JWKS fetching/cache helpers and JWS verification behind the `jose` feature.
- Provider traits used by `openauth-social-providers` and OpenAuth core.

## Quick Start

```rust
use openauth_oauth::oauth2::{
    create_authorization_url, AuthorizationUrlRequest, ProviderOptions,
};

let request = AuthorizationUrlRequest::try_new(
    "github",
    ProviderOptions {
        client_id: Some("github-client-id".into()),
        client_secret: Some("github-client-secret".into()),
        ..ProviderOptions::default()
    },
    "https://github.com/login/oauth/authorize",
    "https://app.example.com/api/auth/callback/github",
    "csrf-state",
)?
.scope("read:user")
.scope("user:email")
.code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

let url = create_authorization_url(request)?;
# let _ = url;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Provider authors can use this crate directly. Application code should usually
configure social providers through `openauth-social-providers`.

## Security Notes

- Request builders validate required OAuth fields.
- Token parsing rejects malformed field types and invalid expiry values.
- JWS verification rejects HMAC algorithms unless explicitly allowed.
- JWKS responses are cached and refetched when a token references an unknown
  `kid`.
- Provider errors avoid returning access, refresh, ID, or revocation tokens.

## Status

Experimental beta. Helper APIs, request builders, and validation behavior may
change before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
