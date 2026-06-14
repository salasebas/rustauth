# rustauth-oauth

OAuth client primitives for RustAuth.

## What It Is

`rustauth-oauth` contains low-level OAuth 2.0 and OIDC client-side helpers used
by RustAuth core and social provider definitions. Most applications consume it
indirectly through `rustauth` or `rustauth-social-providers`.

It does not turn your server into an OAuth provider. Use
`rustauth-oauth-provider` for authorization-server behavior.

## What It Provides

- [`OAuth2Client`](src/oauth2/client.rs) — configured provider client (authorization URL, code exchange, refresh, client credentials).
- Authorization URL construction (`create_authorization_url`, advanced).
- Token form builders (`create_authorization_code_request`, …) and `exchange_authorization_code` / `refresh_access_token_at` for discovery-based flows.
- OAuth token parsing (`get_oauth2_tokens`) and validation helpers.
- PKCE code challenge generation.
- JWKS fetching/cache helpers and JWS verification behind the `jose` feature.
- [`SocialOAuthProvider`](src/oauth2/provider.rs) trait used by `rustauth-social-providers` and RustAuth core.

## Quick Start

```rust
use rustauth_oauth::oauth2::{ClientSecret, OAuth2Client, ProviderOptions};

let client = OAuth2Client::builder(
    "github",
    ProviderOptions {
        client_id: Some("github-client-id".into()),
        client_secret: Some(ClientSecret::new("github-client-secret")?),
        ..ProviderOptions::default()
    },
)
.authorization_endpoint("https://github.com/login/oauth/authorize")?
.token_endpoint("https://github.com/login/oauth/access_token")?
.default_scope("read:user")
.default_scope("user:email")
.build()?;

let url = client
    .authorization_url("csrf-state", "https://app.example.com/api/auth/callback/github")?
    .code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    .build()?;

let tokens = client
    .exchange_code("authorization-code", "https://app.example.com/api/auth/callback/github")?
    .code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    .send()
    .await?;
# let _ = (url, tokens);
# Ok::<(), rustauth_oauth::oauth2::OAuthError>(())
```

Provider authors should build one `OAuth2Client` per provider. Application code should usually configure social providers through `rustauth-social-providers`.

## Feature Flags

`default = []`. Enable `jose` when you need JWKS fetch/cache and JWS verification
helpers (used by `rustauth-core` via `rustauth-oauth/jose` shim or `rustauth-oauth/jose`).

```toml
rustauth-oauth = { version = "0.2.0", default-features = false, features = ["jose"] }
```

## Security Notes

- Request builders validate required OAuth fields.
- Token parsing rejects malformed field types and invalid expiry values.
- `ClientSecret` redacts in `Debug` output.
- JWS verification rejects HMAC algorithms unless explicitly allowed.
- JWKS responses are cached and refetched when a token references an unknown `kid`.
- Provider errors avoid returning access, refresh, ID, or revocation tokens.

## Status

Experimental beta. Helper APIs, request builders, and validation behavior may
change before stable release.

## Better Auth compatibility

Server-side OAuth/OIDC client primitives only. Aligned with Better Auth 1.6.9
where it matters; RustAuth is not a line-by-line port. For route-level parity,
test counts, differences, and gaps, see [UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
