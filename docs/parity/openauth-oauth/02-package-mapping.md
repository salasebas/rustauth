# 02 — Package mapping: `openauth-oauth` ↔ `@better-auth/core/oauth2`

## 1:1 file map

| Upstream (`packages/core/src/oauth2/`) | OpenAuth (`crates/openauth-oauth/src/oauth2/`) | Notes |
| --- | --- | --- |
| `index.ts` | `mod.rs` + `lib.rs` | Public re-exports |
| `oauth-provider.ts` | `provider.rs` + `tokens.rs` | Types split: trait in `provider`, tokens in `tokens` |
| `create-authorization-url.ts` | `authorization_url.rs` | |
| `utils.ts` | `utils.rs` | PKCE + `get_oauth2_tokens` + `get_primary_client_id` |
| `validate-authorization-code.ts` | `validate_authorization_code.rs` + `token_validation.rs` | `validateToken` → `token_validation` module |
| `refresh-access-token.ts` | `refresh_access_token.rs` | |
| `client-credentials-token.ts` | `client_credentials_token.rs` | |
| `verify.ts` | `verify.rs` + `jwks.rs` + `introspection.rs` + `claims.rs` | Modular split in Rust |
| *(none)* | `request.rs` | Shared builders + `PROTECTED_OAUTH_PARAMS` |
| *(none)* | `http.rs` | HTTP client + redaction |
| *(none)* | `ssrf.rs` | SSRF guard (Rust-only) |
| *(none)* | `error.rs` | `OAuthError` enum |
| *(none)* | `types.rs` | URL newtypes (`AuthorizationEndpoint`, etc.) |

## Rust modules without a direct upstream equivalent

| Rust module | Purpose | Why it exists |
| --- | --- | --- |
| `request.rs` | Form builders, POST/Basic client auth, param denylist | Factoring + hardening |
| `http.rs` | `OAuthHttpClient`, body/header redaction | Replaces `betterFetch` with explicit control |
| `ssrf.rs` | DNS resolver + redirect policy + IP blocklist | Server-side security |
| `error.rs` | Typed errors | Rust idiom |
| `types.rs` | URL validation in constructors | Type safety |

## Public re-exports

### Upstream (`index.ts`)

```ts
createAuthorizationURL
authorizationCodeRequest, createAuthorizationCodeRequest, validateAuthorizationCode, validateToken
refreshAccessTokenRequest, createRefreshAccessTokenRequest, refreshAccessToken
clientCredentialsTokenRequest, createClientCredentialsTokenRequest, clientCredentialsToken
generateCodeChallenge, getOAuth2Tokens, getPrimaryClientId
getJwks, verifyAccessToken, verifyJwsAccessToken
OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions
```

### OpenAuth (`oauth2/mod.rs`)

| Upstream | OpenAuth | Feature |
| --- | --- | --- |
| `createAuthorizationURL` | `create_authorization_url`, `AuthorizationUrlRequest` | default |
| `validateAuthorizationCode` | `validate_authorization_code`, `validate_authorization_code_with_client` | default |
| `authorizationCodeRequest` | `authorization_code_request`, `create_authorization_code_request` | default |
| `refreshAccessToken` | `refresh_access_token`, `refresh_access_token_with_client` | default |
| `clientCredentialsToken` | `client_credentials_token`, `client_credentials_token_with_client` | default |
| `generateCodeChallenge` | `generate_code_challenge`, `validate_code_verifier` | default |
| `getOAuth2Tokens` | `get_oauth2_tokens` | default |
| `getPrimaryClientId` | `get_primary_client_id` | default |
| `validateToken` | `validate_token`, `validate_token_with_client` | `jose` |
| `getJwks` | `get_jwks`, `get_jwks_with_client`, `clear_jwks_cache` | `jose` |
| `verifyJwsAccessToken` | `verify_jws_access_token` (+ cache/client variants) | `jose` |
| `verifyAccessToken` | `verify_access_token`, `verify_access_token_with_client` | `jose` |
| `ProviderOptions` | `ProviderOptions` | No callbacks (`verifyIdToken`, `getUserInfo`, …) — live in `openauth-social-providers` |
| `ProviderOptions` | `ProviderOptions` | default |
| — | `OAuthHttpClient`, `OAuthHttpClientConfig` | default |
| — | `is_blocked_ip`, `ssrf_guarded_client_builder`, … | default |
| — | `OAuthError` | default |

## Features (`Cargo.toml`)

| Feature | Default | Effect |
| --- | --- | --- |
| `jose` | ✅ yes | Compiles `claims`, `introspection`, `jwks`, `token_validation`, `verify`; depends on `josekit` |
| *(without jose)* | — | OAuth flows, HTTP, PKCE, parsing, SSRF, traits; no JWT/JWKS |

`openauth-core` enables `openauth-oauth/jose` via its `oauth` feature.

## Dependencies

| Crate | Use |
| --- | --- |
| `base64` | PKCE (URL-safe), Basic auth (standard) |
| `josekit` (opt) | JWK/JWS/JWT |
| `reqwest` | HTTP (rustls); SSRF hook on builder |
| `serde` / `serde_json` | Token JSON, OIDC claims |
| `sha2` | PKCE SHA-256 |
| `thiserror` | `OAuthError` |
| `time` | `OffsetDateTime` expiry |
| `tokio` | `spawn_blocking` in DNS resolver |
| `url` | Query building, parsing |

Upstream uses `@better-fetch/fetch`, `@better-auth/utils`, `jose` (npm).

## Split with other OpenAuth crates

```text
@better-auth/core/oauth2          →  openauth-oauth
@better-auth/core/social-providers →  openauth-social-providers  (uses openauth-oauth)
better-auth/src/oauth2            →  openauth-core/src/auth/oauth/
better-auth/plugins/generic-oauth →  openauth-core routes + social providers
@better-auth/oauth-provider       →  openauth-oauth-provider
```

**Packaging decision:** upstream concentrates primitives + 35 providers in `@better-auth/core`. OpenAuth separates primitives (`openauth-oauth`) from IdP implementations (`openauth-social-providers`) to keep the base crate lean and free of per-provider deps.

## Upstream server layer (not in this crate)

| Upstream | OpenAuth |
| --- | --- |
| `better-auth/src/oauth2/state.ts` | `openauth-core/src/auth/oauth/state.rs` |
| `better-auth/src/oauth2/link-account.ts` | `openauth-core/src/auth/oauth/account_linking.rs` |
| `better-auth/src/oauth2/utils.ts` (encrypt) | `openauth-core/src/auth/oauth/tokens.rs` |
| `better-auth/src/oauth2/errors.ts` | `openauth-core/src/auth/oauth/errors.rs` |
| `better-auth/src/api/state/oauth.ts` | Request state in `openauth-core` context |

See [05-boundary-core.md](./05-boundary-core.md).

## Upstream deprecations reflected

| Upstream | OpenAuth |
| --- | --- |
| `createAuthorizationCodeRequest` (sync) | `create_authorization_code_request` — kept for compat; prefer async wrappers |
| `createRefreshAccessTokenRequest` | `create_refresh_access_token_request` |
| `createClientCredentialsTokenRequest` | `create_client_credentials_token_request` |

Rust exposes both styles (sync builder + `*_request` async), analogous to upstream.
