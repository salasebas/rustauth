# openauth-oauth

OAuth client primitives for OpenAuth-RS.

## Status

This package is in experimental beta. Request builders, provider contracts, and
token validation helpers may change before stable release.

## What It Provides

`openauth-oauth` contains OAuth 2.0/OIDC client-side server primitives used by
social providers and OpenAuth core: authorization URL creation, authorization
code exchange requests, refresh requests, token parsing, JWKS helpers, PKCE,
and provider contracts.

## Example

```rust
use openauth_oauth::oauth2::generate_code_challenge;

let challenge = generate_code_challenge("a-long-random-code-verifier")?;
```

Most applications will consume this indirectly through `openauth` or
`openauth-social-providers`; provider authors can use it directly.

## Security Notes

- HTTP helpers use a reusable `reqwest` client with a default timeout and parse
  OAuth error response bodies into typed errors.
- `OAuthHttpClientConfig` can be used to set a custom timeout and user-agent,
  or callers can inject a prebuilt `reqwest::Client`.
- Request builders keep standard OAuth fields from being overwritten by
  authorization-code `additional_params`.
- HTTP Basic client authentication uses standard Base64 encoding for RFC 7617
  compatibility.
- Request structs retain public fields and `Default` for low-level
  compatibility, but `create_*` helpers validate required fields even when a
  caller bypasses `try_new`.
- Token responses are parsed strictly: malformed field types, invalid expiry
  values, and responses without any OAuth token material return typed errors.
- JWS verification allows asymmetric algorithms by default. HMAC algorithms
  (`HS256`, `HS384`, `HS512`) require explicit opt-in with
  `TokenValidationOptions::allow_hmac_algorithms()`.
- JWKS responses are cached per URL and refetched when a token references an
  unknown `kid`; `OAuthJwksCacheConfig` can set TTL and cache size for explicit
  verification calls, and `clear_jwks_cache()` is available for rotation or
  tests.
- Required token claims validate both presence and basic type shape for JWT and
  introspection payloads.
- Default provider errors do not include access, refresh, ID, or revocation
  tokens.

## Upstream Compatibility Notes

This crate follows Better Auth's observable OAuth helper behavior where it
fits Rust server-side boundaries. Intentional differences:

- Authorization-code `additional_params` are additive by default; use
  `override_params` for explicit provider-specific overrides.
- Fluent request methods are provided as ergonomic wrappers around the public
  structs, while preserving the existing struct-based API.
- Remote JWKS verification rejects `HS*` algorithms unless explicitly enabled.
- Verification code is split by concern (`claims`, `token_validation`, `jwks`,
  `introspection`) while compatibility re-exports remain under `oauth2`.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
