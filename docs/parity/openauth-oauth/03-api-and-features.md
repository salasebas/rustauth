# 03 — API and features

Detailed capability matrix between `@better-auth/core/oauth2` and `openauth-oauth`.

## Authorization URL

| Capability | Upstream | OpenAuth | Parity |
| --- | --- | --- | --- |
| `response_type=code` (default) | ✅ | ✅ | ✅ |
| `client_id` (array → primary) | ✅ | ✅ `ClientId::Multiple` | ✅ |
| `redirect_uri` override in options | ✅ | ✅ | ✅ |
| `state` required | ✅ (implicit) | ✅ validated non-empty | ✅+ |
| PKCE S256 (`code_verifier` → challenge) | ✅ | ✅ + RFC 7636 validation | ✅+ |
| Scopes with `scopeJoiner` | ✅ | ✅ `scope_joiner` | ✅ |
| OIDC `claims` param JSON | ✅ | ✅ | ✅ |
| `prompt`, `access_type`, `display`, `login_hint`, `hd` | ✅ | ✅ | ✅ |
| `response_mode`, `duration` | ✅ | ✅ | ✅ |
| Free `additionalParams` | ✅ unrestricted | ⚠️ critical param denylist | ⚡ Rust stricter |
| Params on base endpoint overwritten | ✅ | ✅ standard params win | ✅ |
| `id` param (provider id) | Accepted, **unused** | Stored on request | ✅ |
| `options` as async factory | ✅ `AwaitableFunction` | ❌ sync `ProviderOptions` | ⚠️ see [04](./04-design-decisions.md) |
| URL validation in constructors | ❌ | ✅ `try_new` parses URLs | ⚡ extra Rust |

## Authorization code grant

| Capability | Upstream | OpenAuth | Parity |
| --- | --- | --- | --- |
| `grant_type=authorization_code` | ✅ | ✅ | ✅ |
| `code`, `redirect_uri` | ✅ | ✅ | ✅ |
| `code_verifier` (PKCE) | ✅ | ✅ | ✅ |
| `device_id` | ✅ | ✅ | ✅ |
| `resource` (string or RFC 8707 array) | ✅ | ✅ | ✅ |
| TikTok `client_key` | ✅ | ✅ | ✅ |
| Client auth: POST body | ✅ default | ✅ default | ✅ |
| Client auth: HTTP Basic (RFC 6749) | ✅ standard Base64 | ✅ standard Base64 | ✅ |
| `additionalParams` in body | ✅ if `!body.has(key)` | ⚠️ denylist | ⚡ Rust stricter |
| Custom headers merge | ✅ | ✅ `OAuthFormRequest` | ✅ |
| Public client (no secret) | ✅ | ✅ explicit matrix | ✅ |
| Token response → `OAuth2Tokens` | ✅ `getOAuth2Tokens` | ✅ `get_oauth2_tokens` | ✅ |
| Error handling | throw fetch error | `OAuthError` + redaction | ⚡ |

## Refresh token grant

| Capability | Upstream | OpenAuth | Parity |
| --- | --- | --- | --- |
| `grant_type=refresh_token` | ✅ | ✅ | ✅ |
| Basic auth with `:${secret}` when no client_id | ✅ | ✅ | ✅ |
| `extraParams` | ✅ can overwrite keys | ⚠️ denylist | ⚡ |
| Multi-value `resource` | ✅ | ✅ | ✅ |
| `expires_in` → access expiry | ✅ | ✅ | ✅ |
| `resource` on top-level refresh grant | ❌ `refreshAccessToken()` does not accept `resource` | ✅ `RefreshAccessTokenRequest.resource` | Rust superset |
| `raw` on refresh response | ❌ | ✅ via `get_oauth2_tokens` | |
| `scope` array on refresh response | ❌ string split only | ✅ | |
| `client_key` on refresh body | ❌ | ✅ | Rust extra |

## Client credentials grant

| Capability | Upstream | OpenAuth | Parity |
| --- | --- | --- | --- |
| `grant_type=client_credentials` | ✅ | ✅ | ✅ |
| Requires `client_id` + `client_secret` | ✅ | ✅ enforced | ✅ |
| Optional `scope` | ✅ | ✅ | ✅ |
| `resource` | ✅ | ✅ | ✅ |
| Basic auth encoding | **Base64URL** | **Standard Base64** | ⚠️ upstream quirk |
| Preserves `raw` on response | ❌ | ✅ | ⚡ Rust extra |

## Token parsing (`getOAuth2Tokens`)

| Response field | Upstream | OpenAuth |
| --- | --- | --- |
| `access_token` | ✅ | ✅ at least one of access/refresh/id |
| `refresh_token` | ✅ | ✅ |
| `id_token` | ✅ | ✅ |
| `token_type` | ✅ default Bearer | ✅ |
| `expires_in` → Date/OffsetDateTime | ✅ | ✅ max ~10 years |
| `refresh_token_expires_in` | ✅ (refresh path) | ✅ |
| `scope` string or array | ✅ | ✅ rejects invalid types |
| `raw` full JSON | ✅ | ✅ |

## PKCE (RFC 7636)

| Capability | Upstream | OpenAuth |
| --- | --- | --- |
| SHA-256 + base64url challenge | ✅ | ✅ |
| Verifier length 43–128 | ❌ not validated in core | ✅ `validate_code_verifier` |
| Unreserved charset | ❌ | ✅ |
| Rejection in authorize + token builders | ❌ | ✅ |

## JWT / JWKS (`validateToken`)

| Capability | Upstream | OpenAuth |
| --- | --- | --- |
| Remote JWKS fetch | ✅ `createRemoteJWKSet` (jose internal cache) | ✅ per-URL cache (`get_cached_jwks_for_token`) | ✅ |
| RS256, ES256, EdDSA | ✅ tested | ✅ tested |
| Audience / issuer validation | ✅ tested | ✅ tested |
| kid rotation / multi-key JWKS | ✅ tested | ✅ tested |
| HMAC algorithms | ✅ jose default | ❌ blocked unless `allow_hmac_algorithms` |
| Expired token rejection | implicit jose | ✅ explicit test |
| `validate_token_with_client` | ❌ | ✅ injectable HTTP |

## Access token verify (`verifyAccessToken`)

| Capability | Upstream | OpenAuth |
| --- | --- | --- |
| Local JWS via JWKS URL | ✅ | ✅ `verify_jws_access_token` |
| JWKS cache | Global singleton by kid | Per-URL TTL cache (5 min, 32 entries) |
| Refetch on unknown kid | ✅ | ✅ |
| `clear_jwks_cache` | ❌ | ✅ |
| Opaque token fallback | ✅ swallow JWSInvalid/TypeError | ✅ similar path |
| Remote introspection (RFC 7662) | ✅ | ✅ |
| `remoteVerify.force` skip local | ✅ | ✅ |
| `active: false` rejection | ✅ APIError | ✅ `OAuthError` |
| Scope validation post-verify | ✅ split on spaces | ✅ |
| `azp` → `client_id` mapping | ✅ | ✅ tested |
| Required claims type checks | partial | ✅ explicit tests |
| Upstream unit tests | **0** | **15+** |

## Introspection request shape

| POST field | Upstream | OpenAuth |
| --- | --- | --- |
| `client_id` | ✅ | ✅ |
| `client_secret` | ✅ | ✅ |
| `token` | ✅ | ✅ |
| `token_type_hint=access_token` | ✅ | ✅ |

## Provider traits

| Upstream `OAuthProvider` | OpenAuth |
| --- | --- |
| `createAuthorizationURL` | `SocialOAuthProvider::authorization_url` |
| `validateAuthorizationCode` | `exchange_authorization_code` |
| `getUserInfo` | `fetch_user_info` |
| `refreshAccessToken` (optional) | default Err; async override |
| `revokeToken` (optional) | default Err |
| `verifyIdToken` (optional) | default Err |
| Sign-up / linking flags on `ProviderOptions` | In core linking, not in oauth crate |

Rust separates metadata (`OAuthProviderMetadata`) from the async contract (`SocialOAuthProvider`).

## HTTP client

| Capability | Upstream (`betterFetch`) | OpenAuth |
| --- | --- | --- |
| POST form urlencoded | ✅ | ✅ |
| JSON accept | ✅ | ✅ |
| Error body redaction | ❌ | ✅ secrets/tokens stripped |
| SSRF private IP block | ❌ | ✅ default |
| Injectable client (tests/internal) | partial | ✅ `OAuthHttpClient::new(reqwest::Client)` |
| Timeout config | implicit fetch | ✅ `OAuthHttpClientConfig` |

## Data types

| Type | Upstream | OpenAuth | Differences |
| --- | --- | --- | --- |
| `OAuth2Tokens` | camelCase TS | snake_case Rust + serde aliases | Same JSON wire |
| `OAuth2UserInfo` | id: `string \| number` | id: `String` | Providers stringify numeric IDs |
| `ProviderOptions` | includes TS callbacks | struct without callbacks | Hooks in `openauth-social-providers` |
| Expiry | `Date` | `OffsetDateTime` | Idiomatic |

### Callbacks on `ProviderOptions` (upstream base struct only)

| Upstream field | OpenAuth |
| --- | --- |
| `verifyIdToken` | `SocialOAuthProvider::verify_id_token` / provider |
| `getUserInfo` | trait + types like `HuggingFaceGetUserInfo` |
| `refreshAccessToken` | trait override |
| `mapProfileToUser` | `map_profile_to_user` in per-provider options |

See [07-inventory.md](./07-inventory.md) § Types.

## Upstream features NOT ported in this crate

| Feature | Reason | Where |
| --- | --- | --- |
| `AwaitableFunction<ProviderOptions>` | Sync options sufficient in Rust; async on provider trait | [04](./04-design-decisions.md) |
| Browser redirect handling | Server-only | N/A |
| `betterFetch` retry/caching | reqwest defaults | — |
| OAuth proxy plugin | Not ported | — |
| Generic OAuth plugin routing | Plugin layer | `openauth-core` |
| 35 social provider configs | Separate crate | `openauth-social-providers` |

## Rust EXTRA features (not upstream core)

| Feature | Module |
| --- | --- |
| SSRF guard (DNS + redirects + literal IP) | `ssrf.rs` |
| Protected OAuth param denylist | `request.rs` |
| HTTP error redaction | `http.rs` |
| URL newtypes with validation | `types.rs` |
| PKCE verifier validation | `utils.rs` |
| Token response type validation | `tokens.rs` |
| Unified `OAuthError` enum | `error.rs` |
