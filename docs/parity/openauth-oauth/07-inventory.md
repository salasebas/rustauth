# 07 — Exhaustive inventory (source-code audit)

Audit **2026-06-01** reading every file in:

- Upstream: `reference/upstream-src/1.6.9/repository/packages/core/src/oauth2/` (10 files, 1398 LOC)
- Rust: `crates/openauth-oauth/src/oauth2/` (18 modules + tests)

READMEs were not used as primary sources.

---

## Upstream: exact exports (`index.ts`)

| Export | File | Approx. lines |
| --- | --- | --- |
| `createAuthorizationURL` | `create-authorization-url.ts` | 89 |
| `generateCodeChallenge`, `getOAuth2Tokens`, `getPrimaryClientId` | `utils.ts` | 51 |
| `authorizationCodeRequest`, `createAuthorizationCodeRequest`, `validateAuthorizationCode`, `validateToken` | `validate-authorization-code.ts` | 180 |
| `refreshAccessTokenRequest`, `createRefreshAccessTokenRequest`, `refreshAccessToken` | `refresh-access-token.ts` | 157 |
| `clientCredentialsTokenRequest`, `createClientCredentialsTokenRequest`, `clientCredentialsToken` | `client-credentials-token.ts` | 126 |
| `getJwks`, `verifyJwsAccessToken`, `verifyAccessToken` | `verify.ts` | 221 |
| `OAuth2Tokens`, `OAuth2UserInfo`, `OAuthProvider`, `ProviderOptions` | `oauth-provider.ts` | 222 |

**Types exported without a function:** `VerifyAccessTokenRemote` is exported implicitly via `verify.ts` (interface, not in `index.ts`).

---

## Rust: exact exports (`oauth2/mod.rs`)

| Category | Symbols |
| --- | --- |
| Authorize | `create_authorization_url`, `AuthorizationUrlRequest` |
| Code grant | `AuthorizationCodeRequest`, `ClientTokenRequest`, `create_authorization_code_request`, `authorization_code_request`, `validate_authorization_code`, `validate_authorization_code_with_client` |
| Refresh | `RefreshAccessTokenRequest`, `create_refresh_access_token_request`, `refresh_access_token_request`, `refresh_access_token`, `refresh_access_token_with_client` |
| Client creds | `ClientCredentialsTokenRequest`, `ClientCredentialsGrant`, `create_client_credentials_token_request`, `client_credentials_token_request`, `client_credentials_token`, `client_credentials_token_with_client` |
| Tokens/types | `ClientId`, `ProviderOptions`, `OAuth2Tokens`, `OAuth2UserInfo`, `get_oauth2_tokens`, `get_primary_client_id` |
| PKCE | `generate_code_challenge`, `validate_code_verifier` |
| HTTP | `OAuthHttpClient`, `OAuthHttpClientConfig`, `ClientAuthentication`, `OAuthFormRequest`, `post_form`, `post_form_with_client`, `apply_client_authentication` |
| SSRF | `is_blocked_ip`, `url_host_is_blocked_ip`, `ssrf_guarded_client_builder`, `SsrfGuardResolver` |
| Provider | `OAuthProviderMetadata`, `OAuthProviderContract`, `SocialOAuthProvider`, `SocialAuthorizationUrlRequest`, `SocialAuthorizationCodeRequest`, `SocialIdTokenRequest` |
| JOSE (`jose`) | `TokenValidationOptions`, `TokenValidationResult`, `validate_token`, `validate_token_with_client`, `verify_jws_with_jwks`, `get_jwks`, `get_jwks_with_client`, `clear_jwks_cache`, `verify_jws_access_token` (+ cache/client variants), `verify_access_token`, `verify_access_token_with_client`, `VerifyAccessTokenOptions`, `VerifyAccessTokenRemote`, `OAuthJwksCacheConfig` |
| URL newtypes | `AuthorizationEndpoint`, `TokenEndpoint`, `RedirectUri`, `ClientSecret` |
| Errors | `OAuthError` |

---

## Function-by-function matrix

### `createAuthorizationURL` ↔ `create_authorization_url`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| `options` async factory | ✅ `AwaitableFunction` | ❌ sync | See [04](./04-design-decisions.md) |
| Validates `client_id` present | ❌ | ✅ `try_new` | Rust stricter |
| Validates `state` non-empty | ❌ | ✅ | Rust stricter |
| Validates parseable URLs | ❌ | ✅ | Rust stricter |
| `options.authorizationEndpoint` override | ✅ | ✅ | |
| `options.redirectURI` override | ✅ | ✅ | |
| PKCE S256 | ✅ async `generateCodeChallenge` | ✅ sync + validates verifier | |
| OIDC `claims` JSON | ✅ | ✅ | |
| `duration`, `display`, `login_hint`, `hd`, `access_type`, `response_mode`, `prompt` | ✅ function params | ✅ `AuthorizationUrlRequest` fields | Caller must copy `options.prompt` (same as upstream github) |
| Unrestricted `additionalParams` | ✅ | ❌ denylist | Rust stricter |
| Param `id` | accepted, unused | stored | |
| `scopeJoiner` | ✅ | ✅ `scope_joiner` | |

### `createAuthorizationCodeRequest` ↔ `create_authorization_code_request`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| `grant_type=authorization_code` | ✅ | ✅ | |
| `code_verifier`, `device_id`, `client_key` | ✅ | ✅ | |
| `resource` string/array | ✅ append | ✅ `Vec` → append | |
| Basic auth RFC 7617 standard Base64 | ✅ no form-encode | ✅ **RFC 6749 §2.3.1 form-encode** + Base64 | Rust more correct for `:`, non-ASCII |
| POST auth public client | ✅ secret optional | ✅ | |
| `additionalParams` if `!body.has` | ✅ | ⚠️ denylist | |
| `additional_params` (no overwrite) | ✅ | ✅ | generic-oauth aligned 2026-06-01 |
| Custom headers merge | ✅ | ✅ | |
| Validates code/redirect/PKCE | ❌ | ✅ | |

### `validateAuthorizationCode` ↔ `validate_authorization_code`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| POST token endpoint | ✅ `betterFetch` | ✅ `OAuthHttpClient` | |
| Error handling | throw fetch error | `OAuthError` + redaction | |
| Response mapping | `getOAuth2Tokens` | `get_oauth2_tokens` + type validation | |

### `refreshAccessToken` ↔ `refresh_access_token`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| Basic without client_id | ✅ `:${secret}` | ✅ via `apply_client_authentication` | |
| `extraParams` can overwrite | ✅ `body.set` | ⚠️ denylist + skip existing | |
| **`resource` on top-level `refreshAccessToken()`** | ❌ **not exposed** (only in `refreshAccessTokenRequest`) | ✅ `RefreshAccessTokenRequest.resource` | **Rust superset** |
| Response mapping | manual, no `raw` | `get_oauth2_tokens` with `raw` | |
| `scope` array on response | ❌ string split only | ✅ string or array | Rust more robust |
| `client_key` on refresh body | ❌ | ✅ if present in options | Rust extra |

### `clientCredentialsToken` ↔ `client_credentials_token`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| `scope` required in TS signature | ✅ `scope: string` | ⚠️ `Option<String>` | Rust more flexible |
| Basic auth | **Base64URL** | **Standard Base64 + form-encode** | Upstream quirk |
| POST always id+secret | ✅ | ✅ enforced `try_new` | |
| `raw` on response | ❌ | ✅ | |

### `getOAuth2Tokens` ↔ `get_oauth2_tokens`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| At least one token required | ❌ | ✅ | Rust validates |
| Strict string types | ❌ | ✅ | |
| `expires_in` bounds | ❌ | ✅ max ~10 years | |
| `scope` array | ✅ | ✅ | |
| `raw` preserved | ✅ | ✅ | |

### `validateToken` ↔ `validate_token`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| JWKS fetch | `createRemoteJWKSet` (jose cache) | `get_cached_jwks_for_token` (validate + verify) | ✅ |
| Algorithms | jose default (incl. HS*) | RS/ES/EdDSA; HS opt-in | Rust stricter |
| aud/iss options | ✅ | ✅ + leeway, require_* flags | Rust superset |
| Return type | jose verify result | `TokenValidationResult` | |
| Injectable HTTP | ❌ | ✅ `_with_client` | |

### `getJwks` ↔ `get_jwks`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| Requires token with `kid` | ✅ | ❌ unconditional fetch | Different API |
| Global cache by kid | ✅ module singleton | ✅ per-URL cache on verify path | Different design |
| Custom `jwksFetch` fn | ✅ | ❌ URL string only | Upstream more flexible |

### `verifyJwsAccessToken` ↔ `verify_jws_access_token`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| aud+iss required in opts | ✅ | ✅ | |
| `azp` → `client_id` | ✅ | ✅ | |
| Cache | global kid-based | URL-keyed TTL + max entries + `clear_jwks_cache` | |

### `verifyAccessToken` ↔ `verify_access_token`

| Behavior | Upstream | Rust | Δ |
| --- | --- | --- | --- |
| Opaque fallback local | swallow `JWSInvalid`/`TypeError` | skip local if remote + !parseable JWS | Equivalent with remote |
| Expired JWS + remote | no fallback | no fallback | ✅ aligned (Rust test) |
| Introspection POST | ✅ | ✅ | |
| Introspection claim verify | `UnsecuredJWT.decode` | direct JSON validation | Similar semantics |
| Introspection HTTP error | log + throw INTERNAL | throw HTTP error | |
| Scope check post-verify | ✅ | ✅ | |
| `force` remote | ✅ | ✅ | |
| Upstream tests | **0** | **10+** | |

---

## Types: `ProviderOptions` / `OAuthProvider`

### `ProviderOptions` fields

| Upstream field | Rust `ProviderOptions` | Notes |
| --- | --- | --- |
| `clientId` | `client_id: Option<ClientId>` | Typed |
| `clientSecret` | ✅ | |
| `scope` | ✅ | |
| `disableDefaultScope` | ✅ | Used in social-providers |
| `redirectURI` | ✅ | |
| `authorizationEndpoint` | ✅ | |
| `clientKey` | ✅ | |
| `disableIdTokenSignIn` | ✅ | |
| **`verifyIdToken`** | ❌ | On provider structs (`openauth-social-providers`) |
| **`getUserInfo`** | ❌ | Same |
| **`refreshAccessToken`** | ❌ | Same (`SocialOAuthProvider` trait) |
| **`mapProfileToUser`** | ❌ | Same (`map_profile_to_user` per provider) |
| `disableImplicitSignUp` | ✅ | |
| `disableSignUp` | ✅ | |
| `prompt` | ✅ | Caller copies to `AuthorizationUrlRequest` |
| `responseMode` | ✅ `response_mode` | Same |
| `overrideUserInfoOnSignIn` | ✅ | |

**Decision:** TS callbacks on `ProviderOptions` → methods/fields on Rust provider structs, not on the oauth crate base struct.

### `OAuthProvider` ↔ `SocialOAuthProvider`

| Upstream `OAuthProvider` | Rust | Δ |
| --- | --- | --- |
| `createAuthorizationURL` sync | sync on trait | |
| `validateAuthorizationCode` → `null` on error | `Result<OAuth2Tokens, OAuthError>` | Idiomatic Rust |
| `getUserInfo` → `null` | `Option<OAuth2UserInfo>` async | |
| `refreshAccessToken` optional | default Err; override | |
| `revokeToken` optional | default Err | |
| `verifyIdToken(nonce?)` | `SocialIdTokenRequest` with nonce | |
| Generic profile type `T` | `OAuth2UserInfo` + JSON in social-providers | |
| `disableImplicitSignUp` / `disableSignUp` on provider | on `ProviderOptions` | |

### `OAuth2UserInfo`

| Field | Upstream | Rust |
| --- | --- | --- |
| `id` | `string \| number` | `String` (providers stringify) |
| `email` | `string \| null` | `Option<String>` |
| rest | ✅ | ✅ |

---

## Tests: verified count (`cargo nextest run -p openauth-oauth`)

| Location | Tests |
| --- | --- |
| `tests/oauth2_helpers.rs` | 48 |
| `tests/module_structure.rs` | 2 |
| `src/oauth2/ssrf.rs` (unit) | 7 |
| **Total** | **57** |

### Upstream `core/oauth2` tests

| File | `it(` |
| --- | --- |
| `refresh-access-token.test.ts` | 3 |
| `validate-token.test.ts` | 12 |
| **Total** | **15** |

### Upstream tests using `core/oauth2` outside `core/oauth2/`

| File | Use |
| --- | --- |
| `better-auth/src/social.test.ts` | `refreshAccessToken` in E2E helper (not unit) |
| `oauth-provider/src/token.test.ts` | `createAuthorizationURL`, `createAuthorizationCodeRequest`, `createRefreshAccessTokenRequest`, `createClientCredentialsTokenRequest` as RP |
| `oauth-provider/src/logout.test.ts` | `createAuthorizationURL`, `createAuthorizationCodeRequest` |

These do **not** count as isolated `core/oauth2` tests; they are AS/RP integration.

---

## Real gaps identified (post-audit)

| # | Gap | Severity | Action |
| --- | --- | --- | --- |
| 1 | ~~`validate_token` without JWKS cache~~ | — | **Closed** 2026-06-01 |
| 2 | `get_jwks` without custom fetch fn | Low | Use `get_jwks_with_client` + inject |
| 3 | `AwaitableFunction<ProviderOptions>` | Low | Resolved in async provider layer |
| 4 | Upstream client_credentials Basic Base64URL | Doc | Keep RFC 7617; documented |
| 5 | Callbacks on `ProviderOptions` | N/A | Moved to `openauth-social-providers` |
| 6 | Upstream `refreshAccessToken()` without `resource` | N/A upstream bug/omission | Rust already supports |

**No critical functional gaps** in grants, PKCE, token parsing, JWT verify, or introspection for documented server-side use.

---

## Upstream files without unit tests

| File | Upstream coverage | Rust coverage |
| --- | --- | --- |
| `create-authorization-url.ts` | ❌ | ✅ 4 tests |
| `validate-authorization-code.ts` | ❌ | ✅ 10+ tests |
| `client-credentials-token.ts` | ❌ indirect AS | ✅ 2+ tests |
| `verify.ts` | ❌ | ✅ 15+ tests |
| `utils.ts` (PKCE) | ❌ | ✅ 3 tests |
| `oauth-provider.ts` | ❌ | trait tests 3 |
