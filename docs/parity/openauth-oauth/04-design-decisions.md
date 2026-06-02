# 04 — Design decisions and divergences

Record of **intentional** differences, Rust/server-only limitations, and documented upstream quirks.

## Legend

| Label | Meaning |
| --- | --- |
| **OpenAuth decision** | Deliberate change with documented rationale |
| **Idiomatic Rust** | Same semantics, different shape for the language |
| **Server-only** | Upstream has browser/client piece; does not apply |
| **Upstream quirk** | BA behavior OpenAuth corrects or documents without replicating |
| **Known gap** | Real missing functionality (if any) |

---

## Security hardening

### Protected OAuth parameters

| | Upstream | OpenAuth |
| --- | --- | --- |
| Authorization URL `additionalParams` | Any key can override `state`, PKCE, etc. | **OpenAuth decision:** denylist in `PROTECTED_OAUTH_PARAMS` |
| Token body `additionalParams` / `extraParams` | Only avoids duplicates (`body.has`) | **OpenAuth decision:** critical keys never applicable via generic maps |

**Why:** on an auth server, provider-configured maps must not be able to clear CSRF state or replace already-validated grant types.

### SSRF on outbound HTTP

| | Upstream | OpenAuth |
| --- | --- | --- |
| IP/DNS validation on token/JWKS fetch | ❌ | ✅ **OpenAuth decision:** `ssrf.rs` |

**Why:** the server makes outbound requests to operator-configured URLs; blocking private/metadata ranges reduces SSRF risk.

**Escape hatch:** `OAuthHttpClient::new(custom_reqwest_client)` without guard (tests, internal IdP).

### HTTP error redaction

| | Upstream | OpenAuth |
| --- | --- | --- |
| Filter tokens in error bodies | ❌ | ✅ **OpenAuth decision:** `http.rs` |

**Why:** logs and propagated errors must not include `access_token`, `refresh_token`, `client_secret`.

### HMAC JWT algorithms

| | Upstream | OpenAuth |
| --- | --- | --- |
| HS256/384/512 in verify | jose default | ❌ unless `allow_hmac_algorithms` |

**OpenAuth decision:** avoid accidental symmetric verification with weak secrets; explicit opt-in.

---

## Architecture and packaging

### Split core vs social providers

| Upstream | OpenAuth | Label |
| --- | --- | --- |
| `@better-auth/core` = oauth2 + 35 social providers | `openauth-oauth` + `openauth-social-providers` | **OpenAuth decision** |

**Why:** stable primitives without dragging every IdP config; provider authors depend only on `openauth-oauth`.

### Split primitives vs server integration

| Upstream | OpenAuth | Label |
| --- | --- | --- |
| `core/oauth2` + `better-auth/src/oauth2` in same npm product | `openauth-oauth` + `openauth-core/auth/oauth` | **OpenAuth decision** |

**Why:** primitives crate usable standalone (tests, social providers, SSO) without the full router.

### OAuth authorization server in a separate crate

| Upstream `@better-auth/oauth-provider` | OpenAuth `openauth-oauth-provider` | Label |
| --- | --- | --- |
| Separate npm package | Separate crate | Aligned |

Do not confuse with `openauth-oauth` (client). See [oauth-provider parity](../openauth-oauth-provider/README.md).

---

## Idiomatic Rust

### Error model

| Upstream | OpenAuth |
| --- | --- |
| throw fetch errors, jose throws, sparse `APIError` | `Result<T, OAuthError>` enum (`thiserror`) |

**Label:** Idiomatic Rust. Same observability for callers; better composition with `?`.

### Async provider trait

| Upstream `OAuthProvider` | OpenAuth `SocialOAuthProvider` |
| --- | --- |
| Sync methods; HTTP async internally | Native async trait (`async fn`) |

**Label:** Idiomatic Rust / async ecosystem.

### URL newtypes

| Upstream | OpenAuth |
| --- | --- |
| `string` endpoints | `AuthorizationEndpoint`, `TokenEndpoint`, `RedirectUri` |

**Label:** Idiomatic Rust. Validation in constructor.

### Expiry types

| Upstream `Date` | OpenAuth `OffsetDateTime` |
| --- | --- |

No wire-format impact; JSON serialization unchanged.

---

## Server-only (not ported)

| Upstream | Reason |
| --- | --- |
| `better-auth/client` OAuth helpers | Browser / nanostores |
| `@better-auth/oauth-provider/client` | Injects `oauth_query` into browser fetch |
| `@better-auth/oauth-provider/resource-client` | TS resource-server SDK |
| `oauth-proxy` plugin | Redirect proxy for preview hosts — not prioritized server-only |
| `AwaitableFunction` for lazy client config in TS runtime | Rust resolves options before call; async on provider trait |

---

## Documented upstream quirks

### Basic auth encoding (all grants)

| | Upstream auth-code / refresh | Upstream client_credentials | OpenAuth (all) |
| --- | --- | --- | --- |
| Encoding | Standard Base64, no form-encode | **Base64URL** | Standard Base64 + **RFC 6749 §2.3.1 form-encode** per component |

Rust test: `basic_authentication_form_encodes_reserved_and_non_ascii_credentials`.

### Global JWKS cache

Upstream `verify.ts`:

```ts
let jwks: JSONWebKeySet | undefined; // singleton process-wide
```

OpenAuth: cache keyed by JWKS URL, TTL 5 min, max 32 entries.

**Label:** OpenAuth decision (improvement). Upstream can mix keys from different issuers in long-lived multi-tenant processes.

### `createAuthorizationURL` param `id` unused

Upstream accepts `id` but does not use it in the URL.

OpenAuth stores it on `AuthorizationUrlRequest.id` for provider logging/tracing; same observable behavior.

### `clientCredentialsToken` without `raw` field

Upstream does not assign `raw` on client credentials response.

OpenAuth preserves `raw` via `get_oauth2_tokens` — **OpenAuth decision** (consistency).

### `validate_token` and JWKS cache

| Upstream `validateToken` | OpenAuth `validate_token_with_client` |
| --- | --- |
| `createRemoteJWKSet` — jose caches JWKS | `get_cached_jwks_for_token` (same cache as `verify_jws_access_token`) |

**Label:** Performance parity (2026-06-01). Test: `validate_token_reuses_cached_jwks_for_known_kid`.

### Upstream `refreshAccessToken()` without `resource` parameter

`refreshAccessTokenRequest` accepts `resource`, but the high-level `refreshAccessToken()` in `refresh-access-token.ts` **does not expose it** (lines 98–109).

OpenAuth `refresh_access_token` uses `RefreshAccessTokenRequest.resource`.

**Label:** Rust superset / upstream omission.

---

## Known gaps (minor)

| Gap | Severity | Notes |
| --- | --- | --- |
| `options` async factory (`AwaitableFunction`) | Low | Resolved in async provider layer |
| `verify_access_token` not wired in monorepo | Doc | MCP/AS uses `openauth-oauth-provider` — [08](./08-findings-pass2.md) §3 |
| 1:1 `APIError` message parity | Low | `OAuthError` enum |
| oauth-proxy plugin | N/A | Not planned |
| Upstream tests for `verifyAccessToken` | N/A upstream | Rust already covers |

No critical functional gaps in authorization code, refresh, client_credentials, or PKCE for standard server-side use.

---

## Divergence summary matrix

| Topic | Type | Recommended action |
| --- | --- | --- |
| Protected params | OpenAuth decision | Keep; document in provider configs |
| SSRF guard | OpenAuth decision | Keep default; document escape hatch |
| JWKS cache per URL | OpenAuth decision | Keep |
| client_credentials Basic auth | Upstream quirk | Documented; use POST auth if IdP fails |
| HMAC JWT blocked | OpenAuth decision | Explicit opt-in |
| Async provider trait | Idiomatic Rust | N/A |
| OAuth proxy plugin | Server-only skip | Do not port unless required |
| Encrypt/link/state | Outside crate | See [05-boundary-core.md](./05-boundary-core.md) |
