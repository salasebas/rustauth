# Better Auth 1.6.9 Upstream Parity

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` from `reference/upstream-better-auth/VERSION.md` |
| Upstream package/path | `@better-auth/core` → `packages/core/src/oauth2/`; reexported by `better-auth` → `packages/better-auth/src/oauth2/index.ts` |
| Rust crate | `openauth-oauth` |
| Parity level | High for server-side OAuth/OIDC client primitives |
| Scope | Server-side OAuth client helpers: authorization URL, PKCE, OAuth token grants, token parsing, JWKS/JWS validation, access-token introspection, provider traits |

`openauth-oauth` tracks the low-level OAuth 2.0 and OIDC client helper surface
exported by Better Auth's `@better-auth/core/oauth2` package and reexported by
`better-auth/oauth2`. Better Auth's server runtime also has
`packages/better-auth/src/oauth2/` for OAuth state, account linking, and token
encryption; those map to `openauth-core`, not this helper crate.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| `@better-auth/core/oauth2` export surface | ✅ Implemented | Rust exports matching helper families from `src/oauth2/mod.rs`; names are snake_case and typed. |
| Authorization URL construction | ✅ Implemented | Supports response type, primary client ID, state, scopes, redirect URI, duration, display, login hint, prompt, hosted domain, access type, response mode, claims, and extension params. |
| PKCE challenge generation | ✅ Implemented | Generates S256 challenge and validates RFC 7636 verifier length/charset. |
| Authorization-code request helper | ✅ Implemented | Supports `authorizationCodeRequest`, `createAuthorizationCodeRequest`, `validateAuthorizationCode`, post/basic client auth, PKCE verifier, `device_id`, `client_key`, `resource`, headers, and extension params. |
| Refresh-token request helper | ✅ Implemented | Supports `refreshAccessTokenRequest`, `createRefreshAccessTokenRequest`, `refreshAccessToken`, post/basic client auth, `resource`, extra params, response parsing, and refresh-token expiry. |
| Client-credentials request helper | ✅ Implemented | Supports `clientCredentialsTokenRequest`, `createClientCredentialsTokenRequest`, `clientCredentialsToken`, post/basic client auth, scope, `resource`, and token response parsing. |
| OAuth token parsing | ✅ Implemented | Preserves raw provider fields and rejects malformed token shapes or invalid expiry values. |
| `validateToken` / JWKS verification | ✅ Implemented | Upstream defines `validateToken` in `validate-authorization-code.ts`; Rust maps it to `token_validation.rs` and covers RS256, ES256, EdDSA, kid lookup, empty/missing JWKS, audience, issuer, and temporal claims. |
| `verifyJwsAccessToken` / `verifyAccessToken` | ✅ Implemented | Supports local JWS verification, `VerifyAccessTokenRemote`, opaque-token fallback, remote introspection, active flag, audience, issuer, and scopes. |
| JWKS cache | 🎯 Hardened | Per-process cache is keyed by URL with TTL and entry limits; refetches on unknown `kid`. |
| Provider trait | 🎯 Intentional Rust API | Rust `SocialOAuthProvider` models the observable server-side provider callbacks as an idiomatic trait rather than cloning upstream's TypeScript callback object shape. |
| Rust module splits | 🎯 Hardened | `error.rs`, `request.rs`, `types.rs`, `http.rs`, `ssrf.rs`, and `claims.rs` split validation, transport, and claim handling beyond upstream's file layout. |
| OAuth state, account linking, token encryption | ➖ Out of scope | Upstream `packages/better-auth/src/oauth2/{state,link-account,utils,errors}.ts`; covered by `openauth-core/src/auth/oauth/`. |
| HTTP routes, cookies, sessions, schema | ➖ Out of scope | Server runtime behavior covered by `openauth-core`, provider crates, and integration crates. |
| Social provider implementations | ➖ Out of scope | Upstream `packages/core/src/social-providers/*` consumes these helpers; mapped by `openauth-social-providers`. |
| Social routes, generic-oauth, and SSO/SAML OAuth usage | ➖ Out of scope | Server route/plugin behavior belongs to `openauth-core`, `openauth-plugins`, `openauth-sso`, and provider crates. |
| OAuth/OIDC provider and oauth-proxy plugins | ➖ Out of scope | Authorization-server and proxy behavior belongs to sibling crates or is intentionally omitted here. |
| JWT plugin and telemetry OAuth mentions | ➖ Out of scope | First-party JWT issuance/verification and config detection are not OAuth client primitives. |
| Context/reexport wiring | ➖ Out of scope | `better-auth/src/index.ts`, `utils/index.ts`, `api/state/oauth.ts`, and context setup only reexport or carry OAuth state for server runtime crates. |

## Test Coverage

| Surface | OpenAuth tests | Upstream tests | Notes |
| --- | --- | --- | --- |
| Crate total | 63 by `rg '#\[(tokio::)?test\]' crates/openauth-oauth` | 15 Vitest cases in `packages/core/src/oauth2/*.test.ts` | Local `cargo nextest run -p openauth-oauth -- --list-tests` is unsupported by this nextest version; use the `rg` fallback for counts. Verify with `cargo nextest run -p openauth-oauth`. |
| Authorization URL and PKCE | Covered in `tests/oauth2_helpers.rs` | No direct upstream test file | Local tests cover upstream parameters plus protected param hardening and PKCE verifier validation. |
| Grant request builders | Covered in `tests/oauth2_helpers.rs` | No direct upstream test file | Covers code, refresh, client credentials, post/basic auth, `resource`, `device_id`, `client_key`, and extension params. |
| Token parsing and refresh expiry | Covered in `tests/oauth2_helpers.rs` | `refresh-access-token.test.ts` has 3 cases | Local tests include malformed responses and provider-specific raw fields. |
| JWKS/JWS token validation | Covered in `tests/oauth2_helpers.rs` and `claims.rs` | `validate-token.test.ts` has 12 cases | Local tests mirror algorithms, kid selection, audience, issuer, and failure paths, with extra temporal-claim checks. |
| Access-token introspection | Covered in `tests/oauth2_helpers.rs` | No dedicated upstream OAuth test cases | Local tests cover `verifyAccessToken`, `VerifyAccessTokenRemote`, opaque fallback, force remote, active flag, audience, issuer, scopes, and malformed responses. |
| SSRF and HTTP hardening | Covered in `tests/oauth2_helpers.rs` and `ssrf.rs` | No upstream equivalent | Rust-only hardening for outbound OAuth HTTP calls. |
| Provider trait defaults | Covered in `tests/oauth2_helpers.rs` and `module_structure.rs` | Upstream provider contract in `oauth-provider.ts` | Tests ensure default refresh/revoke errors do not leak tokens and overrides work. |
| Runtime OAuth state/account linking/token encryption | Not in this crate | `packages/better-auth/src/oauth2/*.test.ts` and `social.test.ts` | Mapped to `openauth-core/src/auth/oauth/`, not `openauth-oauth`. |
| Social providers | Not in this crate | Provider-specific upstream tests and `social.test.ts` | Mapped to `openauth-social-providers`; they consume this crate's helper contracts. |
| Social routes, generic-oauth, oauth-proxy, provider/OIDC server, SSO/SAML | Not in this crate | Covered by upstream route/plugin tests | Belongs to `openauth-core`, `openauth-plugins`, `openauth-oauth-provider`, `openauth-sso`, or OIDC/SAML crates. |

## Intentional Differences

| Topic | Better Auth | OpenAuth | Why |
| --- | --- | --- | --- |
| API shape | Object literals, async functions, thrown JS errors | Request structs, typed errors, validated constructors | Idiomatic Rust and fail-closed auth boundaries. |
| Extension params | Authorization `additionalParams` can replace existing query keys | Security-critical OAuth keys are ignored in extension maps | Prevents caller or provider extensions from hijacking state, redirect URI, PKCE, grants, or client auth. |
| HTTP client | Uses Better Fetch without built-in SSRF policy in this package | Default client blocks private/internal IPs, redirects, and literal-IP targets | OAuth endpoints may be attacker-influenced; server-side requests need SSRF guardrails. |
| JWT algorithms | Delegates algorithm policy to `jose` options | Rejects HMAC algorithms by default, explicit opt-in required | Avoids accepting symmetric algorithms for remote JWKS by accident. |
| Basic client auth | Plain Base64 for code/refresh grants, base64url for client credentials | Form-encodes credential components before Base64 | Matches RFC 6749 section 2.3.1 and preserves reserved/non-ASCII credentials safely. |
| JWKS cache | Single module-level JWKS value | URL-keyed cache with TTL, entry cap, clear helper, and unknown-kid refetch | Safer for multiple issuers and long-running services. |
| Provider interface | `OAuthProvider` callbacks for server-side provider implementations | Async `SocialOAuthProvider` trait with default unsupported errors | Rust trait object model and explicit unsupported behavior. |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| OA-OAUTH-1 | Route, cookie, account-linking, token persistence, OAuth state, and schema parity are out of scope for this crate | ➖ | Upstream `packages/better-auth/src/oauth2/*` and API route behavior belongs to `openauth-core/src/auth/oauth/`, provider crates, or integration crates; no `openauth-oauth` helper work remains for this item. |
| OA-OAUTH-2 | `SocialOAuthProvider` is not a one-to-one shape clone of upstream's provider callback object | 🎯 | Intentional Rust API shape. The trait preserves the server-observable callbacks (`createAuthorizationURL`, `validateAuthorizationCode`, `getUserInfo`, optional refresh/revoke/ID-token verification) with typed requests, explicit errors, and default unsupported behavior. |
| OA-OAUTH-3 | Live provider conformance matrix is not maintained in this helper crate | ➖ | Provider-specific quirks belong to `openauth-social-providers` and integration smoke tests. This crate covers shared OAuth wire contracts without requiring live third-party provider credentials. |
| OA-OAUTH-4 | JWKS cache is in-process only | 🎯 | Intentional hardening tradeoff: the cache is URL-keyed, TTL-bound, entry-limited, and clearable, but not shared across service instances. Multi-instance deployments refetch independently. |

## Hardening

- Request builders validate required OAuth fields instead of silently building
  malformed authorization or token requests.
- Protected OAuth parameters cannot be overwritten by extension maps.
- Token parsing rejects malformed field types, invalid expiry values, and
  malformed success JSON.
- HTTP and OAuth error formatting redacts access, refresh, ID, device, subject,
  assertion, and client-secret material.
- JWKS validation rejects HMAC algorithms unless explicitly allowed and refetches
  when a token references an unknown `kid`.
- Default outbound HTTP blocks private, loopback, link-local, metadata,
  documentation, carrier-grade NAT, benchmark, reserved, and unspecified IP
  targets.

## Upstream Lookup

1. Read the pin file at `reference/upstream-better-auth/VERSION.md`.
2. Inspect upstream source at
   `reference/upstream-src/1.6.9/repository/packages/core/src/oauth2/`.
3. Compare exports from upstream core `index.ts` with
   `crates/openauth-oauth/src/oauth2/mod.rs`.
4. Treat `packages/better-auth/src/oauth2/{state,link-account,utils,errors}.ts`
   as server runtime OAuth flow code for `openauth-core/src/auth/oauth/`, not
   this crate.
5. Treat `packages/core/src/social-providers/*` as provider implementations for
   `openauth-social-providers`; they are consumers of these primitives.
6. Treat `packages/better-auth/src/api/routes/{sign-in,callback,account}.ts`,
   `plugins/generic-oauth/*`, SSO/SAML OAuth usage, oauth-proxy, and
   provider/OIDC server packages as sibling crate surfaces.
7. Ignore first-party JWT plugin and telemetry detector matches when auditing
   this crate; they do not implement OAuth client primitives.
8. Treat `better-auth/src/index.ts`, `utils/index.ts`,
   `api/state/oauth.ts`, context setup, and `social.test.ts` as server runtime
   wiring/integration coverage for sibling crates.
9. Compare upstream tests in `validate-token.test.ts` and
   `refresh-access-token.test.ts` with Rust tests in
   `crates/openauth-oauth/tests/oauth2_helpers.rs`, `src/oauth2/claims.rs`, and
   `src/oauth2/ssrf.rs`.
10. Verify with `cargo nextest run -p openauth-oauth`.

| Upstream | Rust |
| --- | --- |
| `index.ts` exports | `src/oauth2/mod.rs` re-exports |
| `create-authorization-url.ts` | `src/oauth2/authorization_url.rs` |
| `validate-authorization-code.ts` | `src/oauth2/validate_authorization_code.rs` |
| `validate-authorization-code.ts` `validateToken` export | `src/oauth2/token_validation.rs` |
| `refresh-access-token.ts` | `src/oauth2/refresh_access_token.rs` |
| `client-credentials-token.ts` | `src/oauth2/client_credentials_token.rs` |
| `utils.ts` | `src/oauth2/utils.rs`, `src/oauth2/tokens.rs` |
| `verify.ts` `getJwks` / `verifyJwsAccessToken` / `verifyAccessToken` | `src/oauth2/verify.rs`, `src/oauth2/jwks.rs`, `src/oauth2/introspection.rs` |
| `oauth-provider.ts` | `src/oauth2/provider.rs`, `src/oauth2/tokens.rs` |
| `validate-token.test.ts` | `tests/oauth2_helpers.rs`, `src/oauth2/claims.rs` |
| `refresh-access-token.test.ts` | `tests/oauth2_helpers.rs` |
| No upstream equivalent | `src/oauth2/error.rs`, `src/oauth2/request.rs`, `src/oauth2/types.rs`, `src/oauth2/http.rs`, `src/oauth2/ssrf.rs`, `src/oauth2/claims.rs` |
| `packages/better-auth/src/oauth2/state.ts` | `openauth-core/src/auth/oauth/state.rs` |
| `packages/better-auth/src/oauth2/link-account.ts` | `openauth-core/src/auth/oauth/account_linking.rs` |
| `packages/better-auth/src/oauth2/utils.ts` | `openauth-core/src/auth/oauth/tokens.rs` |
| `packages/better-auth/src/oauth2/errors.ts` | `openauth-core/src/auth/oauth/errors.rs` |
| `packages/core/src/social-providers/*` | `openauth-social-providers/src/*` |
| `packages/better-auth/src/api/routes/{sign-in,callback,account}.ts` | `openauth-core` social/OAuth route layer |
| `packages/better-auth/src/plugins/generic-oauth/*` | `openauth-plugins` / provider crates |
| `packages/sso/src/routes/*` OAuth usage | `openauth-sso`, `openauth-oidc`, `openauth-saml` |
| `packages/oauth-provider/*`, `plugins/oidc-provider/*`, `plugins/oauth-proxy/*` | `openauth-oauth-provider`, SSO/OIDC/plugin crates |

Back to the crate README: [`README.md`](./README.md). See the workspace parity
index: [`docs/parity/README.md`](../../docs/parity/README.md).
