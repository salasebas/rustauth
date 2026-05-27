# oauth Upstream Parity Audit Plan

> **For agentic workers:** This plan records the server-side upstream parity audit for `crates/openauth-oauth`. It is intentionally scoped to the OAuth 2.0 helper crate, not the separate OAuth/OIDC provider plugins.

**Goal:** Bring the OpenAuth `oauth` package closer to Better Auth server-side OAuth helper behavior where that improves compatibility, correctness, or security.

**Architecture:** `crates/openauth-oauth` is a Rust helper crate for OAuth/OIDC client-side server flows: authorization URL creation, token request construction, token parsing, JWKS verification, introspection, and provider traits. It maps primarily to Better Auth core OAuth helpers under `packages/core/src/oauth2`, with selected package-level state/link-account utilities noted as out of crate scope because OpenAuth handles app state and account linking elsewhere.

**Tech Stack:** Rust, `reqwest`, `url`, `serde_json`, optional `josekit`, `time`; upstream reference is Better Auth 1.6.9 TypeScript.

---

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/create-authorization-url.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/validate-authorization-code.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/refresh-access-token.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/refresh-access-token.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/client-credentials-token.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/oauth-provider.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/utils.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/verify.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/validate-token.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/core/src/oauth2/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/oauth2/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/oauth2/utils.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/oauth2/utils.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/oauth2/state.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/oauth2/link-account.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/oauth2/link-account.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/state/oauth.ts`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/api/routes/callback.ts`
- `upstream/better-auth/1.6.9/package/dist/oauth2/index.d.mts`
- `upstream/better-auth/1.6.9/package/dist/oauth2/utils.d.mts`
- `upstream/better-auth/1.6.9/package/dist/oauth2/state.d.mts`

## OpenAuth Files Inspected

- `crates/openauth-oauth/Cargo.toml`
- `crates/openauth-oauth/src/lib.rs`
- `crates/openauth-oauth/src/oauth2/mod.rs`
- `crates/openauth-oauth/src/oauth2/authorization_url.rs`
- `crates/openauth-oauth/src/oauth2/claims.rs`
- `crates/openauth-oauth/src/oauth2/client_credentials_token.rs`
- `crates/openauth-oauth/src/oauth2/error.rs`
- `crates/openauth-oauth/src/oauth2/http.rs`
- `crates/openauth-oauth/src/oauth2/introspection.rs`
- `crates/openauth-oauth/src/oauth2/jwks.rs`
- `crates/openauth-oauth/src/oauth2/provider.rs`
- `crates/openauth-oauth/src/oauth2/refresh_access_token.rs`
- `crates/openauth-oauth/src/oauth2/request.rs`
- `crates/openauth-oauth/src/oauth2/token_validation.rs`
- `crates/openauth-oauth/src/oauth2/tokens.rs`
- `crates/openauth-oauth/src/oauth2/types.rs`
- `crates/openauth-oauth/src/oauth2/utils.rs`
- `crates/openauth-oauth/src/oauth2/validate_authorization_code.rs`
- `crates/openauth-oauth/src/oauth2/verify.rs`
- `crates/openauth-oauth/tests/oauth2_helpers.rs`
- `crates/openauth-oauth/tests/module_structure.rs`

## Implementation Status

Completed in this worktree:

- Added a regression test for authorization endpoint query parameters that already contain stale standard OAuth values.
- Updated authorization URL construction to replace existing standard query values instead of appending duplicates.
- Audited the remaining upstream package-level OAuth helpers against OpenAuth equivalents in `openauth-core/src/auth/oauth` and social callback routes.
- Added regressions for linked-account token preservation and explicit link attempts against accounts already owned by another user.
- Updated OpenAuth core OAuth account linking to preserve absent token fields and reject cross-user explicit linking instead of treating it as success.
- Verified the focused regression and scoped `openauth-oauth` acceptance loop.

## Confirmed Matches

- Authorization URL construction includes upstream parameters: `response_type`, primary `client_id`, `state`, `scope`, `redirect_uri`, `duration`, `display`, `login_hint`, `prompt`, `hd`, `access_type`, `response_mode`, PKCE `S256` challenge, `claims`, and arbitrary additional params.
- Authorization code token request construction matches upstream grant shape, PKCE field, `client_key`, `device_id`, redirect URI override, repeated `resource` values, optional headers, post auth, and basic auth.
- Refresh token request construction matches upstream grant shape, post/basic auth modes, repeated `resource` values, and extra params.
- Client credentials request construction matches upstream grant shape, `scope`, repeated `resource` values, and post/basic auth modes.
- Token parsing preserves raw provider fields, maps `token_type`, access/refresh/id tokens, `expires_in`, `refresh_token_expires_in`, and scopes.
- `get_primary_client_id` matches upstream primary-client-id semantics for single string and array index 0 while rejecting missing or empty primary values.
- PKCE code challenge generation matches upstream SHA-256 plus unpadded base64url output.
- JWS/JWKS token validation covers Better Auth tested algorithms: RS256, ES256, and EdDSA, plus additional supported algorithms behind the `jose` feature.
- Access-token verification supports local JWKS verification, remote introspection, `force`, `active` validation, issuer/audience checks, `azp` to `client_id` mapping, and required scope checks.
- HTTP success/error handling is more explicit than upstream and redacts sensitive OAuth fields from errors.

## Confirmed Differences

- Better Auth uses `URLSearchParams.set` for authorization URL fields, replacing existing endpoint query values. OpenAuth previously appended standard fields with `append_pair`, so a configured authorization endpoint containing existing `client_id`, `scope`, `redirect_uri`, `code_challenge`, or related standard fields produced duplicate parameters. This is fixed by the implementation recorded below.
- OpenAuth intentionally validates direct struct construction more strictly than upstream TypeScript. Examples: empty state/code/refresh token checks, absolute URL parsing, missing client credentials for client credentials flow, malformed token responses, and redacted error bodies.
- OpenAuth accepts only structured `ClientId` values, while upstream `ProviderOptions.clientId` is `unknown` and can represent provider-specific shapes. This is an intentional Rust type boundary for this crate.
- OpenAuth parses scope strings with `split_whitespace`, while upstream uses `split(" ")`. The Rust behavior avoids empty scopes from repeated spaces.
- OpenAuth treats `expires_in = 0` as an immediate expiration timestamp; upstream truthiness checks treat zero as absent. No change proposed because accepting an explicit zero is defensible OAuth handling and avoids silently dropping provider data.
- OpenAuth uses standard Base64 for HTTP Basic credentials. Upstream uses standard Base64 for authorization-code and refresh-token flows, but `client-credentials-token.ts` uses base64url. No change proposed because RFC 7617 Basic authentication requires standard Base64 and the Rust implementation is production-correct.
- Better Auth package-level OAuth state, token encryption, account linking, and callback route behavior are outside `crates/openauth-oauth` and belong to OpenAuth core/plugin surfaces rather than this helper crate.
- The residual audit found OpenAuth core equivalents for the package-level pieces under `crates/openauth-core/src/auth/oauth` and `crates/openauth-core/src/api/routes/social`. Token encryption and legacy plaintext migration already matched upstream. Account linking had two meaningful differences that are fixed by the follow-up task below.

## Risks

- Duplicate authorization URL parameters can lead to provider-specific ambiguity. Some providers use the first occurrence, some use the last, and some reject the request. If an endpoint was configured with stale or malicious standard parameters, OpenAuth could send conflicting values.
- Changing authorization URL query writing from append semantics to set semantics may alter output for callers who intentionally relied on duplicate standard query keys. That behavior does not match upstream and is unsafe for OAuth fields.
- Existing stricter Rust validation can reject malformed inputs that upstream would pass through to a provider. This is intentionally left unchanged for server-side safety.

## Proposed Fixes

### Task 1: Replace Standard Authorization Query Parameters

**Files:**
- Modify: `crates/openauth-oauth/src/oauth2/authorization_url.rs`
- Test: `crates/openauth-oauth/tests/oauth2_helpers.rs`

- [x] Add a failing regression test proving standard authorization parameters replace existing endpoint query values instead of creating duplicates.
- [x] Update `create_authorization_url` to write standard parameters with set semantics, preserving unrelated endpoint query parameters.
- [x] Keep `additional_params` override semantics aligned with upstream: additional params replace any existing value for their key.
- [x] Run the focused oauth test that covers authorization URL helpers.

### Task 2: Close Package-Level OAuth Account-Linking Gaps

**Files:**
- Modify: `crates/openauth-core/src/auth/oauth/account_linking.rs`
- Modify: `crates/openauth-core/src/api/routes/social/flow.rs`
- Test: `crates/openauth-core/tests/auth/oauth.rs`
- Test: `crates/openauth-core/tests/api/routes/social_oauth.rs`

- [x] Add a failing regression proving existing linked-account tokens are preserved when the provider omits fresh token fields.
- [x] Update linked-account refresh logic to mirror upstream's `undefined` filtering by only updating token/account fields that are present.
- [x] Add a failing regression proving explicit social linking rejects a provider account already owned by a different user.
- [x] Update explicit social link callback behavior to redirect with `account_already_linked_to_different_user` instead of silently succeeding.
- [x] Preserve same-user explicit link support by updating existing account tokens when the account already belongs to the current user.

## Tests To Add Or Update

- Add `create_authorization_url_standard_params_overwrite_endpoint_query_params` in `crates/openauth-oauth/tests/oauth2_helpers.rs`.
- The test should build an authorization endpoint containing stale `client_id`, `scope`, `redirect_uri`, `code_challenge_method`, and `code_challenge` values, then assert each appears once with the OpenAuth-generated value.
- Add `handle_oauth_user_info_preserves_linked_account_tokens_when_provider_omits_them` in `crates/openauth-core/tests/auth/oauth.rs`.
- Add `link_social_callback_rejects_account_owned_by_different_user` in `crates/openauth-core/tests/api/routes/social_oauth.rs`.

## Items Intentionally Left Unchanged

- No implementation of Better Auth package-level `generateState`, `parseState`, `handleOAuthUserInfo`, `decryptOAuthToken`, or `setTokenUtil` in `crates/openauth-oauth`; these require AuthContext, cookies, database verification, account encryption, and user/session adapters.
- The corresponding package-level pieces in `openauth-core` were audited. OpenAuth intentionally keeps encrypted-state-in-URL cookie strategy rather than Better Auth's encrypted-cookie plus random state-param model; that is an architectural difference already covered by tests and not changed here.
- No weakening of Rust validation to match upstream pass-through behavior for malformed URLs, empty credentials, missing tokens, or malformed token responses.
- No change from standard Base64 to base64url for client credentials Basic auth; the existing Rust behavior follows the OAuth/HTTP Basic spec.
- No change to scope parsing whitespace behavior.
- No change to `expires_in = 0` handling.
- No workspace-wide verification unless edits unexpectedly cross crate boundaries.
