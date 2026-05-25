# OAuth Provider Upstream Parity Audit Plan

## Summary

Target crate: `crates/openauth-oauth-provider`.

Upstream package: `upstream/better-auth/1.6.9/repository/packages/oauth-provider`.

OpenAuth's OAuth provider implementation is already broadly mapped to upstream
server-side behavior. The audit found two justified parity fixes:

- upstream `/oauth2/consent` accepts an optional `scope` body field so the end
  user can approve fewer scopes than originally requested; the Rust endpoint
  approved the full pending scope set;
- upstream PKCE policy requires PKCE for public clients, confidential clients by
  default, and any `offline_access` request; the Rust authorize endpoint only
  required PKCE for public clients or clients explicitly marked
  `require_pkce=true`.

## Upstream Files Inspected

- `src/oauth.ts`
- `src/authorize.ts`
- `src/consent.ts`
- `src/continue.ts`
- `src/token.ts`
- `src/introspect.ts`
- `src/revoke.ts`
- `src/userinfo.ts`
- `src/logout.ts`
- `src/metadata.ts`
- `src/register.ts`
- `src/oauthClient/endpoints.ts`
- `src/oauthConsent/endpoints.ts`
- `src/mcp.ts`
- `src/client-resource.ts`
- `src/schema.ts`
- `src/types/index.ts`
- `src/types/oauth.ts`
- `src/types/zod.ts`
- `src/utils/index.ts`
- `src/utils/query-serialization.test.ts`
- `src/utils/timestamps.test.ts`
- All upstream `oauth-provider` package tests, including authorization,
  consent, token, registration, client management, metadata, pairwise subject,
  introspection, revocation, userinfo, logout, MCP, and validation coverage.

## OpenAuth Files Inspected

- `crates/openauth-oauth-provider/src/lib.rs`
- `crates/openauth-oauth-provider/src/options.rs`
- `crates/openauth-oauth-provider/src/authorize.rs`
- `crates/openauth-oauth-provider/src/client.rs`
- `crates/openauth-oauth-provider/src/consent.rs`
- `crates/openauth-oauth-provider/src/endpoints/*`
- `crates/openauth-oauth-provider/src/token/*`
- `crates/openauth-oauth-provider/src/models.rs`
- `crates/openauth-oauth-provider/src/schema.rs`
- `crates/openauth-oauth-provider/src/metadata.rs`
- `crates/openauth-oauth-provider/src/mcp.rs`
- `crates/openauth-oauth-provider/src/utils.rs`
- `crates/openauth-oauth-provider/tests/oauth_provider/*`
- `crates/openauth-oauth-provider/tests/upstream_mapping.md`

## Confirmed Matches

- Provider defaults for scopes, expirations, grants, dynamic client registration,
  token storage, JWT integration, and rate limits match upstream behavior.
- Config validation covers advertised scopes, client registration scopes,
  pairwise secret length, refresh-token grant composition, and client-secret
  storage/JWT compatibility.
- Persistent schema covers OAuth clients, access tokens, refresh tokens, and
  consents with Rust-native snake_case storage names and OAuth-compatible public
  JSON names.
- Metadata, dynamic client registration, client CRUD/privileges, consent
  management, authorization prompts, token grants, JWT and opaque token
  issuance, introspection, revocation, userinfo, logout, pairwise subjects,
  custom hooks, token/client-secret prefixes, custom generators, MCP helpers,
  and safe redirect URL validation have focused Rust tests.
- PKCE now matches upstream server behavior: public clients require S256,
  confidential clients require PKCE by default, confidential clients can opt out
  with `require_pkce=false`, `offline_access` always requires PKCE, partial PKCE
  parameters are rejected, and only S256 is accepted.
- Browser-only upstream client behavior is intentionally out of scope for this
  server-side Rust crate.

## Confirmed Differences

- Upstream `src/consent.ts` accepts optional `scope` in the consent body,
  validates it is a subset of the originally requested scopes, stores only the
  accepted scopes, and issues the authorization code with those accepted scopes.
- Rust `crates/openauth-oauth-provider/src/endpoints/consent.rs` previously
  ignored consent-body scope and always persisted/issued the full pending
  authorization scopes.
- Upstream `src/utils/index.ts` and `src/authorize.ts` require PKCE for public
  clients, confidential clients unless `requirePKCE === false`, and any
  `offline_access` request. They also require `code_challenge` and
  `code_challenge_method` to be supplied together and only accept S256.
- Rust `crates/openauth-oauth-provider/src/endpoints/authorization.rs`
  previously treated PKCE as required only for public clients or when the
  stored client explicitly set `require_pkce=true`.

## Risks

- Deleting pending authorization before validating accepted scopes would make a
  malformed consent request consume the flow. The fix must validate first.
- The narrowed scope list must flow into both consent persistence and the
  authorization code value; otherwise token responses and future consent checks
  diverge.
- Empty accepted scope strings should not silently approve no scopes because
  upstream treats invalid or unrequested consent scopes as `invalid_request`.
- PKCE validation must run after request-URI resolution, redirect validation,
  and scope normalization so the same resolved/defaulted scope set drives the
  upstream policy decision.
- Tests that exercise later prompt or token paths must include valid PKCE rather
  than weakening the server rule.

## Proposed Fixes

- Add `scope: Option<String>` to the consent decision body.
- When consent is accepted and `scope` is present, parse it with existing
  `split_scope`.
- Reject empty accepted scopes or scopes not in the pending authorization scope
  set with `invalid_request` and `Scope not originally requested`.
- Keep pending authorization intact on rejected narrowed-scope validation.
- Use the accepted scope set for both `upsert_consent` and
  `issue_authorization_code_redirect`.
- Replace authorize PKCE gating with a Rust helper matching upstream:
  public client, `offline_access`, then `client.require_pkce.unwrap_or(true)`.
- Reject missing paired PKCE fields with upstream-compatible `invalid_request`
  descriptions.
- Keep S256 as the only accepted `code_challenge_method`.

## Tests To Add Or Update

- Add a focused regression test:
  `consent_endpoint_accepts_subset_and_rejects_unrequested_scope`.
- The test should:
  - request `openid profile email`;
  - submit `openid admin` and assert `400 invalid_request`;
  - reuse the same `request_id` with `openid profile`;
  - assert the callback contains an authorization code;
  - exchange the code and assert token `scope == "openid profile"`;
  - assert persisted consent scopes are exactly `["openid", "profile"]`.
- Update `tests/upstream_mapping.md` so the mapping names the narrowed-consent
  coverage.
- Add a focused PKCE regression test:
  `authorization_code_flow_enforces_upstream_pkce_policy_for_confidential_clients`.
- Update successful authorization-code fixtures to submit S256 challenges and
  matching token `code_verifier` values where upstream now requires PKCE.
- Update request-URI resolver tests so resolved authorization parameters include
  PKCE, matching upstream's rule that only `client_id` is carried from the
  outer authorize URL after request-URI resolution.

## Items Intentionally Left Unchanged

- The browser client plugin and SDK helpers remain out of scope.
- TypeScript-only zod implementation details remain represented by Rust types,
  endpoint parsing, and explicit validators.
- Better Auth request-local `oauth_query` state remains represented by Rust
  pending authorization records.
- Rust's existing GET support for `/oauth2/continue` remains as an additive
  compatibility path even though upstream exposes POST.
- No dependencies are added.
