# JWT, Last Login Method, Magic Link, and MCP Upstream Parity Audit

## Upstream Files Inspected

- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/jwt/{index.ts,sign.ts,verify.ts,utils.ts,types.ts,schema.ts,adapter.ts,jwt.test.ts,rotation.test.ts}`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/last-login-method/{index.ts,last-login-method.test.ts,custom-prefix.test.ts}`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/magic-link/{index.ts,utils.ts,magic-link.test.ts}`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/mcp/{index.ts,authorize.ts,mcp.test.ts}`
- `upstream/better-auth/1.6.9/repository/packages/better-auth/src/plugins/mcp/client/{index.ts,adapters.ts,mcp-client.test.ts}`
- `upstream/better-auth/1.6.9/repository/packages/oauth-provider/src/{mcp.ts,mcp.test.ts}`

## OpenAuth Files Inspected

- `crates/openauth-plugins/src/jwt/**` and `crates/openauth-plugins/tests/jwt/**`
- `crates/openauth-plugins/src/last_login_method/**` and `crates/openauth-plugins/tests/last_login_method/**`
- `crates/openauth-plugins/src/magic_link/**` and `crates/openauth-plugins/tests/magic_link/**`
- `crates/openauth-plugins/src/mcp/**` and `crates/openauth-plugins/tests/mcp/**`
- `crates/openauth-oauth-provider/src/mcp.rs` and `crates/openauth-oauth-provider/tests/oauth_provider/**`

## Confirmed Matches

- JWT has server-only sign/verify endpoints, JWKS generation, key rotation grace filtering, encrypted private key storage by default, custom adapters, custom signing with remote JWKS URL, supported algorithms, `/token`, and `set-auth-jwt` header behavior.
- Last-login-method mirrors upstream resolution for email, OAuth callback, SIWE, passkey, and magic-link routes, only sets the browser-readable method cookie after a session cookie is created, and can contribute a generated user field.
- Magic-link mirrors upstream sign-in and verify flows: metadata forwarding, token generation, optional hashing/custom hashing, allowed-attempt accounting, signup disablement, email verification, session creation, callback redirects, and rate limits. Rust also keeps stronger trusted-origin validation for redirect URLs.
- Legacy MCP exposes upstream-equivalent dynamic registration, authorization, consent, token, session, userinfo, JWKS, discovery, protected-resource metadata, login resume, CORS, and resource-client helper behavior.
- OAuth-provider MCP helper covers URL resource metadata, bearer-token validation, and unauthorized challenge construction for normal URL resources.

## Confirmed Differences And Risks

- JWT `/sign-jwt` accepted only `payload`; upstream accepts an `overrideOptions` object. Rust cannot safely deserialize function callbacks from JSON, but scalar JWT/JWKS options can be supported.
- MCP token endpoint mapped internal failures to OAuth error codes using string matching. This risks returning `invalid_grant` for client authentication failures or `invalid_request` for grant failures when messages change.
- Last-login-method uses `last_login_method` as the Rust logical field key while schema metadata maps it to a custom physical field name. This is intentional but needs persistence coverage.
- Magic-link missing or empty `token` query values resolve to `INVALID_TOKEN` redirects in Rust. Upstream Zod validates presence/type first, but a redirect keeps the user-facing failure path consistent for malformed magic-link URLs and does not weaken security.
- `openauth-oauth-provider::mcp::www_authenticate_for_resources` accepted any string that `url` could parse, including URNs without hosts, and could build malformed `urn:///.well-known/...` challenges. Upstream supports non-URL resources only when a caller provides an explicit mapping.

## Proposed Fixes

- Add serializable JWT `overrideOptions` support for `/sign-jwt`: `jwt.issuer`, `jwt.audience`, `jwt.expirationTime`, and `jwks` scalar key options. Leave callback options intentionally unsupported.
- Replace MCP token string-matching error mapping with a typed internal token error that carries OAuth status, `error`, and `error_description`.
- Add tests for JWT endpoint override options, direct `sign_jwt` override behavior, MCP token error codes, custom last-login database field persistence, magic-link missing/empty token behavior, and URL-only OAuth-provider MCP challenge behavior.
- Tighten OAuth-provider MCP challenge generation to reject hostless/non-hierarchical resources until a mapping-aware API exists.

## Tests To Add Or Update

- `crates/openauth-plugins/tests/jwt/endpoints.rs`: server-only endpoint handler test for JSON `overrideOptions`.
- `crates/openauth-plugins/tests/jwt/sign_verify.rs`: direct override-options regression.
- `crates/openauth-plugins/tests/mcp/token_hardening.rs`: exact OAuth error-code regressions for invalid client id, invalid redirect URI, missing public-client verifier, expired code, invalid code, and invalid client secret.
- `crates/openauth-plugins/tests/last_login_method/mod.rs`: persistence coverage for custom database field names if existing coverage is only schema-level.
- `crates/openauth-plugins/tests/magic_link/mod.rs`: missing/empty token redirects to `INVALID_TOKEN`.
- `crates/openauth-oauth-provider/tests/oauth_provider/oidc_misc.rs`: document URL-only challenge helper behavior with a regression.

## Intentionally Left Unchanged

- No client-side plugin code is ported.
- No new dependencies are needed.
- Magic-link keeps Rust's stronger origin validation.
- OAuth-provider MCP non-URL resource mapping remains unsupported unless a future API adds an explicit mapping parameter; hostless parsed URLs are rejected instead of producing malformed metadata challenges.
