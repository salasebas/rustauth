# Upstream parity: rustauth-oauth-provider

| Field | Value |
| --- | --- |
| Parity pin | Better Auth `1.6.9` from `reference/upstream-better-auth/VERSION.md` |
| Upstream package | `@better-auth/oauth-provider@1.6.9` |
| Upstream path | `reference/upstream-src/1.6.9/repository/packages/oauth-provider/` |
| Rust crate | `crates/rustauth-oauth-provider` |
| Parity level | High server-side parity with documented compatibility gaps |
| Scope | Server-only OAuth 2.1 / OIDC provider routes, OAuth client and consent management, schema, hooks, runtime validation, and MCP resource helpers |

## Summary

`rustauth-oauth-provider` ports the Better Auth OAuth provider server plugin into idiomatic Rust. This document covers only runtime server behavior: endpoint contracts, storage models, option validation, token handling, OAuth client management, consent management, metadata, rate-limit contributions, and MCP protected-resource helpers.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature Parity

| Area | Status | Notes |
| --- | --- | --- |
| Plugin lifecycle hooks | ⚠️ | Upstream uses before/after hooks for signed `oauth_query`, social sign-in continuation, session-cookie resume, and API redirect shaping; Rust covers the observable server flow through endpoint state and verification records. |
| Init constraints and warnings | ⚠️ | Upstream validates plugin setup, secondary-storage/session requirements, and well-known URL placement; Rust uses typed config errors and documented host-runtime expectations. |
| OAuth/OIDC metadata | ✅ | `/.well-known/oauth-authorization-server` and `/.well-known/openid-configuration` are implemented with advertised scopes, claims, JWKS, algorithms, issuer normalization, and cache headers. |
| Authorization endpoint | ✅ | `GET /oauth2/authorize` covers code flow, PKCE, `prompt`, `max_age`, `request_uri`, JSON redirect responses, RFC 9207 `iss`, consent/login redirects, and loopback IP redirect matching. |
| Consent and continue flow | ✅ | `POST /oauth2/consent` and `POST /oauth2/continue` are implemented for consent, signup/create, account-selection, and post-login steps; Rust also accepts `GET /oauth2/continue` for compatibility. |
| Verification-store state | ✅ | Pending authorization requests and authorization codes are single-use server records with stored shape validation before token issuance. |
| Token endpoint | ✅ | `authorization_code`, `refresh_token`, and `client_credentials` grants are implemented with Basic/body client auth, grant gating, `resource`/`valid_audiences`, `no-store`, and custom response fields. |
| Refresh rotation and replay | ✅ | Refresh grants rotate tokens, revoke previous tokens, and detect replay against token family state. |
| Introspection and revocation | ✅ | RFC 7662/7009-style POST endpoints require valid client authentication and respect `token_type_hint`. |
| UserInfo | ✅ | Bearer access tokens require `openid` scope and return `sub`, email claims, profile claims, pairwise subjects, and custom userinfo claims. |
| RP-initiated logout | ✅ | `GET /oauth2/end-session` validates `id_token_hint`, client settings, registered logout redirect URI, and `state`. |
| Dynamic client registration | ✅ | `POST /oauth2/register` supports DCR metadata, default scopes, secret expiration, redirect URI hardening, public/confidential clients, and upstream-compatible JSON names. |
| Client management | ⚠️ | Create/read/list/update/delete/rotate/public/prelogin endpoints are implemented with ownership, privileges, signed prelogin query checks, and trusted-client mutation guards; admin update uses `POST` instead of upstream `PATCH`. |
| Consent management | ✅ | Get/list/update/delete consent endpoints enforce session ownership and validate requested scope changes. |
| Schema contributions | 🎯 | Same logical models are present; Rust uses plural snake_case physical tables and fields. |
| Runtime validators | ✅ | Redirect URI safety, dangerous-scheme rejection, loopback HTTP allowance, Basic auth parsing, query preservation, and authorization-code verification parsing are covered. |
| Options and hooks | ✅ | Scope validation, grant validation, pairwise secret length, prompt redirects, consent/client reference resolvers, client privileges, token hashing, custom claims, custom generators, token prefixes, scope expirations, and refresh formatting are covered. |
| Rate-limit contributions | ✅ | Plugin contributes upstream-style defaults for token, authorize, introspect, revoke, register, and userinfo routes; management, consent, continue, and logout enforcement remains host-owned unless separately configured. |
| MCP profile | ✅ | `OAuthProviderOptions::mcp` registers protected-resource metadata, merges MCP authorization-server metadata overrides, and keeps all OAuth flows on `/oauth2/*`; resource-server helpers remain available behind `mcp-client`. |

## Test Coverage

Verify with:

```bash
cargo nextest run -p rustauth-oauth-provider
```

| Surface | RustAuth tests | Upstream tests | Notes |
| --- | ---: | ---: | --- |
| Total measured server/runtime tests | 96 | 261 | Rust count from `rg '#\[(test\|tokio::test)\]' crates/rustauth-oauth-provider`; upstream count from `rg '^\s*(it\|test)\(' packages/oauth-provider/src`. |
| Authorization / prompt / request URI | 26 | 18 | Rust has broad route and decision coverage, including prompt combinations, `request_uri`, loopback redirects, and token exchange edge cases. |
| Token, introspection, revocation, userinfo | 27 | 72 | Rust covers grant types, resource audiences, replay, headers, custom claims, introspection, revocation, and UserInfo; upstream has denser matrix tests. |
| Client registration and management | 17 | 45 | Rust covers DCR, unsafe redirect rejection, ownership, privileges, trusted-client cache, public prelogin, update validation, and rotate-secret constraints. |
| Consent management | 7 | 6 | Rust covers consent accept/reject, narrowed scopes, owner enforcement, update/delete, and continue checks. |
| Metadata, config, schema, rate limits | 13 | 15 | Rust covers defaults, config validation, schema shape, metadata, JWKS defaults, and plugin rate-limit contributions. |
| Pairwise, logout, MCP | 8 | 29 | Rust covers pairwise subjects, registration constraints, RP-initiated logout, MCP protected-resource metadata, and helper behavior. |
| Runtime validators and utilities | Covered indirectly | 28 | Upstream has direct tests for URL validation, authorization-code verification parsing, query preservation, prompt deletion, and timestamp normalization; Rust covers most through endpoint tests. |

## Intentional Differences

| Topic | Better Auth | RustAuth | Why |
| --- | --- | --- | --- |
| Physical schema names | Camel-case logical model fields such as `oauthClient.clientId`. | Plural snake_case tables and fields such as `oauth_clients.client_id`. | Matches Rust and SQL adapter conventions while keeping OAuth JSON payload names stable. |
| JWT integration | Discovers the Better Auth JWT plugin at runtime; init fails with `jwt_config` if missing when JWT is required. | Registers `jwt(...)` separately; oauth-provider `with_init` validates presence when `disable_jwt_plugin` is false; runtime via `jwt_options_from_context`. | ✅ Matches upstream composition. |
| Token storage | Supports configured token storage modes. | Defaults to hashed token storage and rejects encrypted token storage. | Avoids reversible bearer-token storage on auth boundaries. |
| Client-secret storage | Hashes by default when JWT is enabled; encrypts in no-JWT mode. | Same policy, represented as typed `SecretStorage` validation errors. | Fail closed with explicit Rust errors instead of runtime warnings. |
| Continue endpoint | `POST /oauth2/continue`. | `POST /oauth2/continue` plus `GET /oauth2/continue`. | Compatibility for redirect-driven server flows. |
| Validation errors | Throws `APIError` / `BetterAuthError` at runtime. | Uses typed Rust config/runtime errors and explicit OAuth JSON bodies. | Keeps auth-boundary failures observable and fail-closed. |

## Open Gaps / Risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| OAUTH-PROVIDER-001 | Admin update method mismatch | Medium | Upstream registers `PATCH /admin/oauth2/update-client`; Rust currently exposes `POST /admin/oauth2/update-client`. |
| OAUTH-PROVIDER-002 | Lower route-matrix density | Medium | Rust coverage is broad but has fewer direct matrix cases for malformed payloads, timestamp normalization, query serialization, and runtime URL validation helpers. |
| OAUTH-PROVIDER-003 | Rate-limit enforcement is host-dependent | Medium | The plugin contributes rate-limit rules; enforcement depends on the host RustAuth runtime honoring plugin rate limits. |
| OAUTH-PROVIDER-004 | Trusted-client cache is in-process | Medium | Multi-instance deployments should not assume cross-node cache invalidation. |
| OAUTH-PROVIDER-005 | Schema must be migrated before traffic | High | Enabling the plugin adds OAuth client, consent, access-token, and refresh-token tables. |
| OAUTH-PROVIDER-006 | MCP resource-server enforcement is host-owned | Low | The auth server exposes MCP protected-resource metadata; resource servers still decide how to apply bearer validation and challenge responses. |
| OAUTH-PROVIDER-007 | Client-update guardrail matrix | Medium | Rust tests cover immutable auth method, public-secret rotation, invalid scopes, and partial updates; add or keep focused tests for direct `public` / `client_secret` update payloads when changing client update behavior. |
| OAUTH-PROVIDER-008 | No pushed authorization endpoint | Low | `request_uri` is supported through a host resolver callback; there is no first-party pushed authorization endpoint in this crate. |

## Hardening Notes

- Keep `client_secret`, opaque access tokens, refresh tokens, and authorization codes hashed at rest unless an upstream-compatible no-JWT client-secret encryption mode is explicitly required.
- Treat token, introspection, revocation, registration, and userinfo endpoints as rate-limited production surfaces.
- Run adapter migrations before enabling the plugin in a live deployment.
- In multi-instance deployments, use database state or deployment config as the source of truth for trusted clients.
- Validate redirect URIs, post-logout redirect URIs, `resource` audiences, and pairwise sector identifiers as part of client onboarding.
- Keep authorization-code verification values single-use and validate their stored shape before token issuance.
- Treat signed `oauth_query` prelogin data and pending authorization records as short-lived server state.

## Upstream Lookup

1. Read the pin in `reference/upstream-better-auth/VERSION.md`.
2. Open `reference/upstream-src/1.6.9/repository/packages/oauth-provider/`.
3. Start with upstream `src/index.ts` and `src/oauth.ts` for server exports, plugin options, init checks, hooks, route registration, schema merge, and rate limits.
4. Map `src/oauthClient/`, `src/oauthConsent/`, `src/token.ts`, `src/authorize.ts`, `src/register.ts`, `src/introspect.ts`, `src/revoke.ts`, `src/userinfo.ts`, `src/logout.ts`, `src/metadata.ts`, `src/mcp.ts`, `src/middleware/`, `src/utils/`, and `src/types/zod.ts` to Rust modules.
5. Compare upstream `*.test.ts` files with `crates/rustauth-oauth-provider/tests/` and the maintainer matrix in `tests/upstream_mapping.md`.
6. Verify with `cargo nextest run -p rustauth-oauth-provider`.

| Upstream source | Rust source |
| --- | --- |
| `src/index.ts`, `src/oauth.ts`, `src/version.ts` | `src/lib.rs`, `src/options.rs`, `src/endpoints/mod.rs` |
| `src/schema.ts`, `src/types/index.ts`, `src/types/helpers.ts`, `src/types/oauth.ts` | `src/schema.rs`, `src/models.rs`, `src/client.rs`, `src/token/types.rs` |
| `src/authorize.ts`, `src/continue.ts`, `src/consent.ts` | `src/authorize.rs`, `src/endpoints/authorization.rs`, `src/endpoints/consent.rs` |
| `src/token.ts`, `src/introspect.ts`, `src/revoke.ts` | `src/token/`, `src/endpoints/token.rs`, `src/endpoints/introspection.rs` |
| `src/register.ts`, `src/oauthClient/` | `src/client.rs`, `src/endpoints/clients.rs` |
| `src/oauthConsent/` | `src/consent.rs`, `src/endpoints/consent.rs` |
| `src/userinfo.ts`, `src/logout.ts`, `src/metadata.ts`, `src/mcp.ts` | `src/endpoints/userinfo.rs`, `src/endpoints/logout.rs`, `src/metadata.rs`, `src/mcp.rs` |
| `src/middleware/index.ts`, `src/utils/index.ts`, `src/types/zod.ts` | `src/utils.rs`, `src/endpoints/clients.rs`, `src/token/types.rs` |
| `src/*.test.ts`, `src/**/**.test.ts` | `tests/oauth_provider/`, `tests/upstream_mapping.md` |

## Audited Server Files

| Upstream file group | Classification | Rust coverage location |
| --- | --- | --- |
| `src/oauth.ts`, `src/index.ts`, `src/version.ts` | Server plugin registration, init checks, hooks, and metadata | `src/lib.rs`, `src/options.rs`, `src/endpoints/mod.rs` |
| `src/authorize.ts`, `src/consent.ts`, `src/continue.ts` | Authorization and prompt flow runtime | `src/authorize.rs`, `src/endpoints/authorization.rs`, `src/endpoints/consent.rs` |
| `src/token.ts`, `src/introspect.ts`, `src/revoke.ts`, `src/userinfo.ts`, `src/logout.ts` | Token, grant, claims, introspection, revocation, UserInfo, and logout runtime | `src/token/`, `src/endpoints/token.rs`, `src/endpoints/introspection.rs`, `src/endpoints/userinfo.rs`, `src/endpoints/logout.rs` |
| `src/register.ts`, `src/oauthClient/`, `src/oauthConsent/` | Server-side OAuth client and consent management | `src/client.rs`, `src/consent.rs`, `src/endpoints/clients.rs`, `src/endpoints/consent.rs` |
| `src/schema.ts`, `src/types/index.ts`, `src/types/helpers.ts`, `src/types/oauth.ts`, `src/types/zod.ts` | Server models, OAuth data contracts, and runtime validation | `src/schema.rs`, `src/models.rs`, `src/token/types.rs`, `src/utils.rs` |
| `src/metadata.ts`, `src/mcp.ts`, `src/middleware/index.ts`, `src/utils/index.ts` | Well-known metadata, MCP helper, middleware, and runtime utilities | `src/metadata.rs`, `src/mcp.rs`, `src/utils.rs` |
| `src/*.test.ts`, `src/**/**.test.ts` | Server/runtime behavior tests | `tests/oauth_provider/`, `tests/upstream_mapping.md` |

## Links

- [README](./README.md)
- [Upstream parity index](../../docs/parity/README.md)
