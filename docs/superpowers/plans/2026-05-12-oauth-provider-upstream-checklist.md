# OAuth Provider Upstream Checklist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Track the server-side behavior in Better Auth's `packages/oauth-provider` so OpenAuth can implement an idiomatic Rust OAuth 2.1 / OIDC provider without copying TypeScript structure.

**Architecture:** Treat upstream as behavioral reference only. Model the Rust implementation around explicit storage traits, typed endpoint inputs/outputs, typed OAuth/OIDC errors, secure token services, and small modules for authorization, token issuance, client management, consent, discovery, introspection, revocation, logout, and protected-resource support.

**Tech Stack:** Rust, OpenAuth core storage/session contracts, OAuth 2.1, OIDC Core, RFC 8414 authorization server metadata, RFC 7591 dynamic client registration, RFC 7662 introspection, RFC 7009 revocation, RFC 9207 issuer response parameter, RFC 8252 native app loopback redirects, RFC 9728 protected resource metadata, JOSE/JWT/JWK, PKCE S256, constant-time secret comparison, secure random token generation, HMAC-SHA256 pairwise subjects.

---

## How To Use This Guide

This document is a behavioral guide, not a demand to copy Better Auth's TypeScript structure. A checkbox can be marked complete when OpenAuth implements the same server-side intent or a stronger, more secure, more idiomatic Rust behavior that fully covers the upstream case. If OpenAuth deliberately improves upstream behavior, document the improvement near the checked item so future projects can reuse the decision.

## Scope

Upstream source inspected: `upstream/better-auth/1.6.9/repository/packages/oauth-provider`.

This checklist includes only server-side behavior and reusable server/resource-server helpers. Browser-only client injection from `src/client.ts` is intentionally excluded except where tests depend on its server-visible `oauth_query` shape.

Second-pass audit note: upstream has 18 test files, 58 `describe(...)` groups, and 261 `it(...)` cases under this package. The test checklist below groups behavior by test file instead of listing every assertion.

## Upstream Files Mapped

- [ ] `src/index.ts`: public server exports for provider, metadata helpers, MCP handler, and types.
- [ ] `src/oauth.ts`: plugin configuration, defaults, validation, request-state hooks, endpoint registration, rate limits, schema merge.
- [ ] `src/schema.ts`: persistent models for OAuth clients, refresh tokens, opaque access tokens, and consents.
- [ ] `src/types/index.ts`: option contract, authorization query, verification value, stored client/token/consent shapes.
- [ ] `src/types/oauth.ts`: OAuth/OIDC metadata and Dynamic Client Registration types.
- [ ] `src/types/zod.ts`: runtime validation behavior for authorization-code verification values and safe redirect URLs.
- [ ] `src/authorize.ts`: `/oauth2/authorize`, PAR resolution, redirects, prompt handling, consent checks, authorization code creation.
- [ ] `src/consent.ts`: `/oauth2/consent` accept/deny flow and consent persistence.
- [ ] `src/continue.ts`: `/oauth2/continue` for account selection, sign-up continuation, and post-login continuation.
- [ ] `src/token.ts`: `/oauth2/token`, authorization code, refresh token, and client credentials grants.
- [ ] `src/introspect.ts`: `/oauth2/introspect`, JWT/opaque/refresh token validation, RFC 7662 response format.
- [ ] `src/revoke.ts`: `/oauth2/revoke`, JWT no-op revocation, opaque deletion, refresh revocation/replay handling.
- [ ] `src/userinfo.ts`: `/oauth2/userinfo`, OIDC normal claims, scope-filtered user claims, custom claims.
- [ ] `src/logout.ts`: `/oauth2/end-session`, RP-initiated logout, ID token verification, session deletion, post-logout redirect.
- [ ] `src/metadata.ts`: OAuth authorization server metadata, OIDC discovery metadata, standalone metadata response wrappers.
- [ ] `src/register.ts`: `/oauth2/register`, dynamic client registration validation, client creation, schema conversion.
- [ ] `src/oauthClient/index.ts`: authenticated/admin OAuth client endpoint definitions.
- [ ] `src/oauthClient/endpoints.ts`: OAuth client CRUD, public client lookup, secret rotation, ownership and privileges.
- [ ] `src/oauthConsent/index.ts`: authenticated consent endpoint definitions.
- [ ] `src/oauthConsent/endpoints.ts`: consent read/list/update/delete behavior.
- [ ] `src/middleware/index.ts`: signed OAuth query middleware for pre-login public client lookup.
- [ ] `src/utils/index.ts`: common client lookup, secret/token storage, PKCE policy, prompt/query helpers, pairwise subject helpers.
- [ ] `src/mcp.ts`: MCP/protected-resource bearer challenge handling.
- [ ] `src/client-resource.ts`: server/resource-client actions for verifying access tokens and producing protected resource metadata.
- [ ] `src/client.ts`: excluded browser helper, except signed `oauth_query` behavior should be represented server-side.
- [ ] `src/version.ts`: package version export; not relevant to Rust runtime behavior.

## Dependency Equivalents To Decide

- [ ] Better Auth endpoint builder behavior: upstream uses `createAuthEndpoint` to bind method, path, query/body schema, middleware, media types, OpenAPI metadata, and server-only metadata. Rust should expose equivalent route metadata through framework adapters or an OpenAPI generator without leaking framework details into core services.
- [ ] Better Auth middleware behavior: upstream uses `createAuthMiddleware`, `sessionMiddleware`, request state, OAuth state, and post-response cookie parsing. Rust needs explicit middleware/state boundaries for signed OAuth query capture and post-login continuation.
- [ ] Better Auth adapter behavior: upstream relies on `adapter`, `internalAdapter`, verification storage, session lookup/deletion, and schema merging. Rust should express these as traits with model-specific contracts and transaction guidance for token rotation/revocation.
- [ ] Better Auth error behavior: upstream uses `APIError` and `BetterAuthError` with OAuth-compatible `error` and `error_description` fields. Rust should use typed OAuth/OIDC errors and preserve externally observable response bodies/statuses.
- [ ] Better Auth host/fetch helpers: upstream uses loopback host/IP detection and browser fetch metadata detection. Rust needs correct loopback classification and redirect-vs-JSON response negotiation.
- [ ] Better Auth cookie behavior: upstream parses `Set-Cookie` after login to resume the OAuth flow. Rust should design an explicit post-auth continuation hook or equivalent session-established event.
- [ ] JOSE/JWT/JWK functionality: upstream uses `jose` plus Better Auth JWT helpers for signing, verifying, decoding, compact verification, JWKS lookup, and local JWK sets. Rust needs maintained JOSE/JWT/JWK crates or OpenAuth-owned wrappers.
- [ ] Runtime validation: upstream uses `zod` for endpoint body/query validation and safe URL checks. Rust should use typed extractors plus explicit validators, likely `serde`, `url`, and custom validation errors.
- [ ] PKCE: upstream uses `generateCodeChallenge` for S256. Rust needs SHA-256 + base64url without padding.
- [ ] Random identifiers: upstream uses `generateRandomString(32, ...)`. Rust needs cryptographically secure random generation for client IDs, secrets, codes, opaque access tokens, and refresh tokens.
- [ ] Hashing and constant-time comparison: upstream hashes stored client secrets/tokens with SHA-256 base64url by default and compares in constant time. Rust needs a constant-time equality crate and a hash abstraction; consider stronger password-secret storage separately if policy requires it.
- [ ] Symmetric encryption: upstream supports encrypted client secrets when JWT plugin is disabled. Rust needs an AEAD/JWE-equivalent abstraction if this mode is supported.
- [ ] HMAC signatures: upstream signs `oauth_query` and pairwise subject identifiers. Rust needs HMAC-SHA256 or equivalent keyed signing with constant-time verification.
- [ ] Base64/base64url functionality: upstream uses normal base64 for Basic auth and base64url without padding for SHA-256 hashes. Rust needs both encodings with strict decoding behavior.
- [ ] Time duration parsing: upstream accepts numeric/string/date expiration inputs via Better Auth helpers. Rust should expose explicit duration types rather than TypeScript-style flexible inputs.
- [ ] HTTP integration: upstream uses Better Auth endpoint/middleware abstractions. Rust should keep framework-independent core services with adapters for HTTP frameworks.
- [ ] Logging behavior: upstream logs metadata config warnings and internal introspection/revocation failures. Rust should log internal diagnostics without leaking token details to OAuth clients.
- [ ] Test-only dependency behavior: upstream uses Better Auth test clients, Generic OAuth, multi-session, organization, Node handlers, and `listhen` to validate integration flows. Rust integration tests should reproduce the behavioral scenarios with OpenAuth test harnesses rather than port these dependencies.
- [ ] MCP integration: upstream test coverage uses `@modelcontextprotocol/sdk`. Rust support can be implemented as standards-compliant protected-resource metadata and `WWW-Authenticate` challenge behavior without depending on a specific MCP SDK.

## Core Configuration Checklist

- [ ] Provider constructor/config type with defaults for scopes: `openid`, `profile`, `email`, `offline_access`.
- [ ] Provider defaults for code expiry: 600 seconds.
- [ ] Provider defaults for access token expiry: 3600 seconds.
- [ ] Provider defaults for machine-to-machine access token expiry: 3600 seconds.
- [ ] Provider defaults for ID token expiry: 36000 seconds.
- [ ] Provider defaults for refresh token expiry: 2592000 seconds.
- [ ] Provider defaults for grant types: `authorization_code`, `client_credentials`, `refresh_token`.
- [ ] Provider default for dynamic client registration: disabled.
- [ ] Provider default for unauthenticated client registration: disabled.
- [ ] Provider default for JWT-backed access/ID tokens: enabled unless explicitly disabled.
- [ ] Provider default for client secret storage: hashed when JWT is enabled, encrypted when JWT is disabled.
- [ ] Provider default for token storage: hashed.
- [ ] Provider validation that advertised scopes are included in configured scopes.
- [ ] Provider validation that client registration allowed scopes are included in configured scopes.
- [ ] Provider-derived claims list based on enabled scopes.
- [ ] Provider validation that `refresh_token` grant requires `authorization_code` grant.
- [ ] Provider validation that `pairwiseSecret` is at least 32 characters when configured.
- [ ] Provider validation preventing hashed client-secret storage when ID tokens must be signed by client secret.
- [ ] Provider validation warning or rejection for encrypted client-secret storage when JWT plugin is enabled.
- [ ] Provider support for configured valid audiences, including default base URL.
- [ ] Provider support for cached trusted clients by client ID.
- [ ] Provider support for scope-specific access token expirations, choosing the earliest expiry.
- [ ] Provider support for `clientReference` ownership such as organization/team reference.
- [ ] Provider support for `clientPrivileges` authorization hook by action.
- [ ] Provider support for `clientCredentialGrantDefaultScopes`.
- [ ] Provider support for custom access token claims.
- [ ] Provider support for custom ID token claims.
- [ ] Provider support for custom UserInfo claims.
- [ ] Provider support for custom token response envelope fields without overriding standard OAuth fields.
- [ ] Provider support for advertised metadata overrides for scopes and claims.
- [ ] Provider support for prefixes on opaque access tokens, refresh tokens, and client secrets.
- [ ] Provider support for custom generators for client IDs, client secrets, opaque access tokens, and refresh tokens.
- [ ] Provider support for disabling individual endpoint rate limits.
- [ ] Provider support for custom endpoint rate-limit windows and maximums.
- [ ] Provider support for PAR-style `request_uri` resolver.
- [ ] Provider compatibility check for DB-backed sessions when secondary storage is configured.
- [ ] Provider public export surface re-exports metadata helpers, provider constructor, request state getter, MCP handler, and server-side types.
- [ ] Provider init emits actionable warnings for well-known endpoint placement when base path and issuer path differ.
- [ ] Provider init supports unresolved dynamic base URL during initialization without failing prematurely.

## Modularization Checklist

- [ ] Keep provider configuration and endpoint wiring separate from endpoint behavior.
- [ ] Keep persistent schema/model definitions separate from endpoint logic.
- [ ] Keep OAuth/OIDC public types separate from internal storage types.
- [ ] Keep runtime validators separate from endpoint handlers.
- [ ] Keep `/authorize` logic separate from consent and continuation handlers.
- [ ] Keep token grant handlers internally separate: authorization code, client credentials, refresh token.
- [ ] Keep token construction helpers separate: JWT access token, opaque access token, refresh token, ID token.
- [ ] Keep introspection validation helpers separate: JWT access token, opaque access token, refresh token.
- [ ] Keep revocation helpers separate: JWT access token, opaque access token, refresh token.
- [ ] Keep client endpoint definitions separate from client endpoint behavior.
- [ ] Keep consent endpoint definitions separate from consent endpoint behavior.
- [ ] Keep metadata builders separate from HTTP response wrappers.
- [ ] Keep security utilities separate from endpoint modules.
- [ ] Keep protected resource/MCP helpers separate from authorization server endpoints.
- [ ] Prefer small Rust modules matching responsibilities, not one large OAuth provider file.

## Request Hooks And Flow Integration Checklist

- [ ] Request-local OAuth state stores the signed OAuth query across login/consent/continue transitions.
- [ ] Pre-hook detects `oauth_query` in request body.
- [ ] Pre-hook verifies `oauth_query` signature and expiration before using it.
- [ ] Pre-hook strips `sig` and `exp` before persisting query into request state.
- [ ] Pre-hook attaches OAuth query to sign-in/social additional data when path is `/sign-in/social`.
- [ ] Pre-hook attaches OAuth query to sign-in/oauth2 additional data when path is `/sign-in/oauth2`.
- [ ] Pre-hook preserves existing `additionalData.query` when already provided.
- [ ] Post-hook detects session cookie creation after login.
- [ ] Post-hook extracts raw session token prefix from cookie value.
- [ ] Post-hook loads session through internal adapter and attaches it to request context.
- [ ] Post-hook falls back to generic OAuth state when provider-specific state is absent.
- [ ] Post-hook removes forced `login` prompt before resuming authorization.
- [ ] Post-hook detects navigation requests through `Sec-Fetch-Mode: navigate`.
- [ ] Post-hook detects navigation-like requests through HTML accept headers when fetch metadata is absent.
- [ ] Post-hook forces JSON accept behavior for non-navigation login continuations.
- [ ] Post-hook resumes authorization endpoint after login rather than requiring the user to restart flow.

## Storage Models Checklist

- [ ] `oauthClient` model with unique required `clientId`.
- [ ] `oauthClient.clientSecret` optional stored secret.
- [ ] `oauthClient.disabled`, `skipConsent`, `enableEndSession`, `subjectType`, `scopes`.
- [ ] `oauthClient.userId` relation to user.
- [ ] `oauthClient.referenceId` for organization/team ownership.
- [ ] `oauthClient.createdAt`, `updatedAt`, `expiresAt` equivalent.
- [ ] `oauthClient` UI metadata: name, URI, icon/logo, contacts, terms URI, policy URI.
- [ ] `oauthClient` software metadata: software ID, version, statement.
- [ ] `oauthClient.redirectUris` required for redirect-based flows.
- [ ] `oauthClient.postLogoutRedirectUris` for RP-initiated logout.
- [ ] `oauthClient.tokenEndpointAuthMethod`.
- [ ] `oauthClient.grantTypes`.
- [ ] `oauthClient.responseTypes`.
- [ ] `oauthClient.public` and `type` for public/confidential semantics.
- [ ] `oauthClient.requirePKCE`.
- [ ] `oauthClient.metadata` for extra client metadata JSON.
- [ ] `oauthRefreshToken` model with hashed token, client ID, session ID, user ID, reference ID, expiry, creation time, revoked time, auth time, immutable scopes.
- [ ] `oauthRefreshToken.sessionId` nullable to survive deleted sessions.
- [ ] `oauthAccessToken` model for opaque access tokens with hashed token, client ID, optional session/user/reference/refresh IDs, expiry, creation time, scopes.
- [ ] `oauthAccessToken.token` unique.
- [ ] `oauthConsent` model with client ID, user ID, reference ID, scopes, createdAt, updatedAt.
- [ ] Verification/authorization-code storage using hashed code as identifier, expiry, creation/update time, and JSON/structured verification value.

## OAuth Types And Validation Checklist

- [ ] Grant type enum: `authorization_code`, `client_credentials`, `refresh_token`.
- [ ] Explicitly unsupported grant types: implicit, password, device code, JWT bearer, SAML bearer.
- [ ] Token endpoint auth methods: `client_secret_basic`, `client_secret_post`, `none`.
- [ ] Bearer methods metadata: header and body.
- [ ] Authorization server metadata type per RFC 8414.
- [ ] Authorization server metadata type includes optional service documentation, UI locales, policy URI, terms URI, token endpoint signing algorithms, introspection endpoint signing algorithms, and revocation endpoint signing algorithms.
- [ ] OIDC metadata type with userinfo endpoint, subject types, ID token algs, claims, end-session endpoint, prompt values.
- [ ] Dynamic Client Registration request/response type per RFC 7591 with OpenAuth server extensions.
- [ ] Dynamic Client Registration type accepts `jwks` and `jwks_uri` metadata even though upstream strips/does not persist them; OpenAuth should either intentionally reject, persist, or document unsupported behavior.
- [ ] Protected resource metadata type per RFC 9728.
- [ ] Protected resource metadata type includes TLS client certificate bound access token flag.
- [ ] Protected resource metadata type includes authorization details types support field.
- [ ] Protected resource metadata type includes DPoP signing algorithms and DPoP-bound-token-required flag.
- [ ] Authorization query type with response type, request URI, redirect URI, scope, state, client ID, prompt, display, locales, max age, ACR values, login hint, ID token hint, PKCE fields, nonce.
- [ ] Verification value type for authorization codes with type, original query, session ID, user ID, reference ID, auth time.
- [ ] Safe URL validator blocks `javascript:`, `data:`, and `vbscript:`.
- [ ] Safe URL validator requires HTTPS except HTTP loopback hosts.
- [ ] Safe URL validator allows custom schemes for mobile/native apps.
- [ ] Safe URL tests for localhost, 127.0.0.1, `[::1]`, malicious subdomains, invalid URLs, and empty strings.

## Endpoint Surface Checklist

- [ ] `GET /.well-known/oauth-authorization-server`.
- [ ] `GET /.well-known/openid-configuration`.
- [ ] `GET /oauth2/authorize`.
- [ ] `POST /oauth2/consent`.
- [ ] `POST /oauth2/continue`.
- [ ] `POST /oauth2/token`.
- [ ] `POST /oauth2/introspect`.
- [ ] `POST /oauth2/revoke`.
- [ ] `GET /oauth2/userinfo`.
- [ ] `GET /oauth2/end-session`.
- [ ] `POST /oauth2/register`.
- [ ] `POST /admin/oauth2/create-client`.
- [ ] `POST /oauth2/create-client`.
- [ ] `GET /oauth2/get-client`.
- [ ] `GET /oauth2/public-client`.
- [ ] `POST /oauth2/public-client-prelogin`.
- [ ] `GET /oauth2/get-clients`.
- [ ] `PATCH /admin/oauth2/update-client`.
- [ ] `POST /oauth2/update-client`.
- [ ] `POST /oauth2/client/rotate-secret`.
- [ ] `POST /oauth2/delete-client`.
- [ ] `GET /oauth2/get-consent`.
- [ ] `GET /oauth2/get-consents`.
- [ ] `POST /oauth2/update-consent`.
- [ ] `POST /oauth2/delete-consent`.

## Endpoint Builder And OpenAPI Checklist

- [ ] All HTTP endpoints have an explicit path and method equivalent to upstream `createAuthEndpoint`.
- [ ] Query endpoints define typed query schemas before calling behavior services.
- [ ] Body endpoints define typed body schemas before calling behavior services.
- [ ] Session-protected endpoints apply session middleware or an equivalent authenticated extractor.
- [ ] Server-only endpoints are marked as server-only in route metadata or kept out of public client SDK generation.
- [ ] OAuth token endpoint accepts `application/x-www-form-urlencoded`.
- [ ] OAuth introspection endpoint accepts `application/x-www-form-urlencoded`.
- [ ] OAuth revocation endpoint accepts `application/x-www-form-urlencoded`.
- [ ] Authorization endpoint documents query parameters and 302/error response shapes.
- [ ] Consent endpoint documents redirect response shape.
- [ ] Continue endpoint documents redirect response shape.
- [ ] Token endpoint documents request body, success response, and OAuth error response.
- [ ] Introspection endpoint documents request body and RFC 7662 response shape.
- [ ] Revocation endpoint documents request body and empty success response.
- [ ] UserInfo endpoint documents bearer auth and possible 401/403-like errors.
- [ ] End-session endpoint documents logout success and optional redirect URI.
- [ ] Register endpoint documents RFC 7591 client response.
- [ ] Client management endpoints document public vs server-only fields.
- [ ] Consent management endpoints document authenticated user ownership behavior.
- [ ] OpenAPI metadata stays generated from typed endpoint contracts where possible.
- [ ] Endpoint modules expose behavior functions that can be tested without an HTTP framework.
- [ ] Endpoint modules do not require browser-only client code to function.
- [ ] If OpenAuth uses a better OpenAPI/router architecture than upstream, mark these complete when the same externally visible contract is documented and testable.

## Authorization Endpoint Checklist

- [ ] Reject `/authorize` when `authorization_code` grant is not enabled.
- [ ] Require request context.
- [ ] Resolve `request_uri` through configured resolver before normal validation.
- [ ] Reject `request_uri` when resolver is absent.
- [ ] Reject invalid or expired resolved request URI.
- [ ] Preserve URL `client_id` when replacing front-channel params with resolved PAR params.
- [ ] Store signed/serialized OAuth query in request state.
- [ ] Require `client_id`.
- [ ] Require `response_type`.
- [ ] Support only `response_type=code`.
- [ ] Parse prompt values: `none`, `login`, `consent`, `create`, `select_account`.
- [ ] Reject `select_account` prompt when account selection page is not configured.
- [ ] Lookup client from trusted cache or database.
- [ ] Reject missing client.
- [ ] Reject disabled client.
- [ ] Require requested redirect URI to match a registered redirect URI.
- [ ] Support RFC 8252 loopback IP redirect URI matching with port ignored for IP literals only.
- [ ] Reject non-loopback redirect URI port mismatch.
- [ ] Reject loopback redirect URI path mismatch.
- [ ] Validate requested scopes against client scopes or provider scopes.
- [ ] Default omitted scope to client scopes or provider scopes.
- [ ] Determine PKCE requirement from public client, offline access scope, or per-client setting.
- [ ] Require code challenge and method when PKCE is required.
- [ ] Require both code challenge and code challenge method when either is present.
- [ ] Support only `code_challenge_method=S256`.
- [ ] Redirect unauthenticated users to login or signup flow.
- [ ] Return `login_required` to client when `prompt=none` and login is required.
- [ ] Force account selection for `prompt=select_account`.
- [ ] Invoke account-selection hook and redirect when account selection is required.
- [ ] Return `account_selection_required` when `prompt=none` and selection is required.
- [ ] Invoke signup hook and redirect to signup/setup flow when required.
- [ ] Return `interaction_required` when `prompt=none` and signup/setup interaction is required.
- [ ] Invoke post-login hook and redirect when an additional server-side selection is required.
- [ ] Force consent screen for `prompt=consent`.
- [ ] Resolve consent reference ID from post-login hook.
- [ ] Skip consent when client has `skipConsent`.
- [ ] Lookup existing consent by client, user, and optional reference ID.
- [ ] Require consent when no consent exists or requested scopes exceed granted scopes.
- [ ] Return `consent_required` when `prompt=none` and consent is required.
- [ ] Create single-use authorization code with hashed stored identifier.
- [ ] Store authorization-code verification value with original query, user ID, session ID, reference ID, and auth time.
- [ ] Redirect back to client with `code`, original `state`, and `iss`.
- [ ] Format OAuth error redirects with `error`, `error_description`, optional `state`, and `iss`.
- [ ] Validate issuer URL by forcing HTTPS for non-loopback, stripping query/fragment, and trimming trailing slash.
- [ ] Return JSON redirect shape for fetch/API requests and real redirects for navigation requests.

## Consent And Continuation Checklist

- [ ] Consent endpoint requires signed OAuth query in request state.
- [ ] Consent endpoint requires `client_id` in OAuth query.
- [ ] Consent endpoint validates accepted scopes are a subset of originally requested scopes.
- [ ] Consent denial returns `access_denied` redirect to client.
- [ ] Consent acceptance creates a new consent when none exists.
- [ ] Consent acceptance updates existing consent scopes and timestamp.
- [ ] Consent acceptance supports reference ID.
- [ ] Consent acceptance can approve fewer scopes than originally requested.
- [ ] Consent acceptance resumes authorization after removing `consent` prompt.
- [ ] Continue endpoint rejects missing continuation flags.
- [ ] Continue endpoint supports `selected=true` and removes `select_account` prompt.
- [ ] Continue endpoint supports `created=true` and removes `create` prompt.
- [ ] Continue endpoint supports `postLogin=true` and resumes authorization with post-login bypass.
- [ ] Continue endpoint returns JSON redirect shape.

## Token Endpoint Checklist

- [ ] Token endpoint dispatches by grant type.
- [ ] Reject unsupported grant types according to provider config.
- [ ] Reject missing grant type with OAuth error.
- [ ] Accept form-encoded token requests.
- [ ] Parse client credentials from HTTP Basic auth.
- [ ] Support `client_secret_post` credentials.
- [ ] Support public clients with PKCE and no secret.
- [ ] Authorization-code grant requires `client_id`, `code`, and `redirect_uri`.
- [ ] Authorization-code grant requires either valid client secret or code verifier.
- [ ] Authorization-code grant loads authorization-code verification value by hashed code.
- [ ] Authorization-code grant deletes code immediately after lookup to enforce single-use.
- [ ] Authorization-code grant rejects expired code.
- [ ] Authorization-code grant validates verification value schema.
- [ ] Authorization-code grant validates code client ID matches token request client ID.
- [ ] Authorization-code grant validates redirect URI matches original authorization request.
- [ ] Authorization-code grant validates client credentials and scope permission.
- [ ] Authorization-code grant enforces PKCE when required.
- [ ] Authorization-code grant rejects verifier absent when challenge was used.
- [ ] Authorization-code grant rejects verifier present when challenge was not used.
- [ ] Authorization-code grant verifies S256 challenge.
- [ ] Authorization-code grant rejects missing/deleted user.
- [ ] Authorization-code grant rejects missing/expired session.
- [ ] Authorization-code grant preserves original session auth time for ID token `auth_time`.
- [ ] Client credentials grant requires client ID and client secret.
- [ ] Client credentials grant rejects OIDC scopes: `openid`, `profile`, `email`, `offline_access`.
- [ ] Client credentials grant validates requested scopes against client/provider scopes.
- [ ] Client credentials grant defaults scopes from client scopes, configured M2M defaults, or provider scopes.
- [ ] Refresh token grant requires client ID and refresh token.
- [ ] Refresh token grant decodes prefix/custom formatted refresh token.
- [ ] Refresh token grant looks up hashed stored refresh token.
- [ ] Refresh token grant validates client ID matches stored refresh token.
- [ ] Refresh token grant rejects expired refresh token.
- [ ] Refresh token grant treats reuse of revoked refresh token as replay and deletes all refresh tokens for user/client.
- [ ] Refresh token grant allows same or narrower scope set only.
- [ ] Refresh token grant validates client credentials, requiring secret for confidential clients.
- [ ] Refresh token grant rejects missing/deleted user.
- [ ] Refresh token grant preserves refresh token auth time.
- [ ] Token creation validates `resource` audience against configured valid audiences.
- [ ] Token creation adds `/oauth2/userinfo` audience when `openid` scope is present.
- [ ] Token creation issues JWT access tokens when a resource/audience is requested and JWT is enabled.
- [ ] Token creation issues opaque access tokens when no audience is requested or JWT is disabled.
- [ ] Opaque access tokens are stored hashed with client/session/user/reference/refresh linkage.
- [ ] Refresh tokens are issued only for user flows with `offline_access`.
- [ ] Refresh token rotation revokes old refresh token and creates a new one.
- [ ] Opaque access tokens can be linked to refresh token ID when created before access token.
- [ ] ID tokens are issued when user flow includes `openid`.
- [ ] ID token includes normal claims, issuer, subject, audience, nonce, iat, exp, optional sid, auth_time, acr.
- [ ] ID token uses pairwise subject when configured for the client.
- [ ] ID token omits issuance for public clients when JWT plugin is disabled and there is no client secret.
- [ ] JWT-disabled ID token mode signs with HS256 using decrypted client secret.
- [ ] Custom ID token claims can override non-pinned normal/custom claims but not security claims set after custom claims.
- [ ] Custom token response fields are included in authorization-code responses.
- [ ] Custom token response fields are included in client-credentials responses.
- [ ] Custom token response fields cannot override standard OAuth fields.
- [ ] Token response includes `Cache-Control: no-store` and `Pragma: no-cache`.
- [ ] Token response includes `access_token`, `expires_in`, `expires_at`, `token_type=Bearer`, `scope`, optional `refresh_token`, optional `id_token`.

## Client Registration And Management Checklist

- [ ] Dynamic registration endpoint is forbidden when disabled.
- [ ] Dynamic registration requires authenticated session unless unauthenticated registration is enabled.
- [ ] Unauthenticated registration rejects `client_credentials` grant.
- [ ] Unauthenticated registration forces `token_endpoint_auth_method=none`.
- [ ] Unauthenticated registration clears `type=web` when converting confidential metadata to public.
- [ ] Registration defaults scope from configured client registration default scopes or provider scopes.
- [ ] Registration validates public/confidential type consistency.
- [ ] Registration requires redirect URIs for authorization-code flows.
- [ ] Registration validates authorization-code grant requires `code` response type.
- [ ] Registration validates `subject_type` is `public` or `pairwise`.
- [ ] Registration rejects pairwise subject type without server pairwise secret.
- [ ] Registration rejects pairwise clients with redirect URIs on different hosts until sector identifier URI support exists.
- [ ] Registration validates requested scopes against allowed scopes.
- [ ] Dynamic registration rejects `require_pkce=false`.
- [ ] Dynamic registration rejects `skip_consent`.
- [ ] Client creation generates client ID.
- [ ] Confidential client creation generates client secret.
- [ ] Public client creation omits client secret.
- [ ] Client creation stores client secret according to configured storage mode.
- [ ] Client creation applies client secret expiration for dynamic confidential clients.
- [ ] Client creation applies user ID or reference ID ownership.
- [ ] Client creation strips unsupported JWK metadata from stored schema.
- [ ] Client creation stores extra metadata in metadata JSON.
- [ ] Client creation returns RFC 7591 JSON and only returns raw client secret once.
- [ ] Client creation response uses `201`, `Cache-Control: no-store`, and `Pragma: no-cache`.
- [ ] OAuth-to-schema conversion maps all standard DCR fields to storage fields.
- [ ] Schema-to-OAuth conversion maps storage fields back to DCR response fields.
- [ ] Schema conversion round-trips subject type, metadata, scopes, expiry timestamps, and client flags.
- [ ] Authenticated create-client endpoint supports standard DCR fields.
- [ ] Admin create-client endpoint supports server-only fields: secret expiry, skip consent, end-session enablement, require PKCE, subject type, metadata.
- [ ] Get-client endpoint requires session, privileges, ownership, and never returns stored client secret.
- [ ] Public-client endpoint returns only public display fields and hides disabled clients.
- [ ] Public-client-prelogin endpoint is gated by signed OAuth query and provider option.
- [ ] List-clients endpoint lists by reference ID when configured or by user ID otherwise.
- [ ] Update-client endpoint requires session, privileges, ownership, and rejects trusted cached clients.
- [ ] Update-client endpoint returns unchanged client when update body is empty.
- [ ] Update-client endpoint validates merged client metadata before persistence.
- [ ] Update-client endpoint does not allow client secret updates.
- [ ] Update-client endpoint does not allow public/confidential auth method mutation through normal update.
- [ ] Admin update-client endpoint supports server-only update fields.
- [ ] Rotate-secret endpoint requires confidential client and rejects public clients.
- [ ] Rotate-secret endpoint stores new secret and returns raw prefixed secret once.
- [ ] Delete-client endpoint requires session, privileges, ownership, and rejects trusted cached clients.
- [ ] Client privilege hook is called for create, read, update, delete, list, and rotate actions.

## Consent Management Checklist

- [ ] Get-consent endpoint requires session.
- [ ] Get-consent endpoint requires consent ID.
- [ ] Get-consent endpoint returns not found for missing consent.
- [ ] Get-consent endpoint enforces consent owner.
- [ ] List-consents endpoint requires session and lists current user's consents.
- [ ] Update-consent endpoint requires session and owner.
- [ ] Update-consent endpoint validates updated scopes are allowed by the related client/provider.
- [ ] Update-consent endpoint updates timestamp.
- [ ] Delete-consent endpoint requires session and owner.
- [ ] Delete-consent endpoint deletes by ID.

## Introspection Checklist

- [ ] Introspection endpoint requires client credentials.
- [ ] Introspection endpoint accepts Basic credentials and post credentials.
- [ ] Introspection endpoint strips `Bearer ` prefix from token input.
- [ ] Introspection endpoint validates caller client credentials.
- [ ] Introspection tries access token when hint is absent or `access_token`.
- [ ] Introspection tries refresh token when hint is absent or `refresh_token`.
- [ ] Introspection with wrong explicit hint returns inactive/error behavior matching RFC 7662.
- [ ] JWT access token validation verifies signature through JWKS.
- [ ] JWT access token validation verifies audience and issuer.
- [ ] JWT access token validation returns inactive for expired token.
- [ ] JWT access token validation returns inactive for invalid audience/issuer.
- [ ] JWT access token validation verifies `azp` client exists, is enabled, and matches caller client when provided.
- [ ] JWT access token validation checks linked session if `sid` exists and clears session ID when expired/missing.
- [ ] Opaque access token validation strips configured prefix.
- [ ] Opaque access token validation looks up hashed token.
- [ ] Opaque access token validation returns inactive for expired token.
- [ ] Opaque access token validation verifies stored client exists, is enabled, and matches caller client.
- [ ] Opaque access token validation checks linked session and clears session ID when expired/missing.
- [ ] Opaque access token validation includes custom access token claims.
- [ ] Refresh token validation decodes prefix/custom format.
- [ ] Refresh token validation looks up hashed token.
- [ ] Refresh token validation returns inactive for wrong client, expired token, or revoked token.
- [ ] Refresh token validation checks linked session and clears session ID when expired/missing.
- [ ] Introspection response includes active, issuer, client_id, sub, sid, exp, iat, scope, and custom claims when active.
- [ ] Introspection response resolves pairwise `sub` at presentation time.
- [ ] Introspection returns `active: false` instead of leaking token parsing details for invalid tokens.

## Revocation Checklist

- [ ] Revocation endpoint requires client ID.
- [ ] Revocation endpoint requires secret for confidential clients.
- [ ] Revocation endpoint accepts Basic credentials and post credentials.
- [ ] Revocation endpoint strips `Bearer ` prefix from token input.
- [ ] Revocation endpoint validates caller client credentials.
- [ ] Revocation tries access token when hint is absent or `access_token`.
- [ ] Revocation tries refresh token when hint is absent or `refresh_token`.
- [ ] JWT access token revocation verifies token but performs no server-side deletion.
- [ ] JWT access token revocation treats expired or invalid audience/issuer as harmless no-op.
- [ ] Opaque access token revocation strips configured prefix.
- [ ] Opaque access token revocation looks up hashed token.
- [ ] Opaque access token revocation deletes token only when it belongs to caller client.
- [ ] Refresh token revocation decodes prefix/custom format.
- [ ] Refresh token revocation looks up hashed token.
- [ ] Refresh token revocation replay detection deletes all refresh tokens for user/client when already revoked token is submitted.
- [ ] Refresh token revocation deletes all access tokens linked to that refresh token.
- [ ] Refresh token revocation marks refresh token revoked.
- [ ] Revocation returns success/no body for unknown token cases allowed by RFC 7009.

## UserInfo Checklist

- [ ] UserInfo endpoint reads bearer token from authorization header.
- [ ] UserInfo endpoint rejects missing authorization token.
- [ ] UserInfo endpoint validates JWT or opaque access token through introspection utilities.
- [ ] UserInfo endpoint requires `openid` scope.
- [ ] UserInfo endpoint rejects missing subject.
- [ ] UserInfo endpoint rejects deleted/missing user.
- [ ] UserInfo normal claims always include subject.
- [ ] UserInfo includes profile claims only with `profile` scope: name, picture, given name, family name.
- [ ] UserInfo includes email claims only with `email` scope: email, email_verified.
- [ ] UserInfo resolves pairwise subject for configured pairwise clients.
- [ ] UserInfo merges custom userinfo claims.
- [ ] UserInfo supports programmatic/server calls with headers but no full HTTP request object.

## RP-Initiated Logout Checklist

- [ ] End-session endpoint requires `id_token_hint`.
- [ ] End-session endpoint accepts optional `client_id`, `post_logout_redirect_uri`, and `state`.
- [ ] End-session derives client ID from ID token audience when omitted.
- [ ] End-session rejects invalid ID token decode.
- [ ] End-session validates client exists and is not disabled.
- [ ] End-session requires client `enableEndSession`.
- [ ] End-session verifies ID token through JWKS when JWT plugin is enabled.
- [ ] End-session verifies HS256 ID token with decrypted client secret when JWT plugin is disabled.
- [ ] End-session validates issuer matches.
- [ ] End-session validates explicit client ID matches ID token audience.
- [ ] End-session requires ID token `sid`.
- [ ] End-session deletes matching session by token or ID.
- [ ] End-session treats already-deleted sessions as successful.
- [ ] End-session redirects only when `post_logout_redirect_uri` exactly matches registered URI.
- [ ] End-session appends `state` to valid post-logout redirect.
- [ ] Dynamic registration blocks `enable_end_session`; admin/server creation can enable it.

## Metadata And Discovery Checklist

- [ ] OAuth metadata returns issuer, authorization endpoint, token endpoint, JWKS URI, registration endpoint, introspection endpoint, revocation endpoint.
- [ ] OAuth metadata returns scopes supported, response types, response modes, grant types, token endpoint auth methods, introspection auth methods, revocation auth methods, S256 PKCE support, and RFC 9207 issuer parameter support.
- [ ] OAuth metadata type can represent optional service documentation, UI locales, OP policy URI, OP terms URI, and endpoint auth signing algorithm fields even if defaults omit them.
- [ ] OAuth metadata omits JWKS URI when JWT plugin is disabled.
- [ ] OAuth metadata includes `none` auth method when public unauthenticated clients are supported.
- [ ] OAuth metadata returns empty response types when authorization-code grant is disabled.
- [ ] OIDC metadata is available only when `openid` scope is configured.
- [ ] OIDC metadata includes UserInfo endpoint.
- [ ] OIDC metadata includes supported subject types, including pairwise only when pairwise secret is configured.
- [ ] OIDC metadata includes ID token signing algorithms from configured JWK algorithm, default EdDSA, or HS256 when JWT plugin is disabled.
- [ ] OIDC metadata includes claims supported from advertised metadata or derived claims.
- [ ] OIDC metadata includes end-session endpoint.
- [ ] OIDC metadata includes ACR values and prompt values.
- [ ] Standalone metadata wrappers produce JSON response with cache headers.
- [ ] Metadata wrappers resolve dynamic base URL from incoming request.
- [ ] Metadata cache control uses short public max-age with stale-while-revalidate and stale-if-error semantics.

## Protected Resource And MCP Checklist

- [ ] Protected resource metadata helper returns resource identifier and authorization server list.
- [ ] Protected resource metadata allows override of any RFC 9728 field.
- [ ] Protected resource metadata can represent JWKS URI.
- [ ] Protected resource metadata can represent bearer methods supported.
- [ ] Protected resource metadata can represent resource signing algorithms.
- [ ] Protected resource metadata can represent resource name, documentation, policy URI, and terms URI.
- [ ] Protected resource metadata can represent TLS client certificate bound access tokens.
- [ ] Protected resource metadata can represent authorization details types.
- [ ] Protected resource metadata can represent DPoP signing algorithms and DPoP required flag.
- [ ] Protected resource metadata rejects `openid` scope for resource servers.
- [ ] Protected resource metadata warns or rejects inappropriate OIDC profile/email/phone/address scopes unless silenced.
- [ ] Protected resource metadata validates scopes against provider scopes plus configured external scopes.
- [ ] Resource token verification supports local JWT verification via JWKS URL.
- [ ] Resource token verification supports remote introspection for confidential resource clients.
- [ ] Resource token verification requires explicit audience and issuer when auth context cannot infer them.
- [ ] Resource token verification maps unauthorized failures to MCP-compatible `WWW-Authenticate` header.
- [ ] MCP handler extracts bearer token and passes verified payload to protected handler.
- [ ] MCP error handler emits one `Bearer resource_metadata="..."` challenge per URL audience.
- [ ] MCP error handler supports non-URL resource metadata mappings.
- [ ] MCP error handler fails clearly when non-URL resource mapping is missing.

## Security Helpers Checklist

- [ ] Trusted client cache with expiry-aware retrieval.
- [ ] Client lookup checks trusted cache first and database second.
- [ ] Signed OAuth query verification checks signature in constant time.
- [ ] Signed OAuth query verification checks expiration.
- [ ] Client secret storage supports hashed default mode.
- [ ] Client secret storage supports encrypted mode.
- [ ] Client secret storage supports custom hash/verify implementation.
- [ ] Client secret storage supports custom encrypt/decrypt implementation.
- [ ] Client secret verification strips required configured prefix.
- [ ] Client secret verification rejects wrong prefix.
- [ ] Token storage hashes authorization codes, access tokens, and refresh tokens.
- [ ] Token lookup hashes candidate token before database lookup.
- [ ] Basic auth parser rejects malformed base64 decoded values with no colon, empty ID, or empty secret.
- [ ] Client credentials validation rejects missing client.
- [ ] Client credentials validation rejects disabled client.
- [ ] Client credentials validation requires secret for confidential clients.
- [ ] Client credentials validation rejects secret sent for public clients.
- [ ] Client credentials validation compares stored and provided secrets in constant time.
- [ ] Client credentials validation checks requested scopes against client allowed scopes.
- [ ] Prompt parser ignores unsupported prompt values.
- [ ] Pairwise sector identifier uses first redirect URI host.
- [ ] Pairwise subject uses HMAC-SHA256 over sector and user ID.
- [ ] Pairwise subject falls back to public user ID when client is public subject type or no secret is configured.
- [ ] Query serialization preserves repeated parameters as arrays.
- [ ] Prompt deletion removes only the requested prompt and preserves repeated query params.
- [ ] PKCE policy requires PKCE for public clients.
- [ ] PKCE policy requires PKCE for `offline_access`.
- [ ] PKCE policy defaults confidential clients to require PKCE unless `requirePKCE=false`.
- [ ] Timestamp normalization accepts Date-equivalent, epoch milliseconds, numeric strings, and ISO strings.
- [ ] Timestamp normalization rejects invalid values.
- [ ] Session auth-time resolution reads direct and nested `createdAt` / `created_at` values.
- [ ] Session auth-time resolution does not fall back to `updatedAt`.

## Rate Limiting Checklist

- [ ] Default `/oauth2/token` limit: 20 requests per 60 seconds.
- [ ] Default `/oauth2/authorize` limit: 30 requests per 60 seconds.
- [ ] Default `/oauth2/introspect` limit: 100 requests per 60 seconds.
- [ ] Default `/oauth2/revoke` limit: 30 requests per 60 seconds.
- [ ] Default `/oauth2/register` limit: 5 requests per 60 seconds.
- [ ] Default `/oauth2/userinfo` limit: 60 requests per 60 seconds.
- [ ] Custom rate-limit values are accepted per endpoint.
- [ ] Per-endpoint rate limiting can be disabled.
- [ ] Rate limits are applied by endpoint path, not by broad route prefixes.

## Rust Improvement Candidates

These are not mandatory copies from upstream. Mark the related checklist items complete when the Rust implementation covers upstream behavior and documents the improvement.

- [ ] Use database transactions for authorization-code consumption plus token issuance where the storage backend supports it.
- [ ] Use database transactions for refresh-token rotation plus linked opaque access-token creation/deletion where the storage backend supports it.
- [ ] Use database transactions or idempotent operations for revocation of refresh tokens and linked opaque access tokens.
- [ ] Store token hashes with domain separation by token type, and consider keyed hashing/pepper support for database-leak resistance.
- [ ] Use secret wrapper types with redacted debug output and zeroization for client secrets, refresh tokens, and signing/encryption keys.
- [ ] Prefer explicit duration types in public Rust config instead of accepting multiple timestamp input shapes.
- [ ] Make standard JWT/OAuth security claims non-overridable by construction rather than relying on merge order.
- [ ] Represent OAuth errors as typed enums with guaranteed status/body mapping.
- [ ] Expose authorization, token, introspection, revocation, and metadata logic as framework-independent services plus thin HTTP adapters.
- [ ] Add first-class Pushed Authorization Request storage/endpoint if OpenAuth wants fuller PAR support than upstream's resolver hook.
- [ ] Add sector identifier URI support for pairwise clients if OpenAuth needs multi-host pairwise clients.
- [ ] Add optional DPoP and mTLS-bound access-token support only when implemented end-to-end, not just advertised in metadata.
- [ ] Add conformance-style tests for RFC edge cases beyond upstream when behavior is security-sensitive.

## Test Coverage Checklist From Upstream

- [ ] `authorize.test.ts`: issuer URL validation.
- [ ] `authorize.test.ts`: unauthenticated authorization redirects to login.
- [ ] `authorize.test.ts`: `prompt=none` unauthenticated returns `login_required`.
- [ ] `authorize.test.ts`: PAR request URI resolution signs resolved params.
- [ ] `authorize.test.ts`: PAR ignores front-channel params not in stored request.
- [ ] `authorize.test.ts`: successful authorize includes `iss`.
- [ ] `authorize.test.ts`: error responses include `iss`.
- [ ] `authorize.test.ts`: metadata issuer matches authorization response issuer.
- [ ] `authorize.test.ts`: `prompt=none` with required consent returns `consent_required`.
- [ ] `oauth.test.ts`: plugin init requires JWT unless JWT requirement is disabled.
- [ ] `oauth.test.ts`: secondary storage requires DB-backed sessions.
- [ ] `oauth.test.ts`: dynamic base URL init behavior.
- [ ] `oauth.test.ts`: generic OAuth sign-in/discovery integration against provider.
- [ ] `oauth.test.ts`: fetch-based login returns JSON redirect.
- [ ] `oauth.test.ts`: navigation/html login returns HTTP redirect.
- [ ] `oauth.test.ts`: deleted/disabled client during OAuth flow returns JSON error redirect.
- [ ] `oauth.test.ts`: prompt flows for login, create, consent, select_account, none, and post-login.
- [ ] `oauth.test.ts`: config validation for scopes, advertised metadata, grants, storage modes, and issuers.
- [ ] `oauth.test.ts`: default/custom/disabled rate limits.
- [ ] `pkce-optional.test.ts`: public clients always require PKCE.
- [ ] `pkce-optional.test.ts`: confidential clients require PKCE by default.
- [ ] `pkce-optional.test.ts`: confidential clients can opt out of PKCE for non-offline flows.
- [ ] `pkce-optional.test.ts`: `offline_access` always requires PKCE.
- [ ] `pkce-optional.test.ts`: PKCE auth/token consistency checks.
- [ ] `pkce-optional.test.ts`: mismatched PKCE challenge rejection.
- [ ] `pkce-optional.test.ts`: admin create persists `require_pkce`.
- [ ] `token.test.ts`: authorization-code exchange for openid/profile/email/offline_access combinations.
- [ ] `token.test.ts`: authorization-code exchange without state.
- [ ] `token.test.ts`: JWT vs opaque access token issuance based on resource.
- [ ] `token.test.ts`: refresh with same scopes and narrower scopes.
- [ ] `token.test.ts`: refresh cannot expand scopes.
- [ ] `token.test.ts`: refresh token replay protection.
- [ ] `token.test.ts`: client credentials opaque and JWT tokens.
- [ ] `token.test.ts`: custom ID token claims and pinned security claim precedence.
- [ ] `token.test.ts`: token prefixes for opaque access, refresh, and client secret.
- [ ] `token.test.ts`: encrypted client secret mismatch and custom decrypt error handling.
- [ ] `token.test.ts`: loopback redirect URI port/path behavior.
- [ ] `token.test.ts`: scope preservation through authorization-code flow.
- [ ] `token.test.ts`: custom token response fields.
- [ ] `token.test.ts`: verification value schema strict required fields with passthrough extensibility.
- [ ] `introspect.test.ts`: unauthenticated introspection failure.
- [ ] `introspect.test.ts`: JWT access token introspection.
- [ ] `introspect.test.ts`: opaque access token introspection.
- [ ] `introspect.test.ts`: refresh token introspection.
- [ ] `introspect.test.ts`: wrong token type hints.
- [ ] `introspect.test.ts`: introspection without hints.
- [ ] `introspect.test.ts`: tokens remain introspectable with logged-out user/session handling.
- [ ] `introspect.test.ts`: access and refresh token prefix handling.
- [ ] `revoke.test.ts`: unauthenticated revocation failure.
- [ ] `revoke.test.ts`: JWT, opaque access, and refresh token revocation.
- [ ] `revoke.test.ts`: wrong token type hints.
- [ ] `revoke.test.ts`: revocation without hints.
- [ ] `revoke.test.ts`: access and refresh token prefix handling.
- [ ] `userinfo.test.ts`: unauthenticated UserInfo failure.
- [ ] `userinfo.test.ts`: UserInfo requires openid scope.
- [ ] `userinfo.test.ts`: opaque and JWT access token UserInfo.
- [ ] `userinfo.test.ts`: server API UserInfo with headers only.
- [ ] `userinfo.test.ts`: scope-filtered UserInfo for sub-only, profile-only, and email-only.
- [ ] `logout.test.ts`: invalid ID token hint failure.
- [ ] `logout.test.ts`: dynamic registration cannot enable RP-initiated logout.
- [ ] `logout.test.ts`: logout requires client enablement.
- [ ] `logout.test.ts`: logout succeeds with JWT plugin.
- [ ] `logout.test.ts`: logout redirects to registered post-logout URI.
- [ ] `logout.test.ts`: logout succeeds with JWT plugin disabled.
- [ ] `metadata.test.ts`: OIDC and OAuth metadata variants.
- [ ] `metadata.test.ts`: advertised metadata scopes and claims.
- [ ] `metadata.test.ts`: remote JWKS URL.
- [ ] `metadata.test.ts`: disabled JWT plugin metadata.
- [ ] `metadata.test.ts`: dynamic base URL metadata wrappers.
- [ ] `metadata.test.ts`: protected resource metadata validation.
- [ ] `register.test.ts`: missing body, unauthenticated, and authenticated registration.
- [ ] `register.test.ts`: type/grant/response validation.
- [ ] `register.test.ts`: confidential and public registration behavior.
- [ ] `register.test.ts`: metadata persistence and unknown field stripping.
- [ ] `register.test.ts`: unauthenticated DCR auth-method override.
- [ ] `register.test.ts`: unauthenticated DCR full PKCE flow.
- [ ] `register.test.ts`: organization/reference client ownership.
- [ ] `register.test.ts`: skip consent blocked in DCR.
- [ ] `oauthClient/endpoints.test.ts`: client create/get/public/prelogin/list/update/rotate/delete.
- [ ] `oauthClient/endpoints.test.ts`: client cannot become public through update.
- [ ] `oauthClient/endpoints.test.ts`: client secret cannot be updated directly.
- [ ] `oauthClient/endpoints-privileges.test.ts`: client privilege hook for all client management actions.
- [ ] `oauthConsent/endpoints.test.ts`: consent create/get/list/update/delete.
- [ ] `oauthConsent/endpoints.test.ts`: update rejects scopes not granted to client.
- [ ] `pairwise.test.ts`: pairwise cross-RP unlinkability.
- [ ] `pairwise.test.ts`: pairwise determinism for same client.
- [ ] `pairwise.test.ts`: public subject fallback.
- [ ] `pairwise.test.ts`: same-host sector behavior.
- [ ] `pairwise.test.ts`: consistent subject between ID token and UserInfo.
- [ ] `pairwise.test.ts`: introspection and refresh behavior with pairwise subjects.
- [ ] `pairwise.test.ts`: JWT access token keeps real user ID as subject.
- [ ] `pairwise.test.ts`: DCR validation for pairwise subject type and sector hosts.
- [ ] `pairwise.test.ts`: pairwise secret length validation and metadata.
- [ ] `mcp.test.ts`: MCP bearer challenge header generation.
- [ ] `mcp.test.ts`: bad access token maps to protected-resource challenge.
- [ ] `mcp.test.ts`: server-client MCP OAuth flow with dynamic registration.
- [ ] `mcp.test.ts`: authenticated MCP resource access.
- [ ] `utils/timestamps.test.ts`: timestamp normalization and auth-time resolution.
- [ ] `utils/query-serialization.test.ts`: repeated query parameter preservation and prompt deletion.
- [ ] `types/zod.test.ts`: safe redirect URL validation.

## Excluded From This Server Plan

- [ ] Browser fetch plugin behavior from `src/client.ts`, except the server must support signed `oauth_query` parameters produced by clients.
- [ ] TypeScript package build, `tsdown`, `vitest`, and package export mechanics.
- [ ] Better Auth client SDK ergonomics that are not necessary for Rust server behavior.
- [ ] TypeScript-only inference helpers.

## Implementation Order Recommendation

- [ ] Build typed config, storage models, errors, validators, and helper utilities first.
- [ ] Add client registration and client management before authorization flow.
- [ ] Add authorization, consent, continuation, and authorization-code storage.
- [ ] Add token endpoint with authorization-code grant first, then refresh token, then client credentials.
- [ ] Add metadata discovery once configured endpoints and types are stable.
- [ ] Add introspection, revocation, UserInfo, and logout.
- [ ] Add pairwise subject support once ID token/UserInfo/introspection paths exist.
- [ ] Add protected resource metadata and MCP bearer challenge behavior.
- [ ] Add rate limiting and final integration tests across the full flow.

## Self-Review

- [ ] Spec coverage checked against every upstream source file under `packages/oauth-provider/src`.
- [ ] Browser-only and TypeScript-only behavior excluded from the server checklist.
- [ ] Dependencies that drive functionality are listed with Rust-equivalent decisions required.
- [ ] Tests are grouped by upstream test file and behavior, not by every individual assertion.
- [ ] Checklist is implementation-agnostic and can be reused to mark completion in other projects.
