# Out of scope: client-only, oidc-provider, test-utils

This document lists upstream **plugin-scope** functionality that OpenAuth **does not port** in `openauth-plugins` and why.

---

## oidc-provider → `openauth-oauth-provider`

| Field | Detail |
|-------|--------|
| Upstream | `packages/better-auth/src/plugins/oidc-provider/` |
| OpenAuth | `crates/openauth-oauth-provider` |
| Status | **Explicitly replaced** — `tests/plugins.rs` |
| Upstream tests | ~42 (`oidc.test.ts`, `utils/prompt.test.ts`) |

### Why it is not in plugins

1. Upstream deprecated `oidc-provider` in favor of `@better-auth/oauth-provider`.
2. OIDC/OAuth2 provider is a large surface (authorize, token, consent, registration, JWKS) — deserves its own crate.
3. `mcp` reuses OAuth tables (`oauthApplication`, `oauthAccessToken`, `oauthConsent`) implemented in OpenAuth in `src/mcp/schema.rs`, not via legacy oidc-provider.

### Upstream routes (reference)

| Method | Route |
|--------|------|
| GET | `/.well-known/openid-configuration` |
| GET | `/oauth2/authorize` |
| GET/POST | `/oauth2/consent` |
| POST | `/oauth2/token` |
| GET | `/oauth2/userinfo` |
| POST | `/oauth2/register` |
| GET/DELETE | `/oauth2/client/:id` |
| GET/POST | `/oauth2/endsession` |

> Parity for that crate: document in `docs/parity/openauth-oauth-provider/` in a future iteration.

---

## test-utils

| Field | Detail |
|-------|--------|
| Upstream | `packages/better-auth/src/plugins/test-utils/` |
| OpenAuth | Not ported |
| Upstream tests | ~27 |

Helpers for Better Auth integration tests (mock auth instance, fixtures). In OpenAuth each plugin has helpers in `tests/<plugin>/helpers.rs` or shared modules in `openauth-core` test utilities.

**Decision:** not production functionality; parity not required.

---

## Client-only exports per plugin

Each upstream plugin includes `client.ts` re-exported from `better-auth/client/plugins`. OpenAuth is **server-only**; these exports are not implemented in Rust.

| Plugin | Upstream client export | What it does (client) | Server impact |
|--------|------------------------|----------------------|---------------|
| admin | `adminClient()` | Typed client for admin routes | None |
| anonymous | `anonymousClient()` | Anonymous sign-in from browser | None |
| custom-session | `customSessionClient()` | Enriched session type inference | None |
| device-authorization | `deviceAuthorizationClient()` | Poll device flow | None |
| email-otp | `emailOTPClient()` | Send/verify OTP | None |
| generic-oauth | `genericOAuthClient()` | Start OAuth2 | None |
| jwt | `jwtClient()` | Fetch token/JWKS hints | None |
| last-login-method | `lastLoginMethodClient()` | Read login-method cookie | None |
| magic-link | `magicLinkClient()` | Request magic link | None |
| mcp | `mcpAuthClient()` | Hono/Node resource-server middleware | **TS server middleware only** — no Rust equivalent in plugins |
| multi-session | `multiSessionClient()` | List/switch sessions | None |
| one-tap | `oneTapClient()` | Google One Tap UI + hooks | **Browser hooks**; server route `/one-tap/callback` is ported |
| one-time-token | `oneTimeTokenClient()` | Generate/verify OTT | None |
| organization | `organizationClient()`, `inferOrgAdditionalFields()`, `clientSideHasPermission()` | Org CRUD + client permissions | `clientSideHasPermission` is a client optimization; server has `/organization/has-permission` |
| phone-number | `phoneNumberClient()` | Phone OTP | None |
| siwe | `siweClient()` | Wallet sign-in UX | None |
| two-factor | `twoFactorClient()` | 2FA UI hooks | None |
| username | `usernameClient()` | Username sign-in | None |
| api-key | `apiKeyClient()` (`@better-auth/api-key`) | CRUD keys | None |
| oidc-provider | `oidcClient()` (deprecated) | Type inference | None |

---

## additional-fields: special case

| Aspect | Upstream | OpenAuth |
|---------|----------|----------|
| Server plugin | **Does not exist** — only `client.ts` | `additional_fields()` contributes schema + init |
| Upstream purpose | Infer TS types for extra user/session fields | SQL migrations + runtime validation |
| Upstream tests | 12 (client types) | 3 (server schema) |

**Decision:** Rust needs explicit schema for adapters; we port the server part upstream delegates to the TS ORM/adapter.

---

## MCP client middleware

Upstream `mcp/client/` provides middleware for Hono/Node servers that validate MCP/OAuth tokens.

| Component | Upstream | OpenAuth |
|------------|----------|----------|
| MCP server routes | ✅ `mcp/index.ts` | ✅ `src/mcp/` |
| Client middleware | ✅ `mcp/client/` | ➖ Not ported |
| Client tests | ~28 in `mcp-client.test.ts` | N/A |

Rust consumers should validate tokens with `openauth-core` session/JWT APIs or custom Axum middleware.

---

## TS-only functionality not portable to Rust

| Upstream feature | Exclusion reason |
|------------------|------------------|
| `$InferServerPlugin` / type inference | TS type system |
| `hideMetadata` utils | TS plugin metadata serialization |
| Dynamic `trustedProviders` per request | Not modeled yet — static `trusted_providers` |
| Closures in serializable options | Rust: callbacks yes, JSON metadata no |

See also `SERVER_PARITY.md` in the crate.

---

## Upstream monorepo packages outside `better-auth/src/plugins`

These are **not** part of the `openauth-plugins` analysis but appear in the monorepo:

| Package | OpenAuth crate |
|---------|----------------|
| `sso` | `openauth-sso` |
| `scim` | `openauth-scim` |
| `passkey` | *(planned)* |
| `stripe` | — |
| `oauth-provider` | `openauth-oauth-provider` |
| Adapters | `openauth-sqlx`, etc. |
