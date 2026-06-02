# Parity: mcp

| Field | Value |
|-------|-------|
| Upstream | `packages/better-auth/src/plugins/mcp/` (embeds `oidcProvider`) |
| OpenAuth | `crates/openauth-plugins/src/mcp/` |
| Plugin ID | `mcp` |
| Tests | **30** OA / **36** BA `it()` (incl. upstream client adapter tests) |
| Global status | 🎯 **Intentional** — OA implements `/mcp/userinfo` + `/mcp/jwks` (upstream: metadata without handler) |

---

## Server endpoints

| Method | Route | OA | BA registered | Notes |
|--------|------|:--:|:-------------:|-------|
| GET | `/.well-known/oauth-authorization-server` | ✅ | ✅ | |
| GET | `/.well-known/oauth-protected-resource` | ✅ | ✅ | |
| POST | `/mcp/register` | ✅ | ✅ | |
| GET | `/mcp/authorize` | ✅ | ✅ | |
| POST | `/oauth2/consent` | ✅ | ✅ | BA via `oidcProvider.endpoints.oAuthConsent` |
| POST | `/mcp/token` | ✅ | ✅ | |
| GET | `/mcp/userinfo` | ✅ | metadata only | BA metadata points here; **no handler** in snapshot 1.6.9 |
| GET | `/mcp/jwks` | ✅ | metadata only | Same |
| GET | `/mcp/get-session` | ✅ | ✅ | |

Upstream `getMCPProviderMetadata` (`mcp/index.ts` L74–75) declares `userinfo_endpoint` and `jwks_uri` under `/mcp/*`. OpenAuth implements those routes in `userinfo.rs` — **parity with documented metadata**, not necessarily with upstream handlers.

---

## Upstream exports not ported (server TS)

| Export | Purpose | OpenAuth |
|--------|-----------|----------|
| `withMcpAuth` | Hono/Node resource-server middleware | ➖ N/A Rust |
| `getMCPProviderMetadata` | OIDC metadata | ✅ equivalent in `metadata.rs` |
| `mcp/client/*` | Client adapter | ➖ client-only |

---

## Schema

OAuth tables (`oauthApplication`, `oauthAccessToken`, `oauthConsent`) — aligned. Upstream reuses embedded `oidc-provider` schema; OpenAuth in `mcp/schema.rs`.

---

## Hooks

| Hook | OA | BA |
|------|:--:|:--:|
| After `*` — resume OAuth after login | ✅ | ✅ (`oidc_login_prompt` cookie) |

---

## OpenAuth tests

| File | Focus |
|---------|---------|
| `mod.rs` | registration, metadata |
| `token_hardening.rs` | PKCE, tokens |
| `consent.rs` | consent flow |
| `metadata_userinfo.rs` | userinfo |
| `login_resume.rs` | post-login resume |
| `client_helpers.rs` | helpers (not MCP TS client) |

---

## Intentional differences

- OpenAuth `/mcp/userinfo` and `/mcp/jwks` close the metadata-vs-implementation gap upstream.
- No port of `withMcpAuth` (Hono/Node ecosystem).
