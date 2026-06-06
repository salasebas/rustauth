# openauth-core — Better Auth upstream parity

| Field | Value |
| --- | --- |
| **Parity pin** | Better Auth **1.6.9** ([`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md)) |
| **Upstream packages** | `@better-auth/core` + `better-auth` server runtime (see scope boundary) |
| **Rust crate** | `openauth-core` |
| **Parity level** | **High** (core server contracts); **Partial** (options depth, session tests, output filtering) |
| **Audit status** | **Complete** (server-only inventory, 2026-06-05) — all in-scope files classified; gaps below are implementation deltas, not missing review |

## Summary

OpenAuth merges `@better-auth/core` and the `better-auth` server runtime into one crate.
Core HTTP paths, verification storage, cookies, crypto, adapter traits, plugin DB hooks,
and rate limiting align closely with 1.6.9. Documented gaps are behavioral (session
test depth, `shouldSkipSessionRefresh`, output field filtering on responses, dynamic
options callbacks) — not unreviewed files.

## Scope boundary (server-only)

| Upstream path | Disposition |
| --- | --- |
| `packages/core/src/{db,api,context,error,env,utils}/` | **In scope** → `openauth-core` |
| `packages/better-auth/src/{api,cookies,crypto,context,auth,db,oauth2,state,utils}/` | **In scope** → `openauth-core` |
| `packages/core/src/oauth2/` | **Sibling** → `openauth-oauth` |
| `packages/core/src/social-providers/`, `better-auth/src/social-providers/` | **Sibling** → `openauth-social-providers` |
| `packages/core/src/instrumentation/` | **Sibling** → `openauth-telemetry` |
| `better-auth/src/plugins/` | **Sibling** → `openauth-plugins` |
| `better-auth/src/adapters/` | **Sibling** → `openauth-sqlx`, `tokio-postgres`, … |
| `better-auth/src/integrations/` | **Sibling** → `openauth-axum` |
| `better-auth/src/auth/{full,minimal}.ts`, `auth/base.ts` handler loop | **Sibling** → `openauth` facade |
| `better-auth/src/test-utils/`, `*.test.ts` | Test harness — not parity surface |
| `better-auth/src/types/*.ts`, `db/to-zod.ts`, `db/field.ts` | Schema/inference helpers — no runtime parity target |

**Inventory:** 143 Rust `src/*.rs`, 81 test files, 55 upstream `@better-auth/core` server
`.ts`, 98 upstream `better-auth` server `.ts` (excl. `client/`, `plugins/`) — all mapped.

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| Core HTTP routes | ✅ | `core_auth_async_endpoints` — same paths as upstream core routes |
| Session routes | ⚠️ | Implemented; 9 Rust vs 56 upstream `session-api` tests |
| Password / email verification / delete-user | ✅ | Route + service layers |
| Cookies & chunked store | ✅ | `ChunkedCookieStore`, cache, defer/disable refresh |
| Crypto (password, JWT/JWE, secrets) | ⚠️ | Implemented; secret rotation: 8 Rust vs 38 upstream tests |
| Verification token storage | ✅ | `verification.rs` + `VerificationStore` |
| Secondary session storage | ✅ | `session.rs` + optional storage index |
| DB adapter traits & `MemoryAdapter` | ✅ | Contract + reference impl |
| DB mutation hooks | ✅ | `db/hooks/`, `with-hooks` parity |
| Internal adapter (user/session/verification CRUD) | ⚠️ | Missing `listUsers`, `countTotalUsers`, batch `findSessions`, `refreshUserSessions` on user update |
| Schema output on responses | ⚠️ | `filter_output_fields` exists but not wired on route JSON; upstream `parseUserOutput`/`parseSessionOutput` on every response |
| Rate limiting | ✅ | Router-level; Redis via `openauth-redis` for multi-instance |
| CSRF / origin guards | ✅ | `api/security.rs` |
| Trusted origins (static + request-aware) | ✅ | `auth/trusted_origins.rs` |
| Request-scoped state | ✅ | `define_request_state`, session user/path |
| Skip session refresh (per-request) | ❌ | `api/state/should-session-refresh.ts` not wired (G3) |
| `freshSessionMiddleware` | ⚠️ | `fresh_age` on delete-user only (G2) |
| `requireResourceOwnership` middleware | ❌ | Upstream `api/middlewares/authorization.ts` — no core export (G7) |
| `onAPIError` hook | ⚠️ | `throw`, redirect, custom handler ✅; `customizeDefaultErrorPage` ❌ (G10) |
| OAuth link-account / state | ⚠️ | `auth/oauth/*`; missing `oauthState` CSRF field, `skipStateCookieCheck` (G11) |
| OAuth / social HTTP routes | ⚠️ | Feature `oauth`; providers in sibling crate |
| Options / context init | ⚠️ | No dynamic `baseURL`, async `trustedOrigins`/`trustedProviders`, `trustedProxyHeaders` (G12) |
| Plugin schema merge | ✅ | `plugin/schema.rs`, `context/plugins.rs` |
| Plugin migration metadata | ⚠️ | Names only; upstream supports migration objects (G13) |
| Router / plugin pipeline | ✅ | `router.rs`, `plugin_pipeline.rs` vs `api/index.ts` |
| OpenAPI metadata | ⚠️ | Core routes exposed; incomplete vs upstream |
| Programmatic `auth.api` / endpoint caller | ➖ | `openauth` facade — HTTP router is the Rust integration surface |

## Test coverage

| Surface | OpenAuth | Upstream | Notes |
| --- | ---: | ---: | --- |
| Crate total | 541 | — | ~491 in-scope excl. feature-gated OAuth/social suites |
| `@better-auth/core` server | — | 148 `it()` | Excl. `oauth2/`, `instrumentation/`, `social-providers/` |
| `better-auth` server runtime | — | ~798 `it()` | Excl. `plugins/` |
| HTTP routes | 116 | 177 | `session-api.test.ts`: 56 |
| Context / init | 25 | 115 | `create-context.test.ts` |
| DB layer | 140 | 56+ | `internal-adapter.test.ts`: 33 |
| Cookies | 31 | 54 | |
| Crypto / secrets | 39 | 50+ | `secret-rotation.test.ts`: 38 |
| Auth / OAuth | 35 | 55+ | `social.test.ts`: 40; `link-account.test.ts`: 15 |
| Middleware / rate limit | 34 | 52 | |
| Router / pipeline | 44+ | 51+ | `to-auth-endpoints.test.ts` |
| Options | 11 | (in context) | |
| `onAPIError` | 2 | partial | `tests/api/router.rs` |

```bash
cargo nextest run -p openauth-core
```

Match HTTP status, error codes, cookie names, and DB mutations.

## Intentional differences

| Topic | Better Auth | OpenAuth | Why |
| --- | --- | --- | --- |
| Trusted providers | array or function | `trusted_providers: Vec<String>` | Dynamic callback API not yet public |
| Error payloads | upstream string shapes | typed JSON / redirect | equivalent security behavior |
| SQL identifiers | flexible Kysely style | strict ASCII; reject invalid | fail-closed SQL boundary |
| `LIKE` filters | wildcards from input | escape `%`, `_`, `\` | untrusted input cannot broaden queries |
| `GET /ok` | JSON `{"ok": true}` | plain-text `OK` | minimal liveness probe |
| Request state | `AsyncLocalStorage` | Tokio `task_local` | idiomatic async Rust |
| Schema validation | Zod (`to-zod.ts`) | JSON Schema / OpenAPI | different stack, same routes |

## Open gaps / risks

| ID | Gap | Severity | Notes |
| --- | --- | --- | --- |
| G1 | Session route test depth | Medium | cookie-cache refresh, chunked read path, `needsRefresh` |
| G2 | Reusable fresh-session middleware | Medium | upstream pluggable; Rust only on delete-user |
| G3 | `shouldSkipSessionRefresh` | Medium | per-request flag in upstream `get-session` |
| G4 | Context/options init coverage | Medium | 115 upstream context tests vs shallow Rust options |
| G5 | CSRF/origin in route tests | Low | helpers disable checks; code in `api/security.rs` |
| G6 | Distributed rate limits | Medium | in-memory default; use `openauth-redis` |
| G7 | `requireResourceOwnership` | Low | plugin resource checks |
| G8 | Secret rotation test depth | Low | 8 vs 38 upstream |
| G9 | Dynamic `trustedProviders` | Low | needs callback API or per-request `AuthContext` |
| G10 | Error page theming | Low | `customizeDefaultErrorPage` not implemented |
| G11 | OAuth state hardening | Low | `oauthState` CSRF nonce, `skipStateCookieCheck` |
| G12 | Dynamic `baseURL` / async origins | Medium | `auth/base.ts` per-request clone — in `openauth` facade |
| G13 | Plugin migration bodies | Low | names collected; SQL execution in adapter crates |
| G14 | Output field filtering on routes | Medium | `filter_output_fields` not applied to JSON responses |
| G15 | Internal adapter admin queries | Low | `listUsers`, `countTotalUsers`, batch session find |

## Hardening

- OAuth implicit linking in `handle_oauth_user_info` (verified-email, trusted-provider gate,
  `disable_implicit_linking` fail-closed).
- SQL `LIKE`/`ILIKE` escaping and per-segment identifier quoting.
- Production fail-closed on ambiguous deployment + default secrets.
- Chunked cookie split/join (`cookies/chunked.rs`).

## Upstream lookup

1. Pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Fetch: `./scripts/fetch-upstream-better-auth.sh` →
   `reference/upstream-src/1.6.9/repository/`.
3. Compare in-scope paths only (scope boundary table above).
4. Map by HTTP path and `*.test.ts` → `src/` and `tests/`.

### Upstream → Rust mapping

| Upstream | Rust |
| --- | --- |
| `packages/core/src/db/` | `src/db/` |
| `packages/core/src/api/` | `src/api/endpoint.rs`, `src/plugin/endpoint.rs` |
| `packages/core/src/context/` | `src/context/` |
| `packages/core/src/error/`, `env/`, `utils/` | `src/error*.rs`, `env/`, `utils/` |
| `packages/better-auth/src/api/routes/` | `src/api/routes/` |
| `packages/better-auth/src/api/middlewares/origin-check.ts` | `src/api/security.rs` |
| `packages/better-auth/src/api/middlewares/authorization.ts` | — (G7) |
| `packages/better-auth/src/api/rate-limiter/` | `src/rate_limit.rs` |
| `packages/better-auth/src/api/index.ts`, `to-auth-endpoints.ts` | `src/api/router.rs`, `plugin_pipeline.rs` |
| `packages/better-auth/src/api/state/` | `src/context/request_state.rs`, `auth/oauth/state.rs` |
| `packages/better-auth/src/cookies/`, `crypto/` | `src/cookies/`, `crypto/` |
| `packages/better-auth/src/context/` | `src/context/builder.rs`, `secrets.rs` |
| `packages/better-auth/src/auth/trusted-origins.ts` | `src/auth/trusted_origins.rs` |
| `packages/better-auth/src/db/` | `src/db/`, `session.rs`, `verification.rs` |
| `packages/better-auth/src/oauth2/link-account.ts` | `src/auth/oauth/account_linking.rs` |
| `packages/better-auth/src/state.ts` | `src/auth/oauth/state.rs` |
| `packages/better-auth/src/utils/url.ts`, `get-request-ip.ts` | `src/utils/url.rs`, `ip.rs` |
| `packages/core/src/db/plugin.ts` | `src/plugin/schema.rs` |
| `packages/better-auth/src/options` (via `init-options`) | `src/options/*` |
| `packages/better-auth/src/api/routes/error.ts` + `onAPIError` | `api/on_api_error.rs`, `routes/error.rs` |

## Links

- [Crate README](./README.md)
- [Parity index](../../docs/parity/README.md)
