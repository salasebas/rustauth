# Parity: `openauth-oauth` ↔ `@better-auth/core/oauth2`

**Server-only** parity documentation between OpenAuth and Better Auth **v1.6.9**.

| Field | Value |
| --- | --- |
| Upstream npm | `@better-auth/core@1.6.9` (`oauth2/` submodule) |
| Upstream path | `reference/upstream-src/1.6.9/repository/packages/core/src/oauth2/` |
| Rust crate | `crates/openauth-oauth` (`openauth-oauth` on crates.io) |
| Parity pin | [`reference/upstream-better-auth/VERSION.md`](../../../reference/upstream-better-auth/VERSION.md) |
| Related crate (AS) | [`openauth-oauth-provider`](../openauth-oauth-provider/README.md) — **out of scope here** |
| Server integration | `openauth-core/src/auth/oauth/` ↔ `better-auth/src/oauth2/` — see [05-boundary-core.md](./05-boundary-core.md) |

## Package relationship (upstream split vs OpenAuth)

Better Auth splits the OAuth ecosystem across several packages/routes. OpenAuth mirrors that split with separate crates.

| Role | Upstream Better Auth | OpenAuth |
| --- | --- | --- |
| OAuth **client** primitives (authorize URL, token exchange, PKCE, JWKS) | `@better-auth/core` → `packages/core/src/oauth2/` | **`openauth-oauth`** (this crate) |
| Social provider contract | `@better-auth/core` → `packages/core/src/social-providers/` | **`openauth-social-providers`** (separate crate) |
| OAuth state, linking, token encryption at rest | `better-auth/src/oauth2/` + `api/state/oauth.ts` | **`openauth-core/src/auth/oauth/`** |
| Generic OAuth plugin (custom IdPs) | `better-auth/src/plugins/generic-oauth/` | Core routes + `openauth-social-providers` / plugins |
| Authorization server (OAuth 2.1 / OIDC AS) | `@better-auth/oauth-provider` | **`openauth-oauth-provider`** |
| OAuth proxy (dev/preview) | `better-auth/src/plugins/oauth-proxy/` | **Not ported** (decision: server-only, no redirect proxy) |
| Browser client / nanostores | `better-auth/client`, `@better-auth/oauth-provider/client` | **N/A** (server-only) |

**This document covers only `openauth-oauth` ↔ `@better-auth/core/oauth2`.** HTTP integration (callback, sign-in) and account linking live in `openauth-core` and are documented in [05-boundary-core.md](./05-boundary-core.md) as a boundary, not as a duplicate of this crate.

## Index

| Document | Contents |
| --- | --- |
| [01-overview.md](./01-overview.md) | Executive summary, scope, parity status |
| [02-package-mapping.md](./02-package-mapping.md) | File ↔ upstream module map, dependencies, features |
| [03-api-and-features.md](./03-api-and-features.md) | Public API matrix, grants, JWT/JWKS, traits |
| [04-design-decisions.md](./04-design-decisions.md) | Intentional divergences, gaps, upstream quirks |
| [05-boundary-core.md](./05-boundary-core.md) | What is **not** in this crate (core, generic-oauth, social) |
| [06-tests.md](./06-tests.md) | Vitest ↔ Rust counts, coverage matrix |
| [07-inventory.md](./07-inventory.md) | **Exhaustive audit** function-by-function (source: code + tests) |
| [08-findings-pass2.md](./08-findings-pass2.md) | **Second pass:** `aud` introspection, `verify_access_token` wiring, generic-oauth params |
| [09-parity-closeout-2026-06.md](./09-parity-closeout-2026-06.md) | **June 2026 closeout:** closed gaps and explicit backlog |

## Quick verification

```bash
cargo fmt --all --check
cargo clippy -p openauth-oauth --all-targets -- -D warnings
cargo nextest run -p openauth-oauth
```

| Metric | Upstream (`core/oauth2`) | OpenAuth (`openauth-oauth`) |
| --- | --- | --- |
| Dedicated test files | 2 (`*.test.ts`) | 2 (`tests/*.rs`) + 1 unit module (`ssrf.rs`) |
| `it(` / `test(` | **15** | — |
| `#[test]` | — | **24** |
| `#[tokio::test]` | — | **31** |
| **Total Rust tests** | — | **57** (verified with `cargo nextest run -p openauth-oauth`) |

## Summary status (client primitives)

| Area | Parity with BA 1.6.9 | Notes |
| --- | --- | --- |
| Authorization URL + PKCE | **High** | Rust hardens protected params; upstream allows override |
| Authorization code grant | **High** | POST/Basic, `resource`, `device_id`, TikTok `client_key` |
| Refresh token grant | **High** | `refresh_token_expires_in` supported |
| Client credentials grant | **High** | Different Basic encoding upstream (see [04](./04-design-decisions.md)) |
| Token parsing (`getOAuth2Tokens`) | **High** | Rust validates types/expiry; preserves `raw` |
| `validateToken` (social JWKS) | **High** | JWKS cache shared with `verify_jws` (2026-06-01) |
| `verifyAccessToken` + introspection | **High** | Optional `aud` parity on introspect; JWS→remote fallback |
| SSRF on outbound HTTP | **Extra (Rust)** | Not in upstream core |
| Protected param denylist | **Extra (Rust)** | Security hardening |
| JWKS cache | **Improved** | Per URL + TTL; upstream: global singleton by `kid` |
| `OAuthProvider` trait | **Partial** | Rust: async `SocialOAuthProvider`; upstream: sync + callbacks |
| State / linking / encrypt at rest | **N/A here** | In `openauth-core` — see [05](./05-boundary-core.md) |
| Core unit tests | 15 | **57** — broader coverage on grants, SSRF, introspection |

Last documented audit: **2026-06-01** (Better Auth `v1.6.9`, commit `f484269`).
