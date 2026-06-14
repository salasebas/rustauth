# Upstream parity — rustauth-axum

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
RustAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `better-auth` (`better-auth/node`, `better-auth/next-js`, `better-auth/svelte-kit`, `better-auth/solid-start`) |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/better-auth/src/integrations/` + `src/auth/base.ts` (`handler`) + `src/utils/url.ts` (proxy/base URL) |
| **Rust crate** | `crates/rustauth-axum/` (`src/{router,request,response,options,error}.rs`) |
| **Parity level** | High (HTTP mount + request/response bridge) |
| **Scope** | Server-side only: mount RustAuth under `base_path`, collect request bodies, propagate `ConnectInfo` IP, opt-in public URL inference, preserve HTTP metadata on responses. Auth routes, CSRF, cookies, and rate-limit policy live in `rustauth` / `rustauth-core`. |

## Summary

Upstream exposes thin server adapters that delegate to `auth.handler(Request)`.
`rustauth-axum` is the Axum equivalent: catch-all routing, Axum↔`ApiRequest`/
`ApiResponse` conversion, and adapter-only hardening (body limits, build-time mount
validation). Closest upstream shapes are `toNextJsHandler`, `toSvelteKitHandler`,
`toSolidStartHandler`, and `toNodeHandler` (via `better-call/node`, not vendored in
the reference tree).

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| `auth.handler(Request)` pass-through | ✅ | `handle(auth, options, request)` → `auth.handler_async` (`src/router.rs`) |
| Catch-all mount under `base_path` | ✅ | `RustAuthAxumExt::into_router` nests `any()` routes; `/` and empty `base_path` supported |
| Per-method handler maps (Next/Solid) | 🎯 | Single `any()` catch-all; same routes, different Axum idiom |
| `svelteKitHandler` / `isAuthPath` middleware | ➖ | SvelteKit-only app middleware; Axum uses `into_router` / manual `into_routes` nest |
| Headers / status / body / `Set-Cookie` | ✅ | Multi-value headers and extensions preserved (`http_contract.rs`) |
| Request body collection + limit | 🎯 | 10 MiB default; JSON `413 PAYLOAD_TOO_LARGE` (`body_limit.rs`) |
| `ConnectInfo` client IP | ✅ | Injected as `RequestClientIp`; spoofed `x-forwarded-for` ignored by default |
| `base_url` inference (unconfigured) | 🎯 | Opt-in `infer_base_url_from_request`; proxy trust is a separate adapter flag |
| Forwarded header validation | ✅ | Malicious `x-forwarded-*` rejected; falls back to `Host` (`router.rs`, `social.rs`) |
| `base_url` ↔ `base_path` consistency | 🎯 | Build-time router validation before mount (`routing.rs`) |
| `fromNodeHeaders` | 🎯 | Node `IncomingHttpHeaders` helper not exposed; Axum uses native `HeaderMap` |
| `toNodeHandler` (`better-call/node`) | ➖ | Node-specific helper; Axum-native request/response bridge is the Rust adapter surface |
| Dynamic multi-tenant `baseURL` config | ➖ | Upstream `BetterAuthOptions.baseURL` object; see `rustauth-core` |

## Test coverage

| Surface | RustAuth (Rust) | Upstream | Notes |
| --- | --- | --- | --- |
| Adapter unit tests | 10 | — | `src/router.rs` (base path, inference, validation) |
| Adapter integration tests | 42 | — | `routing.rs` (15), `adapter_regression.rs` (10), `body_limit.rs` (3), `http_contract.rs` (4), `security.rs` (6), `social.rs` (4) |
| End-to-end through Axum mount | 22 | — | `security_upstream.rs` (8), `password.rs` (3), `error_contract.rs` (3), `email_*.rs` (5), others (3) |
| Integration handler Vitest | — | **0** | No server-handler tests under `src/integrations/` |
| Related `auth.handler` proxy/base URL | adapter overlap | **5** `it()` | Adapter behavior covered by `social.rs` / `security.rs`; `to-auth-endpoints.test.ts` pipeline coverage is core scope |
| **Total (this crate)** | **74** | **0** (integrations) | Verify below |

```bash
cargo nextest run -p rustauth-axum
```

## Intentional differences

| Topic | Better Auth 1.6.9 | RustAuth | Why |
| --- | --- | --- | --- |
| Mount model | Framework route maps or `svelteKitHandler` middleware | Axum `nest` + catch-all | Idiomatic Tower composition |
| Proxy / base URL trust | `advanced.trustedProxyHeaders` on auth options | `RustAuthAxumOptions` flags | Explicit adapter-boundary opt-in |
| Unconfigured `baseURL` | Inferred inside `auth.handler` when missing | Disabled by default; opt-in inference | Safer production default |
| Request body | Host framework owns parsing | Adapter collects with structured errors | Fail-closed at auth boundary |
| Production client IP | Node socket or configured headers | `ConnectInfo` or trusted core IP headers | Fail-closed when neither is available |
| Internal handler errors | Framework-dependent | Sanitized `500` JSON (`error_contract.rs`) | No leak of internal messages in production |

## Open gaps and risks

No open server-side Axum adapter gaps remain for the Better Auth 1.6.9
integration surface.

| ID | Previous gap / risk | Status | Notes |
| --- | --- | --- | --- |
| G1 | Body-consuming Tower middleware before auth routes | Closed | Covered by `body_limit.rs`; empty drained bodies return stable `400 INVALID_REQUEST_BODY` JSON. README still warns users not to order such middleware before auth routes. |
| G2 | Production omitting `into_make_service_with_connect_info` | Closed | Covered by `security.rs` and `adapter_regression.rs`; production rate limits use `ConnectInfo`, and a real TCP listener test verifies `into_make_service_with_connect_info::<SocketAddr>()`. |
| G3 | `svelteKitHandler` / `isAuthPath` not ported | Out of scope | SvelteKit app middleware filters requests before framework resolve; Axum composition uses explicit `router` / `nest` at `base_path`. No client or SvelteKit helper belongs in this crate. |
| G4 | `better-call/node` not in reference tree | Out of scope | Node `IncomingMessage` / `ServerResponse` adaptation is external npm scope. `rustauth-axum` owns the Axum-native `Request<Body>` / `Response<Body>` bridge instead. |
| G5 | No 1:1 map to `to-auth-endpoints.test.ts` proxy suite | Core scope | `to-auth-endpoints.test.ts` exercises endpoint pipeline and trusted-proxy core behavior. Adapter-relevant proxy behavior is covered by `social.rs` / `security.rs`; the full suite is tracked in `rustauth-core`. |

## Hardening notes

- Default body limit 10 MiB; oversize → `413` JSON (`PAYLOAD_TOO_LARGE`).
- `x-forwarded-host` / `x-forwarded-proto` require both inference and `trust_proxy_headers_for_base_url`.
- Spoofed `x-forwarded-for` ignored unless core `ip_address.headers` lists it.
- `use_connect_info_for_ip(false)` in production fails closed on rate limits.
- Invalid `base_path` / mismatched `base_url` rejected at router build time.
- Do not run body-consuming middleware on auth routes before this adapter.

## Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Run `./scripts/fetch-upstream-better-auth.sh` if `reference/upstream-src/` is missing.
3. Server integration sources (`src/integrations/` — all files read):

| File | Server HTTP surface audited |
| --- | --- |
| `node.ts` | `toNodeHandler`, `fromNodeHeaders` |
| `next-js.ts` | `toNextJsHandler` |
| `svelte-kit.ts` | `toSvelteKitHandler`, `svelteKitHandler`, `isAuthPath` |
| `solid-start.ts` | `toSolidStartHandler` |
| `tanstack-start.ts`, `tanstack-start-solid.ts` | No HTTP handler exports |
| `next-js.test.ts` | Skipped (not server-handler tests) |

4. Map upstream → Rust:

| Upstream | Rust |
| --- | --- |
| `toNextJsHandler` / `toSvelteKitHandler` / `toSolidStartHandler` | `routes`, `handle_ref` (`src/router.rs`) |
| `svelteKitHandler`, `isAuthPath` | `router` / `nest` at `base_path` (no middleware filter) |
| `toNodeHandler` → `better-call/node` | `src/request.rs`, `src/response.rs` |
| `fromNodeHeaders` | Not exposed (Axum `HeaderMap` native) |
| `auth/base.ts` `handler(Request)` | `rustauth::RustAuth::handler_async` (core; called by adapter) |
| `utils/url.ts` (`getBaseURL`, proxy validation) | `router.rs` inference helpers + `rustauth-core` URL utils |

5. Map Rust tests → concern:

| Rust tests | Upstream analogue |
| --- | --- |
| `tests/routing.rs`, `tests/adapter_regression.rs` | Handler mount + extensions + plugins through HTTP |
| `tests/http_contract.rs` | Response preservation through `auth.handler` |
| `tests/body_limit.rs` | Adapter-only body collection, limit, and drained-body ordering hazard |
| `tests/security.rs`, `tests/social.rs` | `to-auth-endpoints.test.ts` proxy/base URL scenarios (partial) |
| `tests/security_upstream.rs`, auth flow tests | Core routes through mount (not integration-package scope) |

6. Add a failing Rust test before behavior changes; match status codes, error codes, and side effects.

## Audit status (server-only)

**Done** for this crate. Every server HTTP adapter export under
`packages/better-auth/src/integrations/` is inventoried above; all Rust sources and
tests under `crates/rustauth-axum/` are covered. Related upstream references
(`auth/base.ts` `handler`, `utils/url.ts` proxy helpers) are mapped to
`rustauth-core` / `router.rs` where adapter-relevant.

**Out of scope (not blocking):** `better-call/node` source (external npm dep),
`to-auth-endpoints.test.ts` beyond the proxy block (core handler tests), MCP Hono
middleware in `plugins/mcp/client/adapters.ts` (plugin surface, not `integrations/`).

## Related docs

- [Crate README](./README.md) — usage and quick start
- [Parity index](../../docs/parity/README.md)
