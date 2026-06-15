# Upstream parity — rustauth-actix-web

Better Auth **1.6.9** behavioral reference for contributors and parity audits.
RustAuth is inspired by Better Auth; it is not a line-by-line port.

| Field | Value |
| --- | --- |
| **Parity pin** | [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md) |
| **Upstream package** | `better-auth` (`better-auth/node`, `better-auth/next-js`, `better-auth/svelte-kit`, `better-auth/solid-start`) |
| **Upstream path** | `reference/upstream-src/1.6.9/repository/packages/better-auth/src/integrations/` + `src/auth/base.ts` (`handler`) + `src/utils/url.ts` (proxy/base URL) |
| **Rust crate** | `crates/rustauth-actix-web/` (`src/{router,request,response,options,error}.rs`) |
| **Parity level** | High (HTTP mount + request/response bridge; Axum contract matrix ported) |
| **Scope** | Server-side only: mount RustAuth under `base_path`, collect request bodies, propagate peer IP, opt-in public URL inference, preserve HTTP metadata on responses. Auth routes, CSRF, cookies, and rate-limit policy live in `rustauth` / `rustauth-core`. |

## Summary

Upstream exposes thin server adapters that delegate to `auth.handler(Request)`.
`rustauth-actix-web` is the Actix Web equivalent: catch-all routing, Actix↔`ApiRequest`/
`ApiResponse` conversion, and adapter-only hardening (body limits, build-time mount
validation). Closest upstream shapes are `toNextJsHandler`, `toSvelteKitHandler`,
`toSolidStartHandler`, and `toNodeHandler`.

Status symbols are defined in the [parity index](../../docs/parity/README.md#status-symbols).

## Feature parity

| Area | Status | Notes |
| --- | --- | --- |
| `auth.handler(Request)` pass-through | ✅ | `handle(auth, options, request, payload)` → `auth.handler_async` (`src/router.rs`) |
| Catch-all mount under `base_path` | ✅ | `RustAuthActixWebExt::mount_at_base_path` nests a default-service scope |
| Per-method handler maps (Next/Solid) | 🎯 | Single default-service catch-all; same routes, different Actix idiom |
| Headers / status / body / `Set-Cookie` | ✅ | Duplicate headers preserved (`http_contract.rs`) |
| Response HTTP version | ⚠️ | Not set on Actix `HttpResponse`; Axum `http_contract` version test omitted |
| Response extensions | ⚠️ | Not preserved; Axum `preserves_response_extensions` test omitted |
| Request body collection + limit | ✅ | 10 MiB default; JSON `413 PAYLOAD_TOO_LARGE` (`body_limit.rs`) |
| Peer socket client IP | ✅ | Injected as `RequestClientIp` from `HttpRequest::peer_addr()` |
| Known request extensions | ✅ | `RequestClientIp`, `RequestBaseUrl`, `OAuthBaseUrlOverride` copied (`request.rs`, `adapter_regression.rs`) |
| Arbitrary request extensions | ⚠️ | Custom marker types not copied; use known RustAuth extension types in middleware/plugins |
| `base_url` inference (unconfigured) | ✅ | Opt-in `infer_base_url_from_request`; proxy trust is a separate adapter flag |
| Forwarded header validation | ✅ | Malicious `x-forwarded-*` rejected; falls back to `Host` (`router.rs`) |
| `base_url` ↔ `base_path` consistency | ✅ | Build-time scope validation before mount (`routing.rs`) |

## Test coverage

| Surface | RustAuth (Rust) | Notes |
| --- | --- | --- |
| Adapter unit tests | 12 | `src/router.rs` (base path, inference, validation) |
| Adapter integration tests | 64 | `routing.rs` (16), `adapter_regression.rs` (10), auth flow (29), `body_limit.rs` (3), `http_contract.rs` (3), `error_contract.rs` (3) |
| Auth flow tests | 29 | `storage_smoke.rs` (1), `email_password.rs` (1), `user_session_lifecycle.rs` (2), `session_fields.rs` (1), `accounts.rs` (1), `social.rs` (4), `password.rs` (3), `email_verification.rs` (2), `security.rs` (6), `security_upstream.rs` (8) |
| Omitted vs Axum | 2 | Response HTTP version + response extensions (Actix limitations above) |
| **Total (this crate)** | **76** | Verify below |

```bash
cargo nextest run -p rustauth-actix-web
```

## Better Auth compatibility

This crate mirrors the server integration role of Better Auth's framework
adapters. It does not re-export Better Auth client APIs.

## Intentional differences

- Actix Web uses `web::scope` + `default_service` instead of Axum `Router::route`.
- Client IP comes from `HttpRequest::peer_addr()` rather than Axum `ConnectInfo` (TCP listener test in `adapter_regression.rs` verifies rate limits).
- Response HTTP version is not set on Actix `HttpResponse` (documented in `response.rs`).
- Response extensions from `ApiResponse` are not round-tripped through Actix.
- Only RustAuth-known request extension types are copied into `ApiRequest`; arbitrary middleware marker types are not.
