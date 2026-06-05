# openauth-axum

Axum adapter for OpenAuth-RS.

## What It Is

`openauth-axum` mounts the framework-neutral OpenAuth handler into an Axum
application. Use it when your server is built with Axum and you want OpenAuth
routes under a path such as `/api/auth`.

## What It Provides

- `router(auth)` and `router_with_options(auth, options)` for the common mount.
- `routes(auth)` for applications that already own the mount path.
- `handle_ref` and `handle_ref_with_options` for custom integration code.
- Adapter-only options such as request body limits and Axum `ConnectInfo`
  propagation.
- Optional per-request base URL inference from `Host` or absolute request URIs
  when `OpenAuthOptions::base_url` is not configured, plus explicit opt-in
  support for trusted reverse proxy headers.
- Request and response conversion that preserves headers, extensions, and HTTP
  metadata.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_axum::{router_with_options, OpenAuthAxumOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .build()?;

let app = router_with_options(
    auth,
    OpenAuthAxumOptions::new().body_limit(1024 * 1024),
)?;
# let _ = app;
# Ok::<(), Box<dyn std::error::Error>>(())
```

When Axum is exposed directly to clients, run it with connection info so
OpenAuth can use the real peer socket IP for rate limiting:

```rust
use std::net::SocketAddr;
use axum::serve;
use tokio::net::TcpListener;

# async fn run(app: axum::Router) -> Result<(), Box<dyn std::error::Error>> {
let listener = TcpListener::bind("127.0.0.1:3000").await?;
serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
# Ok(())
# }
```

## Notes

- Default mount path comes from `OpenAuthOptions::base_path`, falling back to
  `/api/auth`.
- `base_path("/")` and `base_path("")` mount OpenAuth routes at the application
  root.
- Request bodies are collected before core and capped at 10 MiB by default.
- Configure `OpenAuthOptions::base_url` for production deployments. If you
  intentionally need request-derived public URLs, enable
  `OpenAuthAxumOptions::infer_base_url_from_request(true)` and configure
  trusted origins explicitly.
- Public `x-forwarded-host` and `x-forwarded-proto` headers are ignored unless
  both base URL inference and
  `OpenAuthAxumOptions::trust_proxy_headers_for_base_url(true)` are enabled.
- Do not trust public `x-forwarded-for` headers unless traffic is terminated by
  a trusted reverse proxy.
- Do not run Tower/Axum body-consuming middleware on auth routes before
  `openauth-axum` (same idea as avoiding `express.json()` before Better Auth on
  Express).

## Status

Experimental beta. Router composition, request extraction, and adapter options
may change before stable release.

## Upstream parity (Better Auth 1.6.9)

Parity pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
There is no `@better-auth/axum` package. This crate maps to Better Auth HTTP
integrations (`better-auth/next-js`, `better-auth/node` via `better-call/node`) and
the fetch-style `auth.handler(Request)` pattern (closest to Hono). Auth logic lives
in `openauth` / `openauth-core`; this crate only mounts and translates HTTP.

| Area | Parity | Notes |
| --- | --- | --- |
| Catch-all mount under `base_path` | High | Axum `nest` + `any()` vs upstream router delegation |
| Headers / status / body preservation | High | Web API ↔ `ApiRequest` / `ApiResponse` |
| Request body limit | Superset | 10 MiB default + JSON `413`; host-dependent upstream |
| Client IP (rate limiting) | Equivalent | `ConnectInfo<SocketAddr>` vs Node socket / headers |
| `base_url` inference | Equivalent (opt-in) | Explicit adapter flags vs implicit handler inference |
| Framework cookie plugins (Next, Svelte, …) | N/A | Server-only `Set-Cookie` responses |
| `toNextJsHandler` / RSC | N/A | TypeScript-only |
| Package tests | Superset | 72 Rust tests vs 5 Vitest in `integrations/` |

Verify: `cargo nextest run -p openauth-axum`.

### Upstream lookup

1. Pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Core HTTP handler: `reference/upstream-src/<version>/repository/packages/better-auth/src/` (`auth.handler`, route mounting).
3. Framework adapters: `packages/better-auth/src/integrations/` (Next.js, Node, Hono).
4. Map `crates/openauth-axum/src/` to fetch-style `Request`/`Response` bridging.
5. Verify: `cargo nextest run -p openauth-axum`.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
