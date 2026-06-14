# rustauth-axum

Axum adapter for RustAuth.

## What It Is

`rustauth-axum` mounts the framework-neutral RustAuth handler into an Axum
application. Use it when your server is built with Axum and you want RustAuth
routes under a path such as `/api/auth`.

## What It Provides

- [`RustAuthAxumExt`](crate::RustAuthAxumExt) — `mount_routes` and `mount_at_base_path`
  for mounting on both [`RustAuth`](rustauth::RustAuth) and [`Arc<RustAuth>`](rustauth::RustAuth).
  Both take [`RustAuthAxumOptions`](crate::RustAuthAxumOptions) explicitly (use
  `RustAuthAxumOptions::default()` for defaults).
- [`handle`](crate::handle) — escape hatch for single-request integration without building
  a router; takes `RustAuthAxumOptions` as the second argument.
- [`RustAuthAxumOptions`](crate::RustAuthAxumOptions) — request body limits, ConnectInfo
  propagation, and optional base URL inference behind explicit proxy trust.
- Request and response conversion that preserves headers, extensions, and HTTP
  metadata.

## Quick Start

```rust
use rustauth::prelude::*;
use rustauth_axum::RustAuthAxumExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .base_url("https://app.example.com/api/auth")
        .build()
        .await?;

    // Apply schema with `rustauth db migrate` before serving traffic.

    let app = auth.mount_at_base_path(
        RustAuthAxumOptions::new().body_limit(1024 * 1024),
    )?;
    # let _ = app;
    Ok(())
}
```

When Axum is exposed directly to clients, run it with connection info so
RustAuth can use the real peer socket IP for rate limiting:

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

## Choosing a mount API

| Goal | API | Notes |
|------|-----|-------|
| Standalone auth server | `auth.mount_at_base_path(RustAuthAxumOptions::default())` | Nests at `base_path` |
| Shared `Arc<RustAuth>` in app state | `auth.mount_routes(RustAuthAxumOptions::default())` + your `.nest()` | You control prefix |
| Let rustauth-axum nest | `auth.mount_at_base_path(RustAuthAxumOptions::default())` | Do not nest again |
| Custom state on auth routes | `mount_routes(options)` | Same as above |

When you nest manually with `mount_routes()`, ensure your outer
`.nest(prefix, …)` uses the same path as `RustAuthOptions::base_path` and that
`base_url` matches. The fallible mount helpers validate this; you can also call
[`validate_mount_config`](crate::validate_mount_config) explicitly before
nesting.

## Notes

- Default mount path comes from `RustAuthOptions::base_path`, falling back to
  `/api/auth`.
- `base_path("/")` and `base_path("")` mount RustAuth routes at the application
  root.
- Request bodies are collected before core and capped at 10 MiB by default.
- Configure `RustAuthOptions::base_url` for production deployments. If you
  intentionally need request-derived public URLs, enable
  `RustAuthAxumOptions::infer_base_url_from_request(true)` and configure
  trusted origins explicitly.
- Public `x-forwarded-host` and `x-forwarded-proto` headers are ignored unless
  both base URL inference and
  `RustAuthAxumOptions::trust_proxy_headers_for_base_url(true)` are enabled.
- Do not trust public `x-forwarded-for` headers unless traffic is terminated by
  a trusted reverse proxy.
- Do not run Tower/Axum body-consuming middleware on auth routes before
  `rustauth-axum` (same idea as avoiding `express.json()` before Better Auth on
  Express).

## Status

Experimental beta. Router composition, request extraction, and adapter options
may change before stable release.

## Better Auth compatibility

Server-side Axum HTTP adapter for mounting RustAuth routes. Aligned with Better
Auth **1.6.9** where it matters for this crate; RustAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
