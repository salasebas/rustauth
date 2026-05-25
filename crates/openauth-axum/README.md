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
- Per-request base URL inference from `Host` or absolute request URIs when
  `OpenAuthOptions::base_url` is not configured, with explicit opt-in support
  for trusted reverse proxy headers.
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
- When `base_url` is omitted, public URLs are inferred from the request. Public
  `x-forwarded-host` and `x-forwarded-proto` headers are ignored unless
  `OpenAuthAxumOptions::trust_proxy_headers_for_base_url(true)` is enabled.
- Do not trust public `x-forwarded-for` headers unless traffic is terminated by
  a trusted reverse proxy.

## Status

Experimental beta. Router composition, request extraction, and adapter options
may change before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
