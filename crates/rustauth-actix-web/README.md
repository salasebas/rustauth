# rustauth-actix-web

Actix Web adapter for RustAuth.

## What It Is

`rustauth-actix-web` mounts the framework-neutral RustAuth handler into an Actix
Web application. Use it when your server is built with Actix Web and you want
RustAuth routes under a path such as `/api/auth`.

## What It Provides

- [`RustAuthActixWebExt`](crate::RustAuthActixWebExt) — `mount_routes` and
  `mount_at_base_path` for mounting on both [`RustAuth`](rustauth::RustAuth) and
  [`Arc<RustAuth>`](rustauth::RustAuth). Both take
  [`RustAuthActixWebOptions`](crate::RustAuthActixWebOptions) explicitly (use
  `RustAuthActixWebOptions::default()` for defaults).
- [`handle`](crate::handle) — escape hatch for single-request integration without
  building a scope; takes `RustAuthActixWebOptions` as the second argument.
- [`RustAuthActixWebOptions`](crate::RustAuthActixWebOptions) — request body
  limits, peer socket IP propagation, and optional base URL inference behind
  explicit proxy trust.

## Quick Start

```rust
use std::sync::Arc;

use actix_web::{App, HttpServer};
use rustauth::prelude::*;
use rustauth_actix_web::{RustAuthActixWebExt, RustAuthActixWebOptions};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth = Arc::new(
        RustAuth::builder()
            .secret("secret-a-at-least-32-chars-long!!")
            .base_url("https://app.example.com/api/auth")
            .build()
            .await
            .expect("valid RustAuth config"),
    );

    HttpServer::new(move || {
        App::new().service(
            auth.mount_at_base_path(RustAuthActixWebOptions::default())
                .expect("valid RustAuth Actix mount"),
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

When Actix Web is exposed directly to clients, ensure the server records peer
socket addresses so RustAuth can use the real client IP for rate limiting. The
adapter reads `HttpRequest::peer_addr()` when
`use_peer_addr_for_ip` is enabled (the default).

## Choosing a mount API

| Goal | API | Notes |
|------|-----|-------|
| Standalone auth server | `auth.mount_at_base_path(RustAuthActixWebOptions::default())` | Nests at `base_path` |
| Shared `Arc<RustAuth>` in app state | `auth.mount_routes(RustAuthActixWebOptions::default())` + your `.service()` nest | You control prefix |
| Let rustauth-actix-web nest | `auth.mount_at_base_path(RustAuthActixWebOptions::default())` | Do not nest again |
| Custom state on auth routes | `mount_routes(options)` | Same as above |

When you nest manually with `mount_routes()`, ensure your outer scope uses the
same path as `RustAuthOptions::base_path` and that `base_url` matches. The
fallible mount helpers validate this; you can also call
[`validate_mount_config`](crate::validate_mount_config) explicitly before
nesting.

## Notes

- Default mount path comes from `RustAuthOptions::base_path`, falling back to
  `/api/auth`.
- `base_path("/")` and `base_path("")` mount RustAuth routes at the application
  root.
- Default request body limit is 10 MiB; oversized bodies return JSON
  `413 PAYLOAD_TOO_LARGE`.
- Configure `RustAuthOptions::base_url` for production deployments. If you
  intentionally need request-derived public URLs, enable
  `RustAuthActixWebOptions::infer_base_url_from_request(true)` and configure
  trusted origins explicitly.
- Public `x-forwarded-host` and `x-forwarded-proto` headers are ignored unless
  both base URL inference and
  `RustAuthActixWebOptions::trust_proxy_headers_for_base_url(true)` are enabled.
- Do not trust public `x-forwarded-for` headers unless traffic is terminated by
  a trusted reverse proxy.
- Do not run body-consuming Actix middleware on auth routes before
  `rustauth-actix-web` (same idea as avoiding `express.json()` before Better Auth on
  Express).
- `actix-web` is pinned with `default-features = false` in the workspace; only
  the features required by this adapter are enabled.

## Actix adapter limitations

Compared to `rustauth-axum`, this adapter intentionally does not preserve:

- **Response HTTP version** — Actix `HttpResponse` has no safe response-version
  setter; status, headers, and body are preserved (`src/response.rs`).
- **Opaque response extensions** — `http::Extensions` is not iterable; custom
  `ApiResponse` extension types are not round-tripped through Actix.
- **Arbitrary request extensions** — only RustAuth-known types are copied from
  `HttpRequest` into `ApiRequest`: `RequestClientIp`, `RequestBaseUrl`, and
  `OAuthBaseUrlOverride` (`src/request.rs`). Plugin or middleware extensions
  outside that set are not forwarded unless you set one of those types explicitly.

Contract tests cover the preserved behavior; omitted Axum cases are documented in
[UPSTREAM.md](./UPSTREAM.md).

## Status

Experimental beta. Scope composition, request extraction, and adapter options
may change before stable release.

## Better Auth compatibility

Server-side Actix Web HTTP adapter for mounting RustAuth routes. Aligned with Better
Auth **1.6.9** where it matters for this crate; RustAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
