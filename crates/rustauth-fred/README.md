# rustauth-fred

Redis and Valkey integrations for RustAuth using `fred`.

## What It Is

`rustauth-fred` provides the same Redis-compatible RustAuth integration points
as `rustauth-redis`, but through the `fred` client. Use it when your
application already uses `fred` or wants Valkey/Redis support through that
client ecosystem.

## Naming

RustAuth storage backends share one vocabulary:

| Type | Role |
|------|------|
| `FredStores` | Rate limit + secondary storage sharing one `fred` client |
| `FredOptions` | Connection options for both stores |
| `apply_to_options` | Wire both stores into [`RustAuthOptions`] |

`FredRustAuthStores` and `FredRustAuthOptions` are type aliases kept for
migration.

## What It Provides

- `FredStores`: one shared `fred` client for rate limiting and secondary storage
  (recommended entry point).
- `FredRateLimitStore`: distributed atomic rate limiting through Lua.
- `FredSecondaryStorage`: secondary key-value storage for sessions,
  verification state, SSO state, and plugin data.
- `list_keys()` / `clear()` on secondary storage (`SCAN`, not `KEYS`).
- Redis and Valkey URL normalization (internal; pass `valkey://` URLs directly
  to `connect`).
- Optional `native-tls` and `rustls` feature flags forwarded to `fred`.

## Quick Start

```rust
use rustauth::{RustAuth, RustAuthOptions};
use rustauth_fred::FredStores;

let stores = FredStores::connect("valkey://127.0.0.1:6379").await?;

let auth = RustAuth::builder()
    .options(stores.apply_to_options(
        RustAuthOptions::new().secret("secret-a-at-least-32-chars-long!!"),
    ))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`apply_to_options` wires both `secondary_storage` and distributed rate limiting
in one call.

### Individual store

```rust
use rustauth::{RustAuth, RateLimitOptions};
use rustauth_fred::FredRateLimitStore;

let store = FredRateLimitStore::connect("redis://127.0.0.1:6379").await?;

let auth = RustAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .rate_limit(
        RateLimitOptions::secondary_storage(store)
            .enabled(true)
            .window(60)
            .max(100),
    )
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Secondary storage uses raw string values and TTLs in seconds. Operational
helpers such as `list_keys()` and `clear()` use `SCAN` instead of `KEYS`.

## Status

Experimental beta. URL handling, key layout, Lua script behavior, and
rate-limit/secondary-storage contracts may change before stable release.

## Better Auth compatibility

Server-side Redis/Valkey secondary storage and rate limiting via `fred`. Aligned
with Better Auth **1.6.9** where it matters for this crate; RustAuth is not a
line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Sibling crate `rustauth-redis`](../rustauth-redis/README.md)
- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
