# rustauth-redis

Redis and Valkey integrations for RustAuth using `redis-rs`.

## What It Is

`rustauth-redis` provides Redis-compatible backing stores for RustAuth rate
limiting and secondary key-value storage. Use it when your application already
uses `redis-rs` or wants a small Redis integration.

Use `rustauth-fred` instead when your application standardizes on the `fred`
client.

## Naming

RustAuth storage backends share one vocabulary:

| Type | Role |
|------|------|
| `RedisStores` | Rate limit + secondary storage sharing one `ConnectionManager` |
| `RedisOptions` | Connection options for both stores |
| `apply_to_options` | Wire both stores into [`RustAuthOptions`] |

`RedisRustAuthStores` and `RedisRustAuthOptions` are type aliases kept for
migration.

## What It Provides

- `RedisStores`: one shared `ConnectionManager` for rate limiting and secondary
  storage (recommended entry point).
- `RedisRateLimitStore`: distributed atomic rate limiting through Lua.
- `RedisSecondaryStorage`: secondary storage for sessions, verification state,
  SSO state, and plugin data that opt into secondary storage.
- `list_keys()` / `clear()` on secondary storage (`SCAN`, matching `rustauth-fred`).
- `redis://`, `rediss://`, `valkey://`, and `valkeys://` URL support. Valkey
  schemes are normalized internally. TLS schemes (`rediss://`, `valkeys://`)
  require enabling a TLS feature; see [TLS](#tls).

## Quick Start

```rust
use rustauth::{RustAuth, RustAuthOptions};
use rustauth_redis::RedisStores;

let stores = RedisStores::connect("redis://127.0.0.1:6379").await?;

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

### Individual stores

```rust
use rustauth::{RustAuth, RustAuthOptions, RateLimitOptions};
use rustauth_redis::RedisRateLimitStore;
use std::sync::Arc;
use rustauth_redis::RedisSecondaryStorage;

let store = RedisRateLimitStore::connect("redis://127.0.0.1:6379").await?;
let storage = RedisSecondaryStorage::connect("redis://127.0.0.1:6379").await?;

let auth = RustAuth::builder()
    .options(
        RustAuthOptions::new()
            .secret("secret-a-at-least-32-chars-long!!")
            .secondary_storage(Arc::new(storage))
            .rate_limit(RateLimitOptions::secondary_storage(store).enabled(true)),
    )
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## TLS

TLS connections are opt-in. `rediss://` and `valkeys://` URLs only work when a
redis-rs TLS backend is compiled in through one of these crate features:

```toml
# rustls backend (pure Rust)
rustauth-redis = { version = "0.2.0", features = ["rustls"] }

# or native-tls backend (system TLS)
rustauth-redis = { version = "0.2.0", features = ["native-tls"] }
```

Without a TLS feature, opening a `rediss://` or `valkeys://` URL fails with an
`InvalidClientConfig` error because the TLS backend is not enabled.

## Status

Experimental beta. URL handling, key layout, Lua script behavior, and storage
contracts may change before stable release.

## Better Auth compatibility

Server-side Redis/Valkey secondary storage and rate limiting via `redis-rs`.
Aligned with Better Auth **1.6.9** where it matters for this crate; RustAuth is
not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
