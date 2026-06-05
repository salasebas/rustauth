# openauth-redis

Redis and Valkey integrations for OpenAuth-RS using `redis-rs`.

## What It Is

`openauth-redis` provides Redis-compatible backing stores for OpenAuth rate
limiting and secondary key-value storage. Use it when your application already
uses `redis-rs` or wants a small Redis integration.

Use `openauth-fred` instead when your application standardizes on the `fred`
client.

## What It Provides

- `RedisRateLimitStore`: distributed atomic rate limiting through Lua.
- `RedisSecondaryStorage`: secondary storage for sessions, verification state,
  SSO state, and plugin data that opt into secondary storage.
- `RedisOpenAuthStores`: one shared `ConnectionManager` for both stores.
- `list_keys()` / `clear()` on secondary storage (`SCAN`, matching `openauth-fred`).
- `redis://`, `rediss://`, `valkey://`, and `valkeys://` URL support. TLS
  schemes (`rediss://`, `valkeys://`) require enabling a TLS feature; see
  [TLS](#tls).

## Quick Start

```rust
use openauth::{OpenAuth, RateLimitOptions};
use openauth_redis::RedisRateLimitStore;

let store = RedisRateLimitStore::connect("redis://127.0.0.1:6379").await?;

let auth = OpenAuth::builder()
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

Secondary storage is configured through `OpenAuthOptions`:

```rust
use std::sync::Arc;
use openauth::{OpenAuth, OpenAuthOptions};
use openauth_redis::RedisSecondaryStorage;

let storage = RedisSecondaryStorage::connect("redis://127.0.0.1:6379").await?;

let auth = OpenAuth::builder()
    .options(
        OpenAuthOptions::new()
            .secret("secret-a-at-least-32-chars-long!!")
            .secondary_storage(Arc::new(storage)),
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
openauth-redis = { version = "0.0.6", features = ["rustls"] }

# or native-tls backend (system TLS)
openauth-redis = { version = "0.0.6", features = ["native-tls"] }
```

Without a TLS feature, opening a `rediss://` or `valkeys://` URL fails with an
`InvalidClientConfig` error because the TLS backend is not enabled.

## Status

Experimental beta. URL handling, key layout, Lua script behavior, and storage
contracts may change before stable release.

## Upstream parity (Better Auth 1.6.9)

Upstream: `@better-auth/redis-storage` (ioredis). Sibling crate: `openauth-fred`
(same contract, `fred` client). Secondary-storage KV adapter parity is **high**;
session payload interchange depends on `openauth-core`, not this crate.

### Status

| Area | Status | Notes |
| --- | --- | --- |
| Secondary storage (`get`/`set`/`delete`) | **High** | Prefix + `secondary:` namespace; `ttl=0` → `SET` without TTL |
| `list_keys` / `clear` | **High** | `SCAN` (not upstream `KEYS`) |
| Rate limit Redis | **Extension** | `RedisRateLimitStore` + Lua; upstream reuses secondary KV as JSON |
| Session data interchange | **Low** | Key layout and JSON differ in `openauth-core` |
| Auto rate limit on secondary only | **Gap (core)** | Upstream defaults RL to secondary; OpenAuth requires explicit wiring |

**Tests:** **19** `nextest` in this crate; email sign-up E2E with Redis in `openauth-fred`.
Upstream `packages/redis-storage/` has no package-local tests; behavior is inferred
from `redis-storage.ts` plus `better-auth/src/db/secondary-storage.test.ts`.

### Intentional differences

- `list_keys` / `clear` use `SCAN` instead of upstream `KEYS` for safer production scans.
- `RedisRateLimitStore` is a dedicated Lua-backed store; upstream reuses secondary KV as JSON.
- Default key prefix is `openauth:` (upstream defaults to `better-auth:`).
- `rediss://` / `valkeys://` TLS requires an explicit crate feature (`rustls` or `native-tls`).

### Open gaps/risks

- Session payloads are not portable to Better Auth without `openauth-core` migration.
- Rate-limit wiring is explicit in OpenAuth; upstream can default rate limiting to secondary storage.
- Wire rate-limit JSON separately from secondary storage when comparing to upstream deployments.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/redis-storage/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-redis/src/` to `redis-storage.ts` and shared secondary-storage tests under `packages/better-auth/src/db/`.
4. Add a failing Rust integration test before changing behavior; match key layout, TTL semantics, and storage side effects—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
