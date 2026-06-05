# openauth-fred

Redis and Valkey integrations for OpenAuth-RS using `fred`.

## What It Is

`openauth-fred` provides the same Redis-compatible OpenAuth integration points
as `openauth-redis`, but through the `fred` client. Use it when your
application already uses `fred` or wants Valkey/Redis support through that
client ecosystem.

## What It Provides

- `FredRateLimitStore`: distributed atomic rate limiting through Lua.
- `FredSecondaryStorage`: secondary key-value storage for sessions,
  verification state, SSO state, and plugin data.
- `FredOpenAuthStores`: one shared `fred` client for both stores.
- `list_keys()` / `clear()` on secondary storage (`SCAN`, not `KEYS`).
- Redis and Valkey URL normalization.
- Optional `native-tls` and `rustls` feature flags forwarded to `fred`.

## Quick Start

```rust
use openauth::{OpenAuth, RateLimitOptions};
use openauth_fred::FredRateLimitStore;

let store = FredRateLimitStore::connect_valkey("valkey://127.0.0.1:6379").await?;

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

Secondary storage uses raw string values and TTLs in seconds. Operational
helpers such as `list_keys()` and `clear()` use `SCAN` instead of `KEYS`.

Shared client:

```rust
use openauth::{OpenAuth, OpenAuthOptions};
use openauth_fred::FredOpenAuthStores;

let stores = FredOpenAuthStores::connect("redis://127.0.0.1:6379").await?;
let auth = OpenAuth::builder()
    .options(stores.apply_to_options(
        OpenAuthOptions::new().secret("secret-a-at-least-32-chars-long!!"),
    ))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Status

Experimental beta. URL handling, key layout, Lua script behavior, and
rate-limit/secondary-storage contracts may change before stable release.

## Upstream parity (Better Auth 1.6.9)

Upstream: `@better-auth/redis-storage` (ioredis). This crate is the Fred-client
variant; see `openauth-redis` for the `redis-rs` sibling. Estimated server parity:
**~95%** vs literal upstream adapter; **~98%** vs the OpenAuth secondary-storage
contract (namespaces, validations).

### Status

| Area | Status | Notes |
| --- | --- | --- |
| Secondary storage CRUD + TTL | **High (~95%)** | Default prefix `openauth:`; `secondary:` namespace |
| `list_keys` / `clear` | **High** | `SCAN` vs upstream `KEYS`; empty prefix rejected |
| Rate limit Redis | **Extension** | `FredRateLimitStore` + Lua; not in upstream npm package |
| Shared client | **Supported** | `FredOpenAuthStores` bundles both stores on one `fred::Client` |
| Session data interchange | **Low** | Core key layout differs from Better Auth |
| Auto rate limit on secondary only | **Gap (core)** | Requires explicit `RateLimitOptions::secondary_storage` |

**Tests:** **34** `nextest`; includes email sign-up and session flows with real Redis.
Upstream `packages/redis-storage/` has no package-local tests; behavior is inferred
from `redis-storage.ts` plus `better-auth/src/db/secondary-storage.test.ts`.

### Intentional differences

- `list_keys` / `clear` use `SCAN` instead of upstream `KEYS`; empty prefix is rejected.
- `FredRateLimitStore` is a dedicated Lua-backed store; upstream reuses secondary KV as JSON.
- `FredOpenAuthStores` shares one `fred::Client` across rate limit and secondary storage.
- Default key prefix is `openauth:` (upstream defaults to `better-auth:`).

### Open gaps/risks

- Session payload interchange depends on `openauth-core`, not this crate.
- Rate-limit wiring is explicit in OpenAuth; upstream can default rate limiting to secondary storage.
- Product parity for session payloads requires validating `openauth-core` key layout separately.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/redis-storage/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-fred/src/` to `redis-storage.ts` and shared secondary-storage tests under `packages/better-auth/src/db/`.
4. Add a failing Rust integration test before changing behavior; match key layout, TTL semantics, and storage side effects—not TypeScript types.

## Links

- [Sibling crate `openauth-redis`](../openauth-redis/README.md)
- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
