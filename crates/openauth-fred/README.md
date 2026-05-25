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

## Status

Experimental beta. URL handling, key layout, Lua script behavior, and
rate-limit/secondary-storage contracts may change before stable release.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
