# openauth-fred

Redis and Valkey integrations for OpenAuth-RS using `fred`.

## Status

This package is in experimental beta. URL handling, key layout, Lua script
behavior, and rate-limit contracts may change before stable release.

## What It Provides

`openauth-fred` provides the same distributed `RateLimitStore` contract as the
Redis integration, but through the `fred` client. It supports Redis and Valkey
URLs and uses Lua scripting for atomic consume decisions.

It also provides `FredSecondaryStorage`, an async key-value implementation of
OpenAuth's secondary-storage contract for sessions, verification state, SSO
state, and plugin data that can live outside the primary database.

## Rate Limit Example

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
```

## Secondary Storage Example

```rust
use std::sync::Arc;

use openauth::OpenAuth;
use openauth_fred::{FredSecondaryStorage, FredSecondaryStorageOptions};

let storage = FredSecondaryStorage::connect_with_options(
    "redis://127.0.0.1:6379",
    FredSecondaryStorageOptions {
        key_prefix: "better-auth:".to_owned(),
        ..FredSecondaryStorageOptions::default()
    },
)
.await?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .secondary_storage(Arc::new(storage))
    .build()?;
```

Secondary-storage values are stored as raw strings. JSON serialization belongs
to OpenAuth consumers. TTL values are seconds. `list_keys()` and `clear()` use
Redis `SCAN` instead of `KEYS` so operational utilities do not block large
keyspaces.

## Testing

Integration tests probe Docker Compose defaults (`redis://127.0.0.1:6379` and
`valkey://127.0.0.1:6380`) and skip unavailable default targets. If
`OPENAUTH_FRED_REDIS_URL` or `OPENAUTH_FRED_VALKEY_URL` is set, that explicit
target must be reachable and tests fail if it is not.

Use this crate when your application already uses `fred`; use `openauth-redis`
when you prefer `redis-rs`.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
