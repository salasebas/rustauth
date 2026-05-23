# openauth-redis

Redis and Valkey integrations for OpenAuth-RS using `redis-rs`.

## Status

This package is in experimental beta. URL handling, key layout, Lua script
behavior, secondary-storage layout, and rate-limit contracts may change before
stable release.

## What It Provides

`openauth-redis` provides Redis/Valkey-backed integrations through `redis-rs`:

- `RedisRateLimitStore` implements distributed atomic rate limiting using Lua
  scripting.
- `RedisSecondaryStorage` implements OpenAuth secondary key-value storage for
  sessions, verification tokens, and plugin data that opt into secondary
  storage.

Both stores accept `valkey://` and `valkeys://` aliases.

## Example

```rust
use std::sync::Arc;

use openauth::{OpenAuth, OpenAuthOptions, RateLimitOptions};
use openauth_redis::{RedisRateLimitStore, RedisSecondaryStorage};

let rate_limit_store = RedisRateLimitStore::connect("redis://127.0.0.1:6379").await?;
let secondary_storage = RedisSecondaryStorage::connect("redis://127.0.0.1:6379").await?;

let auth = OpenAuth::builder()
    .options(
        OpenAuthOptions::new()
            .secret("secret-a-at-least-32-chars-long!!")
            .secondary_storage(Arc::new(secondary_storage))
            .rate_limit(
                RateLimitOptions::custom_storage(Arc::new(rate_limit_store))
                    .enabled(true)
                    .window(60)
                    .max(100),
            ),
    )
    .build()?;
```

Use this crate when your application already uses `redis-rs`; use
`openauth-fred` when you prefer the `fred` client.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
