# OpenAuth

OpenAuth is a Rust authentication toolkit.

## Status

OpenAuth is experimental. APIs, crate boundaries, and behavior may change before
the project reaches a stable release.

## Rate Limiting

OpenAuth rate limiting is route-aware and uses an async atomic consume contract.
The default `Memory` backend is a Governor-backed local limiter and is best for
development, tests, and single-instance deployments.

```rust
use openauth::{OpenAuth, RateLimitOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .rate_limit(RateLimitOptions::memory().enabled(true).window(60).max(100))
    .build()?;
```

For multi-instance deployments, use a distributed `RateLimitStore` instead of
local memory. `openauth-sqlx` provides SQLx-backed stores when the application
already depends on a SQL database, and `openauth-redis` provides a Redis-backed
store for higher-throughput shared enforcement. Very high traffic deployments
can opt into hybrid mode, which runs a local Governor prefilter before the SQLx or
Redis store while keeping the distributed decision authoritative.

```rust
use openauth::{HybridRateLimitOptions, OpenAuth, RateLimitOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .rate_limit(
        RateLimitOptions::secondary_storage(redis_store)
            .window(60)
            .max(100)
            .hybrid(HybridRateLimitOptions::enabled().local_multiplier(2)),
    )
    .build()?;
```

Custom stores should implement `RateLimitStore::consume` atomically. The legacy
`RateLimitStorage` `get`/`set` adapter is kept for compatibility, but it is not
safe for distributed enforcement unless the underlying implementation provides
its own atomicity.

The existing initializer helpers remain available:

```rust
use openauth::{open_auth, OpenAuthOptions};

let auth = open_auth(OpenAuthOptions::new()
    .secret("secret-a-at-least-32-chars-long!!"))?;
```

## License

OpenAuth is licensed under the MIT License. See [LICENSE](LICENSE).
