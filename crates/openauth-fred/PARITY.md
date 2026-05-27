# openauth-fred Server-Side Upstream Parity

Target upstream package: `@better-auth/redis-storage` from Better Auth 1.6.9.

This crate is considered server-side parity complete for the OpenAuth Fred
surface. The remaining differences are intentional Rust/OpenAuth design choices
or behavior delegated to upstream consumers and the `fred` client.

Estimated server-side parity: **98%**.

## Upstream Surface Covered

- Redis-backed secondary storage `get`, `set`, and `delete`.
- Optional TTL behavior: expiration is applied only for positive TTL values.
- Prefix-based storage isolation.
- Operational key listing and clearing.
- Session storage through OpenAuth email sign-up and `get-session`.
- Session storage when sessions are also stored in the database.
- Session deletion from Fred secondary storage even when database sessions are
  preserved.
- Verification storage through password-reset token creation and deletion.
- Distributed rate limiting through OpenAuth's Rust-native `RateLimitStore`
  extension.

## Intentional OpenAuth Differences

- Default key prefix is `openauth:` instead of upstream `better-auth:`.
- `list_keys()` and `clear()` use Redis `SCAN` instead of upstream `KEYS` to
  avoid blocking large production keyspaces.
- Redis glob metacharacters in prefixes are escaped for `SCAN`, so prefixes are
  treated literally.
- Empty prefixes are rejected for `list_keys()` and `clear()` to avoid
  accidental whole-keyspace operations.
- `scan_count` must be greater than zero for `list_keys()` and `clear()`.
- Valkey URL aliases are supported by normalizing `valkey://` and `valkeys://`
  to Redis-compatible URLs before handing them to `fred`.
- `FredRateLimitStore` exists as an OpenAuth-specific atomic rate-limit backend;
  upstream Redis storage only provides secondary storage and lets core rate
  limiting consume it.

## Remaining Non-Blocking Gaps

- There is no TypeScript-style `redisStorage(config)` factory because the Rust
  API exposes `FredSecondaryStorage::new` and async connect constructors.
- OAuth/stateless Redis smoke cases are not duplicated inside this crate. The
  Fred crate now covers the server-side session-storage behavior those smoke
  tests assert; provider-specific OAuth behavior belongs to OpenAuth core/social
  provider tests.
- Cluster, Sentinel, and TLS deployment behavior is delegated to `fred` and the
  crate feature flags. This crate verifies URL normalization and feature wiring,
  not every Redis deployment topology.

## Verification

Scoped verification for this crate:

```bash
cargo fmt --all --check
cargo clippy -p openauth-fred --all-targets -- -D warnings
cargo nextest run -p openauth-fred
```
