# Changelog

All notable changes to `openauth-redis` are documented in this file.

## [Unreleased]

### Added

- `RedisOpenAuthStores` connects rate limiting and secondary storage through one
  `ConnectionManager`.
- `RedisOpenAuthStores::apply_to_options` wires `secondary_storage` and
  `RateLimitOptions::secondary_storage` in one call.
- `RedisSecondaryStorage::list_keys` and `clear` using `SCAN`, matching
  `openauth-fred`.
- `connect_with_options`, `connect_redis`, and `connect_valkey` on both stores.
- `scan_count` on `RedisSecondaryStorageOptions`.
- Live Redis/Valkey coverage runs the shared `SecondaryStorage` contract suite,
  including `set_if_not_exists`, `compare_and_set`, `delete_if_value`, `take`,
  atomic concurrency behavior, and TTL expiry.

### Fixed

- `RedisSecondaryStorage::take` uses `GETDEL` for atomic read-delete.
- `RedisSecondaryStorage::set_if_not_exists` with `Some(0)` no longer deletes
  an existing key; it is a non-destructive no-op that returns `Ok(false)`
  (OPE-163).

### Changed

- `set` with `Some(0)` deletes the key instead of storing without expiration,
  matching `openauth-core` expiry semantics and `openauth-fred`.
- Empty `key_prefix` is rejected for secondary storage and rate limit keys.
- Rate limit Lua resets the bucket when `(now - last_request) > window` (was
  `>=`), matching Better Auth `onResponseRateLimit` window rollover.

### Fixed

- Secondary storage `get`, `set`, and `delete` validate `key_prefix` before Redis
  commands.
- Made TLS connections work for documented `rediss://` and `valkeys://` URLs by
  adding opt-in `rustls` and `native-tls` crate features that enable the
  corresponding redis-rs TLS backend. Without a TLS feature these URLs now fail
  with a clear `InvalidClientConfig` error, and the README documents the
  opt-in.

## [0.0.6] - 2026-05-24

### Changed

- Updated Redis integration behavior and documentation around rate limiting.

### Fixed

- Hardened Redis rate-limit coverage.

## [0.0.5] - 2026-05-19

### Added

- Published the beta Redis integration release line.

