# Changelog

All notable changes to `openauth-fred` are documented in this file.

## [Unreleased]

### Added

- `FredOpenAuthStores` shares one `fred` client between rate limiting and
  secondary storage.
- `FredOpenAuthStores::apply_to_options` wires `secondary_storage` and
  `RateLimitOptions::secondary_storage` in one call.
- Live Redis/Valkey coverage runs the shared `SecondaryStorage` contract suite,
  including `set_if_not_exists`, `compare_and_set`, `delete_if_value`, `take`,
  atomic concurrency behavior, and TTL expiry.
- `examples/full-app` Fred profiles now use `FredOpenAuthStores`, demonstrating
  shared Fred secondary storage plus distributed rate limiting.

### Fixed

- `FredSecondaryStorage::set_if_not_exists` with `Some(0)` no longer deletes
  an existing key; it is a non-destructive no-op that returns `Ok(false)`
  (OPE-163).
- `FredSecondaryStorage::set_if_not_exists` now treats Redis `SET ... NX` `OK` /
  nil replies as create-or-skip booleans instead of trying to parse the reply
  directly as a boolean.
- `FredSecondaryStorage::take` uses Redis `GETDEL` for atomic read-delete parity
  with `openauth-redis`.
- `FredRateLimitStore` rejects an empty `key_prefix` before calling Redis.
- Aligned secondary storage with `openauth-redis` by storing keys under the
  explicit `secondary:` namespace (`{key_prefix}secondary:{key}`) instead of
  `{key_prefix}{key}`. Logical keys are now portable between
  `FredSecondaryStorage` and `RedisSecondaryStorage` on a shared instance and
  prefix. This changes the physical Redis key layout: existing Fred records
  written under the old layout are not read by this version.
- Fixed `FredSecondaryStorage::clear()` deleting co-located
  `{key_prefix}rate-limit:*` keys when secondary storage and
  `FredRateLimitStore` shared the same `key_prefix` on one Redis/Valkey
  instance. `list_keys` / `clear` now scan only `{key_prefix}secondary:*`
  (OPE-37).
- Fixed `FredSecondaryStorage` so `get`, `set`, and `delete` reject an empty
  `key_prefix` instead of operating at the Redis/Valkey root namespace,
  matching the validation already enforced by `list_keys` and `clear`.

## [0.0.6] - 2026-05-24

### Added

- Added Fred-backed secondary storage support.
- Added configuration and error modules for the Fred integration.
- Added expanded rate-limit and configuration coverage.

### Changed

- Updated script and store handling for the secondary storage path.

## [0.0.5] - 2026-05-19

### Added

- Published the beta Fred integration release line.

