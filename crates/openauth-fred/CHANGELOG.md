# Changelog

All notable changes to `openauth-fred` are documented in this file.

## [Unreleased]

### Fixed

- Aligned secondary storage with `openauth-redis` by storing keys under the
  explicit `secondary:` namespace (`{key_prefix}secondary:{key}`) instead of
  `{key_prefix}{key}`. Logical keys are now portable between
  `FredSecondaryStorage` and `RedisSecondaryStorage` on a shared instance and
  prefix. This changes the physical Redis key layout: existing Fred records
  written under the old layout are not read by this version.
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

