# Changelog

All notable changes to `openauth-fred` are documented in this file.

## Unreleased

### Fixed

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

