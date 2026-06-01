# Changelog

All notable changes to `openauth-plugins` are documented in this file.

## Unreleased

### Fixed

- Fixed `organization.create` so unauthenticated requests cannot supply a
  `userId` to create organizations on behalf of another user.
- Fixed the API key `api-key:by-ref:*` listing index losing concurrent writes in
  pure `SecondaryStorage` mode by serializing its read/modify/write through an
  in-process per-reference lock, so concurrent create/delete no longer drop live
  keys from `/api-key/list`.

## [0.0.6] - 2026-05-24

### Added

- Added modular API key storage for database, key listing, and secondary storage
  behavior.
- Added focused organization route modules for create, delete, query, and
  update operations.
- Added focused two-factor route modules for backup codes, enable, disable, and
  TOTP behavior.
- Added integration matrix coverage for plugin behavior.

### Changed

- Modularized plugin storage and route implementations.
- Updated OpenAPI plugin behavior and generic OAuth provider wiring.

## [0.0.5] - 2026-05-19

### Added

- Published the beta plugins release line.

