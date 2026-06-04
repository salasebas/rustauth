# Changelog

All notable changes to `openauth-plugins` are documented in this file.

## Unreleased

### Fixed

- Fixed magic-link verify creating sessions with IP metadata read directly from
  raw `x-forwarded-for` / `x-real-ip` headers instead of the configured
  `advanced.ip_address` resolver, which let clients spoof stored session IPs when
  they could reach the server directly.
- Fixed the MCP token endpoint `refresh_token` grant skipping client
  authentication, so a leaked refresh token for a confidential client could
  mint new tokens without the configured secret; the grant now loads the client,
  rejects disabled clients, and requires a matching `client_secret` (via Basic or
  POST) for confidential clients while still allowing public clients to refresh
  without one.
- Fixed the CAPTCHA plugin matching configured endpoints against the full
  request URI, so a query string or fragment carrying a protected path could
  arm CAPTCHA on an unrelated route (for example
  `/get-session?next=/sign-in/email`); matching now normalizes to the routed
  pathname and compares endpoints on path-segment boundaries.
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

