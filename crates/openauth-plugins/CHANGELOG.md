# Changelog

All notable changes to `openauth-plugins` are documented in this file.

## Unreleased

### Changed

- Re-audited non-organization plugin parity against Better Auth 1.6.9 and
  clarified that API-key pure secondary-storage listing consistency across
  processes is an intentional storage-contract boundary covered by fallback or
  externally atomic storage.
- Added focused Better Auth 1.6.9 parity coverage for API-key expiry/refill,
  Email OTP current-email verification and legacy password-reset alias,
  Two-factor enable/disable session rotation, and Username validation/update
  edges.
- Added organization parity coverage for dynamic access-control custom
  resources, missing-permission reporting, creator-role guards, body-scoped
  leave behavior, create hooks that mutate organization data, and default team
  response shape.

### Fixed

- Two-factor enable with `skip_verification_on_enable` and disable now rotate
  the active session after changing the user's 2FA state.
- Email OTP verification now returns `OTP_EXPIRED` for expired stored OTPs
  instead of treating them as missing.
- Device authorization token exchange atomically consumes approved device codes.
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
  pure `SecondaryStorage` mode by using the new atomic compare-and-set storage
  contract, so multi-process create/delete races no longer drop live keys from
  `/api-key/list` on atomic backends.
- Pure `SecondaryStorage` API-key listing now prunes stale ids from the
  `api-key:by-ref:*` index when the referenced `api-key:by-id:*` record is
  missing, preventing expired or orphaned records from accumulating in the
  listing index.
- Added live Redis/Fred coverage for concurrent API-key creates in pure
  `SecondaryStorage` mode so the production backends exercise the same
  `/api-key/list` reference-index race as the in-memory regression test.
- Added `organization::provision_organization_member` so sibling crates can
  create org memberships through the organization plugin's hooks, limits, and
  role validation instead of writing `member` rows directly.

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

