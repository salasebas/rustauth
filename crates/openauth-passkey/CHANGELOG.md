# Changelog

All notable changes to `openauth-passkey` are documented in this file.

## [Unreleased]

### Fixed

- Fixed the WebAuthn challenge cookie to route through the core auth-cookie
  configuration (`AuthContext::create_auth_cookie`) so it inherits the
  `cookie_prefix` namespace, secure-name prefix, cross-subdomain `domain`, and
  `default_cookie_attributes` instead of using a raw, unnamespaced cookie name.
  The `PasskeyAdvancedOptions::webauthn_challenge_cookie` value is preserved as
  the cookie name segment.
- Fixed WebAuthn verification to honor the configured `user_verification` policy
  end-to-end instead of always verifying with `UserVerificationPolicy::Required`
  while advertising preferred/discouraged settings.
- Route passkey WebAuthn challenges and login sessions through the core
  storage-aware stores so deployments using `secondary_storage` (e.g. Redis)
  with `store_session_in_database(false)` can complete passwordless sign-in and
  challenge verification.

## [0.0.6] - 2026-05-24

### Added

- Added focused authentication, management, and registration route modules.
- Added expanded passkey registration, authentication, SQL, SQLite, and schema
  coverage.

### Changed

- Split passkey route handling into smaller modules and updated option and
  response handling.

## [0.0.5] - 2026-05-19

### Added

- Published the beta passkey release line.

