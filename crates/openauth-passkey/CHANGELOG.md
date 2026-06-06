# Changelog

All notable changes to `openauth-passkey` are documented in this file.

## [Unreleased]

### Changed

- Authentication `after_verification` callbacks now return
  `Result<(), PasskeyAuthenticationRejected>` so policy hooks can abort login
  after WebAuthn proof verification without updating the passkey counter or
  minting a session.

### Fixed

- WebAuthn registration/authentication now returns `InvalidConfig` when origin,
  `rp_id`, or derivations are missing instead of defaulting to localhost.
- Passkey management mutations require a fresh session; authentication rejects
  updates when the credential row is missing (revoked passkeys cannot sign in).
- Align passkey registration stale-session responses with Better Auth (`403` +
  `SESSION_NOT_FRESH`).
- Align passkey verification HTTP status with Better Auth for failed
  registration verification (`500` + `FAILED_TO_VERIFY_REGISTRATION`) and
  missing users after authentication (`500` + `User not found`).
- Include legacy passkeys (rows without `webauthn_credential` JSON) in
  `excludeCredentials` and session-scoped `allowCredentials` via stored
  `credential_id`.
- Pass authenticated `user_id` into authentication extension resolvers.
- Stop re-emitting session cookies on `GET /passkey/list-user-passkeys`
  (upstream returns JSON only).
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
- Fixed passkey login so the created session's IP metadata is resolved through
  the core `advanced.ip_address` resolver (header allow-listing,
  `RequestClientIp`, validation) instead of trusting the raw `X-Forwarded-For`
  header a client can prepend during `/passkey/verify-authentication`.

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

