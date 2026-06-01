# Changelog

All notable changes to `openauth-core` are documented in this file.

## Unreleased

### Added

- Added `cookies::create_auth_cookie` and `AuthContext::create_auth_cookie`,
  exposing the shared cookie naming and attribute policy used by `get_cookies`
  so plugins can build their own cookies with the same `cookie_prefix`,
  secure-name prefix, cross-subdomain `domain`, and `default_cookie_attributes`.
- Added `RateLimitOptions::missing_ip_policy` (`MissingIpPolicy`) to control
  behavior when rate limiting is enabled but no client IP can be resolved.

### Fixed

- Fixed sign-out so `SessionStore::delete_session` failures propagate to
  callers instead of always returning success while cookies are cleared.
- Fixed OAuth token encryption so `encrypt_oauth_tokens` encrypts access,
  refresh, and ID tokens exactly once at the storage boundary (no plaintext
  ID tokens or double-encrypted social sign-in tokens).
- Fixed password-reset callback handling so untrusted redirect URLs are
  rejected before issuing reset flows.
- Fixed email/password sign-up and sign-in session IP metadata to use the
  configured `advanced.ip_address` resolver (header allow-listing,
  `RequestClientIp`, validation) instead of trusting raw `X-Forwarded-For` or
  `X-Real-IP` values.
- Fixed shared SQL/Postgres rate-limit count decoding so negative persisted
  values return an adapter error instead of wrapping to huge `u64` counts.
- Fixed a rate limit bypass where enabled rate limiting was silently skipped in
  production when no client IP could be resolved (missing `RequestClientIp`
  extension or trusted IP header). Such requests now fail closed by default
  (`MissingIpPolicy::Deny`); `SharedBucket` and `Allow` policies are available
  for deployments that need a shared anonymous bucket or the legacy behavior.
  Requests with `advanced.ip_address.disable_ip_tracking` remain unaffected.
- Fixed trusted server-side dispatch so `AuthRouter::handle_async_server` can
  reach plugin `server_only` endpoints, while public `handle_async` still
  returns `404` for them.
- Fixed session cookie cache authentication so cached session data is only
  returned after the backing session token still exists and is unexpired.

## [0.0.6] - 2026-05-24

### Added

- Added route service modules for email/password, password, session, and user
  behavior.
- Added database adapter harness support, schema builder modules, join support,
  hook pipelines, and ID policy coverage.
- Added typed option modules for email/password, email verification, password,
  and session configuration.
- Added secret handling and JWE secret helpers.

### Changed

- Hardened auth flows, session storage, account linking, password routes,
  session routes, SQL schema planning, migrations, and rate limiting.
- Split large account, password, social, database factory, schema, and hook
  modules into focused units.
- Gated JOSE crypto support behind feature flags where possible.

### Fixed

- Preserved body encoding details in request errors.
- Fixed migration checks for unique constraints and table existence.

## [0.0.5] - 2026-05-19

### Added

- Published the beta core release line.

