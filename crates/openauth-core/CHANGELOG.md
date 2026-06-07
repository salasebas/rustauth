# Changelog

All notable changes to `openauth-core` are documented in this file.

## Unreleased

### Changed

- **Breaking:** `EmailPasswordOptions::default()` now sets `enabled: false`.
  Email/password routes reject requests until callers opt in with
  `.email_password(EmailPasswordOptions::new().enabled(true))`.
- **Breaking:** `SecondaryStorage::compare_and_set` and
  `SecondaryStorage::delete_if_value` are now required methods. Implementations
  must provide real atomic compare-and-write/delete semantics instead of
  inheriting a best-effort `get` + write default.

### Added

- Added the `test-utils` feature with a reusable `SecondaryStorage` contract
  suite that storage adapter crates can run against their live implementations.
- Added typed `AuthPlugin::with_state` / `AuthPlugin::state` support so sibling
  crates can discover plugin-owned runtime options without parsing public
  metadata.
- Added `db::ensure_executable_migration_plan`, a shared preflight that rejects
  migration plans containing non-executable warnings so every SQL adapter
  refuses warning/error plans identically before mutating the database.
- Added `cookies::create_auth_cookie` and `AuthContext::create_auth_cookie`,
  exposing the shared cookie naming and attribute policy used by `get_cookies`
  so plugins can build their own cookies with the same `cookie_prefix`,
  secure-name prefix, cross-subdomain `domain`, and `default_cookie_attributes`.
- Added `RateLimitOptions::missing_ip_policy` (`MissingIpPolicy`) to control
  behavior when rate limiting is enabled but no client IP can be resolved.
- Exposed `rate_limit::resolve_client_ip` so plugin crates that create sessions
  outside the core auth flows (e.g. passkey login) persist the same validated
  client IP instead of trusting raw forwarding headers.

### Fixed

- Fixed `/sign-in/email` so a successful sign-in with a trusted `callbackURL`
  returns `redirect: true`, the callback URL in the JSON `url` field, and a
  matching `Location` header instead of always reporting `redirect: false`.
- Ambiguous deployments fail closed unless `OpenAuthOptions::development` or
  `RUST_ENV=development|test` (including `cargo-nextest`, which sets `NEXTEST`)
  is set; production posture rejects the default secret and enables rate limits.
- OAuth authorization `state` is atomically consumed on parse.
- User-delete database hooks fail closed when delete snapshot preload errors.
- Delete-account verification rejects expired tokens.
- Secondary-storage user→session index entries expire with the backing session.
- Fixed secure-cookie session resolution so `get_session_cookie` only accepts
  the `__Secure-` prefixed name (and its legacy alias) when secure cookies are
  configured, instead of preferring the unprefixed `open-auth.session_token`
  first. This prevents a sibling app or subdomain that can write parent-domain
  cookies from shadowing the victim's secure session, and `delete_session_cookie`
  now also expires the unprefixed fallback so a planted shadow cannot keep
  forcing anonymous responses.
- Fixed `rememberMe: false` (browser-session) sessions becoming persistent
  after sensitive flows. `/change-password` with `revokeOtherSessions: true`
  and `/change-email` immediate updates previously reissued the session cookie
  with `Max-Age` (dropping the non-remembered marker), and the change-password
  replacement session was minted with the full session lifetime. These flows
  now resolve the current non-remembered state from the signed `dont_remember`
  marker and preserve it: the reissued cookie stays a browser-session cookie
  and the replacement session expires on the 1-day non-remembered window.
- Fixed social OAuth `form_post` callbacks (e.g. Apple's
  `response_mode=form_post`) being blocked by origin/CSRF checks. The POST
  `/callback/:id` endpoint now bypasses the cross-site navigation block so it
  can reflect the provider form into the GET callback, where the signed OAuth
  `state` is still validated. Other social sign-in/link POST endpoints remain
  protected.
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

