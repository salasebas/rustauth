# Changelog

All notable changes to the OpenAuth workspace are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

## Unreleased

### Fixed

- Fixed `rememberMe: false` sessions becoming persistent after sensitive
  account flows. `/change-password` with `revokeOtherSessions: true` and
  `/change-email` immediate email updates now preserve the non-remembered
  browser-session cookie (no `Max-Age`, `dont_remember` marker retained) and
  mint the change-password replacement session on the 1-day non-remembered
  window instead of the full session lifetime.
- Fixed `openauth-redis` documenting `rediss://`/`valkeys://` TLS URLs without
  compiling a redis-rs TLS backend, which made `connect()` fail with an
  `InvalidClientConfig` error. TLS is now opt-in through the new `rustls` and
  `native-tls` crate features, and the README documents how to enable them.
- Fixed social OAuth `form_post` callbacks (such as Apple's
  `response_mode=form_post`) being rejected with
  `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`. Only the POST `/callback/:id` endpoint
  now bypasses the cross-site navigation block so the provider form is reflected
  into the GET callback, where the signed OAuth `state` is still validated;
  other social sign-in/link POST endpoints stay protected.
- Fixed the OIDC SSO callback so it validates the ID token before trusting a
  UserInfo response. Providers with a `userInfoEndpoint` configured previously
  skipped ID token validation, allowing login and implicit account linking from
  a successful UserInfo fetch even when the token response omitted the ID token
  or returned an expired/malformed token or one with a missing/mismatched
  `nonce`. The callback now requires a valid ID token (enforcing issuer,
  audience, expiration, subject, `nonce`, and `azp`) and reconciles the UserInfo
  `sub` with the ID token subject (OIDC Core 5.3.2).
- Fixed OAuth HTTP and social-provider networking so outbound requests block
  literal private/loopback IPs by default, social userinfo calls use the
  guarded client, and ID token verification rejects opaque tokens and tokens
  missing standard JWT claims where providers verify locally.
- Fixed OAuth authorization and token request builders so generic
  `additional_params` cannot override `state`, PKCE fields, or other standard
  OAuth parameters, and HTTP Basic client credentials are form-encoded per RFC
  6749 §2.3.1 before Base64 encoding.
- Fixed core auth flows so sign-out surfaces session deletion failures,
  password-reset callbacks reject untrusted redirect URLs, email/password
  session IP metadata uses the configured `advanced.ip_address` resolver
  instead of raw forwarding headers, and `encrypt_oauth_tokens` encrypts
  access, refresh, and ID tokens once at the storage boundary without leaving
  ID tokens plaintext or double-encrypting tokens.
- Fixed passkey WebAuthn verification to honor the configured
  `user_verification` policy instead of always requiring user verification at
  the webauthn-rs layer.
- Fixed Postgres and SQLx rate-limit persistence so negative stored counts
  fail closed instead of wrapping to huge values when decoded.
- Fixed Stripe checkout success fallback to reconcile trialing subscriptions
  missed by the primary webhook path and organization seat sync to clamp
  subscription quantities to at least one seat.
- Fixed trusted server-side dispatch so `AuthRouter::handle_async_server` can
  reach plugin `server_only` endpoints (such as the JWT plugin's `/sign-jwt`
  and `/verify-jwt`), while public `handle_async` still returns `404` for them.
- Fixed the async router consuming route rate limits after plugin middlewares,
  which let CAPTCHA rejections (missing/invalid responses or provider errors)
  bypass route throttling and force repeated outbound provider calls; the route
  rate limit is now consumed before plugin middlewares run.
- Fixed the CAPTCHA plugin matching protected endpoints against the full
  request URI, which let a query string or fragment carrying a protected path
  (such as `/get-session?next=/sign-in/email`) arm CAPTCHA on unrelated routes;
  matching now normalizes to the routed pathname and compares configured
  endpoints on path-segment boundaries.
- Fixed session cookie cache authentication so cached session data is only
  returned after the backing session token still exists and is unexpired.
- Fixed Axum request base URL inference so request-derived `Host` values are
  not trusted origins, and disabled that inference by default.
- Fixed organization plugin `organization.create` so unauthenticated requests
  cannot supply a `userId` to create organizations on behalf of another user.
- Fixed `openauth-tokio-postgres` and `openauth-deadpool-postgres` leaving
  connections in open transactions when `transaction()` or rate-limit `consume()`
  is cancelled or panics mid-callback, which could let a later `COMMIT` persist
  aborted auth writes (cross-request transaction bleed).

## [0.0.6] - 2026-05-24

### Added

- Added server-side SCIM provisioning support with users, groups, bulk
  operations, filtering, patching, metadata routes, token handling, and adapter
  conformance coverage.
- Added OAuth 2.1/OpenID Connect provider parity work, including authorization,
  client, consent, token, introspection, metadata, logout, and userinfo
  endpoint modules.
- Added standalone `openauth-oidc` and `openauth-saml` crates split from SSO
  internals.
- Added richer i18n locale responses and the `openauth` umbrella feature for
  re-exporting i18n.
- Added Fred-backed secondary storage support and stronger SQL/Postgres adapter
  conformance coverage.

### Changed

- Hardened core auth flows, sessions, password routes, account linking,
  database schema planning, SQL migrations, and route service boundaries.
- Split large route, storage, adapter, CLI, passkey, plugin, and provider
  modules into smaller focused modules.
- Gated JOSE crypto dependencies behind feature flags where possible.
- Updated Axum integration contracts for routing, request conversion, response
  handling, and error behavior.
- Updated release automation and manual release documentation to include every
  workspace crate in dependency order.
- Updated CI and local test guidance to use `cargo-nextest` for faster test
  execution.
- Added a Docker Compose helper that recreates stale test service containers
  and verifies published ports before integration tests run.

### Fixed

- Fixed request error reporting so body encoding context is preserved.
- Fixed SQL migration checks for unique constraints and table existence.
- Fixed Postgres migration constraint introspection.
- Fixed SCIM resource mutation and filter validation behavior.
- Fixed social provider token authentication method defaults.

## [0.0.5] - 2026-05-19

### Changed

- Published the beta workspace release line to crates.io.
- Updated release automation to continue when a crate version already exists.

## [0.0.3] - 2026-05-15

### Added

- Published an early OpenAuth pre-release.
