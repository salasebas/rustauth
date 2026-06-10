# Changelog

All notable changes to the OpenAuth workspace are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

## Unreleased

## [0.1.1] - 2026-06-09

### Added

- `openauth-social-providers`: application-facing catalog under `providers::*`,
  with `SocialProviderConfig`, `SocialProviderConfigBuilder`, `ProviderId`, and
  `CognitoPoolConfig` for registering built-in social OAuth providers with
  `OpenAuthOptions::social_provider`.
- `openauth-social-providers`: `advanced::*` module for low-level provider
  request types, profile structs, endpoint constants, and HTTP helpers.

- `openauth-example-full-app`: `postgres-deadpool` adapter profile (`deadpool-postgres`
  over `tokio-postgres`) in the sidebar and database studio, sharing the same
  Postgres URL as `postgres-sqlx`.
- `openauth-example-full-app`: adapter labels now expose the SQL driver explicitly
  as `postgres-sqlx` and `mysql-sqlx` (`postgres` / `mysql` remain accepted aliases).

### Changed

- **Breaking:** Storage adapter crates (`openauth-sqlx`, `openauth-deadpool-postgres`,
  `openauth-tokio-postgres`, `openauth-redis`, `openauth-fred`) now lead with
  bundled `*Stores` types and `apply_to_options` for the recommended app-dev
  setup. See each crate's README and CHANGELOG for removed constructors and
  migration re-exports (`openauth_core::db` is canonical).
- **Breaking:** `openauth-social-providers` no longer exposes per-provider modules
  at the crate root. Use `openauth_social_providers::providers::{github, google,
  …}` for app setup and `openauth_social_providers::advanced::{github, …}` for
  low-level OAuth types and tests.
- **Breaking:** public provider factories now take `SocialProviderConfig` (or
  `SocialProviderConfig::builder().build()?`) instead of `ProviderOptions` or
  per-provider `*Options` structs.
- `openauth-sqlx`, `openauth-tokio-postgres`: Postgres migration planning now
  loads schema snapshots with a fixed set of batched catalog queries instead of
  per-column `information_schema` round trips.

### Fixed

- `openauth-sqlx`, `openauth-tokio-postgres`: Postgres migration introspection
  no longer spends tens of seconds in `constraint_column_usage` lookups during
  `run_migrations` / seed workflows on large auth schemas.
- `openauth-example-full-app`: dynamic SQL auth profiles now open adapters with
  the plugin-augmented example schema, fixing `is_anonymous` / session creation
  failures on `postgres-sqlx`, `postgres-deadpool`, `mysql-sqlx`, and `sqlite`
  profiles after seeding or reset.
- `openauth-core`: MySQL DDL now maps foreign-key string columns to
  `VARCHAR(255)` so plugin migrations can add referenced columns on existing
  tables.
- `openauth-core`: removed the self-referencing `dev-dependencies` entry that
  blocked `cargo publish` for `0.1.0` on crates.io (integration tests already
  enable `test-utils` via `--all-features`).
- `openauth-telemetry`: `TelemetryPublisher::publish` now waits for the async
  `init` bootstrap event before emitting command-specific events, so CLI debug
  output and downstream collectors always see `init` precede `cli_generate` /
  `cli_migrate`.
- `openauth-example-full-app`: database seeding runs inside one adapter
  transaction, fills required plugin columns, and skips redundant migration
  passes for faster Postgres/MySQL studio workflows.
- `openauth-example-full-app`: MySQL integration coverage now runs seed and
  schema-reset scenarios in one test to avoid cross-runtime races against the
  shared dev database.

## [0.1.0] - 2026-06-08




### Added

- `openauth-oauth-provider`: optional MCP profile via `OAuthProviderOptions::mcp`
  (`McpOptions`), protected-resource metadata at
  `/.well-known/oauth-protected-resource`, and resource-server helpers behind
  the `mcp-client` feature (`McpAuthClient`, introspect-based verification).
- `docs/superpowers/plans/2026-06-08-unify-mcp-into-oauth-provider.md` and
  `docs/superpowers/plans/2026-06-08-snake-case-logical-schema-names.md`.

### Changed

- **Breaking:** Removed the standalone `openauth-plugins::mcp` authorization-server
  plugin. MCP clients must use `openauth-oauth-provider` with `mcp: Some(...)`;
  OAuth flows use `/oauth2/*` instead of `/mcp/*`.
- **Breaking:** Standardized plugin database **logical** table and field names to
  idiomatic `snake_case` (singular logical tables, plural physical tables).
  HTTP JSON request/response bodies remain **camelCase** (Better Auth parity);
  OAuth/OIDC protocol endpoints that follow RFC snake_case (device authorization,
  token grants) are unchanged.
- `examples/full-app` wires `oauth_provider` with MCP instead of the removed MCP
  plugin.

### Removed

- `openauth-plugins::mcp` plugin, CLI wiring, and integration tests (behavior
  consolidated into `openauth-oauth-provider`).

### Fixed

- `openauth-example-full-app`: profile preferences no longer return `502` when
  Redis is unreachable in the default SQLite flow; reads fall back to startup
  config and writes use an in-process store until Redis is available.
- `openauth-example-full-app`: smoke tests now inject a loopback client IP so
  `oneshot` auth probes match production `ConnectInfo` behavior instead of
  failing closed with `429` under `MissingIpPolicy::Deny`.
- `openauth-example-full-app`: MySQL schema reset now lists tables through
  `information_schema` with an explicit `CAST(... AS CHAR)` (recent MySQL builds
  expose table-name columns as `VARBINARY`), disables foreign-key checks on a
  single pooled connection, and drops tables in batches so reset works again on
  busy dev databases.
- `openauth-example-full-app`: database seeding runs inside one adapter
  transaction and skips redundant migration passes for faster Postgres/MySQL
  studio workflows.
- `openauth-example-full-app`: the database viewer no longer runs full SQL
  migration planning on read-only table loads; migrations run once per cached
  adapter when seeding, which avoids Postgres-specific introspection slowness
  while browsing tables.
- `openauth-example-full-app`: seed and reset actions now disable each other
  and show a loading state on the active control until the request completes.
- `openauth-core`, `openauth-sqlx`, `openauth-tokio-postgres`,
  `openauth-deadpool-postgres`: SQL-backed standalone rate-limit stores now
  reject invalid rules (`window = 0`, `max = 0`, and oversized window
  conversions) with `OpenAuthError::InvalidConfig`, matching the in-memory,
  Redis, and Fred stores.
- `openauth-core`, `openauth-redis`, `openauth-fred`: rate-limit rule
  validation now lives in `openauth_core::options::validate_rate_limit_rule`
  so every store shares one implementation and error messages.

### Added

- `openauth-oidc`: exported `REQUIRED_DISCOVERY_FIELDS` and upstream-matching
  discovery helpers (`validate_discovery_url`, `fetch_discovery_document`,
  `validate_discovery_document`, `normalize_discovery_urls`,
  `select_token_endpoint_authentication`) with additional parity tests.

### Changed

- **Breaking:** Email/password sign-in and sign-up are now opt-in. Fresh
  `OpenAuth::builder().secret(...).adapter(...).build()` no longer exposes
  `/sign-up/email` or `/sign-in/email` until you enable them explicitly:

  ```rust
  use openauth::{EmailPasswordOptions, OpenAuth};

  OpenAuth::builder()
      .secret(secret)
      .adapter(adapter)
      .email_password(EmailPasswordOptions::new().enabled(true))
      .build()?;
  ```

  Sign-up only can stay disabled while sign-in remains available:

  ```rust
  .email_password(
      EmailPasswordOptions::new()
          .enabled(true)
          .disable_sign_up(true),
  )
  ```

### Changed

- `openauth-telemetry`: `get_telemetry_auth_config` reports global hook presence,
  logger settings, `onAPIError` configuration (URL redacted), custom password
  hash/verify callbacks, change-email confirmation hooks, verification
  `disableCleanup`, schema alias presence, and structured `init_database_hooks`
  from `OpenAuthOptions`.
- `openauth-core`: `ModelSchemaOptions` on user/session/account/verification/rate-limit
  options and `InitDatabaseHooksOptions` for Better Auth-shaped schema aliases and
  init-time database hooks (bridged into plugin hook execution).

### Added

- `openauth-i18n`: `AsyncLocaleResolver` and `I18nOptions::get_locale_async`
  for Better Auth 1.6.9 async `getLocale` callbacks on `AuthRouter::handle_async`.
- `openauth-core`: `AuthPlugin::with_on_response_async` hook run during async
  response finalization (before synchronous `on_response` hooks).
- `openauth-passkey`: `PasskeySchemaOptions` and `PasskeyOptions::schema` for
  physical passkey table/column renames (Better Auth `options.schema` /
  `mergeSchema` server parity).
- Added SSO audit event `DomainVerificationRevoked` (`Warn`) when a provider
  update clears a previously verified domain after issuer/domain changes or
  OIDC/SAML trust-boundary edits.
- Extended `openauth-cli` parity with Better Auth v1.6.9: `info --json` / `--copy`,
  `db generate -y` confirmation flow, global `-c` for `--cwd`, `init --seed-secrets`,
  and parity docs under `docs/parity/openauth-cli/09-parity-closure.md`.
- Documented CLI telemetry for `generate` / `migrate` (`cli_generate`, `cli_migrate`):
  env vars, payload/redaction summary, opt-out guidance, and docs regression tests.

### Changed

- Passkey authentication `after_verification` callbacks can now reject login
  after WebAuthn proof verification, matching Better Auth's throw/reject
  semantics and preventing counter updates or session minting on policy failure.

### Fixed

- `openauth-core`: `/update-user` no longer accepts plugin schema user fields
  marked as non-input (for example admin `role`/`banned` or two-factor
  `two_factor_enabled`); schema-backed updates now honor `DbField.input` and
  validate values against `DbFieldType`.
- Fixed the full-app example so `OPENAUTH_EXAMPLE_BASE_URL` preserves reverse-proxy
  path prefixes when rebuilding static and dynamic auth URLs, and malformed values
  now fail fast with `InvalidConfig` instead of silently falling back to localhost.
- Full-app example alternate backend selection no longer silently replaces
  operator-supplied database URLs with hard-coded defaults; unconfigured backends
  fail closed when explicit URL configuration is present.
- Ambiguous deployments (neither explicit `production` nor `development`) now
  fail closed: default secrets are rejected, rate limiting defaults on, and
  secure cookies apply without inferring localhost origins.
- OAuth `state` is consumed atomically when parsed; token exchange requires a
  PKCE `code_verifier` when the authorization step used PKCE.
- Delete-account verification rejects expired tokens; user-delete database
  hooks fail closed when delete snapshot preload errors.
- SQL adapter constructors apply configured database hooks once (no
  double-wrapping). Secondary-storage user→session indexes honor session TTL.
- Passkey WebAuthn setup no longer falls back to localhost when origin/rp_id are
  missing; management routes require a fresh session; authentication rejects
  credential counter updates that miss the stored row.
- Legacy passkey rows without `webauthn_credential` JSON can authenticate again:
  OpenAuth reconstructs `webauthn-rs` credential state from the stored COSE
  public key and backfills the hidden JSON after successful verification.
- Passkey session-scoped `allowCredentials` omits legacy rows with corrupt or
  unsupported COSE `public_key` values.
- Stripe subscription reconciliation paginates list results and releases
  orphaned schedules after failed period-end updates.
- `SecondaryStorage::take` on Fred/Redis uses atomic `GETDEL`.
- Fixed `/sso/update-provider` so domain verification is revoked when nested
  OIDC or SAML configuration changes alter the effective IdP trust boundary (not
  only top-level `issuer` or `domain`). Safe SP-only metadata such as OIDC
  auxiliary endpoints or SAML `callbackUrl` updates preserve verification.
- Fixed SQLite adapters accepting writes that violate foreign keys when using a
  multi-connection `SqlitePool` created without `PRAGMA foreign_keys = ON` on
  every checkout. `connect`/`sqlite_pool_options` configure the pool hook, and
  `SqliteAdapter::new(pool)` now enables foreign keys on each acquired connection
  and transaction.
- Fixed SAML ACS assertion replay detection so concurrent posts with the same
  assertion ID cannot both mint sessions. Replay markers are now claimed
  atomically via `SsoStateStore::try_create` (Redis/Valkey `SET NX` when
  secondary storage is configured, serialized verification writes otherwise).
- Fixed MCP OAuth refresh grants so presented refresh tokens are single-use.
  Refresh now atomically rotates the stored access/refresh token pair in place
  instead of inserting a new row and leaving the previous tokens valid until
  expiry.
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
- Fixed magic-link verify so session IP metadata uses the configured
  `advanced.ip_address` resolver instead of trusting raw forwarding headers.
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
