# Changelog

All notable changes to the RustAuth workspace are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project follows [Semantic Versioning](https://semver.org/) while the API is still pre-1.0.

## [Unreleased]

### Changed

#### Official plugins (`rustauth-plugins`)

- Email OTP verification create/get endpoints are now server-only routes, preventing public
  HTTP dispatch while preserving server-side OTP generation and retrieval flows.

## [0.3.0] - 2026-06-15

### Added

#### Storage adapters (`rustauth-diesel`)

- `rustauth-diesel` — async Diesel adapters for Postgres and MySQL (`diesel-postgres`,
  `diesel-mysql` features on the `rustauth` umbrella crate).
- Integration CI coverage for `rustauth-diesel` with Postgres and MySQL services.

#### Web integration (`rustauth-actix-web`)

- New `rustauth-actix-web` crate with `RustAuthActixWebExt` (`mount_at_base_path`, `mount_routes`,
  `handle`) and `RustAuthActixWebOptions`.
- Integration tests aligned with the Axum adapter contract (routing, HTTP/error contracts, auth
  flows, security scenarios).
- Docs-site guide at `/docs/integrations/actix-web`, `examples/actix-web-minimal`, and CI matrix
  coverage for `rustauth-actix-web --all-features`.

#### CLI (`rustauth-cli`)

- `rustauth init --framework actix-web` writes Actix-oriented `rustauth.toml` metadata and prints
  an Actix Web mount snippet.
- Workspace inspection and telemetry detect Actix Web when both `actix-web` and
  `rustauth-actix-web` appear in `Cargo.toml`.

### Changed

#### CLI (`rustauth-cli`)

- **Breaking:** `rustauth init` requires `--framework axum` or `--framework actix-web`. The
  previous implicit default (`axum`) and workspace auto-detection fallback were removed.
- **Breaking:** `database.adapter` is required in `rustauth.toml` and for `rustauth init` (via
  `--adapter` or workspace detection). The previous implicit default (`sqlx`) was removed.

## [0.2.0] - 2026-06-14

Initial public working release of **RustAuth** — an unofficial Rust authentication toolkit
inspired by [Better Auth](https://www.better-auth.com/). This is the first published
release line under the `rustauth` / `rustauth-*` crate namespace.

### Added

#### Core (`rustauth`, `rustauth-core`)

- Framework-neutral auth server: `RustAuth`, `RustAuthBuilder`, `RustAuthOptions`, sessions,
  cookies, rate limiting, email/password (opt-in), account linking, verification flows, and
  Better Auth–shaped HTTP JSON (camelCase request/response bodies).
- `rustauth::prelude` for the recommended application surface.
- `AuthPlugin` hook system, global hooks, background task dispatch, and outbound email/SMS
  delivery via `dispatch_outbound` (never block HTTP responses on senders).
- Database schema planning, SQL migrations, secondary storage contracts, and standalone
  rate-limit stores (memory, SQL, Redis/Valkey).
- `rustauth.toml` + `rustauth db` CLI integration for schema status, generate, and migrate.
- Default cookie prefix `rustauth`; configuration via `RUSTAUTH_*` environment variables and
  `rustauth.toml`.

#### Web integration (`rustauth-axum`)

- Axum router mounting via `RustAuthAxumExt` (`mount_at_base_path`, `into_router`, `handle`, …).

#### CLI (`rustauth-cli`)

- `rustauth init`, `info`, `secret`, `db status|generate|migrate`, plugin/schema helpers,
  parity with Better Auth v1.6.9 CLI flows, and opt-in telemetry for generate/migrate.

#### Official plugins (`rustauth-plugins`)

- Access control, additional fields, admin, anonymous users, API keys, bearer sessions,
  CAPTCHA, custom sessions, device authorization, email OTP, generic OAuth, Have I Been
  Pwned, JWT, last login method, magic link, multi-session, OAuth proxy, one-tap, one-time
  tokens, OpenAPI, organizations (with dynamic access control), phone number, SIWE, two-factor,
  and username plugins.

#### Enterprise identity

- `rustauth-oauth` — OAuth 2.0/OIDC client primitives (`OAuth2Client`, flow builders, PKCE,
  guarded outbound HTTP).
- `rustauth-social-providers` — built-in social OAuth providers (GitHub, Google, Discord, Slack,
  Apple, and more) with `SocialProviderConfig`.
- `rustauth-oauth-provider` — OAuth 2.1 / OpenID Connect authorization server, consent, token,
  introspection, logout, userinfo, and optional MCP protected-resource metadata.
- `rustauth-oidc` — OIDC relying-party helpers for external IdPs.
- `rustauth-saml` — experimental SAML 2.0 service-provider helpers.
- `rustauth-sso` — enterprise SSO aggregator with provider management and domain verification.
- `rustauth-scim` — SCIM 2.0 provisioning (users, groups, bulk, filter, patch).
- `rustauth-passkey` — WebAuthn / passkey plugin (`webauthn-rs`).
- `rustauth-stripe` — Stripe billing and webhook integration.
- `rustauth-i18n` — localized auth responses with async locale resolution.
- `rustauth-telemetry` — optional anonymous telemetry payloads.

#### Storage adapters

- `rustauth-sqlx` — SQLite, Postgres, and MySQL via SQLx.
- `rustauth-tokio-postgres` — minimal `tokio-postgres` adapter.
- `rustauth-deadpool-postgres` — pooled Postgres for production.
- `rustauth-redis` — Redis/Valkey rate limits and secondary storage (`redis-rs`).
- `rustauth-fred` — Redis/Valkey rate-limit store (`fred` client).

#### Examples and docs

- `examples/backend-reference`, `examples/full-app`, and `examples/cli-migrate-playground`.
- Parity documentation against Better Auth 1.6.9 under `docs/parity/`.
- Documentation site at [rustauth.dev](https://rustauth.dev).

### Notes

- Email/password sign-in and sign-up are **opt-in** (`EmailPasswordOptions::enabled(true)`).
- Several crates ship with `default = []`; enable dialect/features explicitly (`sqlite`, `oidc`,
  `http`, `jose`, enterprise plugin features, or `full` on the umbrella `rustauth` crate).
- Apply schema with `rustauth db migrate` before serving traffic; `RustAuth::run_migrations` is
  not part of the public server API.
- Public duration fields use `time::Duration` directly across core, plugins, and passkey options.

[0.3.0]: https://github.com/salasebas/rustauth/releases/tag/v0.3.0
[0.2.0]: https://github.com/salasebas/rustauth/releases/tag/v0.2.0
