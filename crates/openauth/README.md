# openauth

Main application crate for OpenAuth-RS.

## What It Is

`openauth` is the crate most applications should start with. It re-exports the
core builder, options, HTTP handler, database contracts, plugin contracts, and
selected integration crates behind feature flags.

Depend on lower-level crates directly when you are building adapters, plugins,
or very small binaries that do not need the umbrella surface.

## Quick Start

```rust
use openauth::{EmailPasswordOptions, OpenAuth, RateLimitOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .email_password(EmailPasswordOptions::new().enabled(true))
    .rate_limit(RateLimitOptions::memory().enabled(true).window(60).max(100))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Attach an adapter when you need durable users, sessions, accounts, plugin data,
or migrations:

```rust
use openauth::{EmailPasswordOptions, OpenAuth};
use openauth_sqlx::SqliteAdapter;
use sqlx::sqlite::SqlitePoolOptions;

let pool = SqlitePoolOptions::new().connect("sqlite://openauth.db").await?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .email_password(EmailPasswordOptions::new().enabled(true))
    .adapter(SqliteAdapter::new(pool))
    .build()?;

auth.run_migrations().await?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Feature Flags

- `i18n`: re-export `openauth-i18n`.
- `plugins`: re-export `openauth-plugins`.
- `passkey`: re-export `openauth-passkey`.
- `sso`: re-export `openauth-sso`.
- `oidc`: re-export relying-party OIDC helpers.
- `saml` and `saml-signed`: re-export experimental SAML helpers.
- `scim`: re-export server-side SCIM provisioning.
- `stripe`: re-export server-side Stripe billing integration.
- `telemetry`: re-export the telemetry surface from
  [`openauth-telemetry`](../openauth-telemetry/README.md) (`create_telemetry`,
  `get_telemetry_auth_config`, `TelemetryContext`, `TelemetryEvent`,
  `TelemetryPublisher`, `TelemetryTestHooks`, `CustomTrackFn`) and wire the
  publisher during async initialization (`OpenAuthBuilder::build_async`,
  `open_auth_*_async`). This feature also enables `openauth-telemetry/oauth` so
  social-provider config snapshots match Better Auth parity. Async constructors
  are available without this feature; see the linked crate docs for sink setup
  and enablement precedence.
- `sqlx-sqlite`, `sqlx-postgres`, `sqlx-mysql`: SQLx adapters.
- `tokio-postgres` and `deadpool-postgres`: Postgres adapters.

## Choosing The Right Crate

- Start with `openauth` for applications.
- Use `openauth-core` for adapter/plugin internals.
- Use `openauth-sso` to consume external enterprise IdPs.
- Use `openauth-oauth-provider` when your app must issue OAuth/OIDC tokens.
- Use `openauth-axum` to mount OpenAuth in Axum.

## Status

Experimental beta. Public re-exports, feature flags, and crate boundaries may
change before stable release.

## Upstream parity (Better Auth 1.6.9)

The `openauth` crate maps to the public `better-auth` npm package—the surface
most applications import. Server runtime (routes, cookies, crypto, sessions)
lives in [`openauth-core`](../openauth-core/README.md); this crate re-exports
that API and optional integrations behind feature flags.

There is no separate upstream package for the facade. Parity is the union of
`openauth-core` and whichever optional crates you enable (`i18n`, `plugins`,
`passkey`, `sso`, `oidc`, `saml`, `scim`, `stripe`, `telemetry`, SQL/Redis
adapters).

| Concern | Parity crate |
| --- | --- |
| Builder, handler, sessions, accounts | `openauth-core` |
| Enterprise SSO (OIDC/SAML routes) | `openauth-sso` |
| OAuth/OIDC authorization server | `openauth-oauth-provider` |
| SQL / Redis persistence | `openauth-sqlx`, `openauth-redis`, … |
| Framework mount (Axum) | `openauth-axum` |
| Browser / React / Vue clients | N/A (server-only) |

**Parity level:** High for core auth when using default integrations; SAML and
some product plugins remain experimental or feature-gated.

### Upstream lookup

1. Pin: [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Public API exports: `reference/upstream-src/<version>/repository/packages/better-auth/src/` (fetch via `./scripts/fetch-upstream-better-auth.sh`).
3. Map `crates/openauth/src/lib.rs` re-exports to upstream `index.ts` and package `exports`.
4. Server behavior: [`openauth-core`](../openauth-core/README.md#upstream-parity-better-auth-169).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
