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
use openauth::{OpenAuth, RateLimitOptions};

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .rate_limit(RateLimitOptions::memory().enabled(true).window(60).max(100))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Attach an adapter when you need durable users, sessions, accounts, plugin data,
or migrations:

```rust
use openauth::OpenAuth;
use openauth_sqlx::SqliteAdapter;
use sqlx::sqlite::SqlitePoolOptions;

let pool = SqlitePoolOptions::new().connect("sqlite://openauth.db").await?;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
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
  `open_auth_*_async`). Async constructors are available without this feature;
  see the linked crate docs for sink setup and enablement precedence.
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

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
