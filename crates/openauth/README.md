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
or migrations. Enable the matching SQLx dialect on the `openauth` crate
(`sqlx-sqlite`, `sqlx-postgres`, or `sqlx-mysql`):

```toml
[dependencies]
openauth = { version = "0.1.0", features = ["sqlx-sqlite"] }
```

```rust
use openauth::{EmailPasswordOptions, OpenAuth};
use openauth::sqlx::SqliteAdapter;
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

## Social Sign-In

Built-in OAuth providers live in [`openauth-social-providers`](../openauth-social-providers/README.md)
and are re-exported as `openauth::social_providers`. Register providers on the
builder:

```rust
use openauth::OpenAuth;
use openauth::social_providers::providers::github;
use openauth::social_providers::SocialProviderConfig;

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .social_provider(github(SocialProviderConfig::new(
        std::env::var("GITHUB_CLIENT_ID")?,
        std::env::var("GITHUB_CLIENT_SECRET")?,
    )))
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `SocialProviderConfig::builder()` when credentials or scopes are loaded in
separate steps. Low-level provider types remain under
`openauth::social_providers::advanced`.

## Feature Flags

- `i18n`: re-export `openauth-i18n`.
- `plugins`: re-export `openauth-plugins`.
- `oauth-provider`: re-export `openauth-oauth-provider` as `openauth::oauth_provider`.
- `passkey`: re-export `openauth-passkey`.
- `sso`: re-export `openauth-sso` (includes `openauth::sso::oidc` and, with the
  `saml` feature, `openauth::sso::saml`).
- `oidc`: enable OIDC route support on `openauth-sso` (does not add a top-level
  `openauth::oidc` re-export).
- `saml` and `saml-signed`: enable SAML routes on `openauth-sso` (does not add a
  top-level `openauth::saml` re-export).
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
- Enable `oauth-provider` on `openauth` (or depend on `openauth-oauth-provider`
  directly) when your app must issue OAuth/OIDC tokens.
- Use `openauth-axum` to mount OpenAuth in Axum.

## Enterprise plugins (quick start)

```toml
[dependencies]
openauth = { version = "0.1.1", features = ["sso", "scim", "passkey", "oauth-provider"] }
```

```rust
use openauth::{OpenAuth, OpenAuthOptions};
use openauth::oauth_provider::{oauth_provider, OAuthProviderOptions};
use openauth::passkey::{passkey, PasskeyOptions};
use openauth::scim::{scim, ScimOptions};
use openauth::sso::{sso, SsoOptions};

let options = OpenAuthOptions::new()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugins(vec![
        sso(SsoOptions::default()),
        scim(ScimOptions::default().token_storage(openauth::scim::ScimTokenStorage::Hashed)),
        passkey(PasskeyOptions::default().rp_id("app.example.com")),
        oauth_provider(OAuthProviderOptions {
            login_page: "/login".to_owned(),
            consent_page: "/consent".to_owned(),
            ..OAuthProviderOptions::default()
        })?,
    ]);

let auth = OpenAuth::builder().options(options).build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Status

Experimental beta. Public re-exports, feature flags, and crate boundaries may
change before stable release.

## Better Auth compatibility

Server-side public entry crate (builder, handler, re-exports). Aligned with
Better Auth **1.6.9** where it matters for this crate; OpenAuth is not a
line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
