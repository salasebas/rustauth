# rustauth

Main application crate for RustAuth.

## What It Is

`rustauth` is the crate most applications should start with. Use [`prelude`](crate::prelude)
for the app-dev surface, then reach into focused modules (`rustauth::db`, `rustauth::plugin`,
`rustauth::api`, …) when you extend adapters, plugins, or endpoints.

Depend on `rustauth-core` directly only for adapter/plugin internals or very small binaries
that do not need the umbrella crate.

## Quick Start

```rust
use rustauth::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .base_url("https://app.example.com/api/auth")
        .email_password(EmailPasswordOptions::new().enabled(true))
        .rate_limit(RateLimitOptions::memory().enabled(true).window(60).max(100))
        .build()
        .await?;

    # let _ = auth;
    Ok(())
}
```

Attach an adapter when you need durable users, sessions, accounts, plugin data,
or migrations. Enable the matching SQLx dialect on the `rustauth` crate
(`sqlx-sqlite`, `sqlx-postgres`, or `sqlx-mysql`):

```toml
[dependencies]
rustauth = { version = "0.1.0", features = ["sqlx-sqlite"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use rustauth::prelude::*;
use rustauth::sqlx::SqliteAdapter;
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePoolOptions::new().connect("sqlite://rustauth.db").await?;

    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .base_url("https://app.example.com/api/auth")
        .email_password(EmailPasswordOptions::new().enabled(true))
        .adapter(SqliteAdapter::new(pool))
        .build()
        .await?;

    // Apply schema with `rustauth db migrate` before serving traffic.
    Ok(())
}
```

For Postgres or MySQL with Diesel, enable `diesel-postgres` or `diesel-mysql` on
the `rustauth` crate:

```toml
[dependencies]
rustauth = { version = "0.2.0", features = ["diesel-postgres"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use rustauth::prelude::*;
use rustauth::diesel::{DieselPostgresAdapter, DieselPostgresStores};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = DieselPostgresAdapter::connect(
        "postgres://user:password@localhost:5432/rustauth",
    )
    .await?;

    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .base_url("https://app.example.com/api/auth")
        .email_password(EmailPasswordOptions::new().enabled(true))
        .adapter(adapter)
        .build()
        .await?;

    // Or bundle adapter + SQL rate limits:
    let stores = DieselPostgresStores::connect(
        "postgres://user:password@localhost:5432/rustauth",
    )
    .await?;
    let _options = stores.apply_to_options(RustAuthOptions::default());

    Ok(())
}
```

For MySQL with Diesel, enable `diesel-mysql` and use `rustauth::diesel::DieselMysqlStores`
or `DieselMysqlAdapter` the same way as the Postgres example above.

Configure `rustauth.toml` with the same adapter and plugins, then run
`rustauth db migrate --yes` in local setup, CI, or release jobs before starting
the server. For Diesel backends:

```toml
[database]
adapter = "diesel"
provider = "postgres"   # or "mysql"
url_env = "DATABASE_URL"
```

See [docs/database-migrations.md](../../docs/database-migrations.md).

Mount into Axum with [`rustauth-axum`](../rustauth-axum/README.md) or Actix Web with [`rustauth-actix-web`](../rustauth-actix-web/README.md):

```rust
use rustauth::prelude::*;
use rustauth_axum::RustAuthAxumExt;

let app = auth.mount_at_base_path(RustAuthAxumOptions::default())?;
```

```rust
use rustauth::prelude::*;
use rustauth_actix_web::RustAuthActixWebExt;

let scope = auth.mount_at_base_path(RustAuthActixWebOptions::default())?;
```

## Plugins

Enable the `plugins` feature to re-export `rustauth-plugins`, then register
official plugins on the builder:

```rust
use rustauth::RustAuth;
use rustauth_plugins::prelude::*;

let auth = RustAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .plugin(admin())
    .plugins(vec![bearer(), jwt()?])
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

- `.plugin(x)` appends one plugin.
- `.plugins(vec![...])` appends a batch (like chaining `.plugin`).

When configuring [`RustAuthOptions`](https://docs.rs/rustauth-core/latest/rustauth_core/options/struct.RustAuthOptions.html)
directly, `.plugin` and `.plugins` both append; use `.set_plugins` to replace
the entire plugin list.

## Social Sign-In

Built-in OAuth providers live in [`rustauth-social-providers`](../rustauth-social-providers/README.md)
and are re-exported as `rustauth::social_providers`. Register providers on the
builder:

```rust
use rustauth::RustAuth;
use rustauth::social_providers::providers::github;
use rustauth::social_providers::SocialProviderConfig;

let auth = RustAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .social_provider(github(SocialProviderConfig::new(
        std::env::var("GITHUB_CLIENT_ID")?,
        std::env::var("GITHUB_CLIENT_SECRET")?,
    ))?)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `SocialProviderConfig::builder()` when credentials or scopes are loaded in
separate steps. Low-level provider types remain under
`rustauth::social_providers::advanced`.

## Feature Flags

- `jose`: forward `rustauth-core/jose` (recommended for production cookie JWE).
- `oauth`: forward `rustauth-core/oauth` (re-exports `rustauth::oauth`).
- `social-providers`: forward social provider packages (requires `oauth`).
- `full`: restore 0.1.x implicit behavior (`jose` + `oauth` + `social-providers`).
- `plugins`: re-export `rustauth-plugins` (does **not** imply `oauth`; enable
  `oauth` / `social-providers` explicitly when you need social sign-in).
- `oauth-provider`: re-export `rustauth-oauth-provider` as `rustauth::oauth_provider`.
- `passkey`: re-export `rustauth-passkey`.
- `sso`: re-export `rustauth-sso` (includes `rustauth::sso::oidc` and, with the
  `saml` feature, `rustauth::sso::saml`).
- `oidc`: enable OIDC route support on `rustauth-sso` (does not add a top-level
  `rustauth::oidc` re-export).
- `saml` and `saml-signed`: enable SAML routes on `rustauth-sso` (does not add a
  top-level `rustauth::saml` re-export).
- `scim`: re-export server-side SCIM provisioning.
- `stripe`: re-export [`rustauth-stripe`](../rustauth-stripe/README.md) as
  `rustauth::stripe` (`stripe`, `StripeOptions`, `StripeClient`, …).
- `i18n`: re-export [`rustauth-i18n`](../rustauth-i18n/README.md) as
  `rustauth::i18n`.
- `telemetry`: re-export [`rustauth-telemetry`](../rustauth-telemetry/README.md)
  under `rustauth::telemetry` (`create_telemetry`, `TelemetryContext`,
  `TelemetryEvent`, `TelemetryPublisher`, `CustomTrackFn`, …) and wire the
  publisher during [`RustAuthBuilder::build`](crate::RustAuthBuilder::build).
  This feature also enables `rustauth-telemetry/oauth` so social-provider
  config snapshots match Better Auth parity.
- `sqlx-sqlite`, `sqlx-postgres`, `sqlx-mysql`: SQLx adapters.
- `diesel-postgres`, `diesel-mysql`: Diesel adapters (re-export `rustauth-diesel`).
- `tokio-postgres` and `deadpool-postgres`: Postgres adapters.

## Choosing The Right Crate

- Start with `rustauth` for applications.
- Use `rustauth-core` for adapter/plugin internals.
- Use `rustauth-sso` to consume external enterprise IdPs.
- Enable `oauth-provider` on `rustauth` (or depend on `rustauth-oauth-provider`
  directly) when your app must issue OAuth/OIDC tokens.
- Use `rustauth-axum` to mount RustAuth in Axum.
- Use `rustauth-actix-web` to mount RustAuth in Actix Web.

## Enterprise plugins (quick start)

```toml
[dependencies]
rustauth = { version = "0.2.0", features = ["sso", "scim", "passkey", "oauth-provider"] }
```

```rust
use rustauth::{RustAuth, RustAuthOptions};
use rustauth::oauth_provider::{oauth_provider, OAuthProviderOptions};
use rustauth::passkey::{passkey, PasskeyOptions};
use rustauth::scim::{scim, ScimOptions};
use rustauth::sso::{sso, SsoOptions};

let options = RustAuthOptions::new()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .plugins(vec![
        sso(SsoOptions::default()),
        scim(ScimOptions::default().token_storage(rustauth::scim::ScimTokenStorage::Hashed)),
        passkey(PasskeyOptions::default().rp_id("app.example.com")),
        oauth_provider(OAuthProviderOptions {
            login_page: "/login".to_owned(),
            consent_page: "/consent".to_owned(),
            ..OAuthProviderOptions::default()
        })?,
    ]);

let auth = RustAuth::builder().options(options).build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Status

**0.2.0** — initial public working release. Pre-1.0; public APIs may still change before 1.0.

## Better Auth compatibility

Server-side public entry crate (builder, handler, re-exports). Aligned with
Better Auth **1.6.9** where it matters for this crate; RustAuth is not a
line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
