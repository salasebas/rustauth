# OpenAuth-RS

OpenAuth-RS is an unofficial Rust authentication toolkit inspired by Better
Auth. It is server-first: the crates focus on authentication primitives,
storage contracts, HTTP endpoints, OAuth/OIDC, SSO, SCIM, SAML, passkeys,
plugins, adapters, and integrations that belong on the Rust server side.

## Status

OpenAuth-RS is in experimental beta. APIs, crate boundaries, endpoint behavior,
and storage contracts can change before a stable release. Treat it as a project
for early adopters and contributors, not as a frozen production interface.

## Basic Usage

```rust
use openauth::{open_auth, OpenAuthOptions};

let auth = open_auth(
    OpenAuthOptions::new()
        .secret("secret-a-at-least-32-chars-long!!")
        .base_url("https://app.example.com/api/auth"),
)?;
```

Most applications will combine the top-level `openauth` crate with a web
adapter, a database adapter, and whichever plugins or provider crates they need.

## Package Guide

Markdown links can point directly to each package README. Start with the
top-level crate, then add feature crates as your application needs them.

| Package | Purpose |
| --- | --- |
| [OpenAuth](crates/openauth/README.md) | Public entry crate and re-export surface. |
| [OpenAuth Core](crates/openauth-core/README.md) | Shared contracts, errors, options, cookies, sessions, storage, and routing primitives. |
| [OpenAuth Axum](crates/openauth-axum/README.md) | Axum router integration for the framework-neutral HTTP core. |
| [OpenAuth CLI](crates/openauth-cli/README.md) | Command-line helpers for init, diagnostics, secrets, schemas, migrations, and plugins. |
| [OpenAuth Plugins](crates/openauth-plugins/README.md) | Official server-side plugin modules such as admin, organization, JWT, API keys, email OTP, magic link, and more. |
| [OpenAuth Passkey](crates/openauth-passkey/README.md) | Server-side WebAuthn/passkey plugin backed by `webauthn-rs`. |
| [OpenAuth OAuth](crates/openauth-oauth/README.md) | OAuth client primitives and request/response helpers. |
| [OpenAuth OAuth Provider](crates/openauth-oauth-provider/README.md) | OAuth 2.1 and OpenID Connect provider support. |
| [OpenAuth OIDC](crates/openauth-oidc/README.md) | Enterprise OIDC relying-party support for external IdPs. |
| [OpenAuth SAML](crates/openauth-saml/README.md) | SAML 2.0 service-provider support, XML hardening, ACS, metadata, and SLO helpers. |
| [OpenAuth Social Providers](crates/openauth-social-providers/README.md) | Social OAuth provider definitions for GitHub, Google, Discord, Slack, and other providers. |
| [OpenAuth SSO](crates/openauth-sso/README.md) | Enterprise SSO aggregator, provider management, domain verification, and feature-gated OIDC/SAML route composition. |
| [OpenAuth SCIM](crates/openauth-scim/README.md) | SCIM provisioning for users and groups, independent from login. |
| [OpenAuth Stripe](crates/openauth-stripe/README.md) | Stripe billing and webhook integration surface. |
| [OpenAuth i18n](crates/openauth-i18n/README.md) | Internationalization plugin for localized auth responses. |
| [OpenAuth Telemetry](crates/openauth-telemetry/README.md) | Optional telemetry payload generation and publishing hooks. |
| [OpenAuth SQLx](crates/openauth-sqlx/README.md) | SQLx adapters for SQLite, Postgres, MySQL, and SQL-backed rate limiting. |
| [OpenAuth Deadpool Postgres](crates/openauth-deadpool-postgres/README.md) | Pooled Postgres adapter recommended for production Postgres deployments. |
| [OpenAuth Tokio Postgres](crates/openauth-tokio-postgres/README.md) | Minimal `tokio-postgres` adapter for apps that already own a client. |
| [OpenAuth Redis](crates/openauth-redis/README.md) | Redis/Valkey rate-limit and secondary storage using `redis-rs`. |
| [OpenAuth Fred](crates/openauth-fred/README.md) | Redis/Valkey rate-limit store using the `fred` client. |

## Repository

Source code lives at [sebasxsala/openauth-rs](https://github.com/sebasxsala/openauth-rs).

## Enterprise Identity Model

`openauth-oauth-provider` is for OpenAuth acting as an OAuth 2.1/OIDC
authorization server. `openauth-oidc` is the opposite direction: OpenAuth is a
client of external enterprise IdPs such as Okta, Entra ID, Auth0, Google
Workspace, or Keycloak.

Use `openauth-oidc` when you only need OIDC enterprise login without SAML/XML
dependencies. Use `openauth-saml` when you only need SAML 2.0 service-provider
behavior. Use `openauth-sso` when you want the convenience plugin that combines
provider management, domain verification, audit hooks, and enabled OIDC/SAML
routes. Use `openauth-scim` separately for provisioning.

## License

OpenAuth-RS is licensed under the MIT License. See [LICENSE](LICENSE).
