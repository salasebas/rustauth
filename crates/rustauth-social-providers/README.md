# rustauth-social-providers

Social OAuth provider definitions for RustAuth.

## What It Is

`rustauth-social-providers` contains server-side provider definitions used by
RustAuth social sign-in. It builds on `rustauth-oauth` and keeps provider
metadata, scopes, profile mapping, and token-auth behavior out of application
code.

## What It Provides

Provider modules include Apple, Atlassian, Cognito, Discord, Dropbox, Facebook,
Figma, GitHub, GitLab, Google, Hugging Face, Kakao, Kick, Line, Linear,
LinkedIn, Microsoft Entra ID, Naver, Notion, PayPal, Reddit, Salesforce, Slack,
Spotify, TikTok, Twitch, Twitter/X, Vercel, VK, WeChat, Zoom, and others.

## Quick Start

```rust
use rustauth::RustAuth;
use rustauth_social_providers::providers::{github, google};
use rustauth_social_providers::SocialProviderConfig;

// Short form when you already have both credentials.
let github = github(SocialProviderConfig::new(
    std::env::var("GITHUB_CLIENT_ID")?,
    std::env::var("GITHUB_CLIENT_SECRET")?,
));

// Builder when credentials or options are assembled step by step.
let google = google(
    SocialProviderConfig::builder()
        .client_id(std::env::var("GOOGLE_CLIENT_ID")?)
        .client_secret(std::env::var("GOOGLE_CLIENT_SECRET")?)
        .build()?,
);

let auth = RustAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .social_provider(github)
    .social_provider(google)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Amazon Cognito needs pool metadata in addition to client credentials:

```rust
use rustauth_social_providers::providers::cognito;
use rustauth_social_providers::{CognitoPoolConfig, SocialProviderConfig};

let cognito = cognito(
    SocialProviderConfig::new("client-id", "client-secret"),
    CognitoPoolConfig::new("auth.example.com", "us-east-1", "us-east-1_pool"),
)?;
```

Browser redirects and UI remain application/client concerns. This crate only
defines server-side OAuth provider behavior.

## Configuration

| Type | Use |
|------|-----|
| `SocialProviderConfig::new(id, secret)` | Both credentials available up front |
| `SocialProviderConfig::from_env("GITHUB")` | Load `{PREFIX}_CLIENT_ID` and `{PREFIX}_CLIENT_SECRET` from the environment |
| `SocialProviderConfig::from_env_with_keys("TIKTOK", &["CLIENT_KEY"])` | Same as `from_env`, plus optional extra credential keys |
| `SocialProviderConfig::builder()` | Load `client_id`, `client_secret`, scopes, and flags separately; `build()?` validates required fields |
| `ProviderId` | Stable ids (`ProviderId::GITHUB`, `ProviderId::MICROSOFT`, …) instead of string literals |
| `providers::microsoft` | Alias for `providers::microsoft_entra_id` ([`ProviderId::MICROSOFT`](src/config.rs)) |
| `CognitoPoolConfig` | Extra Cognito pool metadata for `providers::cognito` |

## Catalog vs advanced

[`providers`](src/providers/mod.rs) factories accept [`SocialProviderConfig`] and wire
**client credentials only**. Provider-specific authorization parameters (Google
`hd`, Microsoft `tenant_id`, Discord `prompt`, and similar) require
`rustauth_social_providers::advanced` or extended builder options.

## Advanced API

Low-level OAuth request types, endpoint constants, profile structs, and HTTP
helpers live under `rustauth_social_providers::advanced` for custom integrations,
provider-specific options, and crate tests.

### Constructor convention

Each advanced provider module exposes a free-function factory:

```rust
advanced::{provider}::{provider}(Options) -> Result<Provider, OAuthError>
```

For example, `advanced::google::google(GoogleOptions)`, or
`advanced::microsoft_entra_id::microsoft_entra_id(MicrosoftEntraIdOptions)`.
The catalog alias `advanced::microsoft_entra_id::microsoft()` delegates to
`microsoft_entra_id()`. Prefer these factories over `Provider::new` (deprecated).
All provider factories return `Result<_, OAuthError>`.

## Status

Experimental beta. Provider coverage, scopes, profile mapping, and provider
edge-case behavior may change before stable release.

## Better Auth compatibility

Server-side social OAuth provider definitions (metadata, scopes, profile mapping,
token auth). Aligned with Better Auth **1.6.9** where it matters for this crate;
RustAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/salasebas/rustauth)
