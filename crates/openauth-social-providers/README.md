# openauth-social-providers

Social OAuth provider definitions for OpenAuth-RS.

## What It Is

`openauth-social-providers` contains server-side provider definitions used by
OpenAuth social sign-in. It builds on `openauth-oauth` and keeps provider
metadata, scopes, profile mapping, and token-auth behavior out of application
code.

## What It Provides

Provider modules include Apple, Atlassian, Cognito, Discord, Dropbox, Facebook,
Figma, GitHub, GitLab, Google, Hugging Face, Kakao, Kick, Line, Linear,
LinkedIn, Microsoft Entra ID, Naver, Notion, PayPal, Reddit, Salesforce, Slack,
Spotify, TikTok, Twitch, Twitter/X, Vercel, VK, WeChat, Zoom, and others.

## Quick Start

```rust
use openauth::OpenAuth;
use openauth_social_providers::providers::{github, google};
use openauth_social_providers::SocialProviderConfig;

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

let auth = OpenAuth::builder()
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
use openauth_social_providers::providers::cognito;
use openauth_social_providers::{CognitoPoolConfig, SocialProviderConfig};

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
| `SocialProviderConfig::builder()` | Load `client_id`, `client_secret`, scopes, and flags separately; `build()?` validates required fields |
| `ProviderId` | Stable ids (`ProviderId::GITHUB`, …) instead of string literals |
| `CognitoPoolConfig` | Extra Cognito pool metadata for `providers::cognito` |

## Advanced API

Low-level OAuth request types, endpoint constants, profile structs, and HTTP
helpers live under `openauth_social_providers::advanced` for custom integrations,
provider-specific options, and crate tests.

## Status

Experimental beta. Provider coverage, scopes, profile mapping, and provider
edge-case behavior may change before stable release.

## Better Auth compatibility

Server-side social OAuth provider definitions (metadata, scopes, profile mapping,
token auth). Aligned with Better Auth **1.6.9** where it matters for this crate;
OpenAuth is not a line-by-line port.

For route-level parity, test counts, intentional differences, and known gaps, see
[UPSTREAM.md](./UPSTREAM.md).

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
