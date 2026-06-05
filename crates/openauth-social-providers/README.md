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
use openauth_oauth::oauth2::ProviderOptions;
use openauth_social_providers::github::github;

let github = github(ProviderOptions {
    client_id: Some("github-client-id".into()),
    client_secret: Some("github-client-secret".into()),
    ..ProviderOptions::default()
});

let auth = OpenAuth::builder()
    .secret("secret-a-at-least-32-chars-long!!")
    .base_url("https://app.example.com/api/auth")
    .social_provider(github)
    .build()?;
# let _ = auth;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Browser redirects and UI remain application/client concerns. This crate only
defines server-side OAuth provider behavior.

## Status

Experimental beta. Provider coverage, scopes, profile mapping, and provider
edge-case behavior may change before stable release.

## Upstream parity (Better Auth 1.6.9)

Upstream: `@better-auth/core` → `packages/core/src/social-providers/` (**35**
built-in providers). HTTP routes (`/sign-in/social`, callbacks) live in `openauth-core`.
Wire parity is **high (33/35)**; hook override surface is partial by design.

### Status

| Area | Status | Notes |
| --- | --- | --- |
| Provider registry | **High** | All **35** providers; `PROVIDER_IDS` matches upstream order |
| Wire parity (URLs, scopes, defaults) | **High (33/35)** | Discord/Roblox `+` scopes, Railway optional PKCE fixed |
| Provider unit tests | **Beyond upstream** | **310** Rust tests; upstream has **0** in `social-providers/` |
| Hook overrides (`mapProfileToUser`, etc.) | **Partial** | Typed overrides on **10/35**; architectural vs upstream `ProviderOptions` |
| Open gaps (wire) | **Minor** | Facebook opaque token verify (stricter); Twitch JWKS verify (stricter) |

Social E2E from upstream `social.test.ts` belongs in `openauth-core`, not this crate.

### Intentional differences

- Provider hook overrides are typed Rust traits on **10/35** providers instead of
  global `ProviderOptions` callbacks on every provider.
- Facebook opaque-token verification and Twitch JWKS verification are stricter than
  upstream for safer server-side token acceptance.
- Async `SocialOAuthProvider` replaces upstream's synchronous provider functions.

### Open gaps/risks

- Remaining wire gaps are limited to stricter Facebook/Twitch token verification.
- Full `mapProfileToUser` / `getUserInfo` override ergonomics are not exposed on all
  **35** providers yet.
- OAuth route and account-linking E2E parity is owned by `openauth-core`, not this crate.

### Upstream lookup

1. Read the pin in [`reference/upstream-better-auth/VERSION.md`](../../reference/upstream-better-auth/VERSION.md).
2. Open `reference/upstream-src/<version>/repository/packages/core/src/social-providers/` (run `./scripts/fetch-upstream-better-auth.sh` if missing).
3. Map Rust modules in `crates/openauth-social-providers/src/` to upstream provider `.ts` files by provider id, authorize/token URLs, scopes, and profile mapping.
4. Add a failing Rust integration test before changing behavior; match wire URLs, scopes, defaults, and profile fields—not TypeScript types.

## Links

- [Root README](../../README.md)
- [Repository](https://github.com/sebasxsala/openauth-rs)
