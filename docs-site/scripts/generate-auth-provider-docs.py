#!/usr/bin/env python3
"""One-shot generator for authentication/*.mdx (plan 006)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "content/docs/authentication"

CATALOG = {
    "atlassian": ("Atlassian", "ATLASSIAN", ""),
    "figma": ("Figma", "FIGMA", ""),
    "github": (
        "GitHub",
        "GITHUB",
        "Request the `user:email` scope in your GitHub OAuth app.",
    ),
    "huggingface": ("Hugging Face", "HUGGINGFACE", ""),
    "kakao": ("Kakao", "KAKAO", ""),
    "kick": ("Kick", "KICK", ""),
    "line": ("LINE", "LINE", ""),
    "linear": ("Linear", "LINEAR", ""),
    "linkedin": ("LinkedIn", "LINKEDIN", ""),
    "naver": ("Naver", "NAVER", ""),
    "notion": ("Notion", "NOTION", ""),
    "polar": ("Polar", "POLAR", ""),
    "railway": ("Railway", "RAILWAY", ""),
    "slack": ("Slack", "SLACK", ""),
    "twitter": ("Twitter / X", "TWITTER", ""),
    "vercel": ("Vercel", "VERCEL", ""),
    "vk": ("VK", "VK", ""),
}

ADVANCED = {
    "apple": """use rustauth::social_providers::advanced::apple::{apple, AppleOptions};

.social_provider(apple(AppleOptions {
    oauth: SocialProviderConfig::from_env("APPLE")?.into_provider_options(),
    app_bundle_identifier: std::env::var("APPLE_APP_BUNDLE_ID").ok(),
    audience: std::env::var("APPLE_AUDIENCE").map(|v| vec![v]).unwrap_or_default(),
})?)""",
    "cognito": """use rustauth::social_providers::{CognitoPoolConfig, SocialProviderConfig};

.social_provider(providers::cognito(
    SocialProviderConfig::from_env("COGNITO")?,
    CognitoPoolConfig::new(
        std::env::var("COGNITO_DOMAIN")?,
        std::env::var("COGNITO_REGION")?,
        std::env::var("COGNITO_USER_POOL_ID")?,
    ),
)?)""",
    "discord": """use rustauth::social_providers::advanced::discord::{discord, DiscordOptions, DiscordPrompt};

.social_provider(discord(DiscordOptions {
    oauth: SocialProviderConfig::from_env("DISCORD")?.into_provider_options(),
    prompt: DiscordPrompt::Consent,
    permissions: None,
})?)""",
    "dropbox": """use rustauth::social_providers::advanced::dropbox::{DropboxProvider, DropboxProviderOptions, DropboxAccessType};

.social_provider(DropboxProvider::new(DropboxProviderOptions {
    oauth: SocialProviderConfig::from_env("DROPBOX")?.into_provider_options(),
    access_type: Some(DropboxAccessType::Offline),
})?)""",
    "facebook": """use rustauth::social_providers::advanced::facebook::{facebook, FacebookOptions};

.social_provider(facebook(FacebookOptions {
    oauth: SocialProviderConfig::from_env("FACEBOOK")?.into_provider_options(),
    fields: vec!["email".into(), "name".into()],
    config_id: std::env::var("FACEBOOK_CONFIG_ID").ok(),
    ..FacebookOptions::default()
})?)""",
    "gitlab": """use rustauth::social_providers::advanced::gitlab::{gitlab, GitlabOptions};

.social_provider(gitlab(GitlabOptions {
    oauth: SocialProviderConfig::from_env("GITLAB")?.into_provider_options(),
    issuer: std::env::var("GITLAB_ISSUER").ok(),
})?)""",
    "google": """use rustauth::social_providers::advanced::google::{google, GoogleAccessType, GoogleDisplay, GoogleOptions};

.social_provider(google(GoogleOptions {
    oauth: SocialProviderConfig::from_env("GOOGLE")?.into_provider_options(),
    access_type: Some(GoogleAccessType::Offline),
    display: Some(GoogleDisplay::Page),
    hd: std::env::var("GOOGLE_HD").ok(),
})?)""",
    "microsoft": """use rustauth::social_providers::advanced::microsoft_entra_id::{microsoft_entra_id, MicrosoftEntraIdOptions};

.social_provider(microsoft_entra_id(MicrosoftEntraIdOptions {
    oauth: SocialProviderConfig::from_env("MICROSOFT")?.into_provider_options(),
    tenant_id: std::env::var("MICROSOFT_TENANT_ID").ok(),
    ..MicrosoftEntraIdOptions::default()
})?)""",
    "paybin": """use rustauth::social_providers::advanced::paybin::{paybin, PaybinOptions};

.social_provider(paybin(PaybinOptions {
    oauth: SocialProviderConfig::from_env("PAYBIN")?.into_provider_options(),
    issuer: std::env::var("PAYBIN_ISSUER").ok(),
})?)""",
    "paypal": """use rustauth::social_providers::advanced::paypal::{paypal, PayPalEnvironment, PayPalOptions};

.social_provider(paypal(PayPalOptions {
    oauth: SocialProviderConfig::from_env("PAYPAL")?.into_provider_options(),
    environment: PayPalEnvironment::Sandbox,
    ..PayPalOptions::default()
})?)""",
    "reddit": """use rustauth::social_providers::advanced::reddit::{reddit, RedditOptions};

.social_provider(reddit(RedditOptions {
    oauth: SocialProviderConfig::from_env("REDDIT")?.into_provider_options(),
    duration: Some("permanent".into()),
})?)""",
    "roblox": """use rustauth::social_providers::advanced::roblox::{roblox, RobloxOptions, RobloxPrompt};

.social_provider(roblox(RobloxOptions {
    oauth: SocialProviderConfig::from_env("ROBLOX")?.into_provider_options(),
    prompt: RobloxPrompt::Login,
})?)""",
    "salesforce": """use rustauth::social_providers::advanced::salesforce::{salesforce, SalesforceEnvironment, SalesforceOptions};

.social_provider(salesforce(SalesforceOptions {
    oauth: SocialProviderConfig::from_env("SALESFORCE")?.into_provider_options(),
    environment: SalesforceEnvironment::Sandbox,
    ..SalesforceOptions::default()
})?)""",
    "twitch": """use rustauth::social_providers::advanced::twitch::{twitch, TwitchOptions};

.social_provider(twitch(TwitchOptions {
    oauth: SocialProviderConfig::from_env("TWITCH")?.into_provider_options(),
    claims: vec!["user:read:email".into()],
    ..TwitchOptions::default()
})?)""",
    "wechat": """use rustauth::social_providers::advanced::wechat::{WeChatLang, WeChatProvider, WeChatProviderOptions};

.social_provider(WeChatProvider::new(WeChatProviderOptions {
    oauth: SocialProviderConfig::from_env("WECHAT")?.into_provider_options(),
    lang: Some(WeChatLang::En),
})?)""",
    "zoom": """use rustauth::social_providers::advanced::zoom::{zoom, ZoomOptions};

.social_provider(zoom(ZoomOptions {
    oauth: SocialProviderConfig::from_env("ZOOM")?.into_provider_options(),
    pkce: true,
})?)""",
}

SPOTIFY = """use rustauth::social_providers::providers;
use rustauth::social_providers::SocialProviderConfig;

let spotify_config = SocialProviderConfig::builder()
    .client_id(std::env::var("SPOTIFY_CLIENT_ID")?)
    .client_secret(std::env::var("SPOTIFY_CLIENT_SECRET")?)
    .scope(["user-read-email", "user-read-private"])
    .build()?;

RustAuth::builder()
    // ...
    .social_provider(providers::spotify(spotify_config)?)"""

TIKTOK = """use rustauth::social_providers::providers;
use rustauth::social_providers::SocialProviderConfig;

RustAuth::builder()
    // ...
    .social_provider(providers::tiktok(
        SocialProviderConfig::from_env_with_keys("TIKTOK", &["CLIENT_KEY"])?,
    )?)"""


def catalog_body(slug: str, title: str, env: str, notes: str) -> str:
    extra = f"\n\n{notes}" if notes else ""
    return f"""---
title: {title}
description: {title} OAuth provider for RustAuth.
---

Register an OAuth application in the {title} developer console. Set the redirect URL to:

```
{{RUSTAUTH_BASE_URL}}/callback/{slug}
```

For local development, when `RUSTAUTH_BASE_URL` is `http://127.0.0.1:3000/api/auth`, use `http://127.0.0.1:3000/api/auth/callback/{slug}`.

## Configure RustAuth

```toml
[dependencies]
rustauth = {{ version = "0.1", features = ["social-providers"] }}
```

```rust
use rustauth::prelude::*;
use rustauth::social_providers::providers;
use rustauth::social_providers::SocialProviderConfig;

let auth = RustAuth::builder()
    .secret(std::env::var("RUSTAUTH_SECRET")?)
    .base_url(std::env::var("RUSTAUTH_BASE_URL")?)
    .social_provider(providers::{slug}(
        SocialProviderConfig::from_env("{env}")?,
    )?)
    .build()
    .await?;
```

Environment variables: `{env}_CLIENT_ID`, `{env}_CLIENT_SECRET`.{extra}

## Sign in

Redirect browsers to:

```
GET {{base_url}}/sign-in/social?provider={slug}
```

RustAuth completes the flow at `GET {{base_url}}/callback/{slug}`. RustAuth does not ship a browser client — use your app's BFF or direct redirects. See [basic usage](/docs/basic-usage).
"""


def split_advanced_chain(chain: str) -> tuple[str, str]:
    imports: list[str] = []
    body: list[str] = []
    for line in chain.strip().splitlines():
        if line.startswith("use "):
            imports.append(line)
        elif line.strip():
            body.append(line)
    extra = ("\n" + "\n".join(imports)) if imports else ""
    return extra, "\n".join(body)


def advanced_body(slug: str, title: str, env: str, chain: str) -> str:
    extra_imports, provider_chain = split_advanced_chain(chain)
    return f"""---
title: {title}
description: {title} OAuth provider for RustAuth.
---

Register an OAuth application with {title}. Set the redirect URL to `{{RUSTAUTH_BASE_URL}}/callback/{slug}`.

## Configure RustAuth

```toml
[dependencies]
rustauth = {{ version = "0.1", features = ["social-providers"] }}
```

```rust
use rustauth::prelude::*;
use rustauth::social_providers::providers;
use rustauth::social_providers::SocialProviderConfig;{extra_imports}

let auth = RustAuth::builder()
    .secret(std::env::var("RUSTAUTH_SECRET")?)
    .base_url(std::env::var("RUSTAUTH_BASE_URL")?)
    {provider_chain}
    .build()
    .await?;
```

Credentials: `{env}_CLIENT_ID`, `{env}_CLIENT_SECRET` (and any provider-specific env vars shown above).

## Sign in

```
GET {{base_url}}/sign-in/social?provider={slug}
```

Callback: `GET {{base_url}}/callback/{slug}`.
"""


def main() -> None:
    for slug, (title, env, notes) in CATALOG.items():
        (ROOT / f"{slug}.mdx").write_text(catalog_body(slug, title, env, notes))

    env_map = {
        "apple": "APPLE",
        "cognito": "COGNITO",
        "discord": "DISCORD",
        "dropbox": "DROPBOX",
        "facebook": "FACEBOOK",
        "gitlab": "GITLAB",
        "google": "GOOGLE",
        "microsoft": "MICROSOFT",
        "paybin": "PAYBIN",
        "paypal": "PAYPAL",
        "reddit": "REDDIT",
        "roblox": "ROBLOX",
        "salesforce": "SALESFORCE",
        "twitch": "TWITCH",
        "wechat": "WECHAT",
        "zoom": "ZOOM",
    }
    title_map = {
        "microsoft": "Microsoft Entra ID",
        "wechat": "WeChat",
    }
    for slug, chain in ADVANCED.items():
        title = title_map.get(slug, slug.replace("-", " ").title())
        (ROOT / f"{slug}.mdx").write_text(
            advanced_body(slug, title, env_map[slug], chain)
        )

    (ROOT / "spotify.mdx").write_text(
        f"""---
title: Spotify
description: Spotify OAuth provider for RustAuth.
---

Register a Spotify application and set the redirect URL to `{{RUSTAUTH_BASE_URL}}/callback/spotify`.

## Configure RustAuth

Use `SocialProviderConfig::builder()` when you need explicit scopes:

```rust
{SPOTIFY}
    .build()
    .await?;
```

## Sign in

```
GET {{base_url}}/sign-in/social?provider=spotify
```
"""
    )

    (ROOT / "tiktok.mdx").write_text(
        f"""---
title: TikTok
description: TikTok OAuth provider for RustAuth.
---

TikTok uses `CLIENT_KEY` in addition to `CLIENT_ID` and `CLIENT_SECRET`.

## Configure RustAuth

```rust
{TIKTOK}
    .build()
    .await?;
```

Set `TIKTOK_CLIENT_ID`, `TIKTOK_CLIENT_SECRET`, and `TIKTOK_CLIENT_KEY`.

## Sign in

```
GET {{base_url}}/sign-in/social?provider=tiktok
```
"""
    )


if __name__ == "__main__":
    main()
