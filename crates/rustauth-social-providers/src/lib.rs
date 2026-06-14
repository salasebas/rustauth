//! Server-side social OAuth provider definitions for RustAuth.
//!
//! # Application setup
//!
//! ```rust
//! use rustauth_social_providers::providers::github;
//! use rustauth_social_providers::SocialProviderConfig;
//!
//! # fn example() -> Result<(), rustauth_oauth::oauth2::OAuthError> {
//! let github = github(SocialProviderConfig::new("client-id", "client-secret"))?;
//! # let _ = github;
//! # Ok(())
//! # }
//! ```
//!
//! When credentials come from separate sources, use the builder:
//!
//! ```rust
//! use rustauth_social_providers::providers::github;
//! use rustauth_social_providers::SocialProviderConfig;
//!
//! # fn example(client_id: String, client_secret: String) -> Result<(), rustauth_oauth::oauth2::OAuthError> {
//! let github = github(
//!     SocialProviderConfig::builder()
//!         .client_id(client_id)
//!         .client_secret(client_secret)
//!         .scope(["read:user"])
//!         .build()?,
//! );
//! # let _ = github;
//! # Ok(())
//! # }
//! ```
//!
//! Register the returned provider with `RustAuthOptions::social_provider`.
//!
//! Low-level OAuth request types, endpoint constants, profile structs, and HTTP
//! primitives live under [`advanced`].

mod apple;
mod atlassian;
mod cognito;
mod discord;
mod dropbox;
mod facebook;
mod figma;
mod github;
mod gitlab;
mod google;
mod huggingface;
mod kakao;
mod kick;
mod line;
mod linear;
mod linkedin;
mod microsoft_entra_id;
mod naver;
mod notion;
mod paybin;
mod paypal;
mod polar;
mod railway;
mod reddit;
mod roblox;
mod runtime;
mod salesforce;
mod slack;
mod spotify;
mod tiktok;
mod twitch;
mod twitter;
mod vercel;
mod vk;
mod wechat;
mod zoom;

mod config;
mod http;

pub mod advanced;
pub mod providers;

pub use config::{
    CognitoPoolConfig, ProviderId, SocialProviderConfig, SocialProviderConfigBuilder,
};
pub use runtime::ProviderIdentity;

pub const PROVIDER_IDS: &[&str] = &[
    "apple",
    "atlassian",
    "cognito",
    "discord",
    "facebook",
    "figma",
    "github",
    "microsoft",
    "google",
    "huggingface",
    "slack",
    "spotify",
    "twitch",
    "twitter",
    "dropbox",
    "kick",
    "linear",
    "linkedin",
    "gitlab",
    "tiktok",
    "reddit",
    "roblox",
    "salesforce",
    "vk",
    "zoom",
    "notion",
    "kakao",
    "naver",
    "line",
    "paybin",
    "paypal",
    "polar",
    "railway",
    "vercel",
    "wechat",
];

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
