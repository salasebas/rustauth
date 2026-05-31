//! Server-side social OAuth provider definitions for OpenAuth.
//!
//! This crate mirrors Better Auth's built-in social provider catalog while
//! exposing Rust-native typed options, explicit errors, and provider runtime
//! implementations used by OpenAuth social sign-in.

pub mod apple;
pub mod atlassian;
pub mod cognito;
pub mod discord;
pub mod dropbox;
pub mod facebook;
pub mod figma;
pub mod github;
pub mod gitlab;
pub mod google;
pub mod http;
pub mod huggingface;
pub mod kakao;
pub mod kick;
pub mod line;
pub mod linear;
pub mod linkedin;
pub mod microsoft_entra_id;
pub mod naver;
pub mod notion;
pub mod paybin;
pub mod paypal;
pub mod polar;
pub mod railway;
pub mod reddit;
pub mod roblox;
mod runtime;
pub mod salesforce;
pub mod slack;
pub mod spotify;
pub mod tiktok;
pub mod twitch;
pub mod twitter;
pub mod vercel;
pub mod vk;
pub mod wechat;
pub mod zoom;

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
