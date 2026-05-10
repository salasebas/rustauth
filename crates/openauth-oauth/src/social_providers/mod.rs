//! Social provider structure for OpenAuth.
//!
//! Provider modules are placeholders in the initial core port.

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
    "dropbox",
    "facebook",
    "figma",
    "github",
    "gitlab",
    "google",
    "huggingface",
    "kakao",
    "kick",
    "line",
    "linear",
    "linkedin",
    "microsoft",
    "naver",
    "notion",
    "paybin",
    "paypal",
    "polar",
    "railway",
    "reddit",
    "roblox",
    "salesforce",
    "slack",
    "spotify",
    "tiktok",
    "twitch",
    "twitter",
    "vercel",
    "vk",
    "wechat",
    "zoom",
];
