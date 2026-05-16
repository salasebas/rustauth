//! Official OpenAuth plugin module surface.
//!
//! Plugin modules are ported against the Better Auth upstream reference where
//! the behavior belongs on the server side, then shaped as idiomatic Rust APIs.

pub mod access;
pub mod additional_fields;
pub mod admin;
pub mod anonymous;
pub mod bearer;
pub mod captcha;
pub mod custom_session;
pub mod device_authorization;
pub mod email_otp;
pub mod generic_oauth;
pub mod haveibeenpwned;
pub mod jwt;
pub mod last_login_method;
pub mod magic_link;
pub mod mcp;
pub mod multi_session;
pub mod oauth_proxy;
pub mod one_tap;
pub mod one_time_token;
pub mod open_api;
pub mod organization;
pub mod phone_number;
pub mod siwe;
pub mod two_factor;
pub mod username;

pub const PLUGIN_IDS: &[&str] = &[
    access::UPSTREAM_PLUGIN_ID,
    additional_fields::UPSTREAM_PLUGIN_ID,
    admin::UPSTREAM_PLUGIN_ID,
    anonymous::UPSTREAM_PLUGIN_ID,
    bearer::UPSTREAM_PLUGIN_ID,
    captcha::UPSTREAM_PLUGIN_ID,
    custom_session::UPSTREAM_PLUGIN_ID,
    device_authorization::UPSTREAM_PLUGIN_ID,
    email_otp::UPSTREAM_PLUGIN_ID,
    generic_oauth::UPSTREAM_PLUGIN_ID,
    haveibeenpwned::UPSTREAM_PLUGIN_ID,
    jwt::UPSTREAM_PLUGIN_ID,
    last_login_method::UPSTREAM_PLUGIN_ID,
    magic_link::UPSTREAM_PLUGIN_ID,
    mcp::UPSTREAM_PLUGIN_ID,
    multi_session::UPSTREAM_PLUGIN_ID,
    oauth_proxy::UPSTREAM_PLUGIN_ID,
    one_tap::UPSTREAM_PLUGIN_ID,
    one_time_token::UPSTREAM_PLUGIN_ID,
    open_api::UPSTREAM_PLUGIN_ID,
    organization::UPSTREAM_PLUGIN_ID,
    phone_number::UPSTREAM_PLUGIN_ID,
    siwe::UPSTREAM_PLUGIN_ID,
    two_factor::UPSTREAM_PLUGIN_ID,
    username::UPSTREAM_PLUGIN_ID,
];

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
