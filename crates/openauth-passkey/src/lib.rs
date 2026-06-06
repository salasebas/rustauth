//! Server-side passkey plugin for OpenAuth.
//!
//! The plugin is server-only. It exposes Better Auth-inspired HTTP endpoints
//! under `/passkey/*`, contributes a `passkeys` table to the OpenAuth schema,
//! and uses `webauthn-rs` for WebAuthn ceremony generation and verification.
//!
//! ```rust,no_run
//! use openauth_core::options::OpenAuthOptions;
//! use openauth_passkey::{passkey, PasskeyOptions};
//!
//! let options = OpenAuthOptions::new()
//!     .secret("secret-a-at-least-32-chars-long!!")
//!     .base_url("https://app.example.com")
//!     .plugin(passkey(PasskeyOptions::default()));
//! ```
//!
//! WebAuthn registration and authentication state is persisted server-side in
//! OpenAuth's `verification` storage and keyed by a signed short-lived cookie.
//! This is why the crate enables `webauthn-rs` state serialization: the state is
//! not trusted from the client and is deleted after successful verification.

mod challenge;
mod challenge_rate_limit;
mod cookies;
mod errors;
mod openapi;
mod options;
mod response;
mod routes;
mod schema;
mod session;
mod store;
mod webauthn;

pub use errors::PASSKEY_ERROR_CODES;
pub use options::{
    AfterAuthenticationVerificationInput, AfterRegistrationVerificationInput,
    AuthenticatorAttachment, AuthenticatorSelection, PasskeyAdvancedOptions,
    PasskeyAuthenticationOptions, PasskeyAuthenticationRejected, PasskeyChallengeRateLimit,
    PasskeyExtensionsInput, PasskeyManagementOptions, PasskeyOptions, PasskeyRateLimit,
    PasskeyRegistrationOptions, PasskeyRegistrationUser, RegistrationWebAuthnOptions,
    ResidentKeyRequirement, ResolveRegistrationUserInput, UserVerificationRequirement,
};
pub use store::Passkey;
pub use webauthn::{
    PasskeyAuthenticationStart, PasskeyRegistrationStart, PasskeyWebAuthnBackend,
    RealPasskeyWebAuthnBackend, VerifiedAuthentication, VerifiedPasskeyCredential, WebAuthnConfig,
};

use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};

pub const UPSTREAM_PLUGIN_ID: &str = "passkey";

/// Ceremony endpoints that mint or consume WebAuthn challenges.
pub const RATE_LIMITED_CEREMONY_PATHS: &[&str] = &[
    "/passkey/generate-authenticate-options",
    "/passkey/verify-authentication",
    "/passkey/generate-register-options",
    "/passkey/verify-registration",
];

/// Build the server-side passkey plugin.
pub fn passkey(options: PasskeyOptions) -> AuthPlugin {
    let rate_limit_rule = options.rate_limit_rule();
    let options = std::sync::Arc::new(options);
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID).with_version(env!("CARGO_PKG_VERSION"));
    for path in RATE_LIMITED_CEREMONY_PATHS {
        plugin = plugin.with_rate_limit(PluginRateLimitRule::new(*path, rate_limit_rule.clone()));
    }
    for contribution in schema::contributions(&options.passkey_table) {
        plugin = plugin.with_schema(contribution);
    }
    for code in errors::plugin_error_codes() {
        plugin = plugin.with_error_code(code);
    }
    for endpoint in routes::endpoints(options) {
        plugin = plugin.with_endpoint(endpoint);
    }
    plugin
}
