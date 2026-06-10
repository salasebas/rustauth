//! Email OTP plugin.

mod change_email;
mod endpoints;
mod errors;
mod helpers;
mod hooks;
mod otp;
mod password;
mod registry;
mod response;
mod schema;
mod server;
mod types;

pub use types::{
    ChangeEmailOptions, EmailOtpEncryptor, EmailOtpGenerator, EmailOtpHasher, EmailOtpOptions,
    EmailOtpPayload, EmailOtpType, OtpStorage, ResendStrategy, SendEmailOtp,
};

use openauth_core::options::RateLimitRule;
use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};

pub const UPSTREAM_PLUGIN_ID: &str = "email-otp";

/// Build the Email OTP plugin with default options.
#[must_use]
pub fn email_otp() -> AuthPlugin {
    email_otp_with(EmailOtpOptions::default())
}

/// Build the Email OTP plugin.
#[must_use]
pub fn email_otp_with(options: EmailOtpOptions) -> AuthPlugin {
    let rate_limit = options
        .rate_limit
        .clone()
        .unwrap_or(RateLimitRule { window: 60, max: 3 });
    let hook_options = std::sync::Arc::new(options.clone());
    let plugin = errors::error_codes().fold(
        registry::register(
            AuthPlugin::new(UPSTREAM_PLUGIN_ID).with_version(crate::VERSION),
            options,
        ),
        AuthPlugin::with_error_code,
    );
    let plugin = if hook_options.send_verification_on_sign_up
        && !hook_options.override_default_email_verification
    {
        let options = std::sync::Arc::clone(&hook_options);
        plugin.with_async_after_hook("/sign-up/email", move |context, request, response| {
            hooks::send_verification_after_sign_up(
                context,
                request,
                response,
                std::sync::Arc::clone(&options),
            )
        })
    } else {
        plugin
    };
    let plugin = if hook_options.override_default_email_verification {
        let options = std::sync::Arc::clone(&hook_options);
        plugin.with_async_after_hook(
            "/send-verification-email",
            move |context, request, response| {
                hooks::override_send_verification_email(
                    context,
                    request,
                    response,
                    std::sync::Arc::clone(&options),
                )
            },
        )
    } else {
        plugin
    };
    registry::paths()
        .iter()
        .fold(plugin, |plugin: AuthPlugin, path| {
            plugin.with_rate_limit(PluginRateLimitRule::new(*path, rate_limit.clone()))
        })
}
