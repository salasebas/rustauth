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
    EmailOtpOptionsBuilder, EmailOtpPayload, EmailOtpType, OtpStorage, ResendStrategy,
    SendEmailOtp,
};

use rustauth_core::error::RustAuthError;
use rustauth_core::options::RateLimitRule;
use rustauth_core::plugin::{AuthPlugin, PluginRateLimitRule};

pub const UPSTREAM_PLUGIN_ID: &str = "email-otp";

/// Build the Email OTP plugin.
pub fn email_otp(options: EmailOtpOptions) -> Result<AuthPlugin, RustAuthError> {
    options.validate()?;
    Ok(build_email_otp_plugin(options))
}

fn build_email_otp_plugin(options: EmailOtpOptions) -> AuthPlugin {
    let rate_limit = options.rate_limit.clone().unwrap_or(RateLimitRule {
        window: time::Duration::seconds(60),
        max: 3,
    });
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
        plugin.with_async_after_hook("/sign-up/email", {
            let options = std::sync::Arc::clone(&hook_options);
            move |context, request, response| {
                let options = std::sync::Arc::clone(&options);
                Box::pin(async move {
                    hooks::send_verification_after_sign_up(context, request, response, options)
                        .await
                })
            }
        })
    } else {
        plugin
    };
    let plugin = if hook_options.override_default_email_verification {
        plugin.with_async_after_hook("/send-verification-email", {
            let options = std::sync::Arc::clone(&hook_options);
            move |context, request, response| {
                let options = std::sync::Arc::clone(&options);
                Box::pin(async move {
                    hooks::override_send_verification_email(context, request, response, options)
                        .await
                })
            }
        })
    } else {
        plugin
    };
    registry::paths()
        .iter()
        .fold(plugin, |plugin: AuthPlugin, path| {
            plugin.with_rate_limit(PluginRateLimitRule::new(*path, rate_limit.clone()))
        })
}
