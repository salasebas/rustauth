//! Phone number authentication plugin.

mod endpoints;
mod errors;
mod hooks;
mod options;
mod otp;
mod schema;
mod store;

use std::sync::Arc;

use openauth_core::options::RateLimitRule;
use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};

pub use errors::PHONE_NUMBER_ERROR_CODES;
pub use options::{
    PhoneNumberCallback, PhoneNumberOptions, PhoneNumberSender, PhoneNumberValidator,
    PhoneNumberVerifier, SignUpOnVerification,
};
pub use schema::PhoneNumberSchemaOptions;

pub const UPSTREAM_PLUGIN_ID: &str = "phone-number";

/// Build the phone number plugin with default options.
#[must_use]
pub fn phone_number() -> AuthPlugin {
    phone_number_with(PhoneNumberOptions::default())
}

/// Build the phone number plugin.
#[must_use]
pub fn phone_number_with(options: PhoneNumberOptions) -> AuthPlugin {
    let options = Arc::new(options.with_defaults());
    let schema = options.schema.clone();
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_endpoint(endpoints::sign_in::endpoint(Arc::clone(&options)))
        .with_endpoint(endpoints::send_otp::endpoint(Arc::clone(&options)))
        .with_endpoint(endpoints::verify::endpoint(Arc::clone(&options)))
        .with_endpoint(endpoints::password_reset::request_endpoint(Arc::clone(
            &options,
        )))
        .with_endpoint(endpoints::password_reset::reset_endpoint(options))
        .with_schema(schema::phone_number_field(&schema))
        .with_schema(schema::phone_number_verified_field(&schema))
        .with_rate_limit(PluginRateLimitRule::new(
            "/phone-number/*",
            RateLimitRule {
                window: 60,
                max: 10,
            },
        ))
        .with_error_code(errors::invalid_phone_number())
        .with_error_code(errors::phone_number_exists())
        .with_error_code(errors::phone_number_not_exists())
        .with_error_code(errors::invalid_phone_number_or_password())
        .with_error_code(errors::unexpected_error())
        .with_error_code(errors::otp_not_found())
        .with_error_code(errors::otp_expired())
        .with_error_code(errors::invalid_otp())
        .with_error_code(errors::phone_number_not_verified())
        .with_error_code(errors::phone_number_cannot_be_updated())
        .with_error_code(errors::send_otp_not_implemented())
        .with_error_code(errors::too_many_attempts())
        .with_before_hook("/update-user", hooks::block_unsafe_update_user)
        .with_database_hook(hooks::reset_verified_when_clearing_phone())
}
