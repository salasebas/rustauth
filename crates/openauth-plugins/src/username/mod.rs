//! Username plugin.

mod endpoints;
mod errors;
mod hooks;
mod options;
mod schema;

pub use errors::{
    EMAIL_NOT_VERIFIED, INVALID_DISPLAY_USERNAME, INVALID_USERNAME, INVALID_USERNAME_OR_PASSWORD,
    UNEXPECTED_ERROR, USERNAME_IS_ALREADY_TAKEN, USERNAME_TOO_LONG, USERNAME_TOO_SHORT,
};
pub use options::{UsernameOptions, UsernameValidationError, ValidationOrder, ValidationPhase};
pub use schema::UsernameSchemaOptions;

use openauth_core::plugin::AuthPlugin;

pub const UPSTREAM_PLUGIN_ID: &str = "username";

#[must_use]
pub fn username() -> AuthPlugin {
    username_with(UsernameOptions::default())
}

#[must_use]
pub fn username_with(options: UsernameOptions) -> AuthPlugin {
    let options = std::sync::Arc::new(options);
    let schema = options.schema.clone();
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_endpoint(endpoints::sign_in_username_endpoint(options.clone()))
        .with_endpoint(endpoints::is_username_available_endpoint(options.clone()))
        .with_database_hook(hooks::normalize_create_user_hook(options.clone()))
        .with_database_hook(hooks::normalize_update_user_hook(options.clone()))
        .with_before_hook(
            "/sign-up/email",
            hooks::sign_up_before_hook(options.clone()),
        )
        .with_before_hook("/update-user", hooks::update_user_before_hook(options))
        .with_schema(schema::username_field(&schema))
        .with_schema(schema::display_username_field(&schema));

    for error_code in errors::error_codes() {
        plugin = plugin.with_error_code(error_code);
    }

    plugin
}
