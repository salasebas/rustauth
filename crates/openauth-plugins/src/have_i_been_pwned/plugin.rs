//! Plugin construction for Have I Been Pwned password checks.

use std::sync::Arc;

use openauth_core::plugin::{AuthPlugin, PluginErrorCode, PluginPasswordValidationRejection};

use super::checker::{sha1_prefix_suffix, HaveIBeenPwnedCheckError};
use super::error::{CHECK_FAILED_MESSAGE, PASSWORD_COMPROMISED_CODE, PASSWORD_COMPROMISED_MESSAGE};
use super::options::HaveIBeenPwnedOptions;

pub const UPSTREAM_PLUGIN_ID: &str = "haveibeenpwned";
pub const RUNTIME_PLUGIN_ID: &str = "have-i-been-pwned";

#[must_use]
pub fn have_i_been_pwned() -> AuthPlugin {
    have_i_been_pwned_with(HaveIBeenPwnedOptions::default())
}

#[must_use]
pub fn have_i_been_pwned_with(options: HaveIBeenPwnedOptions) -> AuthPlugin {
    let checker = options.resolved_checker();
    let plugin_options = serde_json::json!({
        "enabled": options.enabled,
        "paths": options.paths,
        "customPasswordCompromisedMessage": options.custom_password_compromised_message,
    });
    let validation_options = options.clone();
    let validation_checker = Arc::clone(&checker);

    AuthPlugin::new(RUNTIME_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(plugin_options)
        .with_error_code(PluginErrorCode::new(
            PASSWORD_COMPROMISED_CODE,
            PASSWORD_COMPROMISED_MESSAGE,
        ))
        .with_password_validator(move |_context, input| {
            let options = validation_options.clone();
            let checker = Arc::clone(&validation_checker);
            Box::pin(async move {
                if !options.enabled || !options.paths.iter().any(|path| path == &input.path) {
                    return Ok(());
                }
                if input.password.is_empty() {
                    return Ok(());
                }
                let (prefix, suffix) = sha1_prefix_suffix(&input.password);
                let compromised = checker
                    .is_hash_suffix_compromised(&prefix, &suffix)
                    .await
                    .map_err(check_error_response)?;
                if compromised {
                    return Err(PluginPasswordValidationRejection::bad_request(
                        PASSWORD_COMPROMISED_CODE,
                        options
                            .custom_password_compromised_message
                            .unwrap_or_else(|| PASSWORD_COMPROMISED_MESSAGE.to_owned()),
                    ));
                }
                Ok(())
            })
        })
}

fn check_error_response(error: HaveIBeenPwnedCheckError) -> PluginPasswordValidationRejection {
    match error {
        HaveIBeenPwnedCheckError::HttpStatus(status) => {
            PluginPasswordValidationRejection::internal_server_error(format!(
                "Failed to check password. Status: {status}"
            ))
        }
        HaveIBeenPwnedCheckError::Transport(_) => {
            PluginPasswordValidationRejection::internal_server_error(CHECK_FAILED_MESSAGE)
        }
    }
}
