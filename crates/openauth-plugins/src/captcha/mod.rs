//! CAPTCHA plugin.

mod error;
mod ip;
mod options;
mod response;

pub mod verify_handlers;

pub use error::{CaptchaConfigError, CaptchaErrorCode};
pub use options::{CaptchaOptions, CaptchaProvider, DEFAULT_ENDPOINTS};

use std::sync::Arc;

use openauth_core::plugin::{AuthPlugin, PluginErrorCode};
use response::error_response;
use verify_handlers::{verify_captcha, VerifyCaptchaInput};

pub const UPSTREAM_PLUGIN_ID: &str = "captcha";

/// Create the CAPTCHA plugin.
pub fn captcha(options: CaptchaOptions) -> Result<AuthPlugin, CaptchaConfigError> {
    options.validate()?;

    let options = Arc::new(options.with_defaults());
    let serialized_options = serde_json::to_value(options.as_ref())
        .map_err(|error| CaptchaConfigError::SerializeOptions(error.to_string()))?;

    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_options(serialized_options)
        .with_error_code(PluginErrorCode::new(
            CaptchaErrorCode::VerificationFailed.as_str(),
            CaptchaErrorCode::VerificationFailed.message(),
        ))
        .with_error_code(PluginErrorCode::new(
            CaptchaErrorCode::MissingResponse.as_str(),
            CaptchaErrorCode::MissingResponse.message(),
        ))
        .with_error_code(PluginErrorCode::new(
            CaptchaErrorCode::UnknownError.as_str(),
            CaptchaErrorCode::UnknownError.message(),
        ));

    for endpoint in options.endpoints.clone() {
        let options = Arc::clone(&options);
        plugin = plugin.with_async_middleware(endpoint, move |context, request| {
            let options = Arc::clone(&options);
            Box::pin(async move {
                let Some(captcha_response) = request
                    .headers()
                    .get("x-captcha-response")
                    .and_then(|value| value.to_str().ok())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                else {
                    return error_response(CaptchaErrorCode::MissingResponse).map(Some);
                };

                let input = VerifyCaptchaInput {
                    options: options.as_ref(),
                    captcha_response: &captcha_response,
                    remote_ip: ip::request_ip(context, request),
                };

                match verify_captcha(input).await {
                    Ok(true) => Ok(None),
                    Ok(false) => error_response(CaptchaErrorCode::VerificationFailed).map(Some),
                    Err(_) => error_response(CaptchaErrorCode::UnknownError).map(Some),
                }
            })
        });
    }

    Ok(plugin)
}
