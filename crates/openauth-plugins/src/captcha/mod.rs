//! CAPTCHA plugin.

mod error;
mod ip;
mod options;
mod response;

pub mod verify_handlers;

pub use error::{CaptchaConfigError, CaptchaErrorCode};
pub use options::{CaptchaOptions, CaptchaProvider, DEFAULT_ENDPOINTS};

use std::sync::Arc;

use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{AuthPlugin, PluginErrorCode};
use openauth_core::utils::url::normalize_pathname;
use response::error_response;
use verify_handlers::{verify_captcha, VerifyCaptchaInput};

pub const UPSTREAM_PLUGIN_ID: &str = "captcha";

/// Create the CAPTCHA plugin.
pub fn captcha_with(options: CaptchaOptions) -> Result<AuthPlugin, OpenAuthError> {
    options
        .validate()
        .map_err(|error| OpenAuthError::InvalidConfig(error.to_string()))?;

    let options = Arc::new(options.with_defaults());
    let serialized_options = serde_json::to_value(options.as_ref())
        .map_err(|error| OpenAuthError::InvalidConfig(error.to_string()))?;

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

    plugin = plugin.with_async_middleware("*", move |context, request| {
        let options = Arc::clone(&options);
        Box::pin(async move {
            let path = normalize_pathname(&request.uri().to_string(), &context.base_path);
            if !options
                .endpoints
                .iter()
                .any(|endpoint| endpoint_matches_path(endpoint, &path))
            {
                return Ok(None);
            }
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

    Ok(plugin)
}

/// Returns whether a configured CAPTCHA `endpoint` protects the routed `path`.
///
/// Matching is performed against the already normalized request pathname only,
/// so query strings and fragments cannot smuggle a protected path into an
/// otherwise unprotected route. An endpoint matches when it equals the path
/// exactly or is a path-segment prefix of it: `/sign-up` protects
/// `/sign-up/email` but not `/sign-up-email` or `/foo/sign-up/email`.
fn endpoint_matches_path(endpoint: &str, path: &str) -> bool {
    let endpoint = endpoint.trim_end_matches('/');
    if endpoint.is_empty() {
        return false;
    }
    path == endpoint
        || path
            .strip_prefix(endpoint)
            .is_some_and(|rest| rest.starts_with('/'))
}
