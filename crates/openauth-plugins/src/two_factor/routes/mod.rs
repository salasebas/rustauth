mod backup_codes;
mod disable;
mod enable;
mod totp;

use std::sync::Arc;

use http::{header, StatusCode};
use openauth_core::api::{ApiRequest, ApiResponse};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};
use serde::Serialize;

use super::cookies::append_cookies;
use super::errors::{error_message, error_response, plugin_error_codes};
use super::flow::sign_in_after_hook;
use super::options::TwoFactorOptions;
use super::schema;

pub fn plugin(options: Arc<TwoFactorOptions>) -> AuthPlugin {
    let mut plugin = AuthPlugin::new(super::UPSTREAM_PLUGIN_ID)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_rate_limit(PluginRateLimitRule::new(
            "/two-factor/*",
            openauth_core::options::RateLimitRule { window: 10, max: 3 },
        ));
    for path in [
        "/sign-in/email",
        "/sign-in/username",
        "/sign-in/phone-number",
    ] {
        plugin = with_sign_in_after_hook(plugin, path, Arc::clone(&options));
    }
    for contribution in schema::contributions(&options.two_factor_table) {
        plugin = plugin.with_schema(contribution);
    }
    for code in plugin_error_codes() {
        plugin = plugin.with_error_code(code);
    }
    for endpoint in endpoints(options) {
        plugin = plugin.with_endpoint(endpoint);
    }
    plugin
}

fn with_sign_in_after_hook(
    plugin: AuthPlugin,
    path: &'static str,
    options: Arc<TwoFactorOptions>,
) -> AuthPlugin {
    plugin.with_async_after_hook(path, move |context, request, response| {
        let options = Arc::clone(&options);
        Box::pin(async move { sign_in_after_hook(context, request, response, options).await })
    })
}

fn endpoints(options: Arc<TwoFactorOptions>) -> Vec<openauth_core::api::AsyncAuthEndpoint> {
    vec![
        enable::enable_endpoint(Arc::clone(&options)),
        disable::disable_endpoint(Arc::clone(&options)),
        enable::get_totp_uri_endpoint(Arc::clone(&options)),
        totp::verify_totp_endpoint(Arc::clone(&options)),
        super::otp_routes::send_otp_endpoint(Arc::clone(&options)),
        super::otp_routes::verify_otp_endpoint(Arc::clone(&options)),
        backup_codes::generate_backup_codes_endpoint(Arc::clone(&options)),
        backup_codes::verify_backup_code_endpoint(Arc::clone(&options)),
        backup_codes::view_backup_codes_endpoint(options),
    ]
}

pub(super) fn request_cookie(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub(super) fn flow_error_response(error: OpenAuthError) -> Result<ApiResponse, OpenAuthError> {
    match error {
        OpenAuthError::Api(code) if code == "INVALID_TWO_FACTOR_COOKIE" => error_response(
            StatusCode::UNAUTHORIZED,
            "INVALID_TWO_FACTOR_COOKIE",
            error_message("INVALID_TWO_FACTOR_COOKIE"),
        ),
        OpenAuthError::Api(code) if code == "INVALID_PASSWORD" => error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_PASSWORD",
            error_message("INVALID_PASSWORD"),
        ),
        OpenAuthError::Api(code) if code == "UNAUTHORIZED" => error_response(
            StatusCode::UNAUTHORIZED,
            "INVALID_TWO_FACTOR_COOKIE",
            error_message("INVALID_TWO_FACTOR_COOKIE"),
        ),
        error => Err(error),
    }
}

pub(super) fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
    cookies: Vec<openauth_core::cookies::Cookie>,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    append_cookies(&mut response, &cookies)?;
    Ok(response)
}
