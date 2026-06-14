//! Unhandled API error handling (`onAPIError` parity).

use http::{header, StatusCode};

use crate::api::{ApiErrorResponse, ApiRequest, ApiResponse};
use crate::context::AuthContext;
use crate::error::RustAuthError;
use crate::error_codes;

use super::response_helpers::json_response;

/// Apply `onAPIError` options when the router pipeline returns an error.
pub(crate) fn handle_on_api_error(
    context: &AuthContext,
    request: &ApiRequest,
    error: RustAuthError,
) -> Result<ApiResponse, RustAuthError> {
    if should_propagate_without_on_api_error(&error) {
        return Err(error);
    }
    let options = &context.options.on_api_error;
    if options.throw {
        return Err(error);
    }
    if let Some(handler) = &options.on_error {
        if let Some(response) = handler.on_error(&error, request)? {
            return Ok(response);
        }
    }
    if let Some(error_url) = options.error_url.as_deref() {
        if let Some(location) = redirect_location_for_error(error_url, &error) {
            return redirect_to_error_url(location);
        }
    }
    default_unhandled_api_error_response(context, &error)
}

fn should_propagate_without_on_api_error(error: &RustAuthError) -> bool {
    matches!(
        error,
        RustAuthError::Api(message)
            if message.contains("async endpoint requires AuthRouter::handle_async")
                || message == "async rate limit storage requires AuthRouter::handle_async"
    )
}

fn default_unhandled_api_error_response(
    context: &AuthContext,
    error: &RustAuthError,
) -> Result<ApiResponse, RustAuthError> {
    let (status, code, message) = classify_unhandled_error(context, error);
    json_response(
        status,
        &ApiErrorResponse {
            code: code.to_owned(),
            message,
            original_message: None,
        },
        Vec::new(),
    )
}

fn classify_unhandled_error(
    context: &AuthContext,
    error: &RustAuthError,
) -> (StatusCode, &'static str, String) {
    match error {
        RustAuthError::InvalidRequestBody { .. }
        | RustAuthError::UnsupportedContentType { .. }
        | RustAuthError::MissingContentType => (
            StatusCode::BAD_REQUEST,
            error_codes::INVALID_REQUEST_BODY,
            error.to_string(),
        ),
        RustAuthError::MissingPathParam { .. } => (
            StatusCode::BAD_REQUEST,
            error_codes::INVALID_REQUEST_BODY,
            error.to_string(),
        ),
        RustAuthError::Api(message) if message.contains("async endpoint requires") => (
            StatusCode::INTERNAL_SERVER_ERROR,
            error_codes::INVALID_REQUEST_BODY,
            message.clone(),
        ),
        _ if context.options.explicit_production() => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Internal Server Error".to_owned(),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            error.to_string(),
        ),
    }
}

fn redirect_location_for_error(error_url: &str, error: &RustAuthError) -> Option<String> {
    let code = percent_encode_path_segment(match error {
        RustAuthError::OAuth(_) => "OAUTH_ERROR",
        _ => "INTERNAL_SERVER_ERROR",
    });
    let separator = if error_url.contains('?') { '&' } else { '?' };
    Some(format!("{error_url}{separator}error={code}"))
}

fn redirect_to_error_url(location: String) -> Result<ApiResponse, RustAuthError> {
    http::Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| RustAuthError::Serialization {
            context: "building onAPIError redirect",
            message: error.to_string(),
        })
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
