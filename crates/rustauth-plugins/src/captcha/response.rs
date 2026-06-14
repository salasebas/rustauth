//! CAPTCHA API responses.

use http::{header, Response, StatusCode};
use rustauth_core::api::ApiResponse;
use rustauth_core::error::RustAuthError;
use serde::Serialize;

use super::error::CaptchaErrorCode;

#[derive(Serialize)]
struct CaptchaErrorBody {
    code: &'static str,
    message: &'static str,
}

pub(crate) fn error_response(code: CaptchaErrorCode) -> Result<ApiResponse, RustAuthError> {
    let status = match code {
        CaptchaErrorCode::MissingResponse => StatusCode::BAD_REQUEST,
        CaptchaErrorCode::VerificationFailed => StatusCode::FORBIDDEN,
        CaptchaErrorCode::UnknownError => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let body = serde_json::to_vec(&CaptchaErrorBody {
        code: code.as_str(),
        message: code.message(),
    })
    .map_err(|error| RustAuthError::Api(error.to_string()))?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| RustAuthError::Api(error.to_string()))
}
