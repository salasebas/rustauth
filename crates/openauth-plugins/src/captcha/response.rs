//! CAPTCHA API responses.

use http::{header, Response, StatusCode};
use openauth_core::api::ApiResponse;
use openauth_core::error::OpenAuthError;
use serde::Serialize;

use super::error::CaptchaErrorCode;

#[derive(Serialize)]
struct CaptchaErrorBody {
    code: &'static str,
    message: &'static str,
}

pub(crate) fn error_response(code: CaptchaErrorCode) -> Result<ApiResponse, OpenAuthError> {
    let status = match code {
        CaptchaErrorCode::MissingResponse => StatusCode::BAD_REQUEST,
        CaptchaErrorCode::VerificationFailed => StatusCode::FORBIDDEN,
        CaptchaErrorCode::UnknownError => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let body = serde_json::to_vec(&CaptchaErrorBody {
        code: code.as_str(),
        message: code.message(),
    })
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}
