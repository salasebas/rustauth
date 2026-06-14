use http::{header, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::error::RustAuthError;
use crate::error_codes::ErrorCode;
use crate::rate_limit::RateLimitRejection;

use super::endpoint::{ApiResponse, Body};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorCode {
    NotFound,
    InvalidOrigin,
    InvalidCallbackUrl,
    InvalidRedirectUrl,
    InvalidErrorCallbackUrl,
    InvalidNewUserCallbackUrl,
    MissingOrNullOrigin,
    CrossSiteNavigationLoginBlocked,
    TooManyRequests,
}

impl ApiErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "NOT_FOUND",
            Self::InvalidOrigin => "INVALID_ORIGIN",
            Self::InvalidCallbackUrl => "INVALID_CALLBACK_URL",
            Self::InvalidRedirectUrl => "INVALID_REDIRECT_URL",
            Self::InvalidErrorCallbackUrl => "INVALID_ERROR_CALLBACK_URL",
            Self::InvalidNewUserCallbackUrl => "INVALID_NEW_USER_CALLBACK_URL",
            Self::MissingOrNullOrigin => "MISSING_OR_NULL_ORIGIN",
            Self::CrossSiteNavigationLoginBlocked => "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
            Self::TooManyRequests => "TOO_MANY_REQUESTS",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NotFound => "Not Found",
            Self::InvalidOrigin => "Invalid origin",
            Self::InvalidCallbackUrl => "Invalid callbackURL",
            Self::InvalidRedirectUrl => "Invalid redirectURL",
            Self::InvalidErrorCallbackUrl => "Invalid errorCallbackURL",
            Self::InvalidNewUserCallbackUrl => "Invalid newUserCallbackURL",
            Self::MissingOrNullOrigin => "Missing or null Origin",
            Self::CrossSiteNavigationLoginBlocked => {
                "Cross-site navigation login blocked. This request appears to be a CSRF attack."
            }
            Self::TooManyRequests => "Too many requests. Please try again later.",
        }
    }
}

impl ErrorCode for ApiErrorCode {
    fn as_str(&self) -> &str {
        (*self).as_str()
    }

    fn message(&self) -> &str {
        (*self).message()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "originalMessage")]
    pub original_message: Option<String>,
}

impl ApiErrorResponse {
    pub fn from_error_code(code: impl ErrorCode) -> Self {
        Self {
            code: code.as_str().to_owned(),
            message: code.message().to_owned(),
            original_message: None,
        }
    }
}

pub fn response(status: StatusCode, body: Body) -> Result<ApiResponse, RustAuthError> {
    Response::builder()
        .status(status)
        .body(body)
        .map_err(|error| RustAuthError::Serialization {
            context: "building API response",
            message: error.to_string(),
        })
}

pub fn api_error(status: StatusCode, code: ApiErrorCode) -> Result<ApiResponse, RustAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse::from_error_code(code)).map_err(|error| {
        RustAuthError::Serialization {
            context: "serializing API error response",
            message: error.to_string(),
        }
    })?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| RustAuthError::Serialization {
            context: "building API error response",
            message: error.to_string(),
        })
}

pub(super) fn rate_limit_response(
    rejection: RateLimitRejection,
) -> Result<ApiResponse, RustAuthError> {
    let mut response = api_error(StatusCode::TOO_MANY_REQUESTS, ApiErrorCode::TooManyRequests)?;
    response.headers_mut().insert(
        "X-Retry-After",
        http::HeaderValue::from_str(&rejection.retry_after.to_string()).map_err(|error| {
            RustAuthError::Serialization {
                context: "building rate limit response headers",
                message: error.to_string(),
            }
        })?,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_codes::ErrorCode;

    fn assert_error_code(code: impl ErrorCode, expected_code: &str, expected_message: &str) {
        assert_eq!(code.as_str(), expected_code);
        assert_eq!(code.message(), expected_message);
    }

    #[test]
    fn api_error_code_implements_error_code_trait() {
        assert_error_code(
            ApiErrorCode::InvalidOrigin,
            "INVALID_ORIGIN",
            "Invalid origin",
        );
    }

    #[test]
    fn api_error_response_from_error_code_matches_inherent_helpers() {
        let code = ApiErrorCode::TooManyRequests;
        let response = ApiErrorResponse::from_error_code(code);
        assert_eq!(response.code, code.as_str());
        assert_eq!(response.message, code.message());
        assert_eq!(response.original_message, None);
    }
}
