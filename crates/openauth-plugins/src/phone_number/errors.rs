use http::StatusCode;
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginErrorCode;

pub const PHONE_NUMBER_ERROR_CODES: &[(&str, &str)] = &[
    ("INVALID_PHONE_NUMBER", "Invalid phone number"),
    ("PHONE_NUMBER_EXIST", "Phone number already exists"),
    ("PHONE_NUMBER_NOT_EXIST", "phone number isn't registered"),
    (
        "INVALID_PHONE_NUMBER_OR_PASSWORD",
        "Invalid phone number or password",
    ),
    ("UNEXPECTED_ERROR", "Unexpected error"),
    ("OTP_NOT_FOUND", "OTP not found"),
    ("OTP_EXPIRED", "OTP expired"),
    ("INVALID_OTP", "Invalid OTP"),
    ("PHONE_NUMBER_NOT_VERIFIED", "Phone number not verified"),
    (
        "PHONE_NUMBER_CANNOT_BE_UPDATED",
        "Phone number cannot be updated",
    ),
    ("SEND_OTP_NOT_IMPLEMENTED", "sendOTP not implemented"),
    ("TOO_MANY_ATTEMPTS", "Too many attempts"),
];

macro_rules! error_code_fn {
    ($name:ident, $code:literal, $message:literal) => {
        pub fn $name() -> PluginErrorCode {
            PluginErrorCode::new($code, $message)
        }
    };
}

error_code_fn!(
    invalid_phone_number,
    "INVALID_PHONE_NUMBER",
    "Invalid phone number"
);
error_code_fn!(
    phone_number_exists,
    "PHONE_NUMBER_EXIST",
    "Phone number already exists"
);
error_code_fn!(
    phone_number_not_exists,
    "PHONE_NUMBER_NOT_EXIST",
    "phone number isn't registered"
);
error_code_fn!(
    invalid_phone_number_or_password,
    "INVALID_PHONE_NUMBER_OR_PASSWORD",
    "Invalid phone number or password"
);
error_code_fn!(unexpected_error, "UNEXPECTED_ERROR", "Unexpected error");
error_code_fn!(otp_not_found, "OTP_NOT_FOUND", "OTP not found");
error_code_fn!(otp_expired, "OTP_EXPIRED", "OTP expired");
error_code_fn!(invalid_otp, "INVALID_OTP", "Invalid OTP");
error_code_fn!(
    phone_number_not_verified,
    "PHONE_NUMBER_NOT_VERIFIED",
    "Phone number not verified"
);
error_code_fn!(
    phone_number_cannot_be_updated,
    "PHONE_NUMBER_CANNOT_BE_UPDATED",
    "Phone number cannot be updated"
);
error_code_fn!(
    send_otp_not_implemented,
    "SEND_OTP_NOT_IMPLEMENTED",
    "sendOTP not implemented"
);
error_code_fn!(too_many_attempts, "TOO_MANY_ATTEMPTS", "Too many attempts");

pub(crate) fn error_response(
    status: StatusCode,
    error: PluginErrorCode,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &ApiErrorResponse {
            code: error.code,
            message: error.message,
            original_message: None,
        },
        Vec::new(),
    )
}

pub(crate) fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<openauth_core::cookies::Cookie>,
) -> Result<ApiResponse, OpenAuthError>
where
    T: serde::Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    for cookie in cookies {
        response.headers_mut().append(
            http::header::SET_COOKIE,
            http::HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

fn serialize_cookie(cookie: &openauth_core::cookies::Cookie) -> String {
    let mut value = format!("{}={}", cookie.name, cookie.value);
    if let Some(max_age) = cookie.attributes.max_age {
        value.push_str(&format!("; Max-Age={max_age}"));
    }
    if let Some(domain) = &cookie.attributes.domain {
        value.push_str(&format!("; Domain={domain}"));
    }
    if let Some(path) = &cookie.attributes.path {
        value.push_str(&format!("; Path={path}"));
    }
    if cookie.attributes.http_only.unwrap_or(false) {
        value.push_str("; HttpOnly");
    }
    if cookie.attributes.secure.unwrap_or(false) {
        value.push_str("; Secure");
    }
    if let Some(same_site) = &cookie.attributes.same_site {
        value.push_str("; SameSite=");
        value.push_str(same_site);
    }
    value
}
