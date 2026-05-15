mod code;
mod decision;
mod openapi;
mod token;
mod verify;

use http::{header, Response, StatusCode};
use openauth_core::api::ApiResponse;
use openauth_core::error::OpenAuthError;
use serde::Serialize;

pub use code::{device_code, DeviceCodeRequest, DeviceCodeResponse};
pub use decision::{device_approve, device_deny, DeviceApprovalRequest};
pub use token::{device_token, DeviceTokenRequest, DeviceTokenResponse};
pub use verify::{device_verify, DeviceVerificationResponse};

#[derive(Debug, Serialize)]
struct SuccessResponse {
    success: bool,
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

fn clean_user_code(user_code: &str) -> String {
    user_code.replace('-', "")
}
