use http::{header, StatusCode};
use serde::{Deserialize, Serialize};

use super::super::shared::{error_response, json_response};
use crate::api::{ApiRequest, ApiResponse, BodyField, BodySchema, JsonSchemaType, PathParams};
use crate::error::RustAuthError;
use serde_json::Value;

const PASSWORD_RESET_MESSAGE: &str =
    "If this email exists in our system, check your email for the reset link";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChangePasswordBody {
    pub(super) current_password: String,
    pub(super) new_password: String,
    #[serde(default)]
    pub(super) revoke_other_sessions: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SetPasswordBody {
    pub(super) new_password: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct VerifyPasswordBody {
    pub(super) password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RequestPasswordResetBody {
    pub(super) email: String,
    #[serde(default)]
    pub(super) redirect_to: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResetPasswordBody {
    pub(super) new_password: String,
    #[serde(default)]
    pub(super) token: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct StatusBody {
    pub(super) status: bool,
}

#[derive(Debug, Serialize)]
struct RequestPasswordResetResponse {
    status: bool,
    message: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct TokenUserResponse {
    pub(super) token: Option<String>,
    pub(super) user: Value,
}

pub(super) fn change_password_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("newPassword", JsonSchemaType::String)
            .description("The new password to set"),
        BodyField::new("currentPassword", JsonSchemaType::String)
            .description("The current password is required"),
        BodyField::optional("revokeOtherSessions", JsonSchemaType::Boolean)
            .description("Must be a boolean value"),
    ])
}

pub(super) fn set_password_body_schema() -> BodySchema {
    BodySchema::object([BodyField::new("newPassword", JsonSchemaType::String)
        .description("The new password to set is required")])
}

pub(super) fn verify_password_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("password", JsonSchemaType::String).description("The password to verify")
    ])
}

pub(super) fn request_password_reset_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("email", JsonSchemaType::String)
            .format("email")
            .description("The email address of the user to send a password reset email to"),
        BodyField::optional("redirectTo", JsonSchemaType::String)
            .description("The URL to redirect the user to reset their password"),
    ])
}

pub(super) fn reset_password_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("newPassword", JsonSchemaType::String)
            .description("The new password to set"),
        BodyField::optional("token", JsonSchemaType::String)
            .description("The token to reset the password"),
    ])
}

pub(super) fn invalid_password() -> Result<ApiResponse, RustAuthError> {
    error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_PASSWORD",
        "Invalid password",
    )
}

pub(super) fn invalid_token() -> Result<ApiResponse, RustAuthError> {
    error_response(StatusCode::BAD_REQUEST, "INVALID_TOKEN", "Invalid token")
}

pub(super) fn password_reset_response() -> Result<ApiResponse, RustAuthError> {
    json_response(
        StatusCode::OK,
        &RequestPasswordResetResponse {
            status: true,
            message: PASSWORD_RESET_MESSAGE,
        },
        Vec::new(),
    )
}

pub(super) fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.replace('+', " "))
    })
}

pub(super) fn path_param<'a>(request: &'a ApiRequest, name: &str) -> Option<&'a str> {
    request
        .extensions()
        .get::<PathParams>()
        .and_then(|params| params.get(name))
}

pub(super) fn redirect_with_query(
    location: &str,
    key: &str,
    value: &str,
) -> Result<ApiResponse, RustAuthError> {
    let separator = if location.contains('?') { '&' } else { '?' };
    redirect(&format!(
        "{location}{separator}{key}={}",
        percent_encode(value)
    ))
}

fn redirect(location: &str) -> Result<ApiResponse, RustAuthError> {
    http::Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| RustAuthError::Serialization {
            context: "building password redirect response",
            message: error.to_string(),
        })
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
