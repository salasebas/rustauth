use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType,
};
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::options::PasswordResetPayload;
use openauth_core::session::SessionStore;
use openauth_core::user::{CreateCredentialAccountInput, DbUserStore};
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::phone_number::errors::{
    error_response, json_response, otp_expired, otp_not_found, too_many_attempts, unexpected_error,
};
use crate::phone_number::options::PhoneNumberOptions;
use crate::phone_number::{otp, store};

#[derive(Debug, Deserialize)]
struct RequestResetBody {
    #[serde(alias = "phoneNumber")]
    phone_number: String,
}

#[derive(Debug, Deserialize)]
struct ResetBody {
    #[serde(alias = "phoneNumber")]
    phone_number: String,
    otp: String,
    #[serde(alias = "newPassword")]
    new_password: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: bool,
}

pub(crate) fn request_endpoint(
    adapter: Arc<dyn DbAdapter>,
    options: Arc<PhoneNumberOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/phone-number/request-password-reset",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("requestPasswordResetPhoneNumber")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(BodySchema::object([BodyField::new(
                "phoneNumber",
                JsonSchemaType::String,
            )])),
        move |_context, request| {
            let adapter = Arc::clone(&adapter);
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: RequestResetBody = parse_request_body(&request)?;
                let code = otp::generate_otp(options.otp_length);
                let identifier = reset_identifier(&body.phone_number);
                otp::create(adapter.as_ref(), identifier, &code, options.expires_in).await?;
                if store::find_by_phone(adapter.as_ref(), &body.phone_number)
                    .await?
                    .is_some()
                {
                    if let Some(sender) = &options.send_password_reset_otp {
                        sender(&body.phone_number, &code)?;
                    }
                }
                json_response(StatusCode::OK, &StatusResponse { status: true }, Vec::new())
            })
        },
    )
}

pub(crate) fn reset_endpoint(
    adapter: Arc<dyn DbAdapter>,
    options: Arc<PhoneNumberOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/phone-number/reset-password",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("resetPasswordPhoneNumber")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(BodySchema::object([
                BodyField::new("phoneNumber", JsonSchemaType::String),
                BodyField::new("otp", JsonSchemaType::String),
                BodyField::new("newPassword", JsonSchemaType::String),
            ])),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: ResetBody = parse_request_body(&request)?;
                if body.new_password.len() < context.password.config.min_password_length {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        openauth_core::plugin::PluginErrorCode::new(
                            "PASSWORD_TOO_SHORT",
                            "Password is too short",
                        ),
                    );
                }
                if body.new_password.len() > context.password.config.max_password_length {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        openauth_core::plugin::PluginErrorCode::new(
                            "PASSWORD_TOO_LONG",
                            "Password is too long",
                        ),
                    );
                }
                if let Some(response) =
                    verify_reset_code(adapter.as_ref(), &options, &body.phone_number, &body.otp)
                        .await?
                {
                    return Ok(response);
                }
                let Some(user) = store::find_by_phone(adapter.as_ref(), &body.phone_number).await?
                else {
                    return error_response(StatusCode::BAD_REQUEST, unexpected_error());
                };
                let users = DbUserStore::new(adapter.as_ref());
                let hash = (context.password.hash)(&body.new_password)?;
                if users
                    .update_credential_password(&user.id, &hash)
                    .await?
                    .is_none()
                {
                    users
                        .create_credential_account(CreateCredentialAccountInput::new(
                            &user.id, hash,
                        ))
                        .await?;
                }
                let user = users.find_user_by_id(&user.id).await?.ok_or_else(|| {
                    OpenAuthError::Adapter("failed to load reset user".to_owned())
                })?;
                if let Some(callback) = &context.options.password.on_password_reset {
                    callback.on_password_reset(
                        PasswordResetPayload { user: user.clone() },
                        Some(&request),
                    )?;
                }
                if context.options.password.revoke_sessions_on_password_reset {
                    SessionStore::new(adapter.as_ref(), context)
                        .delete_user_sessions(&user.id)
                        .await?;
                }
                json_response(StatusCode::OK, &StatusResponse { status: true }, Vec::new())
            })
        },
    )
}

async fn verify_reset_code(
    adapter: &dyn DbAdapter,
    options: &PhoneNumberOptions,
    phone_number: &str,
    code: &str,
) -> Result<Option<openauth_core::api::ApiResponse>, OpenAuthError> {
    let identifier = reset_identifier(phone_number);
    let verifications = DbVerificationStore::new(adapter);
    let Some(verification) = verifications
        .consume_verification_including_expired(&identifier)
        .await?
    else {
        return error_response(StatusCode::BAD_REQUEST, otp_not_found()).map(Some);
    };
    if verification.expires_at <= OffsetDateTime::now_utc() {
        return error_response(StatusCode::BAD_REQUEST, otp_expired()).map(Some);
    }
    let (otp_value, attempts) = otp::decode(&verification.value);
    if attempts >= options.allowed_attempts {
        return error_response(StatusCode::FORBIDDEN, too_many_attempts()).map(Some);
    }
    if otp_value != code {
        let next_attempts = attempts + 1;
        if next_attempts >= options.allowed_attempts {
            return error_response(StatusCode::FORBIDDEN, too_many_attempts()).map(Some);
        }
        verifications
            .create_verification(CreateVerificationInput::new(
                identifier,
                otp::encode(otp_value, next_attempts),
                verification.expires_at,
            ))
            .await?;
        return error_response(
            StatusCode::BAD_REQUEST,
            openauth_core::plugin::PluginErrorCode::new("INVALID_OTP", "Invalid OTP"),
        )
        .map(Some);
    }
    Ok(None)
}

fn reset_identifier(phone_number: &str) -> String {
    format!("{phone_number}-request-password-reset")
}
