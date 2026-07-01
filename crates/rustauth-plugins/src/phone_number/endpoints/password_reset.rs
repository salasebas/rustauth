use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType,
};
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use rustauth_core::options::PasswordResetPayload;
use rustauth_core::outbound::{dispatch_outbound, ready_outbound};
use rustauth_core::user::CreateCredentialAccountInput;
use rustauth_core::verification::CreateVerificationInput;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::phone_number::errors::{
    error_response, invalid_otp, json_response, otp_expired, otp_not_found, too_many_attempts,
    unexpected_error,
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

pub(crate) fn request_endpoint(options: Arc<PhoneNumberOptions>) -> AsyncAuthEndpoint {
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
        move |context, request| {
            let options = Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let body: RequestResetBody = parse_request_body(&request)?;
                if store::find_by_phone(adapter.as_ref(), &body.phone_number)
                    .await?
                    .is_some()
                {
                    let code = otp::generate_otp(options.otp_length);
                    let identifier = reset_identifier(&body.phone_number);
                    otp::create(
                        adapter.as_ref(),
                        &context.secret,
                        identifier,
                        &code,
                        options.expires_in,
                    )
                    .await?;
                    if let Some(sender) = &options.send_password_reset_otp {
                        dispatch_outbound(
                            &context,
                            ready_outbound(sender(&body.phone_number, &code)),
                        );
                    }
                }
                json_response(StatusCode::OK, &StatusResponse { status: true }, Vec::new())
            }
        },
    )
}

pub(crate) fn reset_endpoint(options: Arc<PhoneNumberOptions>) -> AsyncAuthEndpoint {
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
            let options = Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let body: ResetBody = parse_request_body(&request)?;
                if body.new_password.len() < context.password.config.min_password_length {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        rustauth_core::plugin::PluginErrorCode::new(
                            "PASSWORD_TOO_SHORT",
                            "Password is too short",
                        ),
                    );
                }
                if body.new_password.len() > context.password.config.max_password_length {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        rustauth_core::plugin::PluginErrorCode::new(
                            "PASSWORD_TOO_LONG",
                            "Password is too long",
                        ),
                    );
                }
                if let Some(response) =
                    verify_reset_code(&context, &options, &body.phone_number, &body.otp).await?
                {
                    return Ok(response);
                }
                let Some(user) = store::find_by_phone(adapter.as_ref(), &body.phone_number).await?
                else {
                    return error_response(StatusCode::BAD_REQUEST, unexpected_error());
                };
                let users = context.users()?;
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
                    RustAuthError::Adapter("failed to load reset user".to_owned())
                })?;
                if let Some(callback) = &context.options.password.on_password_reset {
                    callback.on_password_reset(
                        PasswordResetPayload { user: user.clone() },
                        Some(&request),
                    )?;
                }
                if context.options.password.revoke_sessions_on_password_reset {
                    context.sessions()?.delete_user_sessions(&user.id).await?;
                }
                json_response(StatusCode::OK, &StatusResponse { status: true }, Vec::new())
            }
        },
    )
}

async fn verify_reset_code(
    context: &AuthContext,
    options: &PhoneNumberOptions,
    phone_number: &str,
    code: &str,
) -> Result<Option<rustauth_core::api::ApiResponse>, RustAuthError> {
    let identifier = reset_identifier(phone_number);
    let verifications = context.verifications()?;
    let Some(verification) = verifications
        .consume_verification_including_expired(&identifier)
        .await?
    else {
        return error_response(StatusCode::BAD_REQUEST, otp_not_found()).map(Some);
    };
    if verification.expires_at <= OffsetDateTime::now_utc() {
        return error_response(StatusCode::BAD_REQUEST, otp_expired()).map(Some);
    }
    let Some(stored_otp) = otp::decode(&verification.value) else {
        return error_response(StatusCode::BAD_REQUEST, invalid_otp()).map(Some);
    };
    if stored_otp.attempts >= options.allowed_attempts {
        return error_response(StatusCode::FORBIDDEN, too_many_attempts()).map(Some);
    }
    if !otp::verify(&context.secret, &identifier, stored_otp, code)? {
        let next_attempts = stored_otp.attempts + 1;
        if next_attempts >= options.allowed_attempts {
            return error_response(StatusCode::FORBIDDEN, too_many_attempts()).map(Some);
        }
        verifications
            .create_verification(CreateVerificationInput::new(
                identifier,
                otp::encode_stored(stored_otp, next_attempts),
                verification.expires_at,
            ))
            .await?;
        return error_response(StatusCode::BAD_REQUEST, invalid_otp()).map(Some);
    }
    Ok(None)
}

fn reset_identifier(phone_number: &str) -> String {
    format!("{phone_number}-request-password-reset")
}
