use std::sync::Arc;

use http::StatusCode;
use rustauth_core::api::{parse_request_body, ApiRequest, ApiResponse};
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use rustauth_core::options::EmailVerificationCallbackPayload;
use serde::Deserialize;

use super::helpers::{authenticated_user, resolve_otp, send_email, validated_email, verify_otp};
use super::otp;
use super::response;
use super::types::{EmailOtpOptions, EmailOtpType};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestEmailChangeBody {
    new_email: String,
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmailBody {
    new_email: String,
    otp: String,
}

pub(super) async fn request_email_change(
    context: AuthContext,
    request: ApiRequest,
    options: Arc<EmailOtpOptions>,
) -> Result<ApiResponse, RustAuthError> {
    if !options.change_email.enabled {
        return response::error(
            StatusCode::BAD_REQUEST,
            "CHANGE_EMAIL_DISABLED",
            "Change email with OTP is disabled",
        );
    }
    let body: RequestEmailChangeBody = parse_request_body(&request)?;
    let new_email = match validated_email(&body.new_email)? {
        Ok(email) => email,
        Err(response) => return Ok(response),
    };
    let user = match authenticated_user(&context, &request).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };
    let current_email = otp::normalize_email(&user.email);
    if new_email == current_email {
        return response::error(
            StatusCode::BAD_REQUEST,
            "EMAIL_IS_THE_SAME",
            "Email is the same",
        );
    }
    if options.change_email.verify_current_email {
        let Some(current_otp) = body.otp else {
            return response::error(
                StatusCode::BAD_REQUEST,
                "OTP_REQUIRED",
                "OTP is required to verify current email",
            );
        };
        if let Some(response) = verify_otp(
            &context,
            &options,
            &context.secret_config,
            &otp::identifier(EmailOtpType::EmailVerification, &current_email),
            &current_otp,
            true,
        )
        .await?
        {
            return Ok(response);
        }
    }
    let identifier = otp::change_email_identifier(&current_email, &new_email);
    let generated = resolve_otp(
        &context,
        &options,
        &context.secret_config,
        &new_email,
        EmailOtpType::ChangeEmail,
        &identifier,
    )
    .await?;
    if context
        .users()?
        .find_user_by_email(&new_email)
        .await?
        .is_some()
    {
        context
            .verifications()?
            .delete_verification(&identifier)
            .await?;
        return response::success();
    }
    if let Some(response) = send_email(
        &context,
        &options,
        &new_email,
        generated,
        EmailOtpType::ChangeEmail,
        Some(&request),
    )? {
        return Ok(response);
    }
    response::success()
}

pub(super) async fn change_email(
    context: AuthContext,
    request: ApiRequest,
    options: Arc<EmailOtpOptions>,
) -> Result<ApiResponse, RustAuthError> {
    if !options.change_email.enabled {
        return response::error(
            StatusCode::BAD_REQUEST,
            "CHANGE_EMAIL_DISABLED",
            "Change email with OTP is disabled",
        );
    }
    let body: ChangeEmailBody = parse_request_body(&request)?;
    let new_email = match validated_email(&body.new_email)? {
        Ok(email) => email,
        Err(response) => return Ok(response),
    };
    let user = match authenticated_user(&context, &request).await? {
        Ok(user) => user,
        Err(response) => return Ok(response),
    };
    let current_email = otp::normalize_email(&user.email);
    if let Some(response) = verify_otp(
        &context,
        &options,
        &context.secret_config,
        &otp::change_email_identifier(&current_email, &new_email),
        &body.otp,
        true,
    )
    .await?
    {
        return Ok(response);
    }
    let users = context.users()?;
    if new_email == current_email {
        return response::error(
            StatusCode::BAD_REQUEST,
            "EMAIL_IS_THE_SAME",
            "Email is the same",
        );
    }
    if users.find_user_by_email(&new_email).await?.is_some() {
        return response::error(
            StatusCode::BAD_REQUEST,
            "EMAIL_ALREADY_IN_USE",
            "Email already in use",
        );
    }
    if let Some(callback) = &context.options.email_verification.before_email_verification {
        callback.before_email_verification(
            EmailVerificationCallbackPayload { user: user.clone() },
            Some(&request),
        )?;
    }
    let updated = users
        .update_user_email(&user.id, &new_email, true)
        .await?
        .unwrap_or(user);
    if let Some(callback) = &context.options.email_verification.after_email_verification {
        callback.after_email_verification(
            EmailVerificationCallbackPayload {
                user: updated.clone(),
            },
            Some(&request),
        )?;
    }
    response::success()
}
