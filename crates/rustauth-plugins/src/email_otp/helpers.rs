use http::{header, StatusCode};
use rustauth_core::api::{ApiRequest, ApiResponse};
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::context::{AuthContext, SecretMaterial};
use rustauth_core::db::{DbValue, User};
use rustauth_core::error::RustAuthError;
use rustauth_core::outbound::dispatch_outbound;
use rustauth_core::session::CreateSessionInput;
use rustauth_core::verification::{CreateVerificationInput, UpdateVerificationInput};
use time::OffsetDateTime;

use super::otp;
use super::response;
use super::types::{EmailOtpOptions, EmailOtpPayload, EmailOtpType, ResendStrategy};

pub(super) async fn resolve_otp(
    context: &AuthContext,
    options: &EmailOtpOptions,
    secret: &SecretMaterial,
    email: &str,
    otp_type: EmailOtpType,
    identifier: &str,
) -> Result<String, RustAuthError> {
    let store = context.verifications()?;
    if options.resend_strategy == ResendStrategy::Reuse {
        if let Some(existing) = store.find_verification(identifier).await? {
            let parts = otp::split_value(&existing.value);
            if existing.expires_at > OffsetDateTime::now_utc()
                && parts.attempts < options.allowed_attempts
            {
                if let Some(plain) = otp::reusable_otp(options, secret, &parts)? {
                    store
                        .update_verification(
                            identifier,
                            UpdateVerificationInput::new().expires_at(expires_at(options)?),
                        )
                        .await?;
                    return Ok(plain);
                }
            } else {
                store.delete_verification(identifier).await?;
            }
        }
    }
    let plain = otp::generate(options, email, otp_type);
    let stored = otp::store(options, secret, &plain)?;
    let input = CreateVerificationInput::new(
        identifier,
        otp::encode_value(&stored, 0),
        expires_at(options)?,
    );
    if store.create_verification(input.clone()).await.is_err() {
        store.delete_verification(identifier).await?;
        store.create_verification(input).await?;
    }
    Ok(plain)
}

pub(super) async fn verify_otp(
    context: &AuthContext,
    options: &EmailOtpOptions,
    secret: &SecretMaterial,
    identifier: &str,
    provided: &str,
    consume: bool,
) -> Result<Option<ApiResponse>, RustAuthError> {
    let store = context.verifications()?;
    let verification = if consume {
        match store
            .take_verification_including_expired(identifier)
            .await?
        {
            Some(verification) => verification,
            None => {
                return response::error(StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP")
                    .map(Some);
            }
        }
    } else {
        match store
            .find_verification_including_expired(identifier)
            .await?
        {
            Some(verification) => verification,
            None => {
                return response::error(StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP")
                    .map(Some);
            }
        }
    };

    if verification.expires_at <= OffsetDateTime::now_utc() {
        if !consume {
            store.delete_verification(identifier).await?;
        }
        return response::error(StatusCode::BAD_REQUEST, "OTP_EXPIRED", "OTP expired").map(Some);
    }

    let parts = otp::split_value(&verification.value);
    if parts.attempts >= options.allowed_attempts {
        if !consume {
            store.delete_verification(identifier).await?;
        }
        return response::error(
            StatusCode::FORBIDDEN,
            "TOO_MANY_ATTEMPTS",
            "Too many attempts",
        )
        .map(Some);
    }

    if !otp::verify(options, secret, &parts.value, provided)? {
        let attempts = parts.attempts.saturating_add(1);
        if attempts >= options.allowed_attempts {
            if !consume {
                store.delete_verification(identifier).await?;
            }
            return response::error(
                StatusCode::FORBIDDEN,
                "TOO_MANY_ATTEMPTS",
                "Too many attempts",
            )
            .map(Some);
        }
        if consume {
            store
                .create_verification(CreateVerificationInput::new(
                    identifier,
                    otp::encode_value(&parts.value, attempts),
                    verification.expires_at,
                ))
                .await?;
        } else {
            store
                .update_verification(
                    identifier,
                    UpdateVerificationInput::new().value(otp::encode_value(&parts.value, attempts)),
                )
                .await?;
        }
        return response::error(StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP").map(Some);
    }
    Ok(None)
}

pub(super) async fn authenticated_user(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Result<User, ApiResponse>, RustAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let Some(result) = SessionAuth::new(context)?
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return response::error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized").map(Err);
    };
    match result.user {
        Some(user) => Ok(Ok(user)),
        None => response::error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized").map(Err),
    }
}

pub(super) async fn create_session(
    context: &AuthContext,
    user_id: &str,
    request: &ApiRequest,
) -> Result<rustauth_core::db::Session, RustAuthError> {
    let expires_at = OffsetDateTime::now_utc() + context.session_config.expires_in;
    let mut input = CreateSessionInput::new(user_id, expires_at);
    let additional_session_fields = context
        .options
        .session
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                name.clone(),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect();
    input = input.additional_fields(additional_session_fields);
    if let Some(user_agent) = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
    {
        input = input.user_agent(user_agent);
    }
    context.sessions()?.create_session(input).await
}

pub(super) fn send_email(
    context: &AuthContext,
    options: &EmailOtpOptions,
    email: &str,
    plain_otp: String,
    otp_type: EmailOtpType,
    request: Option<&ApiRequest>,
) -> Result<Option<ApiResponse>, RustAuthError> {
    let Some(sender) = &options.sender else {
        return response::error(
            StatusCode::BAD_REQUEST,
            "SEND_VERIFICATION_OTP_NOT_CONFIGURED",
            "send email verification is not implemented",
        )
        .map(Some);
    };
    dispatch_outbound(
        context,
        sender.send_email_otp(
            EmailOtpPayload {
                email: email.to_owned(),
                otp: plain_otp,
                otp_type,
            },
            request,
        ),
    );
    Ok(None)
}

pub(super) fn validated_email(email: &str) -> Result<Result<String, ApiResponse>, RustAuthError> {
    let email = otp::normalize_email(email);
    if !otp::valid_email(&email) {
        return response::error(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email").map(Err);
    }
    Ok(Ok(email))
}

pub(super) fn parse_type(value: &str) -> Result<Result<EmailOtpType, ApiResponse>, RustAuthError> {
    match EmailOtpType::try_from(value) {
        Ok(otp_type) => Ok(Ok(otp_type)),
        Err(()) => response::error(
            StatusCode::BAD_REQUEST,
            "INVALID_OTP_TYPE",
            "Invalid OTP type",
        )
        .map(Err),
    }
}

fn expires_at(options: &EmailOtpOptions) -> Result<OffsetDateTime, RustAuthError> {
    Ok(OffsetDateTime::now_utc() + options.expires_in)
}
