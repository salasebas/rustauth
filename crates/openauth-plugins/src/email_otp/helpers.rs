use http::{header, StatusCode};
use openauth_core::api::{ApiRequest, ApiResponse};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::{AuthContext, SecretMaterial};
use openauth_core::db::{DbAdapter, DbValue, User, Verification};
use openauth_core::error::OpenAuthError;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::verification::{
    CreateVerificationInput, DbVerificationStore, UpdateVerificationInput,
};
use time::OffsetDateTime;

use super::otp;
use super::response;
use super::types::{EmailOtpOptions, EmailOtpPayload, EmailOtpType, ResendStrategy};

pub(super) async fn resolve_otp(
    adapter: &dyn DbAdapter,
    options: &EmailOtpOptions,
    secret: &SecretMaterial,
    email: &str,
    otp_type: EmailOtpType,
    identifier: &str,
) -> Result<String, OpenAuthError> {
    let store = DbVerificationStore::new(adapter);
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
    adapter: &dyn DbAdapter,
    options: &EmailOtpOptions,
    secret: &SecretMaterial,
    identifier: &str,
    provided: &str,
    consume: bool,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    let store = DbVerificationStore::new(adapter);
    let Some(verification) = store.find_verification(identifier).await? else {
        return response::error(StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP").map(Some);
    };
    if let Some(response) = reject_if_expired(&store, &verification).await? {
        return Ok(Some(response));
    }
    let parts = otp::split_value(&verification.value);
    if parts.attempts >= options.allowed_attempts {
        store.delete_verification(identifier).await?;
        return response::error(
            StatusCode::FORBIDDEN,
            "TOO_MANY_ATTEMPTS",
            "Too many attempts",
        )
        .map(Some);
    }
    if consume {
        store.delete_verification(identifier).await?;
    }
    if !otp::verify(options, secret, &parts.value, provided)? {
        let attempts = parts.attempts.saturating_add(1);
        if attempts >= options.allowed_attempts {
            store.delete_verification(identifier).await?;
            return response::error(
                StatusCode::FORBIDDEN,
                "TOO_MANY_ATTEMPTS",
                "Too many attempts",
            )
            .map(Some);
        } else if consume {
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
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Result<User, ApiResponse>, OpenAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let Some(result) = SessionAuth::new(adapter, context)
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
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user_id: &str,
    request: &ApiRequest,
) -> Result<openauth_core::db::Session, OpenAuthError> {
    let expires_at = OffsetDateTime::now_utc()
        + time::Duration::seconds(context.session_config.expires_in as i64);
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
    DbSessionStore::new(adapter).create_session(input).await
}

pub(super) fn send_email(
    options: &EmailOtpOptions,
    email: &str,
    plain_otp: String,
    otp_type: EmailOtpType,
    request: Option<&ApiRequest>,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    let Some(sender) = &options.sender else {
        return response::error(
            StatusCode::BAD_REQUEST,
            "SEND_VERIFICATION_OTP_NOT_CONFIGURED",
            "send email verification is not implemented",
        )
        .map(Some);
    };
    sender.send_email_otp(
        EmailOtpPayload {
            email: email.to_owned(),
            otp: plain_otp,
            otp_type,
        },
        request,
    )?;
    Ok(None)
}

pub(super) fn validated_email(email: &str) -> Result<Result<String, ApiResponse>, OpenAuthError> {
    let email = otp::normalize_email(email);
    if !otp::valid_email(&email) {
        return response::error(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email").map(Err);
    }
    Ok(Ok(email))
}

pub(super) fn parse_type(value: &str) -> Result<Result<EmailOtpType, ApiResponse>, OpenAuthError> {
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

fn expires_at(options: &EmailOtpOptions) -> Result<OffsetDateTime, OpenAuthError> {
    Ok(OffsetDateTime::now_utc() + otp::seconds_to_duration(options.expires_in)?)
}

async fn reject_if_expired(
    store: &DbVerificationStore<'_>,
    verification: &Verification,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    if verification.expires_at <= OffsetDateTime::now_utc() {
        store.delete_verification(&verification.identifier).await?;
        return response::error(StatusCode::BAD_REQUEST, "OTP_EXPIRED", "OTP expired").map(Some);
    }
    Ok(None)
}
