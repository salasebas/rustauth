use std::sync::Arc;

use http::StatusCode;
use openauth_core::api::additional_fields;
use openauth_core::api::{parse_request_body, ApiRequest};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{set_session_cookie, CookieOptions, SessionCookieOptions};
use openauth_core::db::DbAdapter;
use openauth_core::options::EmailVerificationCallbackPayload;
use openauth_core::user::{CreateUserInput, DbUserStore};
use openauth_core::verification::DbVerificationStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::helpers::{
    create_session, parse_type, resolve_otp, send_email, validated_email, verify_otp,
};
use super::otp;
use super::response;
use super::types::{EmailOtpOptions, EmailOtpType};

pub(super) const SEND_PATH: &str = "/email-otp/send-verification-otp";
pub(super) const CREATE_PATH: &str = "/email-otp/create-verification-otp";
pub(super) const GET_PATH: &str = "/email-otp/get-verification-otp";
pub(super) const CHECK_PATH: &str = "/email-otp/check-verification-otp";
pub(super) const VERIFY_EMAIL_PATH: &str = "/email-otp/verify-email";
pub(super) const SIGN_IN_PATH: &str = "/sign-in/email-otp";
pub(super) const RESET_PASSWORD_PATH: &str = "/email-otp/reset-password";
pub(super) const REQUEST_CHANGE_EMAIL_PATH: &str = "/email-otp/request-email-change";
pub(super) const CHANGE_EMAIL_PATH: &str = "/email-otp/change-email";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendOtpBody {
    email: String,
    #[serde(rename = "type")]
    otp_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckOtpBody {
    email: String,
    #[serde(rename = "type")]
    otp_type: String,
    otp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyEmailBody {
    email: String,
    otp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInBody {
    email: String,
    otp: String,
    name: Option<String>,
    image: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenUserResponse {
    token: String,
    user: Value,
}

pub(super) fn send_otp<'a>(
    context: &'a AuthContext,
    request: ApiRequest,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
) -> openauth_core::api::EndpointFuture<'a> {
    Box::pin(async move {
        let body: SendOtpBody = parse_request_body(&request)?;
        let email = match validated_email(&body.email)? {
            Ok(email) => email,
            Err(response) => return Ok(response),
        };
        let otp_type = match parse_type(&body.otp_type)? {
            Ok(otp_type) => otp_type,
            Err(response) => return Ok(response),
        };
        if otp_type == EmailOtpType::ChangeEmail {
            return response::error(
                StatusCode::BAD_REQUEST,
                "INVALID_OTP_TYPE",
                "Invalid OTP type",
            );
        }
        let user_exists = DbUserStore::new(adapter.as_ref())
            .find_user_by_email(&email)
            .await?
            .is_some();
        let should_send = otp_type == EmailOtpType::SignIn && !options.disable_sign_up;
        let identifier = otp::identifier(otp_type, &email);
        let otp = resolve_otp(
            adapter.as_ref(),
            &options,
            &context.secret_config,
            &email,
            otp_type,
            &identifier,
        )
        .await?;

        if !user_exists && !should_send {
            DbVerificationStore::new(adapter.as_ref())
                .delete_verification(&identifier)
                .await?;
            return response::success();
        }
        if let Some(response) = send_email(&options, &email, otp, otp_type, Some(&request))? {
            return Ok(response);
        }
        response::success()
    })
}

pub(super) fn check_otp<'a>(
    context: &'a AuthContext,
    request: ApiRequest,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
) -> openauth_core::api::EndpointFuture<'a> {
    Box::pin(async move {
        let body: CheckOtpBody = parse_request_body(&request)?;
        let email = match validated_email(&body.email)? {
            Ok(email) => email,
            Err(response) => return Ok(response),
        };
        let otp_type = match parse_type(&body.otp_type)? {
            Ok(otp_type) => otp_type,
            Err(response) => return Ok(response),
        };
        if otp_type == EmailOtpType::ChangeEmail {
            return response::error(
                StatusCode::BAD_REQUEST,
                "INVALID_OTP_TYPE",
                "Invalid OTP type",
            );
        }
        if DbUserStore::new(adapter.as_ref())
            .find_user_by_email(&email)
            .await?
            .is_none()
        {
            return response::error(StatusCode::BAD_REQUEST, "USER_NOT_FOUND", "User not found");
        }
        if let Some(response) = verify_otp(
            adapter.as_ref(),
            &options,
            &context.secret_config,
            &otp::identifier(otp_type, &email),
            &body.otp,
            false,
        )
        .await?
        {
            return Ok(response);
        }
        response::success()
    })
}

pub(super) fn verify_email<'a>(
    context: &'a AuthContext,
    request: ApiRequest,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
) -> openauth_core::api::EndpointFuture<'a> {
    Box::pin(async move {
        let body: VerifyEmailBody = parse_request_body(&request)?;
        let email = match validated_email(&body.email)? {
            Ok(email) => email,
            Err(response) => return Ok(response),
        };
        if let Some(response) = verify_otp(
            adapter.as_ref(),
            &options,
            &context.secret_config,
            &otp::identifier(EmailOtpType::EmailVerification, &email),
            &body.otp,
            true,
        )
        .await?
        {
            return Ok(response);
        }
        let users = DbUserStore::new(adapter.as_ref());
        let Some(user) = users.find_user_by_email(&email).await? else {
            return response::error(StatusCode::BAD_REQUEST, "USER_NOT_FOUND", "User not found");
        };
        if let Some(callback) = &context.options.email_verification.before_email_verification {
            callback.before_email_verification(
                EmailVerificationCallbackPayload { user: user.clone() },
                Some(&request),
            )?;
        }
        let user = users
            .update_user_email_verified(&user.id, true)
            .await?
            .unwrap_or(user);
        if let Some(callback) = &context.options.email_verification.after_email_verification {
            callback.after_email_verification(
                EmailVerificationCallbackPayload { user: user.clone() },
                Some(&request),
            )?;
        }
        let response_user = additional_fields::user_response_value(
            adapter.as_ref(),
            &context.options.user.additional_fields,
            &user,
        )
        .await?;
        if context
            .options
            .email_verification
            .auto_sign_in_after_verification
        {
            let session = create_session(adapter.as_ref(), context, &user.id, &request).await?;
            let cookies = set_session_cookie(
                &context.auth_cookies,
                &context.secret,
                &session.token,
                SessionCookieOptions {
                    dont_remember: false,
                    overrides: CookieOptions::default(),
                },
            )?;
            return response::json(
                StatusCode::OK,
                &serde_json::json!({ "status": true, "token": session.token, "user": response_user }),
                cookies,
            );
        }
        response::json(
            StatusCode::OK,
            &serde_json::json!({ "status": true, "token": null, "user": response_user }),
            Vec::new(),
        )
    })
}

pub(super) fn sign_in<'a>(
    context: &'a AuthContext,
    request: ApiRequest,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
) -> openauth_core::api::EndpointFuture<'a> {
    Box::pin(async move {
        let raw_body: Value = parse_request_body(&request)?;
        let body_object = match raw_body.as_object() {
            Some(object) => object,
            None => {
                return response::error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_REQUEST_BODY",
                    "request body must be an object",
                );
            }
        };
        let body: SignInBody = serde_json::from_value(raw_body.clone())
            .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;
        let email = match validated_email(&body.email)? {
            Ok(email) => email,
            Err(response) => return Ok(response),
        };
        if let Some(response) = verify_otp(
            adapter.as_ref(),
            &options,
            &context.secret_config,
            &otp::identifier(EmailOtpType::SignIn, &email),
            &body.otp,
            true,
        )
        .await?
        {
            return Ok(response);
        }
        let users = DbUserStore::new(adapter.as_ref());
        let user = if let Some(user) = users.find_user_by_email(&email).await? {
            if !user.email_verified {
                users
                    .update_user_email_verified(&user.id, true)
                    .await?
                    .unwrap_or(user)
            } else {
                user
            }
        } else {
            if options.disable_sign_up {
                return response::error(StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP");
            }
            let mut input =
                CreateUserInput::new(body.name.unwrap_or_default(), &email).email_verified(true);
            if let Some(image) = body.image {
                input = input.image(image);
            }
            match additional_fields::create_values(
                &context.options.user.additional_fields,
                body_object,
            ) {
                Ok(fields) => {
                    input = input.additional_fields(fields);
                }
                Err(message) => {
                    return response::error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_REQUEST_BODY",
                        message.message(),
                    );
                }
            }
            users.create_user(input).await?
        };
        let session = create_session(adapter.as_ref(), context, &user.id, &request).await?;
        let cookies = set_session_cookie(
            &context.auth_cookies,
            &context.secret,
            &session.token,
            SessionCookieOptions::default(),
        )?;
        response::json(
            StatusCode::OK,
            &TokenUserResponse {
                token: session.token,
                user: additional_fields::user_response_value(
                    adapter.as_ref(),
                    &context.options.user.additional_fields,
                    &user,
                )
                .await?,
            },
            cookies,
        )
    })
}
