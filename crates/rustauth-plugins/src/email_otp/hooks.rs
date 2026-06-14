use std::sync::Arc;

use http::StatusCode;
use rustauth_core::api::ApiRequest;
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use rustauth_core::plugin::{PluginAfterHookAction, PluginResponse};
use serde::Deserialize;

use super::helpers::{resolve_otp, send_email, validated_email};
use super::otp;
use super::types::{EmailOtpOptions, EmailOtpType};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailBody {
    email: String,
}

pub async fn send_verification_after_sign_up(
    context: &AuthContext,
    request: &ApiRequest,
    response: PluginResponse,
    options: Arc<EmailOtpOptions>,
) -> Result<PluginAfterHookAction, RustAuthError> {
    if !response.status().is_success() {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    context.require_adapter()?;
    send_email_verification_otp(context, request, &options).await?;
    Ok(PluginAfterHookAction::Continue(response))
}

pub async fn override_send_verification_email(
    context: &AuthContext,
    request: &ApiRequest,
    response: PluginResponse,
    options: Arc<EmailOtpOptions>,
) -> Result<PluginAfterHookAction, RustAuthError> {
    context.require_adapter()?;
    let response = if send_email_verification_otp(context, request, &options)
        .await?
        .is_some()
    {
        success_response()
    } else {
        response
    };
    Ok(PluginAfterHookAction::Continue(response))
}

async fn send_email_verification_otp(
    context: &AuthContext,
    request: &ApiRequest,
    options: &EmailOtpOptions,
) -> Result<Option<()>, RustAuthError> {
    let Some(body) = parse_email_body(request)? else {
        return Ok(None);
    };
    let email = match validated_email(&body.email)? {
        Ok(email) => email,
        Err(_) => return Ok(None),
    };
    let identifier = otp::identifier(EmailOtpType::EmailVerification, &email);
    let generated = resolve_otp(
        context,
        options,
        &context.secret_config,
        &email,
        EmailOtpType::EmailVerification,
        &identifier,
    )
    .await?;
    if context.users()?.find_user_by_email(&email).await?.is_none() {
        context
            .verifications()?
            .delete_verification(&identifier)
            .await?;
        return Ok(Some(()));
    }
    send_email(
        context,
        options,
        &email,
        generated,
        EmailOtpType::EmailVerification,
        Some(request),
    )?;
    Ok(Some(()))
}

fn parse_email_body(request: &ApiRequest) -> Result<Option<EmailBody>, RustAuthError> {
    if request.body().is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(request.body())
        .map(Some)
        .map_err(|error| RustAuthError::Api(format!("invalid request body: {error}")))
}

fn success_response() -> PluginResponse {
    http::Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(br#"{"status":true}"#.to_vec())
        .unwrap_or_else(|_| http::Response::new(Vec::new()))
}
