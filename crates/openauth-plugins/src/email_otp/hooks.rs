use std::sync::Arc;

use http::StatusCode;
use openauth_core::api::ApiRequest;
use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{PluginAfterHookAction, PluginResponse};
use openauth_core::user::DbUserStore;
use openauth_core::verification::DbVerificationStore;
use serde::Deserialize;

use super::helpers::{resolve_otp, send_email, validated_email};
use super::otp;
use super::types::{EmailOtpOptions, EmailOtpType};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailBody {
    email: String,
}

pub fn send_verification_after_sign_up<'a>(
    context: &'a AuthContext,
    request: &'a ApiRequest,
    response: PluginResponse,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
) -> openauth_core::plugin::PluginAfterHookFuture<'a> {
    Box::pin(async move {
        if !response.status().is_success() {
            return Ok(PluginAfterHookAction::Continue(response));
        }
        send_email_verification_otp(context, request, adapter.as_ref(), &options).await?;
        Ok(PluginAfterHookAction::Continue(response))
    })
}

pub fn override_send_verification_email<'a>(
    context: &'a AuthContext,
    request: &'a ApiRequest,
    response: PluginResponse,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
) -> openauth_core::plugin::PluginAfterHookFuture<'a> {
    Box::pin(async move {
        let response = if send_email_verification_otp(context, request, adapter.as_ref(), &options)
            .await?
            .is_some()
        {
            success_response()
        } else {
            response
        };
        Ok(PluginAfterHookAction::Continue(response))
    })
}

async fn send_email_verification_otp(
    context: &AuthContext,
    request: &ApiRequest,
    adapter: &dyn DbAdapter,
    options: &EmailOtpOptions,
) -> Result<Option<()>, OpenAuthError> {
    let Some(body) = parse_email_body(request)? else {
        return Ok(None);
    };
    let email = match validated_email(&body.email)? {
        Ok(email) => email,
        Err(_) => return Ok(None),
    };
    let identifier = otp::identifier(EmailOtpType::EmailVerification, &email);
    let generated = resolve_otp(
        adapter,
        options,
        &context.secret_config,
        &email,
        EmailOtpType::EmailVerification,
        &identifier,
    )
    .await?;
    if DbUserStore::new(adapter)
        .find_user_by_email(&email)
        .await?
        .is_none()
    {
        DbVerificationStore::new(adapter)
            .delete_verification(&identifier)
            .await?;
        return Ok(Some(()));
    }
    send_email(
        options,
        &email,
        generated,
        EmailOtpType::EmailVerification,
        Some(request),
    )?;
    Ok(Some(()))
}

fn parse_email_body(request: &ApiRequest) -> Result<Option<EmailBody>, OpenAuthError> {
    if request.body().is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(request.body())
        .map(Some)
        .map_err(|error| OpenAuthError::Api(format!("invalid request body: {error}")))
}

fn success_response() -> PluginResponse {
    http::Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(br#"{"status":true}"#.to_vec())
        .unwrap_or_else(|_| http::Response::new(Vec::new()))
}
