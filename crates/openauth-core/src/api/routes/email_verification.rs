use std::sync::Arc;

use http::{header, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::shared::{
    additional_session_create_values, auth_session_cookies, current_session, error_response,
    json_response, percent_encode, query_param, record_new_session, request_dont_remember,
    status_openapi_response,
};
use crate::api::response_helpers::redirect_response;
use crate::api::{
    create_auth_endpoint, parse_request_body, request_base_url, AsyncAuthEndpoint,
    AuthEndpointOptions, BodyField, BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::auth::trusted_origins::OriginMatchSettings;
use crate::cookies::Cookie;
use crate::crypto::jwt::{sign_jwt, verify_jwt};
use crate::db::{DbAdapter, User};
use crate::options::{EmailVerificationCallbackPayload, VerificationEmail};
use crate::session::{CreateSessionInput, SessionStore};
use crate::user::DbUserStore;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendVerificationEmailBody {
    email: String,
    #[serde(default, alias = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailVerificationClaims {
    email: String,
    update_to: Option<String>,
    request_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    status: bool,
}

#[derive(Debug, Serialize)]
struct VerifyEmailResponse {
    status: bool,
    user: Option<User>,
}

pub(super) fn send_verification_email_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/send-verification-email",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("sendVerificationEmail")
            .body_schema(send_verification_email_body_schema())
            .openapi(
                OpenApiOperation::new("sendVerificationEmail")
                    .description("Send a verification email to the user")
                    .response("200", status_openapi_response("Success")),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some(sender) = context
                    .options
                    .email_verification
                    .send_verification_email
                    .clone()
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "VERIFICATION_EMAIL_NOT_ENABLED",
                        "Verification email isn't enabled",
                    );
                };
                let body: SendVerificationEmailBody = parse_request_body(&request)?;
                let normalized_email = body.email.to_lowercase();
                let users = DbUserStore::new(adapter.as_ref());
                let session = current_session(adapter.as_ref(), context, &request).await?;

                let user = if let Some((_, session_user, _)) = session {
                    if session_user.email != normalized_email {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "EMAIL_MISMATCH",
                            "Email mismatch",
                        );
                    }
                    if session_user.email_verified {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "EMAIL_ALREADY_VERIFIED",
                            "Email already verified",
                        );
                    }
                    Some(session_user)
                } else {
                    users.find_user_by_email(&normalized_email).await?
                };

                let Some(user) = user else {
                    simulate_verification_token(context, &normalized_email)?;
                    return json_response(StatusCode::OK, &StatusBody { status: true }, Vec::new());
                };
                if user.email_verified {
                    simulate_verification_token(context, &normalized_email)?;
                    return json_response(StatusCode::OK, &StatusBody { status: true }, Vec::new());
                }

                let token = create_email_verification_token(context, &user.email, None, None)?;
                let callback_url = body.callback_url.unwrap_or_else(|| "/".to_owned());
                let url = format!(
                    "{}/verify-email?token={token}&callbackURL={}",
                    request_base_url(context, Some(&request)),
                    percent_encode(&callback_url)
                );
                sender.send_verification_email(
                    VerificationEmail { user, url, token },
                    Some(&request),
                )?;

                json_response(StatusCode::OK, &StatusBody { status: true }, Vec::new())
            })
        },
    )
}

pub(super) fn verify_email_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/verify-email",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("verifyEmail")
            .openapi(
                OpenApiOperation::new("verifyEmail")
                    .description("Verify the email of the user")
                    .parameter(serde_json::json!({
                        "name": "callbackURL",
                        "in": "query",
                        "required": false,
                        "description": "The URL to redirect to after email verification",
                        "schema": { "type": "string" },
                    }))
                    .response(
                        "200",
                        super::shared::json_openapi_response(
                            "Success",
                            json!({
                                "type": "object",
                                "properties": {
                                    "status": { "type": "boolean" },
                                    "user": {
                                        "oneOf": [
                                            { "$ref": "#/components/schemas/User" },
                                            { "type": "null" }
                                        ],
                                    },
                                },
                                "required": ["status", "user"],
                            }),
                        ),
                    )
                    .response("302", super::shared::message_openapi_response("Redirect")),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let callback_url = query_param(&request, "callbackURL");
                let origin_settings = Some(OriginMatchSettings {
                    allow_relative_paths: true,
                });
                if let Some(ref url) = callback_url {
                    if !context.is_trusted_origin_for_request(
                        url,
                        origin_settings,
                        Some(&request),
                    )? {
                        return redirect_with_error("/error", "INVALID_TOKEN");
                    }
                }

                let Some(token) = query_param(&request, "token") else {
                    return verification_error_response(
                        callback_url.as_deref(),
                        "INVALID_TOKEN",
                        "Invalid token",
                    );
                };
                let Some(claims) = verify_jwt::<EmailVerificationClaims>(&token, &context.secret)?
                else {
                    return verification_error_response(
                        callback_url.as_deref(),
                        "INVALID_TOKEN",
                        "Invalid token",
                    );
                };
                let users = DbUserStore::new(adapter.as_ref());
                let Some(user) = users.find_user_by_email(&claims.email).await? else {
                    return verification_error_response(
                        callback_url.as_deref(),
                        "USER_NOT_FOUND",
                        "User not found",
                    );
                };

                if let Some(update_to) = claims.update_to {
                    if let Some(callback) =
                        &context.options.email_verification.before_email_verification
                    {
                        callback.before_email_verification(
                            EmailVerificationCallbackPayload { user: user.clone() },
                            Some(&request),
                        )?;
                    }
                    let updated = users
                        .update_user_email(
                            &user.id,
                            &update_to,
                            claims.request_type.as_deref() == Some("change-email-verification"),
                        )
                        .await?
                        .unwrap_or(user);
                    if let Some(callback) =
                        &context.options.email_verification.after_email_verification
                    {
                        callback.after_email_verification(
                            EmailVerificationCallbackPayload {
                                user: updated.clone(),
                            },
                            Some(&request),
                        )?;
                    }
                    return verify_success_response(
                        callback_url.as_deref(),
                        &VerifyEmailResponse {
                            status: true,
                            user: Some(updated),
                        },
                        Vec::new(),
                    );
                }

                if let Some(callback) =
                    &context.options.email_verification.before_email_verification
                {
                    callback.before_email_verification(
                        EmailVerificationCallbackPayload { user: user.clone() },
                        Some(&request),
                    )?;
                }
                let was_unverified = !user.email_verified;
                let updated = if was_unverified {
                    users
                        .update_user_email_verified(&user.id, true)
                        .await?
                        .unwrap_or(user)
                } else {
                    user
                };
                if let Some(callback) = &context.options.email_verification.after_email_verification
                {
                    callback.after_email_verification(
                        EmailVerificationCallbackPayload {
                            user: updated.clone(),
                        },
                        Some(&request),
                    )?;
                }
                let cookies = if context
                    .options
                    .email_verification
                    .auto_sign_in_after_verification
                    && was_unverified
                {
                    auto_sign_in_after_verification_cookies(
                        adapter.as_ref(),
                        context,
                        &request,
                        &updated,
                        &claims.email,
                    )
                    .await?
                } else {
                    Vec::new()
                };
                verify_success_response(
                    callback_url.as_deref(),
                    &VerifyEmailResponse {
                        status: true,
                        user: None,
                    },
                    cookies,
                )
            })
        },
    )
}

pub(in crate::api) fn create_email_verification_token(
    context: &crate::context::AuthContext,
    email: &str,
    update_to: Option<&str>,
    request_type: Option<&str>,
) -> Result<String, crate::error::OpenAuthError> {
    let expires_in = context
        .options
        .email_verification
        .expires_in
        .unwrap_or(60 * 60);
    sign_jwt(
        &EmailVerificationClaims {
            email: email.to_lowercase(),
            update_to: update_to.map(str::to_owned),
            request_type: request_type.map(str::to_owned),
        },
        &context.secret,
        Duration::seconds(expires_in as i64).whole_seconds(),
    )
}

fn simulate_verification_token(
    context: &crate::context::AuthContext,
    email: &str,
) -> Result<(), crate::error::OpenAuthError> {
    create_email_verification_token(context, email, None, None).map(|_| ())
}

async fn auto_sign_in_after_verification_cookies(
    adapter: &dyn DbAdapter,
    context: &crate::context::AuthContext,
    request: &crate::api::ApiRequest,
    user: &User,
    verified_email: &str,
) -> Result<Vec<Cookie>, crate::error::OpenAuthError> {
    if let Some((session, session_user, _)) = current_session(adapter, context, request).await? {
        if session_user.email == verified_email {
            let dont_remember = request_dont_remember(context, request)?;
            return auth_session_cookies(context, &session, user, dont_remember);
        }
    }

    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(context.session_config.expires_in as i64);
    let mut input = CreateSessionInput::new(&user.id, expires_at)
        .additional_fields_with(additional_session_create_values(context));
    if let Some(user_agent) = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
    {
        input = input.user_agent(user_agent);
    }
    let session = SessionStore::new(adapter, context)
        .create_session(input)
        .await?;
    record_new_session(&session, user)?;
    auth_session_cookies(context, &session, user, false)
}

fn verify_success_response(
    callback_url: Option<&str>,
    body: &VerifyEmailResponse,
    cookies: Vec<Cookie>,
) -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    if let Some(url) = callback_url {
        return redirect_response(url, cookies);
    }
    json_response(StatusCode::OK, body, cookies)
}

fn verification_error_response(
    callback_url: Option<&str>,
    code: &str,
    message: &str,
) -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    if let Some(url) = callback_url {
        return redirect_with_error(url, code);
    }
    error_response(StatusCode::UNAUTHORIZED, code, message)
}

fn redirect_with_error(
    location: &str,
    code: &str,
) -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    let separator = if location.contains('?') { '&' } else { '?' };
    redirect(&format!(
        "{location}{separator}error={}",
        percent_encode(code)
    ))
}

fn redirect(location: &str) -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    http::Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| crate::error::OpenAuthError::Serialization {
            context: "building email verification redirect response",
            message: error.to_string(),
        })
}

fn send_verification_email_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("email", JsonSchemaType::String)
            .description("The email to send the verification email to"),
        BodyField::optional("callbackURL", JsonSchemaType::String)
            .description("The URL to use for email verification callback"),
    ])
}
