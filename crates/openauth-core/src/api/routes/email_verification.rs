use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::Duration;

use super::shared::{
    current_session, error_response, json_response, percent_encode, query_param,
    status_openapi_response,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::crypto::jwt::{sign_jwt, verify_jwt};
use crate::db::{DbAdapter, User};
use crate::options::{EmailVerificationCallbackPayload, VerificationEmail};
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
                    context.base_url,
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
                    ),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some(token) = query_param(&request, "token") else {
                    return invalid_token();
                };
                let Some(claims) = verify_jwt::<EmailVerificationClaims>(&token, &context.secret)?
                else {
                    return invalid_token();
                };
                let users = DbUserStore::new(adapter.as_ref());
                let Some(user) = users.find_user_by_email(&claims.email).await? else {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
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
                    return json_response(
                        StatusCode::OK,
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
                let updated = if !user.email_verified {
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
                        EmailVerificationCallbackPayload { user: updated },
                        Some(&request),
                    )?;
                }
                json_response(
                    StatusCode::OK,
                    &VerifyEmailResponse {
                        status: true,
                        user: None,
                    },
                    Vec::new(),
                )
            })
        },
    )
}

pub(super) fn create_email_verification_token(
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

fn invalid_token() -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    error_response(StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid token")
}

fn send_verification_email_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("email", JsonSchemaType::String)
            .description("The email to send the verification email to"),
        BodyField::optional("callbackURL", JsonSchemaType::String)
            .description("The URL to use for email verification callback"),
    ])
}
