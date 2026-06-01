mod support;

use std::sync::Arc;

use super::shared::{
    error_response, json_response, password_validation_rejection_response, sensitive_session,
    status_openapi_response, unauthorized,
};
use crate::api::services::password as password_service;
use crate::api::services::password::{
    ChangePasswordInput, PasswordServiceError, PasswordServiceErrorOrOpenAuth,
    RequestPasswordResetInput, ResetPasswordInput, SetPasswordInput, VerifyPasswordInput,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use crate::auth::trusted_origins::OriginMatchSettings;
use crate::db::DbAdapter;
use crate::error::OpenAuthError;
use http::{Method, StatusCode};

use support::{
    change_password_body_schema, invalid_password, invalid_token, password_reset_response,
    path_param, query_param, redirect_with_query, request_password_reset_body_schema,
    reset_password_body_schema, set_password_body_schema, verify_password_body_schema,
    ChangePasswordBody, RequestPasswordResetBody, ResetPasswordBody, SetPasswordBody, StatusBody,
    TokenUserResponse, VerifyPasswordBody,
};

pub(super) fn change_password_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/change-password",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("changePassword")
            .body_schema(change_password_body_schema())
            .openapi(
                OpenApiOperation::new("changePassword")
                    .description("Change the password of the user")
                    .response(
                        "200",
                        super::shared::json_openapi_response(
                            "Password successfully changed",
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "token": {
                                        "type": "string",
                                        "nullable": true,
                                        "description": "New session token if other sessions were revoked",
                                    },
                                    "user": {
                                        "$ref": "#/components/schemas/User",
                                    },
                                },
                                "required": ["user"],
                            }),
                        ),
                    ),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_session, user, mut cookies)) =
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let dont_remember = super::shared::request_dont_remember(context, &request)?;
                let body: ChangePasswordBody = parse_request_body(&request)?;
                let mut token = None;
                if let Some(new_session) = match password_service::change_password(
                    adapter.as_ref(),
                    context,
                    &user,
                    ChangePasswordInput {
                        current_password: body.current_password,
                        new_password: body.new_password,
                        revoke_other_sessions: body.revoke_other_sessions.unwrap_or(false),
                        dont_remember,
                    },
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => return password_service_error_response(error),
                } {
                    super::shared::record_new_session(&new_session, &user)?;
                    cookies = super::shared::auth_session_cookies(
                        context,
                        &new_session,
                        &user,
                        dont_remember,
                    )?;
                    token = Some(new_session.token);
                }

                json_response(StatusCode::OK, &TokenUserResponse { token, user }, cookies)
            })
        },
    )
}

pub(super) fn set_password_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/set-password",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("setPassword")
            .body_schema(set_password_body_schema())
            .openapi(
                OpenApiOperation::new("setPassword")
                    .description("Set a password for the current user")
                    .response("200", status_openapi_response("Success")),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_, user, cookies)) =
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: SetPasswordBody = parse_request_body(&request)?;
                if let Err(error) = password_service::set_password(
                    adapter.as_ref(),
                    context,
                    &user,
                    SetPasswordInput {
                        new_password: body.new_password,
                    },
                )
                .await
                {
                    return password_service_error_response(error);
                }
                json_response(StatusCode::OK, &StatusBody { status: true }, cookies)
            })
        },
    )
}

pub(super) fn verify_password_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/verify-password",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("verifyPassword")
            .body_schema(verify_password_body_schema())
            .openapi(
                OpenApiOperation::new("verifyPassword")
                    .description("Verify the current user's password")
                    .response("200", status_openapi_response("Success")),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((_, user, cookies)) =
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: VerifyPasswordBody = parse_request_body(&request)?;
                if let Err(error) = password_service::verify_password(
                    adapter.as_ref(),
                    context,
                    &user,
                    VerifyPasswordInput {
                        password: body.password,
                    },
                )
                .await
                {
                    return password_service_error_response(error);
                }
                json_response(StatusCode::OK, &StatusBody { status: true }, cookies)
            })
        },
    )
}

pub(super) fn request_password_reset_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/request-password-reset",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("requestPasswordReset")
            .body_schema(request_password_reset_body_schema())
            .openapi(
                OpenApiOperation::new("requestPasswordReset")
                    .description("Send a password reset email to the user")
                    .response(
                        "200",
                        super::shared::json_openapi_response(
                            "Success",
                            serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "status": { "type": "boolean" },
                                    "message": { "type": "string" },
                                },
                            }),
                        ),
                    ),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let body: RequestPasswordResetBody = parse_request_body(&request)?;
                password_service::request_password_reset(
                    adapter.as_ref(),
                    context,
                    Some(&request),
                    RequestPasswordResetInput {
                        email: body.email,
                        redirect_to: body.redirect_to,
                    },
                )
                .await?;
                password_reset_response()
            })
        },
    )
}

pub(super) fn reset_password_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/reset-password",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("resetPassword")
            .body_schema(reset_password_body_schema())
            .openapi(
                OpenApiOperation::new("resetPassword")
                    .description("Reset the password for a user")
                    .response("200", status_openapi_response("Success")),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let query_token = query_param(request.uri().query(), "token");
                let body: ResetPasswordBody = parse_request_body(&request)?;
                let Some(token) = body.token.or(query_token) else {
                    return invalid_token();
                };
                if let Err(error) = password_service::reset_password(
                    adapter.as_ref(),
                    context,
                    Some(&request),
                    ResetPasswordInput {
                        token,
                        new_password: body.new_password,
                    },
                )
                .await
                {
                    return password_service_error_response(error);
                }
                json_response(StatusCode::OK, &StatusBody { status: true }, Vec::new())
            })
        },
    )
}

pub(super) fn reset_password_callback_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/reset-password/:token",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("resetPasswordCallback")
            .openapi(
                OpenApiOperation::new("resetPasswordCallback")
                    .description("Redirects the user to the callback URL with the token")
                    .parameter(serde_json::json!({
                        "name": "token",
                        "in": "path",
                        "required": true,
                        "description": "The token to reset the password",
                        "schema": { "type": "string" },
                    }))
                    .parameter(serde_json::json!({
                        "name": "callbackURL",
                        "in": "query",
                        "required": true,
                        "description": "The URL to redirect the user to reset their password",
                        "schema": { "type": "string" },
                    }))
                    .response("302", super::shared::message_openapi_response("Redirect")),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let token = path_param(&request, "token").unwrap_or_default();
                let callback_url = super::shared::query_param(&request, "callbackURL");
                let Some(callback_url) = callback_url else {
                    return redirect_with_query("/error", "error", "INVALID_TOKEN");
                };
                // Prevent open redirects: only follow trusted origins or safe relative
                // paths. Fall back to /error instead of leaking a token or 302'ing to an
                // attacker-controlled target.
                let settings = Some(OriginMatchSettings {
                    allow_relative_paths: true,
                });
                if !context.is_trusted_origin_for_request(
                    &callback_url,
                    settings,
                    Some(&request),
                )? {
                    return redirect_with_query("/error", "error", "INVALID_TOKEN");
                }
                if token.is_empty() {
                    return redirect_with_query(&callback_url, "error", "INVALID_TOKEN");
                }
                if password_service::reset_password_callback_token_is_valid(
                    adapter.as_ref(),
                    context,
                    token,
                )
                .await?
                {
                    redirect_with_query(&callback_url, "token", token)
                } else {
                    redirect_with_query(&callback_url, "error", "INVALID_TOKEN")
                }
            })
        },
    )
}

fn password_service_error_response(
    error: PasswordServiceErrorOrOpenAuth,
) -> Result<crate::api::ApiResponse, OpenAuthError> {
    match error {
        PasswordServiceErrorOrOpenAuth::OpenAuth(error) => Err(error),
        PasswordServiceErrorOrOpenAuth::Service(error) => match error {
            PasswordServiceError::CredentialAccountNotFound => error_response(
                StatusCode::BAD_REQUEST,
                "CREDENTIAL_ACCOUNT_NOT_FOUND",
                "Credential account not found",
            ),
            PasswordServiceError::InvalidPassword => invalid_password(),
            PasswordServiceError::InvalidToken => invalid_token(),
            PasswordServiceError::PasswordAlreadySet => error_response(
                StatusCode::BAD_REQUEST,
                "PASSWORD_ALREADY_SET",
                "Password already set",
            ),
            PasswordServiceError::PasswordTooLong => error_response(
                StatusCode::BAD_REQUEST,
                "PASSWORD_TOO_LONG",
                "Password is too long",
            ),
            PasswordServiceError::PasswordTooShort => error_response(
                StatusCode::BAD_REQUEST,
                "PASSWORD_TOO_SHORT",
                "Password is too short",
            ),
            PasswordServiceError::PasswordValidation(rejection) => {
                password_validation_rejection_response(rejection)
            }
        },
    }
}
