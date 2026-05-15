use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::shared::{
    current_session, error_response, json_response, password_validation_rejection_response,
    status_openapi_response, unauthorized,
};
use crate::api::plugin_pipeline::run_password_validators;
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::crypto::random::generate_random_string;
use crate::db::{DbAdapter, User};
use crate::options::PasswordResetPayload;
use crate::session::{CreateSessionInput, DbSessionStore};
use crate::user::{CreateCredentialAccountInput, DbUserStore};
use crate::verification::{CreateVerificationInput, DbVerificationStore};

const PASSWORD_RESET_MESSAGE: &str =
    "If this email exists in our system, check your email for the reset link";

#[derive(Debug, Deserialize)]
struct ChangePasswordBody {
    #[serde(alias = "currentPassword")]
    current_password: String,
    #[serde(alias = "newPassword")]
    new_password: String,
    #[serde(default, alias = "revokeOtherSessions")]
    revoke_other_sessions: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SetPasswordBody {
    #[serde(alias = "newPassword")]
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct VerifyPasswordBody {
    password: String,
}

#[derive(Debug, Deserialize)]
struct RequestPasswordResetBody {
    email: String,
    #[serde(default, alias = "redirectTo")]
    redirect_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResetPasswordBody {
    #[serde(alias = "newPassword")]
    new_password: String,
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    status: bool,
}

#[derive(Debug, Serialize)]
struct RequestPasswordResetResponse {
    status: bool,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct TokenUserResponse {
    token: Option<String>,
    user: User,
}

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
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: ChangePasswordBody = parse_request_body(&request)?;
                if let Some(response) = validate_password_length(context, &body.new_password)? {
                    return Ok(response);
                }
                let users = DbUserStore::new(adapter.as_ref());
                let Some(account) = users.find_credential_account(&user.id).await? else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "CREDENTIAL_ACCOUNT_NOT_FOUND",
                        "Credential account not found",
                    );
                };
                let Some(password_hash) = account.password.as_deref() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "CREDENTIAL_ACCOUNT_NOT_FOUND",
                        "Credential account not found",
                    );
                };
                if !(context.password.verify)(password_hash, &body.current_password)? {
                    return invalid_password();
                }
                if let Err(rejection) =
                    run_password_validators(context, "/change-password", &body.new_password).await
                {
                    return password_validation_rejection_response(rejection);
                }

                let new_hash = (context.password.hash)(&body.new_password)?;
                users.update_credential_password(&user.id, &new_hash).await?;

                let mut token = None;
                if body.revoke_other_sessions.unwrap_or(false) {
                    let sessions = DbSessionStore::new(adapter.as_ref());
                    sessions.delete_user_sessions(&user.id).await?;
                    let new_session = sessions
                        .create_session(CreateSessionInput::new(
                            &user.id,
                            OffsetDateTime::now_utc()
                                + Duration::seconds(context.session_config.expires_in as i64),
                        ))
                        .await?;
                    super::shared::record_new_session(&new_session, &user)?;
                    cookies = super::shared::auth_session_cookies(
                        context,
                        &new_session,
                        &user,
                        false,
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
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: SetPasswordBody = parse_request_body(&request)?;
                if let Some(response) = validate_password_length(context, &body.new_password)? {
                    return Ok(response);
                }
                let users = DbUserStore::new(adapter.as_ref());
                if users.find_credential_account(&user.id).await?.is_some() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "PASSWORD_ALREADY_SET",
                        "Password already set",
                    );
                }
                let hash = (context.password.hash)(&body.new_password)?;
                users
                    .create_credential_account(CreateCredentialAccountInput::new(&user.id, hash))
                    .await?;
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
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: VerifyPasswordBody = parse_request_body(&request)?;
                let Some(account) = DbUserStore::new(adapter.as_ref())
                    .find_credential_account(&user.id)
                    .await?
                else {
                    return invalid_password();
                };
                let Some(password_hash) = account.password.as_deref() else {
                    return invalid_password();
                };
                if !(context.password.verify)(password_hash, &body.password)? {
                    return invalid_password();
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
                let _redirect_to = body.redirect_to;
                if let Some(user) = DbUserStore::new(adapter.as_ref())
                    .find_user_by_email(&body.email)
                    .await?
                {
                    let token = generate_random_string(24);
                    DbVerificationStore::new(adapter.as_ref())
                        .create_verification(CreateVerificationInput::new(
                            format!("reset-password:{token}"),
                            user.id,
                            OffsetDateTime::now_utc() + Duration::hours(1),
                        ))
                        .await?;
                }
                let _ = context;
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
                if let Some(response) = validate_password_length(context, &body.new_password)? {
                    return Ok(response);
                }
                let identifier = format!("reset-password:{token}");
                let verifications = DbVerificationStore::new(adapter.as_ref());
                let Some(verification) = verifications.find_verification(&identifier).await? else {
                    return invalid_token();
                };
                if verification.expires_at <= OffsetDateTime::now_utc() {
                    return invalid_token();
                }
                if let Err(rejection) =
                    run_password_validators(context, "/reset-password", &body.new_password).await
                {
                    return password_validation_rejection_response(rejection);
                }
                let user_id = verification.value;
                let users = DbUserStore::new(adapter.as_ref());
                let Some(user) = users.find_user_by_id(&user_id).await? else {
                    verifications.delete_verification(&identifier).await?;
                    return invalid_token();
                };
                let new_hash = (context.password.hash)(&body.new_password)?;
                if users
                    .update_credential_password(&user_id, &new_hash)
                    .await?
                    .is_none()
                {
                    users
                        .create_credential_account(CreateCredentialAccountInput::new(
                            &user_id, new_hash,
                        ))
                        .await?;
                }
                verifications.delete_verification(&identifier).await?;
                if let Some(callback) = &context.options.password.on_password_reset {
                    callback.on_password_reset(
                        PasswordResetPayload { user: user.clone() },
                        Some(&request),
                    )?;
                }
                if context.options.password.revoke_sessions_on_password_reset {
                    DbSessionStore::new(adapter.as_ref())
                        .delete_user_sessions(&user.id)
                        .await?;
                }
                json_response(StatusCode::OK, &StatusBody { status: true }, Vec::new())
            })
        },
    )
}

fn change_password_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("newPassword", JsonSchemaType::String)
            .description("The new password to set"),
        BodyField::new("currentPassword", JsonSchemaType::String)
            .description("The current password is required"),
        BodyField::optional("revokeOtherSessions", JsonSchemaType::Boolean)
            .description("Must be a boolean value"),
    ])
}

fn set_password_body_schema() -> BodySchema {
    BodySchema::object([BodyField::new("newPassword", JsonSchemaType::String)
        .description("The new password to set is required")])
}

fn verify_password_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("password", JsonSchemaType::String).description("The password to verify")
    ])
}

fn request_password_reset_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("email", JsonSchemaType::String)
            .format("email")
            .description("The email address of the user to send a password reset email to"),
        BodyField::optional("redirectTo", JsonSchemaType::String)
            .description("The URL to redirect the user to reset their password"),
    ])
}

fn reset_password_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("newPassword", JsonSchemaType::String)
            .description("The new password to set"),
        BodyField::optional("token", JsonSchemaType::String)
            .description("The token to reset the password"),
    ])
}

fn validate_password_length(
    context: &crate::context::AuthContext,
    password: &str,
) -> Result<Option<crate::api::ApiResponse>, crate::error::OpenAuthError> {
    if password.len() < context.password.config.min_password_length {
        return error_response(
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_SHORT",
            "Password is too short",
        )
        .map(Some);
    }
    if password.len() > context.password.config.max_password_length {
        return error_response(
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_LONG",
            "Password is too long",
        )
        .map(Some);
    }
    Ok(None)
}

fn invalid_password() -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_PASSWORD",
        "Invalid password",
    )
}

fn invalid_token() -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    error_response(StatusCode::BAD_REQUEST, "INVALID_TOKEN", "Invalid token")
}

fn password_reset_response() -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    json_response(
        StatusCode::OK,
        &RequestPasswordResetResponse {
            status: true,
            message: PASSWORD_RESET_MESSAGE,
        },
        Vec::new(),
    )
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.replace('+', " "))
    })
}
