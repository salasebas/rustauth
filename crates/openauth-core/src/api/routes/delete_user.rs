use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::shared::{
    error_response, json_response, query_param, request_cookie_header, sensitive_session,
};
use crate::api::response_helpers::redirect_response;
use crate::api::services::user as user_service;
use crate::api::services::user::{DeleteUserError, DeleteUserErrorOrOpenAuth, DeleteUserResult};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::auth::trusted_origins::OriginMatchSettings;
use crate::cookies::delete_session_cookie;
use crate::db::DbAdapter;
use crate::error_codes;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteUserBody {
    #[serde(default, alias = "callbackURL")]
    callback_url: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeleteUserResponse {
    success: bool,
    message: String,
}

pub(super) fn delete_user_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/delete-user",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("deleteUser")
            .body_schema(delete_user_body_schema())
            .openapi(delete_user_openapi("deleteUser", "Delete the user")),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                if !context.options.user.delete_user.enabled {
                    return error_response(
                        StatusCode::NOT_FOUND,
                        error_codes::NOT_FOUND,
                        "Not found",
                    );
                }
                let body: DeleteUserBody = parse_request_body(&request)?;
                if let Some(token) = body.token.as_deref() {
                    return delete_user_by_token(adapter.as_ref(), context, &request, token, None)
                        .await;
                }
                let Some((session, user, _cookies)) =
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return super::shared::unauthorized();
                };
                let result = match user_service::delete_user_with_password_or_fresh_session(
                    adapter.as_ref(),
                    context,
                    Some(&request),
                    &session,
                    &user,
                    body.password.as_deref(),
                    body.callback_url.as_deref(),
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => return delete_user_error_response(error),
                };
                match result {
                    DeleteUserResult::VerificationSent => json_response(
                        StatusCode::OK,
                        &DeleteUserResponse {
                            success: true,
                            message: "Verification email sent".to_owned(),
                        },
                        Vec::new(),
                    ),
                    DeleteUserResult::Deleted => {
                        let cookies = delete_session_cookie(
                            &context.auth_cookies,
                            &request_cookie_header(&request).unwrap_or_default(),
                            false,
                        );
                        json_response(
                            StatusCode::OK,
                            &DeleteUserResponse {
                                success: true,
                                message: "User deleted".to_owned(),
                            },
                            cookies,
                        )
                    }
                }
            })
        },
    )
}

pub(super) fn delete_user_callback_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/delete-user/callback",
        Method::GET,
        AuthEndpointOptions::new().openapi(delete_user_openapi(
            "deleteUserCallback",
            "Callback to complete user deletion with verification token",
        )),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                if !context.options.user.delete_user.enabled {
                    return error_response(
                        StatusCode::NOT_FOUND,
                        error_codes::NOT_FOUND,
                        "Not found",
                    );
                }
                let Some(token) = query_param(&request, "token") else {
                    return invalid_token();
                };
                let callback_url = query_param(&request, "callbackURL");
                delete_user_by_token(
                    adapter.as_ref(),
                    context,
                    &request,
                    &token,
                    callback_url.as_deref(),
                )
                .await
            })
        },
    )
}

async fn delete_user_by_token(
    adapter: &dyn DbAdapter,
    context: &crate::context::AuthContext,
    request: &crate::api::ApiRequest,
    token: &str,
    callback_url: Option<&str>,
) -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    let Some((_, user, _)) = sensitive_session(adapter, context, request).await? else {
        return super::shared::unauthorized();
    };
    if let Err(error) =
        user_service::delete_user_with_token(adapter, context, Some(request), &user, token).await
    {
        return delete_user_error_response(error);
    }
    let cookies = delete_session_cookie(
        &context.auth_cookies,
        &request_cookie_header(request).unwrap_or_default(),
        false,
    );
    if let Some(callback_url) = callback_url {
        let settings = Some(OriginMatchSettings {
            allow_relative_paths: true,
        });
        if context.is_trusted_origin_for_request(callback_url, settings, Some(request))? {
            return redirect_response(callback_url, cookies);
        }
        return redirect_response(
            &format!(
                "/error?error={}",
                url::form_urlencoded::byte_serialize("INVALID_CALLBACK_URL".as_bytes())
                    .collect::<String>()
            ),
            cookies,
        );
    }
    json_response(
        StatusCode::OK,
        &DeleteUserResponse {
            success: true,
            message: "User deleted".to_owned(),
        },
        cookies,
    )
}

fn invalid_token() -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    error_response(
        StatusCode::NOT_FOUND,
        error_codes::INVALID_TOKEN,
        "Invalid token",
    )
}

fn delete_user_error_response(
    error: DeleteUserErrorOrOpenAuth,
) -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    match error {
        DeleteUserErrorOrOpenAuth::OpenAuth(error) => Err(error),
        DeleteUserErrorOrOpenAuth::Service(error) => match error {
            DeleteUserError::InvalidPassword => error_response(
                StatusCode::BAD_REQUEST,
                error_codes::INVALID_PASSWORD,
                "Invalid password",
            ),
            DeleteUserError::InvalidToken => invalid_token(),
            DeleteUserError::SessionExpired => error_response(
                StatusCode::BAD_REQUEST,
                error_codes::SESSION_EXPIRED,
                "Session expired",
            ),
            DeleteUserError::CredentialAccountNotFound => error_response(
                StatusCode::BAD_REQUEST,
                error_codes::CREDENTIAL_ACCOUNT_NOT_FOUND,
                "Credential account not found",
            ),
        },
    }
}

fn delete_user_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::optional("callbackURL", JsonSchemaType::String)
            .description("The callback URL to redirect to after the user is deleted"),
        BodyField::optional("password", JsonSchemaType::String)
            .description("The user's password. Required if session is not fresh"),
        BodyField::optional("token", JsonSchemaType::String)
            .description("The deletion verification token"),
    ])
}

fn delete_user_openapi(operation_id: &str, description: &str) -> OpenApiOperation {
    OpenApiOperation::new(operation_id)
        .description(description)
        .response(
            "200",
            super::shared::json_openapi_response(
                "User deletion processed successfully",
                json!({
                    "type": "object",
                    "properties": {
                        "success": { "type": "boolean" },
                        "message": { "type": "string" },
                    },
                    "required": ["success", "message"],
                }),
            ),
        )
}
