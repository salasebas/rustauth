use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::shared::{auth_session_cookies, error_response, json_response, sensitive_session};
use crate::api::services::user as user_service;
use crate::api::services::user::{
    ChangeEmailError, ChangeEmailErrorOrOpenAuth, ChangeEmailInput, ChangeEmailResult,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::db::{DbAdapter, User};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmailBody {
    new_email: String,
    #[serde(default, alias = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct ChangeEmailResponse {
    status: bool,
    message: &'static str,
    user: Option<User>,
}

pub(super) fn change_email_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/change-email",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("changeEmail")
            .body_schema(change_email_body_schema())
            .openapi(
                OpenApiOperation::new("changeEmail")
                    .description("Change the current user's email")
                    .response(
                        "200",
                        super::shared::json_openapi_response(
                            "Email change request processed successfully",
                            json!({
                                "type": "object",
                                "properties": {
                                    "status": { "type": "boolean" },
                                    "message": { "type": "string", "nullable": true },
                                    "user": {
                                        "oneOf": [
                                            { "$ref": "#/components/schemas/User" },
                                            { "type": "null" }
                                        ],
                                    },
                                },
                                "required": ["status"],
                            }),
                        ),
                    ),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((session, user, _cookies)) =
                    sensitive_session(adapter.as_ref(), context, &request).await?
                else {
                    return super::shared::unauthorized();
                };
                let dont_remember = super::shared::request_dont_remember(context, &request)?;
                let body: ChangeEmailBody = parse_request_body(&request)?;
                let result = match user_service::change_email(
                    adapter.as_ref(),
                    context,
                    Some(&request),
                    user,
                    ChangeEmailInput {
                        new_email: body.new_email,
                        callback_url: body.callback_url,
                    },
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => return change_email_error_response(error),
                };
                match result {
                    ChangeEmailResult::Updated(updated) => {
                        let cookies =
                            auth_session_cookies(context, &session, &updated, dont_remember)?;
                        json_response(
                            StatusCode::OK,
                            &ChangeEmailResponse {
                                status: true,
                                message: "Email updated",
                                user: Some(updated),
                            },
                            cookies,
                        )
                    }
                    ChangeEmailResult::VerificationSent => json_response(
                        StatusCode::OK,
                        &ChangeEmailResponse {
                            status: true,
                            message: "Verification email sent",
                            user: None,
                        },
                        Vec::new(),
                    ),
                }
            })
        },
    )
}

fn change_email_error_response(
    error: ChangeEmailErrorOrOpenAuth,
) -> Result<crate::api::ApiResponse, crate::error::OpenAuthError> {
    match error {
        ChangeEmailErrorOrOpenAuth::OpenAuth(error) => Err(error),
        ChangeEmailErrorOrOpenAuth::Service(error) => match error {
            ChangeEmailError::Disabled => error_response(
                StatusCode::BAD_REQUEST,
                "CHANGE_EMAIL_DISABLED",
                "Change email is disabled",
            ),
            ChangeEmailError::EmailIsSame => error_response(
                StatusCode::BAD_REQUEST,
                "EMAIL_IS_SAME",
                "Email is the same",
            ),
            ChangeEmailError::VerificationEmailNotEnabled => error_response(
                StatusCode::BAD_REQUEST,
                "VERIFICATION_EMAIL_NOT_ENABLED",
                "Verification email isn't enabled",
            ),
        },
    }
}

fn change_email_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("newEmail", JsonSchemaType::String)
            .description("The new email address to set"),
        BodyField::optional("callbackURL", JsonSchemaType::String)
            .description("The URL to redirect to after email verification"),
    ])
}
