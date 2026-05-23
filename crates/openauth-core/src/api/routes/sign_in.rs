use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shared::{
    additional_session_create_values, auth_flow_error_response, auth_session_cookies,
    error_response, json_response, record_new_session, sign_in_email_openapi_response,
    user_response_value,
};
use crate::api::services::email_password as email_password_service;
use crate::api::services::email_password::{
    EmailAuthResult, EmailPasswordServiceError, SignInEmailInput,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::db::DbAdapter;
use crate::error::OpenAuthError;

#[derive(Debug, Deserialize)]
struct SignInEmailBody {
    email: String,
    password: String,
    #[serde(default, alias = "rememberMe")]
    remember_me: Option<bool>,
    #[serde(default, alias = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthTokenUserBody {
    redirect: bool,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    user: Value,
}

pub(super) fn sign_in_email_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-in/email",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInEmail")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(sign_in_email_body_schema())
            .openapi(
                OpenApiOperation::new("signInEmail")
                    .description("Sign in with email and password")
                    .response("200", sign_in_email_openapi_response()),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                if !context.options.email_password.enabled {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "EMAIL_PASSWORD_DISABLED",
                        "Email and password authentication is not enabled",
                    );
                }

                let body: SignInEmailBody = parse_request_body(&request)?;
                let additional_session_fields = additional_session_create_values(context);
                let result = match email_password_service::sign_in_email(
                    adapter.as_ref(),
                    context,
                    &request,
                    SignInEmailInput {
                        email: body.email,
                        password: body.password,
                        remember_me: body.remember_me.unwrap_or(true),
                        callback_url: body.callback_url,
                        additional_session_fields,
                    },
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => return email_password_service_error_response(error),
                };
                email_sign_in_response(adapter.as_ref(), context, result).await
            })
        },
    )
}

async fn email_sign_in_response(
    adapter: &dyn DbAdapter,
    context: &crate::context::AuthContext,
    result: EmailAuthResult,
) -> Result<crate::api::ApiResponse, OpenAuthError> {
    let Some(session) = result.session else {
        return Err(OpenAuthError::Api(
            "email sign-in completed without a session".to_owned(),
        ));
    };
    record_new_session(&session, &result.user)?;
    let cookies = auth_session_cookies(context, &session, &result.user, !result.remember_me)?;
    json_response(
        StatusCode::OK,
        &AuthTokenUserBody {
            redirect: false,
            token: session.token,
            url: None,
            user: user_response_value(adapter, context, &result.user).await?,
        },
        cookies,
    )
}

fn email_password_service_error_response(
    error: EmailPasswordServiceError,
) -> Result<crate::api::ApiResponse, OpenAuthError> {
    match error {
        EmailPasswordServiceError::Disabled => error_response(
            StatusCode::BAD_REQUEST,
            "EMAIL_PASSWORD_DISABLED",
            "Email and password authentication is not enabled",
        ),
        EmailPasswordServiceError::SignUpDisabled => error_response(
            StatusCode::BAD_REQUEST,
            "EMAIL_PASSWORD_SIGN_UP_DISABLED",
            "Email and password sign up is not enabled",
        ),
        EmailPasswordServiceError::UsernameTaken => error_response(
            StatusCode::BAD_REQUEST,
            "USERNAME_IS_ALREADY_TAKEN",
            "Username is already taken. Please try another.",
        ),
        EmailPasswordServiceError::AuthFlow(error) => auth_flow_error_response(error),
        EmailPasswordServiceError::PasswordValidation(rejection) => {
            super::shared::password_validation_rejection_response(rejection)
        }
        EmailPasswordServiceError::OpenAuth(error) => Err(error),
    }
}

fn sign_in_email_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("email", JsonSchemaType::String)
            .format("email")
            .description("Email of the user"),
        BodyField::new("password", JsonSchemaType::String).description("Password of the user"),
        BodyField::optional("callbackURL", JsonSchemaType::String)
            .description("Callback URL to use as a redirect for email verification"),
        BodyField::optional("rememberMe", JsonSchemaType::Boolean)
            .description("If false, the session will not be remembered"),
    ])
}
