use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shared::{
    additional_session_create_values, auth_flow_error_response, auth_session_cookies,
    error_response, invalid_additional_field_response, json_response, message_openapi_response,
    record_new_session, sign_up_email_openapi_response, user_response_value,
};
use crate::api::additional_fields::{create_values, AdditionalFieldError};
use crate::api::services::email_password as email_password_service;
use crate::api::services::email_password::{
    EmailAuthResult, EmailPasswordServiceError, SignUpEmailInput,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::db::DbAdapter;
use crate::error::OpenAuthError;

#[derive(Debug, Deserialize)]
struct SignUpEmailBody {
    name: String,
    email: String,
    password: String,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default, alias = "displayUsername")]
    display_username: Option<String>,
    #[serde(default, alias = "rememberMe")]
    remember_me: Option<bool>,
    #[serde(default, alias = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthTokenUserBody {
    token: Option<String>,
    user: Value,
}

pub(super) fn sign_up_email_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-up/email",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signUpWithEmailAndPassword")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(sign_up_email_body_schema())
            .openapi(
                OpenApiOperation::new("signUpWithEmailAndPassword")
                    .description("Sign up a user using email and password")
                    .response("200", sign_up_email_openapi_response())
                    .response(
                        "422",
                        message_openapi_response(
                            "Unprocessable Entity. User already exists or failed to create user.",
                        ),
                    ),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                if !context.options.email_password.enabled
                    || context.options.email_password.disable_sign_up
                {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "EMAIL_PASSWORD_SIGN_UP_DISABLED",
                        "Email and password sign up is not enabled",
                    );
                }

                let raw_body: Value = parse_request_body(&request)?;
                let Some(body_object) = raw_body.as_object() else {
                    return invalid_additional_field_response(AdditionalFieldError::InvalidType(
                        "request body must be an object".to_owned(),
                    ));
                };
                let body: SignUpEmailBody =
                    serde_json::from_value(raw_body.clone()).map_err(|error| {
                        OpenAuthError::InvalidRequestBody {
                            encoding: "JSON",
                            message: error.to_string(),
                        }
                    })?;
                let additional_user_fields =
                    match create_values(&context.options.user.additional_fields, body_object) {
                        Ok(fields) => fields,
                        Err(error) => return invalid_additional_field_response(error),
                    };
                let additional_session_fields = additional_session_create_values(context);
                let result = match email_password_service::sign_up_email(
                    adapter.as_ref(),
                    context,
                    &request,
                    SignUpEmailInput {
                        name: body.name,
                        email: body.email,
                        password: body.password,
                        image: body.image,
                        username: body.username,
                        display_username: body.display_username,
                        remember_me: body.remember_me.unwrap_or(true),
                        callback_url: body.callback_url,
                        additional_user_fields,
                        additional_session_fields,
                    },
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => return email_password_service_error_response(error),
                };
                email_sign_up_response(adapter.as_ref(), context, result).await
            })
        },
    )
}

async fn email_sign_up_response(
    adapter: &dyn DbAdapter,
    context: &crate::context::AuthContext,
    result: EmailAuthResult,
) -> Result<crate::api::ApiResponse, OpenAuthError> {
    let mut cookies = Vec::new();
    let token = if let Some(session) = result.session {
        record_new_session(&session, &result.user)?;
        cookies = auth_session_cookies(context, &session, &result.user, !result.remember_me)?;
        Some(session.token)
    } else {
        None
    };
    let user = match &result.synthetic_additional_fields {
        Some(fields) => {
            crate::api::output::user_output_value_from_fields(context, &result.user, fields)?
        }
        None => user_response_value(adapter, context, &result.user).await?,
    };
    json_response(StatusCode::OK, &AuthTokenUserBody { token, user }, cookies)
}

fn email_password_service_error_response(
    error: EmailPasswordServiceError,
) -> Result<crate::api::ApiResponse, OpenAuthError> {
    match error {
        EmailPasswordServiceError::Disabled | EmailPasswordServiceError::SignUpDisabled => {
            error_response(
                StatusCode::BAD_REQUEST,
                "EMAIL_PASSWORD_SIGN_UP_DISABLED",
                "Email and password sign up is not enabled",
            )
        }
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

fn sign_up_email_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("name", JsonSchemaType::String).description("The name of the user"),
        BodyField::new("email", JsonSchemaType::String)
            .format("email")
            .description("The email of the user"),
        BodyField::new("password", JsonSchemaType::String).description("The password of the user"),
        BodyField::optional("image", JsonSchemaType::String)
            .description("The profile image URL of the user"),
        BodyField::optional("username", JsonSchemaType::String)
            .description("The username of the user"),
        BodyField::optional("displayUsername", JsonSchemaType::String)
            .description("The display username of the user"),
        BodyField::optional("callbackURL", JsonSchemaType::String)
            .description("The URL to use for email verification callback"),
        BodyField::optional("rememberMe", JsonSchemaType::Boolean)
            .description("If false, the session will not be remembered"),
    ])
}
