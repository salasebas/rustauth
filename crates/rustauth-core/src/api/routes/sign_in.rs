use http::{header, HeaderValue, Method, StatusCode};
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
use crate::error::RustAuthError;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInEmailBody {
    email: String,
    password: String,
    #[serde(default)]
    remember_me: Option<bool>,
    #[serde(default, rename = "callbackURL", alias = "callbackUrl")]
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

pub(super) fn sign_in_email_endpoint() -> AsyncAuthEndpoint {
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
        move |context, request| async move {
            if !context.options.email_password.enabled {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "EMAIL_PASSWORD_DISABLED",
                    "Email and password authentication is not enabled",
                );
            }

            let SignInEmailBody {
                email,
                password,
                remember_me,
                callback_url,
            } = parse_request_body(&request)?;
            let additional_session_fields = additional_session_create_values(&context);
            let result = match email_password_service::sign_in_email(
                &context,
                &request,
                SignInEmailInput {
                    email,
                    password,
                    remember_me: remember_me.unwrap_or(true),
                    callback_url: callback_url.clone(),
                    additional_session_fields,
                },
            )
            .await
            {
                Ok(result) => result,
                Err(error) => return email_password_service_error_response(error),
            };
            email_sign_in_response(&context, result, callback_url).await
        },
    )
}

async fn email_sign_in_response(
    context: &crate::context::AuthContext,
    result: EmailAuthResult,
    callback_url: Option<String>,
) -> Result<crate::api::ApiResponse, RustAuthError> {
    let Some(session) = result.session else {
        return Err(RustAuthError::Api(
            "email sign-in completed without a session".to_owned(),
        ));
    };
    record_new_session(&session, &result.user)?;
    let cookies = auth_session_cookies(context, &session, &result.user, !result.remember_me)?;
    let redirect = callback_url.is_some();
    let mut response = json_response(
        StatusCode::OK,
        &AuthTokenUserBody {
            redirect,
            token: session.token,
            url: callback_url.clone(),
            user: user_response_value(context, &result.user).await?,
        },
        cookies,
    )?;
    if let Some(url) = callback_url {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&url).map_err(|error| RustAuthError::Serialization {
                context: "building email sign-in redirect headers",
                message: error.to_string(),
            })?,
        );
    }
    Ok(response)
}

fn email_password_service_error_response(
    error: EmailPasswordServiceError,
) -> Result<crate::api::ApiResponse, RustAuthError> {
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
        EmailPasswordServiceError::RustAuth(error) => Err(error),
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
