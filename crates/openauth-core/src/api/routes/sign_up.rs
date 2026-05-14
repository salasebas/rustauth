use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shared::{
    additional_session_create_values, auth_flow_error_response, auth_session_cookies,
    email_password_config, error_response, invalid_additional_field_response, json_response,
    message_openapi_response, record_new_session, sign_up_email_openapi_response,
    user_response_value, RequestMetadata,
};
use crate::api::additional_fields::{create_values, AdditionalFieldError};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::auth::email_password::{EmailPasswordAuth, SignUpInput};
use crate::db::DbAdapter;
use crate::error::OpenAuthError;
use crate::user::DbUserStore;

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
}

#[derive(Debug, Serialize)]
struct AuthTokenUserBody {
    token: String,
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
                let raw_body: Value = parse_request_body(&request)?;
                let Some(body_object) = raw_body.as_object() else {
                    return invalid_additional_field_response(AdditionalFieldError::InvalidType(
                        "request body must be an object".to_owned(),
                    ));
                };
                let body: SignUpEmailBody =
                    serde_json::from_value(raw_body.clone()).map_err(|error| {
                        OpenAuthError::Api(format!("invalid request body: {error}"))
                    })?;
                let remember_me = body.remember_me.unwrap_or(true);
                let mut input =
                    SignUpInput::new(body.name, body.email, body.password).remember_me(remember_me);
                if let Some(image) = body.image {
                    input = input.image(image);
                }
                if let Some(username) = body.username {
                    input = input.username(username);
                }
                if let Some(display_username) = body.display_username {
                    input = input.display_username(display_username);
                }
                let additional_user_fields =
                    match create_values(&context.options.user.additional_fields, body_object) {
                        Ok(fields) => fields,
                        Err(error) => return invalid_additional_field_response(error),
                    };
                let additional_session_fields = additional_session_create_values(context);
                input = input
                    .additional_user_fields(additional_user_fields)
                    .additional_session_fields(additional_session_fields);
                input = input.with_request_metadata(&request);
                if context.has_plugin("username") {
                    if let Some(username) = input.username.as_deref() {
                        if DbUserStore::new(adapter.as_ref())
                            .find_user_by_username(username)
                            .await?
                            .is_some()
                        {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "USERNAME_IS_ALREADY_TAKEN",
                                "Username is already taken. Please try another.",
                            );
                        }
                    }
                }

                let auth = EmailPasswordAuth::new(
                    adapter.as_ref(),
                    email_password_config(context),
                    context.password.hash,
                    context.password.verify,
                );
                let result = match auth.sign_up(input).await {
                    Ok(result) => result,
                    Err(error) => return auth_flow_error_response(error),
                };
                record_new_session(&result.session, &result.user)?;
                let cookies =
                    auth_session_cookies(context, &result.session, &result.user, !remember_me)?;
                json_response(
                    StatusCode::OK,
                    &AuthTokenUserBody {
                        token: result.session.token,
                        user: user_response_value(adapter.as_ref(), context, &result.user).await?,
                    },
                    cookies,
                )
            })
        },
    )
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
