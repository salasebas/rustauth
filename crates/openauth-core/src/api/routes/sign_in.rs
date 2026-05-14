use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use super::shared::{
    auth_flow_error_response, auth_session_cookies, email_password_config, json_response,
    record_new_session, sign_in_email_openapi_response, RequestMetadata,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use crate::auth::email_password::{EmailPasswordAuth, SignInInput};
use crate::db::{DbAdapter, User};

#[derive(Debug, Deserialize)]
struct SignInEmailBody {
    email: String,
    password: String,
    #[serde(default, alias = "rememberMe")]
    remember_me: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AuthTokenUserBody {
    redirect: bool,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    user: User,
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
                let body: SignInEmailBody = parse_request_body(&request)?;
                let remember_me = body.remember_me.unwrap_or(true);
                let input = SignInInput::new(body.email, body.password)
                    .remember_me(remember_me)
                    .with_request_metadata(&request);

                let auth = EmailPasswordAuth::new(
                    adapter.as_ref(),
                    email_password_config(context),
                    context.password.hash,
                    context.password.verify,
                );
                let result = match auth.sign_in(input).await {
                    Ok(result) => result,
                    Err(error) => return auth_flow_error_response(error),
                };
                record_new_session(&result.session, &result.user)?;
                let cookies =
                    auth_session_cookies(context, &result.session, &result.user, !remember_me)?;
                json_response(
                    StatusCode::OK,
                    &AuthTokenUserBody {
                        redirect: false,
                        token: result.session.token,
                        url: None,
                        user: result.user,
                    },
                    cookies,
                )
            })
        },
    )
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
