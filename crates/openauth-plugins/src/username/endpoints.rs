use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{set_session_cookie, Cookie, CookieOptions, SessionCookieOptions};
use openauth_core::db::{DbAdapter, User};
use openauth_core::error::OpenAuthError;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::DbUserStore;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::errors;
use super::hooks::validation_error;
use super::options::{UsernameOptions, ValidationPhase};

#[derive(Debug, Deserialize)]
struct SignInUsernameBody {
    username: String,
    password: String,
    #[serde(default, alias = "rememberMe")]
    remember_me: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct IsUsernameAvailableBody {
    username: String,
}

#[derive(Debug, Serialize)]
struct AuthTokenUserBody {
    token: String,
    user: User,
}

#[derive(Debug, Serialize)]
struct AvailabilityBody {
    available: bool,
}

pub fn sign_in_username_endpoint(options: Arc<UsernameOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/sign-in/username",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("signInUsername")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(sign_in_username_body_schema())
            .openapi(
                OpenApiOperation::new("signInUsername")
                    .description("Sign in with username")
                    .response("200", json_openapi_response("Success")),
            ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let body: SignInUsernameBody = parse_request_body(&request)?;
                let username_for_validation = options.username_for_validation(&body.username);
                if let Err(error) =
                    options.validate_username(&username_for_validation, ValidationPhase::Endpoint)
                {
                    return validation_error(error, StatusCode::UNPROCESSABLE_ENTITY);
                }
                let normalized_username = options.normalize_username(&body.username);
                let adapter = required_adapter(context)?;
                let users = DbUserStore::new(adapter.as_ref());
                let Some(user_with_accounts) = users
                    .find_user_by_username_with_accounts(&normalized_username)
                    .await?
                else {
                    let _ = (context.password.hash)(&body.password);
                    return invalid_username_or_password();
                };
                let Some(account) = user_with_accounts
                    .accounts
                    .iter()
                    .find(|account| account.provider_id == "credential")
                else {
                    let _ = (context.password.hash)(&body.password);
                    return invalid_username_or_password();
                };
                let Some(password_hash) = account.password.as_deref() else {
                    let _ = (context.password.hash)(&body.password);
                    return invalid_username_or_password();
                };
                if !(context.password.verify)(password_hash, &body.password)? {
                    return invalid_username_or_password();
                }

                let remember_me = body.remember_me.unwrap_or(true);
                let session = create_session(
                    adapter.as_ref(),
                    context,
                    &user_with_accounts.user,
                    remember_me,
                )
                .await?;
                let cookies = session_cookies(context, &session.token, !remember_me)?;
                json_response(
                    StatusCode::OK,
                    &AuthTokenUserBody {
                        token: session.token,
                        user: user_with_accounts.user,
                    },
                    cookies,
                )
            })
        },
    )
}

pub fn is_username_available_endpoint(options: Arc<UsernameOptions>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/is-username-available",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("isUsernameAvailable")
            .allowed_media_types(["application/x-www-form-urlencoded", "application/json"])
            .body_schema(is_username_available_body_schema()),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let body: IsUsernameAvailableBody = parse_request_body(&request)?;
                let username_for_validation = options.username_for_validation(&body.username);
                if let Err(error) =
                    options.validate_username(&username_for_validation, ValidationPhase::Endpoint)
                {
                    return validation_error(error, StatusCode::UNPROCESSABLE_ENTITY);
                }
                let normalized_username = options.normalize_username(&body.username);
                let adapter = required_adapter(context)?;
                let available = DbUserStore::new(adapter.as_ref())
                    .find_user_by_username(&normalized_username)
                    .await?
                    .is_none();
                json_response(StatusCode::OK, &AvailabilityBody { available }, Vec::new())
            })
        },
    )
}

fn sign_in_username_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("username", JsonSchemaType::String).description("The username of the user"),
        BodyField::new("password", JsonSchemaType::String).description("The password of the user"),
        BodyField::optional("rememberMe", JsonSchemaType::Boolean)
            .description("Remember the user session"),
    ])
}

fn is_username_available_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("username", JsonSchemaType::String).description("The username to check")
    ])
}

async fn create_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
    remember_me: bool,
) -> Result<openauth_core::db::Session, OpenAuthError> {
    let expires_in = if remember_me {
        context.session_config.expires_in
    } else {
        60 * 60 * 24
    };
    let seconds = i64::try_from(expires_in)
        .map_err(|_| OpenAuthError::Api("session expiry is too large".to_owned()))?;
    DbSessionStore::new(adapter)
        .create_session(CreateSessionInput::new(
            &user.id,
            OffsetDateTime::now_utc() + Duration::seconds(seconds),
        ))
        .await
}

fn required_adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig(
            "username plugin endpoints require a database adapter".to_owned(),
        )
    })
}

fn invalid_username_or_password() -> Result<openauth_core::api::ApiResponse, OpenAuthError> {
    errors::error_response(
        StatusCode::UNAUTHORIZED,
        errors::INVALID_USERNAME_OR_PASSWORD,
        "Invalid username or password",
    )
}

fn session_cookies(
    context: &AuthContext,
    token: &str,
    dont_remember: bool,
) -> Result<Vec<Cookie>, OpenAuthError> {
    set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions {
            dont_remember,
            overrides: CookieOptions::default(),
        },
    )
}

fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<openauth_core::api::ApiResponse, OpenAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            http::HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut value = format!("{}={}", cookie.name, cookie.value);
    push_attr(
        &mut value,
        "Max-Age",
        cookie.attributes.max_age.map(|v| v.to_string()),
    );
    push_attr(&mut value, "Expires", cookie.attributes.expires.clone());
    push_attr(&mut value, "Domain", cookie.attributes.domain.clone());
    push_attr(&mut value, "Path", cookie.attributes.path.clone());
    push_flag(&mut value, "Secure", cookie.attributes.secure);
    push_flag(&mut value, "HttpOnly", cookie.attributes.http_only);
    push_attr(&mut value, "SameSite", cookie.attributes.same_site.clone());
    push_flag(&mut value, "Partitioned", cookie.attributes.partitioned);
    value
}

fn push_attr(cookie: &mut String, name: &str, value: Option<String>) {
    if let Some(value) = value {
        cookie.push_str("; ");
        cookie.push_str(name);
        cookie.push('=');
        cookie.push_str(&value);
    }
}

fn push_flag(cookie: &mut String, name: &str, enabled: Option<bool>) {
    if enabled == Some(true) {
        cookie.push_str("; ");
        cookie.push_str(name);
    }
}

fn json_openapi_response(description: &str) -> serde_json::Value {
    serde_json::json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object"
                }
            }
        }
    })
}
