use std::sync::Arc;

use http::{header, Method, StatusCode};
use rustauth_core::api::output::user_output_value;
use rustauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType, OpenApiOperation,
};
use rustauth_core::context::AuthContext;
use rustauth_core::cookies::{set_session_cookie, Cookie, CookieOptions, SessionCookieOptions};
use rustauth_core::crypto::jwt::sign_jwt;
use rustauth_core::db::User;
use rustauth_core::error::RustAuthError;
use rustauth_core::options::VerificationEmail;
use rustauth_core::outbound::dispatch_outbound;
use rustauth_core::session::CreateSessionInput;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::errors;
use super::hooks::validation_error;
use super::options::{UsernameOptions, ValidationPhase};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInUsernameBody {
    username: String,
    password: String,
    #[serde(default)]
    remember_me: Option<bool>,
    #[serde(default, rename = "callbackURL", alias = "callbackUrl")]
    callback_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IsUsernameAvailableBody {
    username: String,
}

#[derive(Debug, Serialize)]
struct AuthTokenUserBody {
    token: String,
    user: Value,
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
            async move {
                let body: SignInUsernameBody = parse_request_body(&request)?;
                let username_for_validation = options.username_for_validation(&body.username);
                if let Err(error) =
                    options.validate_username(&username_for_validation, ValidationPhase::Endpoint)
                {
                    return validation_error(error, StatusCode::UNPROCESSABLE_ENTITY);
                }
                let normalized_username = options.normalize_username(&body.username);
                let users = context.users()?;
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
                if context.options.email_password.require_email_verification
                    && !user_with_accounts.user.email_verified
                {
                    maybe_send_verification_email(
                        &context,
                        &request,
                        &user_with_accounts.user,
                        body.callback_url.as_deref(),
                    )?;
                    return email_not_verified();
                }

                let remember_me = body.remember_me.unwrap_or(true);
                let session =
                    create_session(&context, &user_with_accounts.user, remember_me).await?;
                let cookies = session_cookies(&context, &session.token, !remember_me)?;
                let user =
                    user_output_value(context.adapter_ref()?, &context, &user_with_accounts.user)
                        .await?;
                json_response(
                    StatusCode::OK,
                    &AuthTokenUserBody {
                        token: session.token,
                        user,
                    },
                    cookies,
                )
            }
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
            async move {
                let body: IsUsernameAvailableBody = parse_request_body(&request)?;
                let username_for_validation = options.username_for_validation(&body.username);
                if let Err(error) =
                    options.validate_username(&username_for_validation, ValidationPhase::Endpoint)
                {
                    return validation_error(error, StatusCode::UNPROCESSABLE_ENTITY);
                }
                let normalized_username = options.normalize_username(&body.username);
                let available = context
                    .users()?
                    .find_user_by_username(&normalized_username)
                    .await?
                    .is_none();
                json_response(StatusCode::OK, &AvailabilityBody { available }, Vec::new())
            }
        },
    )
}

fn sign_in_username_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("username", JsonSchemaType::String).description("The username of the user"),
        BodyField::new("password", JsonSchemaType::String).description("The password of the user"),
        BodyField::optional("rememberMe", JsonSchemaType::Boolean)
            .description("Remember the user session"),
        BodyField::optional("callbackURL", JsonSchemaType::String)
            .description("The URL to redirect to after email verification"),
    ])
}

fn is_username_available_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("username", JsonSchemaType::String).description("The username to check")
    ])
}

async fn create_session(
    context: &AuthContext,
    user: &User,
    remember_me: bool,
) -> Result<rustauth_core::db::Session, RustAuthError> {
    let expires_in = if remember_me {
        context.session_config.expires_in
    } else {
        time::Duration::days(1)
    };
    context
        .sessions()?
        .create_session(CreateSessionInput::new(
            &user.id,
            OffsetDateTime::now_utc() + expires_in,
        ))
        .await
}

fn invalid_username_or_password() -> Result<rustauth_core::api::ApiResponse, RustAuthError> {
    errors::error_response(
        StatusCode::UNAUTHORIZED,
        errors::INVALID_USERNAME_OR_PASSWORD,
        "Invalid username or password",
    )
}

fn email_not_verified() -> Result<rustauth_core::api::ApiResponse, RustAuthError> {
    errors::error_response(
        StatusCode::FORBIDDEN,
        errors::EMAIL_NOT_VERIFIED,
        "Email not verified",
    )
}

fn maybe_send_verification_email(
    context: &AuthContext,
    request: &rustauth_core::api::ApiRequest,
    user: &User,
    callback_url: Option<&str>,
) -> Result<(), RustAuthError> {
    if !context.options.email_verification.send_on_sign_in {
        return Ok(());
    }
    let Some(sender) = context
        .options
        .email_verification
        .send_verification_email
        .clone()
    else {
        return Ok(());
    };
    let expires_in = context
        .options
        .email_verification
        .expires_in
        .unwrap_or(time::Duration::hours(1))
        .whole_seconds();
    let token = sign_jwt(
        &EmailVerificationClaims {
            email: user.email.to_lowercase(),
            update_to: None,
            request_type: None,
        },
        &context.secret,
        expires_in,
    )?;
    let callback_url = callback_url.unwrap_or("/");
    let url = format!(
        "{}/verify-email?token={token}&callbackURL={}",
        context.base_url,
        percent_encode(callback_url)
    );
    let send = sender.send_verification_email(
        VerificationEmail {
            user: user.clone(),
            url,
            token,
        },
        Some(request),
    );
    dispatch_outbound(context, send);
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailVerificationClaims {
    email: String,
    update_to: Option<String>,
    request_type: Option<String>,
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn session_cookies(
    context: &AuthContext,
    token: &str,
    dont_remember: bool,
) -> Result<Vec<Cookie>, RustAuthError> {
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
) -> Result<rustauth_core::api::ApiResponse, RustAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| RustAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| RustAuthError::Api(error.to_string()))?;
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            http::HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| RustAuthError::Cookie(error.to_string()))?,
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
