use std::sync::Arc;

use http::{header, HeaderValue, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiErrorResponse, ApiRequest, ApiResponse,
    AsyncAuthEndpoint, AuthEndpointOptions, BodyField, BodySchema, JsonSchemaType,
};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{set_session_cookie, Cookie, CookieOptions, SessionCookieOptions};
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{DbAdapter, Session, User};
use openauth_core::error::OpenAuthError;
use openauth_core::session::DbSessionStore;
use openauth_core::user::DbUserStore;
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::hashing::default_key_hasher;
use super::options::{OneTimeTokenOptions, OneTimeTokenSession, StoreToken};

#[derive(Debug, Serialize)]
struct GenerateResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct VerifyBody {
    token: String,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    session: Session,
    user: User,
}

pub fn generate_endpoint(options: OneTimeTokenOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/one-time-token/generate",
        Method::GET,
        AuthEndpointOptions::new().operation_id("generateOneTimeToken"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                if options.disable_client_request {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Client requests are disabled",
                    );
                }
                let adapter = required_adapter(context)?;
                let Some((session, user, _cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "UNAUTHORIZED",
                        "Unauthorized",
                    );
                };
                let token = generate_and_store_token(
                    adapter.as_ref(),
                    context,
                    &OneTimeTokenSession { session, user },
                    &options,
                )
                .await?;
                json_response(StatusCode::OK, &GenerateResponse { token }, Vec::new())
            })
        },
    )
}

pub fn verify_endpoint(options: OneTimeTokenOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/one-time-token/verify",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("verifyOneTimeToken")
            .allowed_media_types(["application/json"])
            .body_schema(verify_body_schema()),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let body: VerifyBody = parse_request_body(&request)?;
                let adapter = required_adapter(context)?;
                let stored_token = stored_token(context, &body.token, &options)?;
                let identifier = token_identifier(&stored_token);
                let verification_store = DbVerificationStore::new(adapter.as_ref());
                let Some(verification) = verification_store
                    .find_verification_including_expired(&identifier)
                    .await?
                else {
                    return error_response(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid token");
                };
                verification_store.delete_verification(&identifier).await?;
                if verification.expires_at <= OffsetDateTime::now_utc() {
                    return error_response(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Token expired");
                }

                let session_store = DbSessionStore::new(adapter.as_ref());
                let Some(session) = session_store
                    .find_session_including_expired(&verification.value)
                    .await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Session not found",
                    );
                };
                if session.expires_at <= OffsetDateTime::now_utc() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Session expired",
                    );
                }
                let Some(user) = DbUserStore::new(adapter.as_ref())
                    .find_user_by_id(&session.user_id)
                    .await?
                else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Session not found",
                    );
                };

                let cookies = if options.disable_set_session_cookie {
                    Vec::new()
                } else {
                    set_session_cookie(
                        &context.auth_cookies,
                        &context.secret,
                        &session.token,
                        SessionCookieOptions {
                            dont_remember: false,
                            overrides: CookieOptions::default(),
                        },
                    )?
                };
                json_response(StatusCode::OK, &VerifyResponse { session, user }, cookies)
            })
        },
    )
}

pub async fn generate_and_store_token(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    session: &OneTimeTokenSession,
    options: &OneTimeTokenOptions,
) -> Result<String, OpenAuthError> {
    let token = match &options.generate_token {
        Some(generate) => generate(session, context)?,
        None => generate_random_string(32),
    };
    let stored_token = stored_token(context, &token, options)?;
    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(options.expires_in as i64);
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            token_identifier(&stored_token),
            session.session.token.clone(),
            expires_at,
        ))
        .await?;
    Ok(token)
}

async fn current_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<(Session, User, Vec<Cookie>)>, OpenAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let Some(result) = SessionAuth::new(adapter, context)
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    let Some(session) = result.session else {
        return Ok(None);
    };
    let Some(user) = result.user else {
        return Ok(None);
    };
    Ok(Some((session, user, result.cookies)))
}

fn required_adapter(context: &AuthContext) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
    context.adapter().ok_or_else(|| {
        OpenAuthError::InvalidConfig("one-time-token plugin requires a database adapter".to_owned())
    })
}

fn stored_token(
    _context: &AuthContext,
    token: &str,
    options: &OneTimeTokenOptions,
) -> Result<String, OpenAuthError> {
    match &options.store_token {
        StoreToken::Plain => Ok(token.to_owned()),
        StoreToken::Hashed => Ok(default_key_hasher(token)),
        StoreToken::Custom(hash) => hash(token),
    }
}

fn token_identifier(stored_token: &str) -> String {
    format!("one-time-token:{stored_token}")
}

fn verify_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("token", JsonSchemaType::String).description("The token to verify")
    ])
}

fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError>
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
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &ApiErrorResponse {
            code: code.to_owned(),
            message: message.to_owned(),
            original_message: None,
        },
        Vec::new(),
    )
}

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut parts = vec![format!("{}={}", cookie.name, cookie.value)];
    if let Some(max_age) = cookie.attributes.max_age {
        parts.push(format!("Max-Age={max_age}"));
    }
    if let Some(expires) = &cookie.attributes.expires {
        parts.push(format!("Expires={expires}"));
    }
    if let Some(domain) = &cookie.attributes.domain {
        parts.push(format!("Domain={domain}"));
    }
    if let Some(path) = &cookie.attributes.path {
        parts.push(format!("Path={path}"));
    }
    if cookie.attributes.secure == Some(true) {
        parts.push("Secure".to_owned());
    }
    if cookie.attributes.http_only == Some(true) {
        parts.push("HttpOnly".to_owned());
    }
    if let Some(same_site) = &cookie.attributes.same_site {
        parts.push(format!("SameSite={same_site}"));
    }
    if cookie.attributes.partitioned == Some(true) {
        parts.push("Partitioned".to_owned());
    }
    parts.join("; ")
}
