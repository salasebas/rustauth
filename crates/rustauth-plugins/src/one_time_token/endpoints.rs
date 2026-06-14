use http::{header, HeaderValue, Method, StatusCode};
use rustauth_core::api::output::{session_response_cookies, session_user_output};
use rustauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiErrorResponse, ApiRequest, ApiResponse,
    AsyncAuthEndpoint, AuthEndpointOptions, BodyField, BodySchema, JsonSchemaType,
    OpenApiOperation,
};
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::context::AuthContext;
use rustauth_core::cookies::Cookie;
use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::db::{Session, User};
use rustauth_core::error::RustAuthError;
use rustauth_core::verification::CreateVerificationInput;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;

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
    session: Value,
    user: Value,
}

pub fn generate_endpoint(options: OneTimeTokenOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/one-time-token/generate",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("generateOneTimeToken")
            .openapi(
                OpenApiOperation::new("generateOneTimeToken")
                    .description("Generate a one-time token for the current session")
                    .response("200", generate_openapi_response()),
            ),
        move |context, request| {
            let options = options.clone();
            async move {
                if options.disable_client_request {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Client requests are disabled",
                    );
                }
                let adapter = context.require_adapter()?;
                let Some((session, user, cookies)) = current_session(&context, &request).await?
                else {
                    return error_response(
                        StatusCode::UNAUTHORIZED,
                        "UNAUTHORIZED",
                        "Unauthorized",
                    );
                };
                let token = generate_and_store_token(
                    adapter.as_ref(),
                    &context,
                    &OneTimeTokenSession { session, user },
                    &options,
                )
                .await?;
                json_response(StatusCode::OK, &GenerateResponse { token }, cookies)
            }
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
            .body_schema(verify_body_schema())
            .openapi(
                OpenApiOperation::new("verifyOneTimeToken")
                    .description("Verify a one-time token and return its session")
                    .response("200", verify_openapi_response()),
            ),
        move |context, request| {
            let options = options.clone();
            async move {
                let body: VerifyBody = parse_request_body(&request)?;
                let adapter = context.require_adapter()?;
                let stored_token = stored_token(&context, &body.token, &options)?;
                let identifier = token_identifier(&stored_token);
                let verification_store = context.verifications()?;
                let Some(verification) = verification_store
                    .consume_verification_including_expired(&identifier)
                    .await?
                else {
                    return error_response(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid token");
                };
                if verification.expires_at <= OffsetDateTime::now_utc() {
                    return error_response(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Token expired");
                }

                let session_store = context.sessions()?;
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
                let Some(user) = context.users()?.find_user_by_id(&session.user_id).await? else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Session not found",
                    );
                };

                let cookies = if options.disable_set_session_cookie {
                    Vec::new()
                } else {
                    session_response_cookies(&context, &session, &user, false)?
                };
                let output =
                    session_user_output(adapter.as_ref(), &context, &session, &user).await?;
                json_response(
                    StatusCode::OK,
                    &VerifyResponse {
                        session: output.session,
                        user: output.user,
                    },
                    cookies,
                )
            }
        },
    )
}

pub async fn generate_and_store_token(
    _adapter: &dyn rustauth_core::db::DbAdapter,
    context: &AuthContext,
    session: &OneTimeTokenSession,
    options: &OneTimeTokenOptions,
) -> Result<String, RustAuthError> {
    let token = match &options.generate_token {
        Some(generate) => generate(session, context)?,
        None => generate_random_string(32),
    };
    let stored_token = stored_token(context, &token, options)?;
    let expires_at = OffsetDateTime::now_utc() + options.expires_in;
    context
        .verifications()?
        .create_verification(CreateVerificationInput::new(
            token_identifier(&stored_token),
            session.session.token.clone(),
            expires_at,
        ))
        .await?;
    Ok(token)
}

async fn current_session(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<(Session, User, Vec<Cookie>)>, RustAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let Some(result) = SessionAuth::new(context)?
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

fn stored_token(
    _context: &AuthContext,
    token: &str,
    options: &OneTimeTokenOptions,
) -> Result<String, RustAuthError> {
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

fn generate_openapi_response() -> serde_json::Value {
    json!({
        "description": "One-time token generated",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "token": { "type": "string" }
                    },
                    "required": ["token"]
                }
            }
        }
    })
}

fn verify_openapi_response() -> serde_json::Value {
    json!({
        "description": "One-time token verified",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "session": { "$ref": "#/components/schemas/Session" },
                        "user": { "$ref": "#/components/schemas/User" }
                    },
                    "required": ["session", "user"]
                }
            }
        }
    })
}

fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, RustAuthError>
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
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| RustAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<ApiResponse, RustAuthError> {
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
