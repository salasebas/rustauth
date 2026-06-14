use http::{Method, StatusCode};
use rustauth_core::api::output::{session_user_output, SessionUserOutput};
use rustauth_core::api::{
    create_auth_endpoint, parse_request_body, ApiErrorResponse, ApiResponse, AsyncAuthEndpoint,
    AuthEndpointOptions, BodyField, BodySchema, JsonSchemaType, OpenApiOperation,
};
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::context::AuthContext;
use rustauth_core::db::{Session, User};
use rustauth_core::error::RustAuthError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use time::OffsetDateTime;

use super::cookies::{
    active_session_cookies, append_cookies, delete_active_session_cookies, expire_multi_cookie,
    signed_multi_token, signed_multi_tokens,
};
use super::errors::INVALID_SESSION_TOKEN;

#[derive(Debug, Deserialize)]
struct SessionTokenBody {
    #[serde(rename = "sessionToken")]
    session_token: String,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    status: bool,
}

pub fn list_device_sessions_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/multi-session/list-device-sessions",
        Method::GET,
        AuthEndpointOptions::new()
            .operation_id("listDeviceSessions")
            .openapi(
                OpenApiOperation::new("listDeviceSessions")
                    .description("List valid multi-session device sessions from signed cookies")
                    .response("200", list_device_sessions_response()),
            ),
        |context, request| async move {
            let cookie_header = request_cookie_header(&request);
            let Some(adapter) = context.adapter() else {
                return json_response(StatusCode::OK, &Vec::<SessionUserOutput>::new());
            };
            let sessions =
                list_sessions_from_cookies(adapter.as_ref(), &context, &cookie_header).await?;
            json_response(StatusCode::OK, &sessions)
        },
    )
}

pub fn set_active_session_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/multi-session/set-active",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("setActiveSession")
            .allowed_media_types(["application/json"])
            .body_schema(session_token_body_schema())
            .openapi(
                OpenApiOperation::new("setActiveSession")
                    .description("Set a signed multi-session token as the active session")
                    .response("200", session_user_response()),
            ),
        |context, request| async move {
            let body: SessionTokenBody = parse_request_body(&request)?;
            let cookie_header = request_cookie_header(&request);
            if signed_multi_token(&context, &cookie_header, &body.session_token)?.is_none() {
                return invalid_session_token();
            }
            let Some(adapter) = context.adapter() else {
                return invalid_session_token();
            };
            let Some((session, user)) = session_user(&context, &body.session_token).await? else {
                let mut response = invalid_session_token()?;
                append_cookies(
                    &mut response,
                    [expire_multi_cookie(&context, &body.session_token)],
                )?;
                return Ok(response);
            };
            let body = session_user_output(adapter.as_ref(), &context, &session, &user).await?;
            let mut response = json_response(StatusCode::OK, &body)?;
            append_cookies(
                &mut response,
                active_session_cookies(&context, &session, &user, &cookie_header)?,
            )?;
            Ok(response)
        },
    )
}

pub fn revoke_device_session_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/multi-session/revoke",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("revokeDeviceSession")
            .allowed_media_types(["application/json"])
            .body_schema(session_token_body_schema())
            .openapi(
                OpenApiOperation::new("revokeDeviceSession")
                    .description("Revoke a signed multi-session device session")
                    .response("200", status_response()),
            ),
        |context, request| async move {
            let body: SessionTokenBody = parse_request_body(&request)?;
            let cookie_header = request_cookie_header(&request);
            if signed_multi_token(&context, &cookie_header, &body.session_token)?.is_none() {
                return invalid_session_token();
            }
            let Some(adapter) = context.adapter() else {
                return invalid_session_token();
            };
            let Some(current) = SessionAuth::new(&context)?
                .get_session(GetSessionInput::new(cookie_header.clone()).disable_refresh())
                .await?
                .and_then(|result| result.session)
            else {
                return unauthorized();
            };

            context
                .sessions()?
                .delete_session(&body.session_token)
                .await?;
            let mut response = json_response(StatusCode::OK, &StatusBody { status: true })?;
            append_cookies(
                &mut response,
                [expire_multi_cookie(&context, &body.session_token)],
            )?;
            if current.token != body.session_token {
                return Ok(response);
            }

            let next = next_valid_session(adapter.as_ref(), &context, &cookie_header).await?;
            match next {
                Some((session, user)) => append_cookies(
                    &mut response,
                    active_session_cookies(&context, &session, &user, &cookie_header)?,
                )?,
                None => append_cookies(
                    &mut response,
                    delete_active_session_cookies(&context, &cookie_header),
                )?,
            }
            Ok(response)
        },
    )
}

async fn list_sessions_from_cookies(
    adapter: &dyn rustauth_core::db::DbAdapter,
    context: &AuthContext,
    cookie_header: &str,
) -> Result<Vec<SessionUserOutput>, RustAuthError> {
    let tokens = signed_multi_tokens(context, cookie_header)?;
    let mut seen_users = HashSet::new();
    let mut sessions = Vec::new();
    for (_, token) in tokens {
        let Some((session, user)) = session_user(context, &token).await? else {
            continue;
        };
        if session.expires_at <= OffsetDateTime::now_utc() || !seen_users.insert(user.id.clone()) {
            continue;
        }
        sessions.push(session_user_output(adapter, context, &session, &user).await?);
    }
    Ok(sessions)
}

pub async fn next_valid_session(
    _adapter: &dyn rustauth_core::db::DbAdapter,
    context: &AuthContext,
    cookie_header: &str,
) -> Result<Option<(Session, User)>, RustAuthError> {
    for (_, token) in signed_multi_tokens(context, cookie_header)? {
        if let Some(session_user) = session_user(context, &token).await? {
            return Ok(Some(session_user));
        }
    }
    Ok(None)
}

async fn session_user(
    context: &AuthContext,
    token: &str,
) -> Result<Option<(Session, User)>, RustAuthError> {
    let Some(session) = context.sessions()?.find_session(token).await? else {
        return Ok(None);
    };
    let Some(user) = context.users()?.find_user_by_id(&session.user_id).await? else {
        return Ok(None);
    };
    Ok(Some((session, user)))
}

fn request_cookie_header(request: &rustauth_core::api::ApiRequest) -> String {
    request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn session_token_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("sessionToken", JsonSchemaType::String).description("The session token")
    ])
}

fn session_user_response() -> serde_json::Value {
    json_openapi_response(
        "Success",
        json!({
            "type": "object",
            "properties": {
                "session": {
                    "$ref": "#/components/schemas/Session",
                },
                "user": {
                    "$ref": "#/components/schemas/User",
                },
            },
            "required": ["session", "user"],
        }),
    )
}

fn list_device_sessions_response() -> serde_json::Value {
    json_openapi_response(
        "Success",
        json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "session": {
                        "$ref": "#/components/schemas/Session",
                    },
                    "user": {
                        "$ref": "#/components/schemas/User",
                    },
                },
                "required": ["session", "user"],
            },
        }),
    )
}

fn status_response() -> serde_json::Value {
    json_openapi_response(
        "Success",
        json!({
            "type": "object",
            "properties": {
                "status": {
                    "type": "boolean",
                },
            },
            "required": ["status"],
        }),
    )
}

fn json_openapi_response(description: &str, schema: serde_json::Value) -> serde_json::Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": schema,
            },
        },
    })
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Result<ApiResponse, RustAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| RustAuthError::Api(error.to_string()))?;
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| RustAuthError::Api(error.to_string()))
}

fn invalid_session_token() -> Result<ApiResponse, RustAuthError> {
    error_response(
        StatusCode::UNAUTHORIZED,
        INVALID_SESSION_TOKEN,
        "Invalid session token",
    )
}

fn unauthorized() -> Result<ApiResponse, RustAuthError> {
    error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")
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
    )
}
