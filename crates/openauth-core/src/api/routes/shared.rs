use http::{header, HeaderValue, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::api::{ApiErrorResponse, ApiRequest, ApiResponse};
use crate::auth::email_password::{
    AuthFlowError, AuthFlowErrorCode, EmailPasswordConfig, SignInInput, SignUpInput,
};
use crate::auth::session::{GetSessionInput, SessionAuth};
use crate::context::request_state::{
    has_request_state, set_current_new_session, set_current_session_user,
};
use crate::context::AuthContext;
use crate::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use crate::db::{DbAdapter, Session, User};
use crate::error::OpenAuthError;

pub(super) trait RequestMetadata {
    fn with_request_metadata(self, request: &ApiRequest) -> Self;
}

impl RequestMetadata for SignUpInput {
    fn with_request_metadata(mut self, request: &ApiRequest) -> Self {
        if let Some(ip_address) = request_ip(request) {
            self = self.ip_address(ip_address);
        }
        if let Some(user_agent) = request_user_agent(request) {
            self = self.user_agent(user_agent);
        }
        self
    }
}

impl RequestMetadata for SignInInput {
    fn with_request_metadata(mut self, request: &ApiRequest) -> Self {
        if let Some(ip_address) = request_ip(request) {
            self = self.ip_address(ip_address);
        }
        if let Some(user_agent) = request_user_agent(request) {
            self = self.user_agent(user_agent);
        }
        self
    }
}

pub(super) fn email_password_config(context: &AuthContext) -> EmailPasswordConfig {
    EmailPasswordConfig {
        session_expires_in: context.session_config.expires_in,
        dont_remember_session_expires_in: 60 * 60 * 24,
        min_password_length: context.password.config.min_password_length,
        max_password_length: context.password.config.max_password_length,
        require_email_verification: false,
    }
}

pub(super) fn auth_session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
    dont_remember: bool,
) -> Result<Vec<Cookie>, OpenAuthError> {
    let mut cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember,
            overrides: CookieOptions::default(),
        },
    )?;
    if context.options.session.cookie_cache.enabled {
        let max_age = context
            .options
            .session
            .cookie_cache
            .max_age
            .unwrap_or(60 * 5);
        cookies.extend(set_cookie_cache(
            &context.auth_cookies,
            &context.secret,
            &CookieCachePayload {
                session: session.clone(),
                user: user.clone(),
                updated_at: OffsetDateTime::now_utc().unix_timestamp(),
                version: context
                    .options
                    .session
                    .cookie_cache
                    .version
                    .clone()
                    .unwrap_or_else(|| "1".to_owned()),
            },
            context.options.session.cookie_cache.strategy,
            max_age,
        )?);
    }
    Ok(cookies)
}

pub(super) fn record_new_session(session: &Session, user: &User) -> Result<(), OpenAuthError> {
    if has_request_state() {
        set_current_new_session(session.clone(), user.clone())?;
    }
    Ok(())
}

pub(super) fn auth_flow_error_response(error: AuthFlowError) -> Result<ApiResponse, OpenAuthError> {
    let status = match error.code() {
        AuthFlowErrorCode::InvalidEmailOrPassword | AuthFlowErrorCode::EmailNotVerified => {
            StatusCode::UNAUTHORIZED
        }
        AuthFlowErrorCode::StorageError | AuthFlowErrorCode::FailedToCreateSession => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        AuthFlowErrorCode::InvalidEmail
        | AuthFlowErrorCode::InvalidPasswordLength
        | AuthFlowErrorCode::UserAlreadyExists => StatusCode::BAD_REQUEST,
    };
    json_response(
        status,
        &ApiErrorResponse {
            code: error.code_str().to_owned(),
            message: error.message().to_owned(),
            original_message: None,
        },
        Vec::new(),
    )
}

pub(super) fn json_response<T>(
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

pub(super) fn request_cookie_header(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub(super) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == name).then(|| percent_decode(value))
        })
    })
}

pub(super) async fn current_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<(Session, User, Vec<Cookie>)>, OpenAuthError> {
    let cookie_header = request_cookie_header(request).unwrap_or_default();
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
    if has_request_state() {
        set_current_session_user(
            serde_json::to_value(&user).map_err(|error| OpenAuthError::Api(error.to_string()))?,
        )?;
    }
    Ok(Some((session, user, result.cookies)))
}

pub(super) fn error_response(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &ApiErrorResponse {
            code: code.into(),
            message: message.into(),
            original_message: None,
        },
        Vec::new(),
    )
}

pub(super) fn unauthorized() -> Result<ApiResponse, OpenAuthError> {
    error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")
}

pub(super) fn json_openapi_response(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": schema,
            },
        },
    })
}

pub(super) fn message_openapi_response(description: &str) -> Value {
    json_openapi_response(
        description,
        json!({
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                },
            },
        }),
    )
}

pub(super) fn sign_up_email_openapi_response() -> Value {
    json_openapi_response(
        "Successfully created user",
        json!({
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "nullable": true,
                    "description": "Authentication token for the session",
                },
                "user": {
                    "$ref": "#/components/schemas/User",
                },
            },
            "required": ["user"],
        }),
    )
}

pub(super) fn sign_in_email_openapi_response() -> Value {
    json_openapi_response(
        "Success - Returns either session details or redirect URL",
        json!({
            "type": "object",
            "description": "Session response when idToken is provided",
            "properties": {
                "redirect": {
                    "type": "boolean",
                    "enum": [false],
                },
                "token": {
                    "type": "string",
                    "description": "Session token",
                },
                "url": {
                    "type": "string",
                    "nullable": true,
                },
                "user": {
                    "$ref": "#/components/schemas/User",
                },
            },
            "required": ["redirect", "token", "user"],
        }),
    )
}

pub(super) fn get_session_openapi_response() -> Value {
    json_openapi_response(
        "Success",
        json!({
            "type": ["object", "null"],
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

pub(super) fn sign_out_openapi_response() -> Value {
    json_openapi_response(
        "Success",
        json!({
            "type": "object",
            "properties": {
                "success": {
                    "type": "boolean",
                },
            },
        }),
    )
}

pub(super) fn list_sessions_openapi_response() -> Value {
    json_openapi_response(
        "Success",
        json!({
            "type": "array",
            "items": {
                "$ref": "#/components/schemas/Session",
            },
        }),
    )
}

pub(super) fn status_openapi_response(description: &str) -> Value {
    json_openapi_response(
        description,
        json!({
            "type": "object",
            "properties": {
                "status": {
                    "type": "boolean",
                    "description": description,
                },
            },
            "required": ["status"],
        }),
    )
}

pub(super) fn serialize_cookie(cookie: &Cookie) -> String {
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

pub(super) fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &value[index + 1..index + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                decoded.push(byte);
                index += 3;
                continue;
            }
        }
        decoded.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn request_user_agent(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn request_ip(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
}
