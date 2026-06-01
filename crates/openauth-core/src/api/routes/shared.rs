use http::{header, HeaderValue, StatusCode};
use serde::Serialize;
use serde_json::{json, Value};

use crate::api::additional_fields::AdditionalFieldError;
use crate::api::output::{session_response_cookies, user_output_value};
use crate::api::{ApiErrorResponse, ApiRequest, ApiResponse};
use crate::auth::email_password::{AuthFlowError, AuthFlowErrorCode};
use crate::auth::session::{GetSessionInput, SessionAuth};
use crate::context::request_state::{
    has_request_state, set_current_new_session, set_current_session_user,
};
use crate::context::AuthContext;
use crate::cookies::Cookie;
use crate::db::{DbAdapter, DbRecord, DbValue, Session, User};
use crate::error::OpenAuthError;
use crate::plugin::PluginPasswordValidationRejection;

pub(super) fn auth_session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
    dont_remember: bool,
) -> Result<Vec<Cookie>, OpenAuthError> {
    session_response_cookies(context, session, user, dont_remember)
}

pub(super) fn record_new_session(session: &Session, user: &User) -> Result<(), OpenAuthError> {
    if has_request_state() {
        set_current_new_session(session.clone(), user.clone())?;
    }
    Ok(())
}

/// Resolve whether the current request carries a non-remembered (browser
/// session) marker. Mirrors how `SessionAuth::get_session` derives the
/// `dont_remember` flag from the signed marker cookie, so sensitive flows can
/// preserve `rememberMe: false` behavior when reissuing session cookies.
pub(super) fn request_dont_remember(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<bool, OpenAuthError> {
    let cookie_header = request_cookie_header(request).unwrap_or_default();
    let Some(value) = crate::cookies::parse_cookies(&cookie_header)
        .get(&context.auth_cookies.dont_remember_token.name)
        .cloned()
    else {
        return Ok(false);
    };
    Ok(crate::cookies::verify_cookie_value(&value, &context.secret)?.is_some())
}

pub(super) fn auth_flow_error_response(error: AuthFlowError) -> Result<ApiResponse, OpenAuthError> {
    let status = match error.code() {
        AuthFlowErrorCode::InvalidEmailOrPassword => StatusCode::UNAUTHORIZED,
        AuthFlowErrorCode::EmailNotVerified => StatusCode::FORBIDDEN,
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

pub(super) fn invalid_additional_field_response(
    error: AdditionalFieldError,
) -> Result<ApiResponse, OpenAuthError> {
    error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_REQUEST_BODY",
        error.message(),
    )
}

pub(super) fn additional_session_create_values(context: &AuthContext) -> DbRecord {
    context
        .options
        .session
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                field.db_name.clone().unwrap_or_else(|| name.clone()),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect()
}

pub(super) async fn user_response_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
) -> Result<Value, OpenAuthError> {
    user_output_value(adapter, context, user).await
}

pub(super) fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Serialization {
        context: "serializing JSON response body",
        message: error.to_string(),
    })?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Serialization {
            context: "building JSON response",
            message: error.to_string(),
        })?;
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
    current_session_with_cache_policy(adapter, context, request, false).await
}

pub(super) async fn sensitive_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<(Session, User, Vec<Cookie>)>, OpenAuthError> {
    current_session_with_cache_policy(adapter, context, request, true).await
}

async fn current_session_with_cache_policy(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
    disable_cookie_cache: bool,
) -> Result<Option<(Session, User, Vec<Cookie>)>, OpenAuthError> {
    let cookie_header = request_cookie_header(request).unwrap_or_default();
    let mut input = GetSessionInput::new(cookie_header);
    if disable_cookie_cache {
        input = input.disable_cookie_cache();
    }
    let Some(result) = SessionAuth::new(adapter, context)
        .get_session(input)
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
        set_current_session_user(serde_json::to_value(&user).map_err(|error| {
            OpenAuthError::Serialization {
                context: "serializing current session user",
                message: error.to_string(),
            }
        })?)?;
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

pub(super) fn password_validation_rejection_response(
    rejection: PluginPasswordValidationRejection,
) -> Result<ApiResponse, OpenAuthError> {
    error_response(rejection.status, rejection.code, rejection.message)
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
