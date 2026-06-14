use std::sync::Arc;

use http::{header, HeaderValue};
use rustauth_core::api::{serialize_cookie, ApiRequest, ApiResponse, PathParams};
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::context::AuthContext;
use rustauth_core::db::{DbAdapter, User};
use rustauth_core::error::RustAuthError;
use serde_json::json;

use crate::utils;

pub(super) fn valid_provider_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(1..=128).contains(&bytes.len()) {
        return false;
    }
    let Some(first) = bytes.first() else {
        return false;
    };
    let Some(last) = bytes.last() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn invalid_provider_id() -> Result<ApiResponse, RustAuthError> {
    utils::json(
        http::StatusCode::BAD_REQUEST,
        &json!({"code": crate::errors::INVALID_PROVIDER_ID}),
    )
}

#[derive(Debug, serde::Serialize)]
struct RedirectBody {
    url: String,
    redirect: bool,
}

pub(super) fn redirect_json_response(
    url: String,
    redirect: bool,
    cookies: Vec<rustauth_core::cookies::Cookie>,
) -> Result<ApiResponse, RustAuthError> {
    let mut response = utils::json(
        http::StatusCode::OK,
        &RedirectBody {
            url: url.clone(),
            redirect,
        },
    )?;
    if redirect {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&url).map_err(|error| RustAuthError::Api(error.to_string()))?,
        );
    }
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| RustAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

pub(super) fn safe_redirect_field(
    context: &AuthContext,
    value: String,
    code: &'static str,
) -> Result<Result<String, ApiResponse>, RustAuthError> {
    Ok(match utils::safe_redirect_url(context, &value) {
        Some(value) => Ok(value),
        None => Err(invalid_redirect_response(code)?),
    })
}

pub(super) fn optional_safe_redirect_field(
    context: &AuthContext,
    value: Option<String>,
    code: &'static str,
) -> Result<Result<Option<String>, ApiResponse>, RustAuthError> {
    let Some(value) = value else {
        return Ok(Ok(None));
    };
    Ok(match utils::safe_redirect_url(context, &value) {
        Some(value) => Ok(Some(value)),
        None => Err(invalid_redirect_response(code)?),
    })
}

fn invalid_redirect_response(code: &'static str) -> Result<ApiResponse, RustAuthError> {
    utils::json(http::StatusCode::FORBIDDEN, &json!({ "code": code }))
}

pub(super) fn redirect(location: &str) -> Result<ApiResponse, RustAuthError> {
    http::Response::builder()
        .status(http::StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| RustAuthError::Api(error.to_string()))
}

pub(super) fn redirect_with_cookies(
    location: &str,
    cookies: Vec<rustauth_core::cookies::Cookie>,
) -> Result<ApiResponse, RustAuthError> {
    let mut response = http::Response::builder()
        .status(http::StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
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

pub(super) fn redirect_with_error(
    location: &str,
    error: &str,
) -> Result<ApiResponse, RustAuthError> {
    let separator = if location.contains('?') { '&' } else { '?' };
    redirect(&format!(
        "{location}{separator}error={}",
        percent_encode(error)
    ))
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub(super) fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == name).then(|| percent_decode(value))
        })
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                {
                    output.push((high << 4) | low);
                    index += 3;
                    continue;
                }
                output.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn path_param(request: &ApiRequest, name: &str) -> Option<String> {
    request
        .extensions()
        .get::<PathParams>()
        .and_then(|params| params.get(name))
        .map(str::to_owned)
}

pub(super) fn unauthorized() -> Result<ApiResponse, RustAuthError> {
    utils::json(
        http::StatusCode::UNAUTHORIZED,
        &json!({"code": "UNAUTHORIZED", "message": "Authentication required"}),
    )
}

pub(super) async fn authenticated_user(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<(Arc<dyn DbAdapter>, String)>, RustAuthError> {
    Ok(authenticated_session_user(context, request)
        .await?
        .map(|(adapter, user)| (adapter, user.id)))
}

pub(super) async fn authenticated_session_user(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<(Arc<dyn DbAdapter>, User)>, RustAuthError> {
    let Some(adapter) = context.adapter.clone() else {
        return Ok(None);
    };
    let cookie_header = request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(session) = SessionAuth::new(context)?
        .get_session(GetSessionInput::new(cookie_header).disable_refresh())
        .await?
    else {
        return Ok(None);
    };
    let Some(user) = session.user else {
        return Ok(None);
    };
    Ok(Some((adapter, user)))
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProviderIdBody {
    pub(super) provider_id: String,
}
