use http::{header, HeaderValue, StatusCode};
use openauth_core::api::ApiResponse;
use openauth_core::cookies::Cookie;
use openauth_core::error::OpenAuthError;
use serde::Serialize;
use serde_json::json;

pub fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|err| OpenAuthError::Api(err.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|err| OpenAuthError::Api(err.to_string()))?;
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|err| OpenAuthError::Cookie(err.to_string()))?,
        );
    }
    Ok(response)
}

pub fn sign_in_response() -> serde_json::Value {
    json!({
        "description": "Sign in anonymously",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "token": { "type": "string" },
                        "user": { "$ref": "#/components/schemas/User" }
                    }
                }
            }
        }
    })
}

pub fn delete_response() -> serde_json::Value {
    json!({
        "description": "Anonymous user deleted",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": { "success": { "type": "boolean" } }
                }
            }
        }
    })
}

pub fn message_response(description: &str) -> serde_json::Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": { "message": { "type": "string" } },
                    "required": ["message"]
                }
            }
        }
    })
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
