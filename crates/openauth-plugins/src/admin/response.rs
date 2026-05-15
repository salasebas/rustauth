use http::{header, HeaderValue, StatusCode};
use openauth_core::api::ApiResponse;
use openauth_core::cookies::Cookie;
use openauth_core::error::OpenAuthError;
use serde::Serialize;

pub fn json<T: Serialize>(status: StatusCode, body: &T) -> Result<ApiResponse, OpenAuthError> {
    json_with_cookies(status, body, Vec::new())
}

pub fn json_with_cookies<T: Serialize>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError> {
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

pub fn serialize_cookie(cookie: &Cookie) -> String {
    let mut serialized = format!("{}={}", cookie.name, cookie.value);
    if let Some(max_age) = cookie.attributes.max_age {
        serialized.push_str(&format!("; Max-Age={max_age}"));
    }
    if let Some(expires) = &cookie.attributes.expires {
        serialized.push_str("; Expires=");
        serialized.push_str(expires);
    }
    if let Some(domain) = &cookie.attributes.domain {
        serialized.push_str("; Domain=");
        serialized.push_str(domain);
    }
    if let Some(path) = &cookie.attributes.path {
        serialized.push_str("; Path=");
        serialized.push_str(path);
    }
    if cookie.attributes.secure.unwrap_or(false) {
        serialized.push_str("; Secure");
    }
    if cookie.attributes.http_only.unwrap_or(false) {
        serialized.push_str("; HttpOnly");
    }
    if let Some(same_site) = &cookie.attributes.same_site {
        serialized.push_str("; SameSite=");
        serialized.push_str(same_site);
    }
    if cookie.attributes.partitioned.unwrap_or(false) {
        serialized.push_str("; Partitioned");
    }
    serialized
}
