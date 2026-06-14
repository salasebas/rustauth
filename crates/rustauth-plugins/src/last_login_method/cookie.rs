use http::{header, HeaderValue};
use rustauth_core::api::{ApiRequest, ApiResponse};
use rustauth_core::context::AuthContext;
use rustauth_core::cookies::{parse_set_cookie_header, Cookie, CookieOptions};
use rustauth_core::error::RustAuthError;

use super::config::LastLoginMethodOptions;
use super::resolve::LoginMethodContext;

pub fn set_last_login_method_cookie(
    context: &AuthContext,
    request: &ApiRequest,
    mut response: ApiResponse,
    options: &LastLoginMethodOptions,
) -> Result<ApiResponse, RustAuthError> {
    if !sets_session_cookie(context, &response) {
        return Ok(response);
    }

    let login_context = LoginMethodContext::from_request(context, request);
    let Some(method) = options.resolve_login_method(&login_context) else {
        return Ok(response);
    };

    let mut attributes = context.auth_cookies.session_token.attributes.clone();
    attributes.max_age = Some(options.effective_max_age());
    attributes.http_only = Some(false);
    let cookie = Cookie {
        name: options.effective_cookie_name().to_owned(),
        value: percent_encode(&method),
        attributes,
    };
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&serialize_cookie(&cookie))
            .map_err(|error| RustAuthError::Cookie(error.to_string()))?,
    );
    Ok(response)
}

fn sets_session_cookie(context: &AuthContext, response: &ApiResponse) -> bool {
    let session_cookie = context.auth_cookies.session_token.name.as_str();
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| parse_set_cookie_header(value).contains_key(session_cookie))
}

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut parts = vec![format!("{}={}", cookie.name, cookie.value)];
    push_cookie_attributes(&mut parts, &cookie.attributes);
    parts.join("; ")
}

fn push_cookie_attributes(parts: &mut Vec<String>, attributes: &CookieOptions) {
    if let Some(max_age) = attributes.max_age {
        parts.push(format!("Max-Age={max_age}"));
    }
    if let Some(expires) = &attributes.expires {
        parts.push(format!("Expires={expires}"));
    }
    if let Some(domain) = &attributes.domain {
        parts.push(format!("Domain={domain}"));
    }
    if let Some(path) = &attributes.path {
        parts.push(format!("Path={path}"));
    }
    if attributes.secure == Some(true) {
        parts.push("Secure".to_owned());
    }
    if attributes.http_only == Some(true) {
        parts.push("HttpOnly".to_owned());
    }
    if let Some(same_site) = &attributes.same_site {
        parts.push(format!("SameSite={same_site}"));
    }
    if attributes.partitioned == Some(true) {
        parts.push("Partitioned".to_owned());
    }
}

fn percent_encode(value: &str) -> String {
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
