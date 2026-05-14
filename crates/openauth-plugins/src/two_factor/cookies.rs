use http::header;
use openauth_core::api::ApiResponse;
use openauth_core::cookies::{
    sign_cookie_value, verify_cookie_value, AuthCookie, Cookie, CookieOptions,
};
use openauth_core::error::OpenAuthError;

pub const TWO_FACTOR_COOKIE_NAME: &str = "two_factor";
pub const TRUST_DEVICE_COOKIE_NAME: &str = "trust_device";

pub fn plugin_cookie(base: &AuthCookie, name: &str, max_age: u64) -> AuthCookie {
    let mut attributes = base.attributes.clone();
    attributes.max_age = Some(max_age);
    AuthCookie {
        name: base.name.replace("session_token", name),
        attributes,
    }
}

pub fn signed_cookie(
    cookie: &AuthCookie,
    value: &str,
    secret: &str,
) -> Result<Cookie, OpenAuthError> {
    Ok(Cookie {
        name: cookie.name.clone(),
        value: sign_cookie_value(value, secret)?,
        attributes: cookie.attributes.clone(),
    })
}

pub fn expire_cookie(cookie: &AuthCookie) -> Cookie {
    Cookie {
        name: cookie.name.clone(),
        value: String::new(),
        attributes: CookieOptions {
            max_age: Some(0),
            ..cookie.attributes.clone()
        },
    }
}

pub fn read_signed_cookie(
    cookie_header: &str,
    name: &str,
    secret: &str,
) -> Result<Option<String>, OpenAuthError> {
    let Some(value) = openauth_core::cookies::parse_cookies(cookie_header)
        .get(name)
        .cloned()
    else {
        return Ok(None);
    };
    verify_cookie_value(&value, secret)
}

pub fn append_cookies(response: &mut ApiResponse, cookies: &[Cookie]) -> Result<(), OpenAuthError> {
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            http::HeaderValue::from_str(&serialize_cookie(cookie))
                .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(())
}

pub fn serialize_cookie(cookie: &Cookie) -> String {
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
