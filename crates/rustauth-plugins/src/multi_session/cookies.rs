use http::{header, HeaderValue, Response};
use rustauth_core::context::AuthContext;
use rustauth_core::cookies::{
    delete_session_cookie, parse_cookies, sign_cookie_value, verify_cookie_value, Cookie,
    SECURE_COOKIE_PREFIX,
};
use rustauth_core::db::{Session, User};
use rustauth_core::error::RustAuthError;

pub fn multi_cookie_name(context: &AuthContext, token: &str) -> String {
    format!(
        "{}_multi-{}",
        context.auth_cookies.session_token.name,
        token.to_lowercase()
    )
}

pub fn multi_cookie_keys(cookie_header: &str) -> Vec<String> {
    parse_cookies(cookie_header)
        .into_keys()
        .filter(|key| key.contains("_multi-"))
        .collect()
}

pub fn signed_multi_tokens(
    context: &AuthContext,
    cookie_header: &str,
) -> Result<Vec<(String, String)>, RustAuthError> {
    let cookies = parse_cookies(cookie_header);
    let mut tokens = Vec::new();
    for key in multi_cookie_keys(cookie_header) {
        let Some(value) = cookies.get(&key) else {
            continue;
        };
        if let Some(token) = verify_cookie_value(value, &context.secret)? {
            tokens.push((key, token));
        }
    }
    Ok(tokens)
}

pub fn signed_multi_token(
    context: &AuthContext,
    cookie_header: &str,
    token: &str,
) -> Result<Option<String>, RustAuthError> {
    let name = multi_cookie_name(context, token);
    let Some(value) = parse_cookies(cookie_header).get(&name).cloned() else {
        return Ok(None);
    };
    Ok(verify_cookie_value(&value, &context.secret)?.filter(|verified| verified == token))
}

pub fn multi_session_cookie(context: &AuthContext, token: &str) -> Result<Cookie, RustAuthError> {
    Ok(Cookie {
        name: multi_cookie_name(context, token),
        value: sign_cookie_value(token, &context.secret)?,
        attributes: context.auth_cookies.session_token.attributes.clone(),
    })
}

pub fn expire_multi_cookie(context: &AuthContext, token: &str) -> Cookie {
    expire_multi_cookie_name(context, &multi_cookie_name(context, token))
}

pub fn expire_multi_cookie_name(context: &AuthContext, name: &str) -> Cookie {
    let mut attributes = context.auth_cookies.session_token.attributes.clone();
    attributes.max_age = Some(0);
    Cookie {
        name: restore_secure_prefix_case(name),
        value: String::new(),
        attributes,
    }
}

pub fn active_session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
    cookie_header: &str,
) -> Result<Vec<Cookie>, RustAuthError> {
    rustauth_core::api::output::session_response_cookies(
        context,
        session,
        user,
        has_dont_remember_cookie(context, cookie_header)?,
    )
}

pub fn delete_active_session_cookies(context: &AuthContext, cookie_header: &str) -> Vec<Cookie> {
    delete_session_cookie(&context.auth_cookies, cookie_header, false)
}

pub fn append_cookies(
    response: &mut Response<Vec<u8>>,
    cookies: impl IntoIterator<Item = Cookie>,
) -> Result<(), RustAuthError> {
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| RustAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(())
}

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut parts = vec![format!("{}={}", cookie.name, cookie.value)];
    push_attr(&mut parts, "Max-Age", cookie.attributes.max_age);
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

fn push_attr(parts: &mut Vec<String>, name: &str, value: Option<u64>) {
    if let Some(value) = value {
        parts.push(format!("{name}={value}"));
    }
}

fn has_dont_remember_cookie(
    context: &AuthContext,
    cookie_header: &str,
) -> Result<bool, RustAuthError> {
    let Some(value) = parse_cookies(cookie_header)
        .get(&context.auth_cookies.dont_remember_token.name)
        .cloned()
    else {
        return Ok(false);
    };
    Ok(verify_cookie_value(&value, &context.secret)?.is_some())
}

fn restore_secure_prefix_case(name: &str) -> String {
    let lower_prefix = SECURE_COOKIE_PREFIX.to_lowercase();
    if name.to_lowercase().starts_with(&lower_prefix) {
        return name.replacen(&name[..SECURE_COOKIE_PREFIX.len()], SECURE_COOKIE_PREFIX, 1);
    }
    name.to_owned()
}
