use crate::error::OpenAuthError;

use super::chunked::ChunkedCookieStore;
use super::config::merge_options;
use super::parse::parse_cookies;
use super::signing::sign_cookie_value;
use super::types::{AuthCookie, AuthCookies, Cookie, SessionCookieOptions, SECURE_COOKIE_PREFIX};

pub fn get_session_cookie(
    cookie_header: &str,
    cookie_prefix: Option<&str>,
    cookie_name: Option<&str>,
) -> Option<String> {
    let prefix = cookie_prefix.unwrap_or("better-auth");
    let name = cookie_name.unwrap_or("session_token");
    let full_name = format!("{prefix}.{name}");
    let legacy_name = format!("{prefix}-{name}");
    let secure_name = format!("{SECURE_COOKIE_PREFIX}{full_name}");
    let secure_legacy_name = format!("{SECURE_COOKIE_PREFIX}{legacy_name}");
    let cookies = parse_cookies(cookie_header);

    cookies
        .get(&full_name)
        .or_else(|| cookies.get(&secure_name))
        .or_else(|| cookies.get(&legacy_name))
        .or_else(|| cookies.get(&secure_legacy_name))
        .cloned()
}

pub fn set_session_cookie(
    auth_cookies: &AuthCookies,
    secret: &str,
    token: &str,
    options: SessionCookieOptions,
) -> Result<Vec<Cookie>, OpenAuthError> {
    let mut attributes = merge_options(
        auth_cookies.session_token.attributes.clone(),
        options.overrides,
    );
    if options.dont_remember {
        attributes.max_age = None;
    }

    let mut cookies = vec![Cookie {
        name: auth_cookies.session_token.name.clone(),
        value: sign_cookie_value(token, secret)?,
        attributes,
    }];

    if options.dont_remember {
        cookies.push(Cookie {
            name: auth_cookies.dont_remember_token.name.clone(),
            value: sign_cookie_value("true", secret)?,
            attributes: auth_cookies.dont_remember_token.attributes.clone(),
        });
    }

    Ok(cookies)
}

pub fn expire_cookie(cookie: &AuthCookie) -> Cookie {
    let mut attributes = cookie.attributes.clone();
    attributes.max_age = Some(0);
    Cookie {
        name: cookie.name.clone(),
        value: String::new(),
        attributes,
    }
}

pub fn delete_session_cookie(
    auth_cookies: &AuthCookies,
    cookie_header: &str,
    skip_dont_remember: bool,
) -> Vec<Cookie> {
    let mut expired = vec![
        expire_cookie(&auth_cookies.session_token),
        expire_cookie(&auth_cookies.session_data),
        expire_cookie(&auth_cookies.account_data),
    ];
    expired.extend(clean_chunked_cookie(
        &auth_cookies.session_data,
        cookie_header,
    ));
    expired.extend(clean_chunked_cookie(
        &auth_cookies.account_data,
        cookie_header,
    ));
    if !skip_dont_remember {
        expired.push(expire_cookie(&auth_cookies.dont_remember_token));
    }
    expired
}

fn clean_chunked_cookie(cookie: &AuthCookie, cookie_header: &str) -> Vec<Cookie> {
    ChunkedCookieStore::new(
        cookie.name.clone(),
        cookie.attributes.clone(),
        cookie_header,
    )
    .clean()
}
