use crate::error::OpenAuthError;

use super::chunked::ChunkedCookieStore;
use super::config::merge_options;
use super::parse::parse_cookies;
use super::signing::sign_cookie_value;
use super::types::{
    strip_secure_cookie_prefix, AuthCookie, AuthCookies, Cookie, SessionCookieOptions,
    SECURE_COOKIE_PREFIX,
};

pub fn get_session_cookie(
    cookie_header: &str,
    cookie_prefix: Option<&str>,
    cookie_name: Option<&str>,
    secure: bool,
) -> Option<String> {
    let prefix = cookie_prefix.unwrap_or("open-auth");
    let name = cookie_name.unwrap_or("session_token");
    let full_name = format!("{prefix}.{name}");
    let legacy_name = format!("{prefix}-{name}");
    let cookies = parse_cookies(cookie_header);

    // In secure-cookie mode the server only ever sets the `__Secure-` prefixed
    // name, so we accept the secure name (and its legacy `-` separator alias)
    // exclusively. Reading the unprefixed cookie there would let a sibling app
    // or subdomain that can write parent-domain cookies shadow the real secure
    // session. In plain mode the secure names cannot legitimately exist.
    let candidates = if secure {
        [
            format!("{SECURE_COOKIE_PREFIX}{full_name}"),
            format!("{SECURE_COOKIE_PREFIX}{legacy_name}"),
        ]
    } else {
        [full_name, legacy_name]
    };

    candidates
        .iter()
        .find_map(|candidate| cookies.get(candidate))
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
    // In secure mode, also expire the unprefixed fallback name so a shadow
    // cookie planted by a sibling app or subdomain cannot linger and keep
    // forcing anonymous responses after sign-out or an invalid-cookie reset.
    expired.extend(expire_unprefixed_alias(&auth_cookies.session_token));
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

/// Expire the unprefixed alias of a secure-prefixed cookie.
///
/// Returns `None` when the cookie is not secure-prefixed (no shadow alias can
/// exist), otherwise an expired cookie targeting the stripped, unprefixed name.
fn expire_unprefixed_alias(cookie: &AuthCookie) -> Option<Cookie> {
    let stripped = strip_secure_cookie_prefix(&cookie.name);
    (stripped != cookie.name).then(|| {
        let mut expired = expire_cookie(cookie);
        expired.name = stripped.to_owned();
        expired
    })
}
