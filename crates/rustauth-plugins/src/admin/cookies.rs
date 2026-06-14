use rustauth_core::context::AuthContext;
use rustauth_core::cookies::{
    expire_cookie, parse_cookies, set_session_cookie, sign_cookie_value, verify_cookie_value,
    AuthCookie, Cookie, SessionCookieOptions,
};
use rustauth_core::error::RustAuthError;

pub fn cookie_header(request: &rustauth_core::api::ApiRequest) -> String {
    request
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

pub fn admin_session_cookie(context: &AuthContext) -> AuthCookie {
    AuthCookie {
        name: format!(
            "{}.admin_session",
            context
                .options
                .advanced
                .cookie_prefix
                .as_deref()
                .unwrap_or("better-auth")
        ),
        attributes: context.auth_cookies.session_token.attributes.clone(),
    }
}

pub fn set_admin_cookie(
    context: &AuthContext,
    session_token: &str,
    dont_remember_value: Option<&str>,
) -> Result<Cookie, RustAuthError> {
    let cookie = admin_session_cookie(context);
    Ok(Cookie {
        name: cookie.name,
        value: sign_cookie_value(
            &format!(
                "{}:{}",
                session_token,
                dont_remember_value.unwrap_or_default()
            ),
            &context.secret,
        )?,
        attributes: context.auth_cookies.session_token.attributes.clone(),
    })
}

pub fn read_admin_cookie(
    context: &AuthContext,
    cookie_header: &str,
) -> Result<Option<(String, Option<String>)>, RustAuthError> {
    let cookie = admin_session_cookie(context);
    let Some(value) = parse_cookies(cookie_header).get(&cookie.name).cloned() else {
        return Ok(None);
    };
    let Some(unsigned) = verify_cookie_value(&value, &context.secret)? else {
        return Ok(None);
    };
    let (token, dont_remember) = unsigned.split_once(':').unwrap_or((unsigned.as_str(), ""));
    Ok(Some((
        token.to_owned(),
        (!dont_remember.is_empty()).then(|| dont_remember.to_owned()),
    )))
}

pub fn read_dont_remember_cookie(
    context: &AuthContext,
    cookie_header: &str,
) -> Result<Option<String>, RustAuthError> {
    let Some(value) = parse_cookies(cookie_header)
        .get(&context.auth_cookies.dont_remember_token.name)
        .cloned()
    else {
        return Ok(None);
    };
    verify_cookie_value(&value, &context.secret)
}

pub fn session_cookie(context: &AuthContext, token: &str) -> Result<Vec<Cookie>, RustAuthError> {
    session_cookie_with_dont_remember(context, token, false)
}

pub fn session_cookie_with_dont_remember(
    context: &AuthContext,
    token: &str,
    dont_remember: bool,
) -> Result<Vec<Cookie>, RustAuthError> {
    set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions {
            dont_remember,
            ..SessionCookieOptions::default()
        },
    )
}

pub fn expire_admin_cookie(context: &AuthContext) -> Cookie {
    expire_cookie(&admin_session_cookie(context))
}
