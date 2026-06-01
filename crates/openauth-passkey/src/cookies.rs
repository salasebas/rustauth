use http::header;
use openauth_core::api::ApiRequest;
use openauth_core::context::AuthContext;
use openauth_core::cookies::{parse_cookies, sign_cookie_value, verify_cookie_value, Cookie};
use openauth_core::error::OpenAuthError;

use crate::challenge::CHALLENGE_MAX_AGE_SECONDS;
use crate::options::PasskeyOptions;

pub fn challenge_cookie(
    context: &AuthContext,
    options: &PasskeyOptions,
    value: String,
) -> Result<Cookie, OpenAuthError> {
    let auth_cookie = context.create_auth_cookie(
        &options.advanced.webauthn_challenge_cookie,
        Some(CHALLENGE_MAX_AGE_SECONDS),
    )?;
    Ok(Cookie {
        name: auth_cookie.name,
        value: sign_cookie_value(&value, &context.secret)?,
        attributes: auth_cookie.attributes,
    })
}

pub fn challenge_token(
    context: &AuthContext,
    options: &PasskeyOptions,
    request: &ApiRequest,
) -> Result<Option<String>, OpenAuthError> {
    let Some(cookie_header) = request_cookie_header(request) else {
        return Ok(None);
    };
    let cookie_name = challenge_cookie_name(context, options)?;
    let Some(value) = parse_cookies(&cookie_header).get(&cookie_name).cloned() else {
        return Ok(None);
    };
    verify_cookie_value(&value, &context.secret)
}

fn challenge_cookie_name(
    context: &AuthContext,
    options: &PasskeyOptions,
) -> Result<String, OpenAuthError> {
    Ok(context
        .create_auth_cookie(&options.advanced.webauthn_challenge_cookie, None)?
        .name)
}

pub fn request_cookie_header(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
