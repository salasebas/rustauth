use http::{header, HeaderValue, StatusCode};
use serde::Serialize;
use time::OffsetDateTime;

use crate::context::request_state::{has_request_state, set_current_new_session};
use crate::context::AuthContext;
use crate::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use crate::db::{Session, User};
use crate::error::OpenAuthError;

use super::ApiResponse;

pub fn json_response<T>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError>
where
    T: Serialize,
{
    let body = serde_json::to_vec(body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    append_cookies(response.headers_mut(), cookies)?;
    Ok(response)
}

pub fn redirect_response(
    location: &str,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError> {
    let mut response = http::Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Vec::new())
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    append_cookies(response.headers_mut(), cookies)?;
    Ok(response)
}

pub fn redirect_with_error_response(
    location: &str,
    error: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let separator = if location.contains('?') { '&' } else { '?' };
    redirect_response(
        &format!(
            "{location}{separator}error={}",
            url::form_urlencoded::byte_serialize(error.as_bytes()).collect::<String>()
        ),
        Vec::new(),
    )
}

pub fn session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
    dont_remember: bool,
) -> Result<Vec<Cookie>, OpenAuthError> {
    if has_request_state() {
        set_current_new_session(session.clone(), user.clone())?;
    }
    let mut cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember,
            overrides: CookieOptions::default(),
        },
    )?;
    if context.options.session.cookie_cache.enabled {
        let max_age = context
            .options
            .session
            .cookie_cache
            .max_age
            .unwrap_or(60 * 5);
        cookies.extend(set_cookie_cache(
            &context.auth_cookies,
            &context.secret,
            &CookieCachePayload {
                session: session.clone(),
                user: user.clone(),
                updated_at: OffsetDateTime::now_utc().unix_timestamp(),
                version: context
                    .options
                    .session
                    .cookie_cache
                    .version
                    .clone()
                    .unwrap_or_else(|| "1".to_owned()),
            },
            context.options.session.cookie_cache.strategy,
            max_age,
        )?);
    }
    Ok(cookies)
}

pub fn append_cookies(
    headers: &mut http::HeaderMap,
    cookies: Vec<Cookie>,
) -> Result<(), OpenAuthError> {
    for cookie in cookies {
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
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
