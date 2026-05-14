use http::{header, HeaderValue, StatusCode};
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use openauth_core::db::{Session, User};
use openauth_core::error::OpenAuthError;
use serde::Serialize;
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub(super) struct OneTapSessionBody {
    pub token: String,
    pub user: User,
}

pub(super) fn session_response(
    context: &AuthContext,
    session: Session,
    user: User,
    extra_cookies: Vec<Cookie>,
) -> Result<ApiResponse, OpenAuthError> {
    let mut cookies = session_cookies(context, &session, &user)?;
    cookies.extend(extra_cookies);
    json_response(
        StatusCode::OK,
        &OneTapSessionBody {
            token: session.token,
            user,
        },
        cookies,
    )
}

pub(super) fn error_response(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<ApiResponse, OpenAuthError> {
    json_response(
        status,
        &ApiErrorResponse {
            code: code.into(),
            message: message.into(),
            original_message: None,
        },
        Vec::new(),
    )
}

fn json_response<T>(
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
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| OpenAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

fn session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
) -> Result<Vec<Cookie>, OpenAuthError> {
    let mut cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember: false,
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

fn serialize_cookie(cookie: &Cookie) -> String {
    let mut value = format!("{}={}", cookie.name, cookie.value);
    if let Some(max_age) = cookie.attributes.max_age {
        value.push_str(&format!("; Max-Age={max_age}"));
    }
    if let Some(domain) = &cookie.attributes.domain {
        value.push_str(&format!("; Domain={domain}"));
    }
    if let Some(path) = &cookie.attributes.path {
        value.push_str(&format!("; Path={path}"));
    }
    if cookie.attributes.secure.unwrap_or(false) {
        value.push_str("; Secure");
    }
    if cookie.attributes.http_only.unwrap_or(false) {
        value.push_str("; HttpOnly");
    }
    if let Some(same_site) = &cookie.attributes.same_site {
        value.push_str("; SameSite=");
        value.push_str(same_site);
    }
    if cookie.attributes.partitioned.unwrap_or(false) {
        value.push_str("; Partitioned");
    }
    value
}
