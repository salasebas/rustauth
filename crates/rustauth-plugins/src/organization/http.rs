use http::{header, HeaderValue, StatusCode};
use rustauth_core::api::{parse_request_body, ApiErrorResponse, ApiRequest, ApiResponse};
use rustauth_core::auth::session::{GetSessionInput, SessionAuth};
use rustauth_core::context::AuthContext;
use rustauth_core::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use rustauth_core::db::{Session, User};
use rustauth_core::error::RustAuthError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use time::OffsetDateTime;

pub struct CurrentSession {
    pub session: Session,
    pub user: User,
    pub active_organization_id: Option<String>,
    pub active_team_id: Option<String>,
}

pub fn json<T: Serialize>(status: StatusCode, body: &T) -> Result<ApiResponse, RustAuthError> {
    json_with_cookies(status, body, Vec::new())
}

pub fn json_with_cookies<T: Serialize>(
    status: StatusCode,
    body: &T,
    cookies: Vec<Cookie>,
) -> Result<ApiResponse, RustAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| RustAuthError::Api(error.to_string()))?;
    let mut response = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| RustAuthError::Api(error.to_string()))?;
    for cookie in cookies {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&serialize_cookie(&cookie))
                .map_err(|error| RustAuthError::Cookie(error.to_string()))?,
        );
    }
    Ok(response)
}

pub fn error(status: StatusCode, code: &str, message: &str) -> Result<ApiResponse, RustAuthError> {
    json(
        status,
        &ApiErrorResponse {
            code: code.to_owned(),
            message: message.to_owned(),
            original_message: None,
        },
    )
}

pub fn organization_error(status: StatusCode, code: &str) -> Result<ApiResponse, RustAuthError> {
    error(status, code, super::errors::message(code))
}

pub fn body<T: DeserializeOwned>(request: &ApiRequest) -> Result<T, RustAuthError> {
    parse_request_body(request)
}

/// Returns true when the request originates from the internet-facing HTTP
/// router. Server-only inputs (such as an explicit `userId` acting on behalf of
/// another user) must never be trusted for such requests.
pub fn request_is_external() -> bool {
    rustauth_core::context::request_state::is_external_request()
}

pub fn refreshed_session_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
) -> Result<Vec<Cookie>, RustAuthError> {
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
            .unwrap_or(time::Duration::minutes(5));
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
            max_age.whole_seconds() as u64,
        )?);
    }
    Ok(cookies)
}

pub async fn current_session(
    context: &AuthContext,
    request: &ApiRequest,
    store: &super::store::OrganizationStore<'_>,
) -> Result<Option<CurrentSession>, RustAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(result) = SessionAuth::new(context)?
        .get_session(GetSessionInput::new(cookie_header))
        .await?
    else {
        return Ok(None);
    };
    let Some(session) = result.session else {
        return Ok(None);
    };
    let Some(user) = result.user else {
        return Ok(None);
    };
    let active_organization_id = store.active_organization_id(&session.token).await?;
    let active_team_id = store.active_team_id(&session.token).await?;
    Ok(Some(CurrentSession {
        session,
        user,
        active_organization_id,
        active_team_id,
    }))
}

fn serialize_cookie(cookie: &Cookie) -> String {
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
