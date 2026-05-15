use std::sync::Arc;

use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, MemoryAdapter, Session};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::plugin::AuthPlugin;
use openauth_plugins::anonymous::AnonymousUser;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

pub(crate) type TestAdapter = MemoryAdapter;

pub(crate) fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

pub(crate) fn router(
    adapter: Arc<TestAdapter>,
    plugin: AuthPlugin,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_plugins(adapter, vec![plugin])
}

pub(crate) fn router_with_plugins(
    adapter: Arc<TestAdapter>,
    plugins: Vec<AuthPlugin>,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_options(
        adapter,
        OpenAuthOptions {
            plugins,
            secret: Some(secret().to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )
}

pub(crate) fn router_with_options(
    adapter: Arc<TestAdapter>,
    options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

pub(crate) fn request(
    method: Method,
    path: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Vec::new())
}

pub(crate) fn json_request(
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(serde_json::to_vec(&body).unwrap_or_default())
}

pub(crate) fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let context = openauth_core::context::create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

pub(crate) fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

pub(crate) fn response_cookie_header(response: &http::Response<Vec<u8>>) -> String {
    set_cookie_values(response)
        .into_iter()
        .filter_map(|cookie| cookie.split(';').next().map(str::to_owned))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(crate) async fn seed_user(
    adapter: &TestAdapter,
    user: AnonymousUser,
) -> Result<(), OpenAuthError> {
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String(user.id))
                .data("name", DbValue::String(user.name))
                .data("email", DbValue::String(user.email))
                .data("email_verified", DbValue::Boolean(user.email_verified))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(user.created_at))
                .data("updated_at", DbValue::Timestamp(user.updated_at))
                .data("is_anonymous", DbValue::Boolean(user.is_anonymous)),
        )
        .await?;
    Ok(())
}

pub(crate) async fn seed_session(
    adapter: &TestAdapter,
    session: Session,
) -> Result<(), OpenAuthError> {
    adapter
        .create(
            Create::new("session")
                .data("id", DbValue::String(session.id))
                .data("user_id", DbValue::String(session.user_id))
                .data("expires_at", DbValue::Timestamp(session.expires_at))
                .data("token", DbValue::String(session.token))
                .data("ip_address", DbValue::Null)
                .data("user_agent", DbValue::Null)
                .data("created_at", DbValue::Timestamp(session.created_at))
                .data("updated_at", DbValue::Timestamp(session.updated_at)),
        )
        .await?;
    Ok(())
}

pub(crate) fn anonymous_user(id: &str, is_anonymous: bool) -> AnonymousUser {
    let now = OffsetDateTime::now_utc();
    AnonymousUser {
        id: id.to_owned(),
        name: "Ada".to_owned(),
        email: format!("{id}@example.com"),
        email_verified: false,
        image: None,
        created_at: now,
        updated_at: now,
        is_anonymous,
    }
}

pub(crate) fn session(id: &str, user_id: &str, token: &str) -> Session {
    let now = OffsetDateTime::now_utc();
    Session {
        id: id.to_owned(),
        user_id: user_id.to_owned(),
        expires_at: now + Duration::hours(1),
        token: token.to_owned(),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn find_string<'a>(record: &'a DbRecord, field: &str) -> Option<&'a str> {
    match record.get(field) {
        Some(DbValue::String(value)) => Some(value),
        _ => None,
    }
}

pub(crate) fn find_bool(record: &DbRecord, field: &str) -> Option<bool> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Some(*value),
        _ => None,
    }
}

pub(crate) async fn contains_user(adapter: &TestAdapter, user_id: &str) -> bool {
    adapter
        .records("user")
        .await
        .iter()
        .any(|record| matches!(record.get("id"), Some(DbValue::String(id)) if id == user_id))
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}
