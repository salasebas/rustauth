use std::sync::Arc;

use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, MemoryAdapter, Session, User};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

pub const TEST_BASE_URL: &str = "http://localhost:3000";
const TEST_SECRET: &str = "test-secret-123456789012345678901234";

pub fn options_with_plugin(plugin: openauth_core::plugin::AuthPlugin) -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: Some(TEST_BASE_URL.to_owned()),
        secret: Some(TEST_SECRET.to_owned()),
        plugins: vec![plugin],
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}

pub fn router_with_plugin(
    adapter: Arc<MemoryAdapter>,
    plugin: openauth_core::plugin::AuthPlugin,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(options_with_plugin(plugin), adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

pub fn request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{TEST_BASE_URL}{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub async fn seed_user_session(adapter: &MemoryAdapter) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(create_query("user", user_record(user(now))))
        .await?;
    adapter
        .create(create_query(
            "session",
            session_record(session(now, now + Duration::hours(1))),
        ))
        .await?;
    Ok(())
}

pub fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(TEST_SECRET.to_owned()),
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

pub fn jwt_kid(token: &str) -> Result<String, Box<dyn std::error::Error>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let header = token.split('.').next().ok_or("missing header")?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header)?)?;
    Ok(header["kid"].as_str().ok_or("missing kid")?.to_owned())
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

fn user(now: OffsetDateTime) -> User {
    User {
        id: "user_1".to_owned(),
        name: "Ada".to_owned(),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        image: None,
        username: None,
        display_username: None,
        created_at: now,
        updated_at: now,
    }
}

fn session(now: OffsetDateTime, expires_at: OffsetDateTime) -> Session {
    Session {
        id: "session_1".to_owned(),
        user_id: "user_1".to_owned(),
        expires_at,
        token: "token_1".to_owned(),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
    }
}

fn user_record(user: User) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(user.id));
    record.insert("name".to_owned(), DbValue::String(user.name));
    record.insert("email".to_owned(), DbValue::String(user.email));
    record.insert(
        "email_verified".to_owned(),
        DbValue::Boolean(user.email_verified),
    );
    record.insert(
        "image".to_owned(),
        user.image.map(DbValue::String).unwrap_or(DbValue::Null),
    );
    record.insert(
        "username".to_owned(),
        user.username.map(DbValue::String).unwrap_or(DbValue::Null),
    );
    record.insert(
        "display_username".to_owned(),
        user.display_username
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(user.created_at));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(user.updated_at));
    record
}

fn session_record(session: Session) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(session.id));
    record.insert("user_id".to_owned(), DbValue::String(session.user_id));
    record.insert(
        "expires_at".to_owned(),
        DbValue::Timestamp(session.expires_at),
    );
    record.insert("token".to_owned(), DbValue::String(session.token));
    record.insert(
        "ip_address".to_owned(),
        session
            .ip_address
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "user_agent".to_owned(),
        session
            .user_agent
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "created_at".to_owned(),
        DbValue::Timestamp(session.created_at),
    );
    record.insert(
        "updated_at".to_owned(),
        DbValue::Timestamp(session.updated_at),
    );
    record
}
