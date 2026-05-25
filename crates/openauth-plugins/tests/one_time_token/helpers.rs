use std::sync::Arc;

use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::crypto::password::hash_password;
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, FindOne, MemoryAdapter, Session, User, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use time::{Duration, OffsetDateTime};

pub(super) type TestAdapter = MemoryAdapter;

pub(super) fn router_with_plugin(
    plugin: openauth_core::plugin::AuthPlugin,
) -> Result<(Arc<TestAdapter>, AuthRouter), OpenAuthError> {
    router_with_plugin_and_options(plugin, OpenAuthOptions::default())
}

pub(super) fn router_with_plugin_and_options(
    plugin: openauth_core::plugin::AuthPlugin,
    options: OpenAuthOptions,
) -> Result<(Arc<TestAdapter>, AuthRouter), OpenAuthError> {
    let adapter = Arc::new(TestAdapter::default());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(secret().to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![plugin],
            ..options
        },
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router))
}

pub(super) fn signed_session_cookie_with_options(
    token: &str,
    options: OpenAuthOptions,
) -> Result<String, OpenAuthError> {
    let context = openauth_core::context::create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..options
    })?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

pub(super) fn request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub(super) fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub(super) async fn seed_authenticated_session(
    adapter: &TestAdapter,
    expires_at: OffsetDateTime,
) -> Result<String, Box<dyn std::error::Error>> {
    seed_user_and_session(adapter, expires_at).await?;
    Ok(signed_session_cookie("session-token")?)
}

pub(super) async fn seed_user_and_session(
    adapter: &TestAdapter,
    expires_at: OffsetDateTime,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(create_query("user", user_record(user(now))))
        .await?;
    adapter
        .create(create_query(
            "session",
            session_record(session(now, expires_at)),
        ))
        .await?;
    Ok(())
}

pub(super) async fn seed_user_and_credential_account(
    adapter: &TestAdapter,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(create_query("user", user_record(user(now))))
        .await?;
    adapter
        .create(create_query(
            "account",
            credential_account_record("user_1", &hash_password("secret123")?, now),
        ))
        .await?;
    Ok(())
}

pub(super) async fn seed_verification(
    adapter: &TestAdapter,
    identifier: &str,
    value: &str,
    expires_at: OffsetDateTime,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(identifier.to_owned()));
    record.insert(
        "identifier".to_owned(),
        DbValue::String(identifier.to_owned()),
    );
    record.insert("value".to_owned(), DbValue::String(value.to_owned()));
    record.insert("expires_at".to_owned(), DbValue::Timestamp(expires_at));
    record.insert("created_at".to_owned(), DbValue::Timestamp(now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(now));
    adapter.create(create_query("verification", record)).await?;
    Ok(())
}

pub(super) async fn verification_record(
    adapter: &TestAdapter,
    identifier: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(FindOne::new("verification").where_clause(Where::new(
            "identifier",
            DbValue::String(identifier.to_owned()),
        )))
        .await
}

pub(super) fn default_session_expires_at() -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::days(7)
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
        token: "session-token".to_owned(),
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
    record.insert("ip_address".to_owned(), DbValue::Null);
    record.insert("user_agent".to_owned(), DbValue::Null);
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

fn credential_account_record(user_id: &str, password_hash: &str, now: OffsetDateTime) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String("account_1".to_owned()));
    record.insert(
        "provider_id".to_owned(),
        DbValue::String("credential".to_owned()),
    );
    record.insert("account_id".to_owned(), DbValue::String(user_id.to_owned()));
    record.insert("user_id".to_owned(), DbValue::String(user_id.to_owned()));
    record.insert("access_token".to_owned(), DbValue::Null);
    record.insert("refresh_token".to_owned(), DbValue::Null);
    record.insert("id_token".to_owned(), DbValue::Null);
    record.insert("access_token_expires_at".to_owned(), DbValue::Null);
    record.insert("refresh_token_expires_at".to_owned(), DbValue::Null);
    record.insert("scope".to_owned(), DbValue::Null);
    record.insert(
        "password".to_owned(),
        DbValue::String(password_hash.to_owned()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(now));
    record
}

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
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

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}
