use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{
    core_auth_async_endpoints, create_auth_endpoint, response, AsyncAuthEndpoint,
    AuthEndpointOptions, AuthRouter,
};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{
    AdapterFuture, Create, DbAdapter, DbRecord, DbValue, MemoryAdapter, Session, User,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::plugin::AuthPlugin;
use serde_json::json;
use time::{Duration, OffsetDateTime};

pub type TestAdapter = MemoryAdapter;
pub type UnitFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

pub trait AdapterSeed {
    fn insert_user(&self, user: User) -> UnitFuture<'_>;
    fn insert_user_record(&self, record: DbRecord) -> AdapterFuture<'_, ()>;
    fn insert_session(&self, session: Session) -> UnitFuture<'_>;
    fn insert_session_record(&self, record: DbRecord) -> AdapterFuture<'_, ()>;
}

impl AdapterSeed for TestAdapter {
    fn insert_user(&self, user: User) -> UnitFuture<'_> {
        Box::pin(async move {
            let _ = self.create(create_query("user", user_record(user))).await;
        })
    }

    fn insert_user_record(&self, record: DbRecord) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            self.create(create_query("user", record)).await?;
            Ok(())
        })
    }

    fn insert_session(&self, session: Session) -> UnitFuture<'_> {
        Box::pin(async move {
            let _ = self
                .create(create_query("session", session_record(session)))
                .await;
        })
    }

    fn insert_session_record(&self, record: DbRecord) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            self.create(create_query("session", record)).await?;
            Ok(())
        })
    }
}

pub fn router(
    adapter: Arc<TestAdapter>,
    plugin: AuthPlugin,
    options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_extra_async_endpoints(adapter, plugin, options, Vec::new())
}

pub fn router_with_extra_async_endpoints(
    adapter: Arc<TestAdapter>,
    plugin: AuthPlugin,
    options: OpenAuthOptions,
    mut extra_endpoints: Vec<AsyncAuthEndpoint>,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(secret().to_owned()),
            plugins: vec![plugin],
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..options.advanced
            },
            ..options
        },
        adapter.clone(),
    )?;
    let mut endpoints = core_auth_async_endpoints(adapter);
    endpoints.append(&mut extra_endpoints);
    AuthRouter::with_async_endpoints(context, Vec::new(), endpoints)
}

pub fn synthetic_list_device_sessions_endpoint() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/multi-session/list-device-sessions",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| {
            Box::pin(async {
                response(
                    StatusCode::OK,
                    serde_json::to_vec(&json!([
                        {
                            "session": {
                                "id": "session_1",
                                "token": "token_1",
                                "user_id": "user_1"
                            },
                            "user": {
                                "id": "user_1",
                                "name": "Ada"
                            }
                        }
                    ]))
                    .map_err(|error| OpenAuthError::Api(error.to_string()))?,
                )
            })
        },
    )
}

pub fn json_request(
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

pub fn json_request_with_header(
    method: Method,
    path: &str,
    cookie: Option<&str>,
    name: &'static str,
    value: &'static str,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(name, value);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Vec::new())
}

pub fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let context = create_auth_context(OpenAuthOptions {
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

pub fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

pub async fn seed_authenticated_session(
    adapter: &Arc<TestAdapter>,
) -> Result<String, OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    signed_session_cookie("token_1")
}

pub fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

pub fn user(now: OffsetDateTime) -> User {
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

pub fn session(now: OffsetDateTime, expires_at: OffsetDateTime) -> Session {
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

pub fn user_record(user: User) -> DbRecord {
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

pub fn session_record(session: Session) -> DbRecord {
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

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}
