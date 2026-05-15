use std::sync::Arc;

use http::{header, HeaderMap, HeaderValue, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, MemoryAdapter, Session, User};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::plugin::AuthPlugin;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

pub(super) type TestAdapter = MemoryAdapter;

pub(super) fn router(
    adapter: Arc<TestAdapter>,
    plugin: AuthPlugin,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_plugins(adapter, vec![plugin])
}

pub(super) fn router_with_plugins(
    adapter: Arc<TestAdapter>,
    plugins: Vec<AuthPlugin>,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(secret().to_owned()),
            plugins,
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

pub(super) struct SignUpTokens {
    pub(super) raw: String,
    pub(super) signed: String,
}

pub(super) async fn sign_up_and_tokens(
    router: &AuthRouter,
) -> Result<SignUpTokens, Box<dyn std::error::Error>> {
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
            HeaderMap::new(),
        )?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let raw = body["token"]
        .as_str()
        .ok_or("missing sign-up token")?
        .to_owned();
    let signed = auth_token_header(&response).ok_or("missing set-auth-token header")?;
    Ok(SignUpTokens { raw, signed })
}

pub(super) fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
    headers: HeaderMap,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    for (name, value) in headers {
        if let Some(name) = name {
            builder = builder.header(name, value);
        }
    }
    builder.body(body.as_bytes().to_vec())
}

pub(super) fn bearer_request(
    method: Method,
    path: &str,
    token: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer invalid")),
    );
    json_request(method, path, "", cookie, headers)
}

pub(super) fn auth_token_header(response: &http::Response<Vec<u8>>) -> Option<String> {
    response
        .headers()
        .get("set-auth-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub(super) fn exposed_auth_token_count(
    response: &http::Response<Vec<u8>>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let exposed = response
        .headers()
        .get("access-control-expose-headers")
        .ok_or("missing access-control-expose-headers")?
        .to_str()?;
    Ok(exposed
        .split(',')
        .map(str::trim)
        .filter(|header| header.eq_ignore_ascii_case("set-auth-token"))
        .count())
}

pub(super) fn assert_exposes_header(
    response: &http::Response<Vec<u8>>,
    header_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let exposed = response
        .headers()
        .get("access-control-expose-headers")
        .ok_or("missing access-control-expose-headers")?
        .to_str()?;
    assert!(exposed
        .split(',')
        .map(str::trim)
        .any(|header| header.eq_ignore_ascii_case(header_name)));
    Ok(())
}

pub(super) async fn seed_user_and_session(adapter: &TestAdapter) {
    let now = OffsetDateTime::now_utc();
    let _ = adapter
        .create(create_query("user", user_record(user(now))))
        .await;
    let _ = adapter
        .create(create_query(
            "session",
            session_record(session(now, now + Duration::hours(1))),
        ))
        .await;
}

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
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

pub(super) fn percent_encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
