use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{get_cookies, set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, FindOne, MemoryAdapter, Session, User, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_plugins::mcp::{mcp, McpOptions};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

pub async fn router() -> Result<AuthRouter, OpenAuthError> {
    let (router, _) = seeded_router().await?;
    Ok(router)
}

pub async fn seeded_router() -> Result<(AuthRouter, Arc<MemoryAdapter>), OpenAuthError> {
    let adapter = Arc::new(MemoryAdapter::new());
    let now = OffsetDateTime::now_utc();
    seed_user(&adapter, now).await?;
    seed_session(&adapter, now).await?;
    let plugin = mcp(McpOptions {
        login_page: "/login".to_owned(),
        ..McpOptions::default()
    })
    .map_err(|error| OpenAuthError::InvalidConfig(error.to_string()))?
    .into_auth_plugin();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            base_path: Some("/api/auth".to_owned()),
            secret: Some(secret().to_owned()),
            plugins: vec![plugin],
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((router, adapter))
}

pub fn request(method: Method, path: &str, body: &str) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .body(body.as_bytes().to_vec())
}

pub fn json_request(
    method: Method,
    path: &str,
    body: Value,
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body).unwrap_or_default())
}

pub fn form_request(
    method: Method,
    path: &str,
    body: &str,
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
}

pub fn json_body(response: &http::Response<Vec<u8>>) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(response.body())
}

pub fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let auth_cookies = get_cookies(&OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let cookies = set_session_cookie(
        &auth_cookies,
        secret(),
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub async fn seed_client(
    adapter: &MemoryAdapter,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    client_type: &str,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    let mut record = DbRecord::new();
    record.insert("name".to_owned(), DbValue::String("Client".to_owned()));
    record.insert("icon".to_owned(), DbValue::Null);
    record.insert("metadata".to_owned(), DbValue::Null);
    record.insert("clientId".to_owned(), DbValue::String(client_id.to_owned()));
    record.insert(
        "clientSecret".to_owned(),
        DbValue::String(client_secret.to_owned()),
    );
    record.insert(
        "redirectUrls".to_owned(),
        DbValue::String(redirect_uri.to_owned()),
    );
    record.insert("type".to_owned(), DbValue::String(client_type.to_owned()));
    record.insert(
        "authenticationScheme".to_owned(),
        DbValue::String("client_secret_basic".to_owned()),
    );
    record.insert("disabled".to_owned(), DbValue::Boolean(false));
    record.insert("userId".to_owned(), DbValue::Null);
    record.insert("createdAt".to_owned(), DbValue::Timestamp(now));
    record.insert("updatedAt".to_owned(), DbValue::Timestamp(now));
    adapter
        .create(create_query("oauthApplication", record))
        .await?;
    Ok(())
}

pub async fn seed_code(
    adapter: &MemoryAdapter,
    client_id: &str,
    user_id: &str,
    redirect_uri: &str,
    scope: &str,
    code_challenge: Option<&str>,
    code_challenge_method: Option<&str>,
) -> Result<String, OpenAuthError> {
    let code = format!("code_{}", adapter.len("verification").await + 1);
    let value = json!({
        "clientId": client_id,
        "redirectURI": redirect_uri,
        "scope": scope.split_whitespace().collect::<Vec<_>>(),
        "userId": user_id,
        "authTime": OffsetDateTime::now_utc().unix_timestamp(),
        "state": null,
        "codeChallenge": code_challenge,
        "codeChallengeMethod": code_challenge_method,
        "nonce": null
    });
    let now = OffsetDateTime::now_utc();
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(format!("verification_{code}")),
    );
    record.insert("identifier".to_owned(), DbValue::String(code.clone()));
    record.insert("value".to_owned(), DbValue::String(value.to_string()));
    record.insert(
        "expires_at".to_owned(),
        DbValue::Timestamp(now + Duration::minutes(10)),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(now));
    adapter.create(create_query("verification", record)).await?;
    Ok(code)
}

pub async fn seed_access_token(
    adapter: &MemoryAdapter,
    access_token: &str,
    refresh_token: &str,
    client_id: &str,
    user_id: &str,
    scopes: &str,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    let mut record = DbRecord::new();
    record.insert(
        "accessToken".to_owned(),
        DbValue::String(access_token.to_owned()),
    );
    record.insert(
        "refreshToken".to_owned(),
        DbValue::String(refresh_token.to_owned()),
    );
    record.insert(
        "accessTokenExpiresAt".to_owned(),
        DbValue::Timestamp(now + Duration::hours(1)),
    );
    record.insert(
        "refreshTokenExpiresAt".to_owned(),
        DbValue::Timestamp(now + Duration::days(7)),
    );
    record.insert("clientId".to_owned(), DbValue::String(client_id.to_owned()));
    record.insert("userId".to_owned(), DbValue::String(user_id.to_owned()));
    record.insert("scopes".to_owned(), DbValue::String(scopes.to_owned()));
    record.insert("createdAt".to_owned(), DbValue::Timestamp(now));
    record.insert("updatedAt".to_owned(), DbValue::Timestamp(now));
    adapter
        .create(create_query("oauthAccessToken", record))
        .await?;
    Ok(())
}

pub async fn find_record(
    adapter: &MemoryAdapter,
    model: &str,
    field: &str,
    value: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned()))),
        )
        .await
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn seed_user(adapter: &MemoryAdapter, now: OffsetDateTime) -> Result<(), OpenAuthError> {
    let user = User {
        id: "user_1".to_owned(),
        name: "Ada Lovelace".to_owned(),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        image: None,
        username: None,
        display_username: None,
        created_at: now,
        updated_at: now,
    };
    adapter
        .create(create_query("user", user_record(user)))
        .await?;
    Ok(())
}

async fn seed_session(adapter: &MemoryAdapter, now: OffsetDateTime) -> Result<(), OpenAuthError> {
    let session = Session {
        id: "session_1".to_owned(),
        user_id: "user_1".to_owned(),
        expires_at: now + Duration::days(1),
        token: "session_token_1".to_owned(),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
    };
    adapter
        .create(create_query("session", session_record(session)))
        .await?;
    Ok(())
}

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
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
