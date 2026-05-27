use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::cookies::{parse_set_cookie_header, set_session_cookie, SessionCookieOptions};
use openauth_core::crypto::password::hash_password;
use openauth_core::crypto::symmetric_decrypt;
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, FindOne, MemoryAdapter, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_plugins::two_factor::{totp_code, two_factor, TwoFactorOptions};
use serde_json::Value;
use time::OffsetDateTime;

pub(super) async fn seeded_router(
) -> Result<(Arc<MemoryAdapter>, AuthRouter), Box<dyn std::error::Error>> {
    seeded_router_with_options(TwoFactorOptions::default()).await
}

pub(super) async fn seeded_router_with_options(
    two_factor_options: TwoFactorOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), Box<dyn std::error::Error>> {
    seeded_router_with_auth_options(options_with_two_factor(two_factor_options)).await
}

pub(super) async fn seeded_router_with_auth_options(
    options: OpenAuthOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user(adapter.as_ref()).await?;
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router))
}

pub(super) async fn enable_totp(
    adapter: &MemoryAdapter,
    router: &AuthRouter,
) -> Result<String, Box<dyn std::error::Error>> {
    enable_totp_in_table(adapter, router, "twoFactor").await
}

pub(super) async fn enable_totp_in_table(
    adapter: &MemoryAdapter,
    router: &AuthRouter,
    table: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let cookie = sign_in_cookie(router).await?;
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            r#"{"password":"password123"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let record = two_factor_record_in(adapter, table).await?;
    let secret = symmetric_decrypt(secret(), string_field(&record, "secret")?)?;
    let code = totp_code(&secret, 6, 30, OffsetDateTime::now_utc().unix_timestamp());
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-totp",
            &format!(r#"{{"code":"{code}"}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(cookie)
}

pub(super) fn options() -> OpenAuthOptions {
    options_with_two_factor(TwoFactorOptions::default())
}

pub(super) fn options_with_two_factor(two_factor_options: TwoFactorOptions) -> OpenAuthOptions {
    OpenAuthOptions {
        secret: Some(secret().to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        plugins: vec![two_factor(two_factor_options)],
        ..OpenAuthOptions::default()
    }
}

pub(super) async fn sign_in_cookie(
    router: &AuthRouter,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"password123"}"#,
            None,
        )?)
        .await?;
    Ok(cookie_header_from_response(&response))
}

pub(super) async fn passwordless_session_cookie(
    adapter: &MemoryAdapter,
) -> Result<String, Box<dyn std::error::Error>> {
    adapter
        .delete(
            Delete::new("account")
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned()))),
        )
        .await?;
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("session")
                .data("id", DbValue::String("session_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .data("token", DbValue::String("token_1".to_owned()))
                .data(
                    "expires_at",
                    DbValue::Timestamp(now + time::Duration::hours(1)),
                )
                .data("ip_address", DbValue::Null)
                .data("user_agent", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        "token_1",
        SessionCookieOptions::default(),
    )?;
    Ok(cookies
        .into_iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; "))
}

pub(super) async fn two_factor_challenge_cookie(
    router: &AuthRouter,
) -> Result<(String, Value), Box<dyn std::error::Error>> {
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"password123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = serde_json::from_slice(response.body())?;
    Ok((cookie_header_from_response(&response), body))
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

pub(super) fn cookie_header_from_response(response: &http::Response<Vec<u8>>) -> String {
    set_cookie_values(response)
        .iter()
        .filter_map(|value| {
            let parsed = parse_set_cookie_header(value);
            parsed
                .into_iter()
                .next()
                .map(|(name, cookie)| format!("{name}={}", cookie.value))
        })
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

pub(super) fn cookie_value_from_response(
    response: &http::Response<Vec<u8>>,
    name_suffix: &str,
) -> Option<String> {
    set_cookie_values(response).iter().find_map(|value| {
        parse_set_cookie_header(value)
            .into_iter()
            .find_map(|(name, cookie)| name.ends_with(name_suffix).then_some(cookie.value))
    })
}

pub(super) async fn two_factor_record(adapter: &MemoryAdapter) -> Result<DbRecord, OpenAuthError> {
    two_factor_record_in(adapter, "twoFactor").await
}

pub(super) async fn two_factor_record_in(
    adapter: &MemoryAdapter,
    table: &str,
) -> Result<DbRecord, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new(table)
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned()))),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing two factor record".to_owned()))
}

pub(super) async fn user_enabled(adapter: &MemoryAdapter) -> Result<bool, OpenAuthError> {
    let record = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned()))),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing user".to_owned()))?;
    Ok(matches!(
        record.get("two_factor_enabled"),
        Some(DbValue::Boolean(true))
    ))
}

pub(super) fn string_field<'a>(
    record: &'a DbRecord,
    field: &str,
) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing string field {field}"
        ))),
    }
}

pub(super) fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

async fn seed_user(adapter: &MemoryAdapter) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("username", DbValue::String("ada_user".to_owned()))
                .data("display_username", DbValue::String("Ada User".to_owned()))
                .data("two_factor_enabled", DbValue::Boolean(false))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("account")
                .data("id", DbValue::String("account_1".to_owned()))
                .data("provider_id", DbValue::String("credential".to_owned()))
                .data("account_id", DbValue::String("user_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .data("access_token", DbValue::Null)
                .data("refresh_token", DbValue::Null)
                .data("id_token", DbValue::Null)
                .data("access_token_expires_at", DbValue::Null)
                .data("refresh_token_expires_at", DbValue::Null)
                .data("scope", DbValue::Null)
                .data("password", DbValue::String(hash_password("password123")?))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}
