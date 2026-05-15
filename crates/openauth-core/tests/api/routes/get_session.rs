use super::*;
use std::collections::BTreeMap;

use openauth_core::cookies::{set_cookie_cache, CookieCachePayload};
use openauth_core::db::DbFieldType;
use openauth_core::options::{
    CookieCacheOptions, SessionOptions, UserAdditionalField, UserOptions,
};

#[tokio::test]
async fn get_session_route_returns_session_from_signed_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["session"]["token"], "token_1");
    assert_eq!(body["user"]["id"], "user_1");
    Ok(())
}

#[tokio::test]
async fn get_session_route_returns_additional_user_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut record = user_record(user(now));
    record.insert("role".to_owned(), DbValue::String("admin".to_owned()));
    adapter.create(create_query("user", record)).await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter, user_field_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["role"], "admin");
    Ok(())
}

#[tokio::test]
async fn get_session_route_disable_refresh_skips_refresh_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            session: SessionOptions {
                expires_in: Some(60 * 60 * 24),
                ..SessionOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session?disableRefresh=true",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookie_values(&response)
        .iter()
        .all(|value| !value.starts_with("better-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn get_session_route_disable_cookie_cache_forces_database_read(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let db_user = user(now);
    let mut cached_user = db_user.clone();
    cached_user.name = "Cached".to_owned();
    let active_session = session(now, now + Duration::hours(1));
    adapter.insert_user(db_user).await;
    adapter.insert_session(active_session.clone()).await;

    let options = OpenAuthOptions {
        session: SessionOptions {
            cookie_cache: CookieCacheOptions {
                enabled: true,
                max_age: Some(300),
                ..CookieCacheOptions::default()
            },
            ..SessionOptions::default()
        },
        ..OpenAuthOptions::default()
    };
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..options.clone()
    })?;
    let cache_cookies = set_cookie_cache(
        &context.auth_cookies,
        &context.secret,
        &CookieCachePayload {
            session: active_session,
            user: cached_user,
            updated_at: now.unix_timestamp(),
            version: "1".to_owned(),
        },
        context.options.session.cookie_cache.strategy,
        300,
    )?;
    let cookie = format!(
        "{}; {}",
        signed_session_cookie("token_1")?,
        cookie_header(&cache_cookies)
    );
    let router = router_with_options(adapter, options)?;

    let cached_response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    let cached_body: Value = serde_json::from_slice(cached_response.body())?;
    assert_eq!(cached_body["user"]["name"], "Cached");

    let db_response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session?disableCookieCache=true",
            "",
            Some(&cookie),
        )?)
        .await?;
    let db_body: Value = serde_json::from_slice(db_response.body())?;
    assert_eq!(db_body["user"]["name"], "Ada");
    Ok(())
}

fn user_field_options() -> OpenAuthOptions {
    OpenAuthOptions {
        user: UserOptions {
            additional_fields: BTreeMap::from([(
                "role".to_owned(),
                UserAdditionalField::new(DbFieldType::String),
            )]),
            ..UserOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}
