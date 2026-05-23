use super::*;

use openauth_core::cookies::{set_cookie_cache, CookieCachePayload};
use openauth_core::options::{CookieCacheOptions, SessionOptions};

#[tokio::test]
async fn change_password_route_updates_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-password",
            r#"{"currentPassword":"secret123","newPassword":"new-secret123"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["id"], "user_1");
    let account = record_by_string(&adapter, "account", "id", "account_1")
        .await?
        .ok_or("missing account")?;
    let hash = string_field(&account, "password")?;
    assert!(!openauth_core::crypto::password::verify_password(
        hash,
        "secret123"
    )?);
    assert!(openauth_core::crypto::password::verify_password(
        hash,
        "new-secret123"
    )?);
    Ok(())
}

#[tokio::test]
async fn change_password_route_ignores_cookie_cache_for_sensitive_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let active_session = session(now, now + Duration::hours(1));
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
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
            user: user(now),
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

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-password",
            r#"{"currentPassword":"secret123","newPassword":"new-secret123"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "UNAUTHORIZED");
    Ok(())
}
