use time::Duration;

use super::*;

use rustauth_core::cookies::{set_cookie_cache, CookieCachePayload};
use rustauth_core::crypto::password::{hash_password, verify_password};
use rustauth_core::db::DbFieldType;
use rustauth_core::options::{
    CookieCacheOptions, SessionOptions, UserAdditionalField, UserOptions,
};
use std::collections::BTreeMap;

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
    let router = router_with_real_password(adapter.clone())?;
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
    assert!(!verify_password(hash, "secret123")?);
    assert!(verify_password(hash, "new-secret123")?);
    Ok(())
}

#[tokio::test]
async fn change_password_route_returns_additional_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut record = user_record(user(now));
    record.insert("role".to_owned(), DbValue::String("admin".to_owned()));
    adapter.create(create_query("user", record)).await?;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &fast_hash_password("secret123")?,
            now,
        ))
        .await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter, change_password_user_field_options())?;
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
    assert_eq!(body["user"]["role"], "admin");
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
            &fast_hash_password("secret123")?,
            now,
        ))
        .await?;
    let options = RustAuthOptions {
        session: SessionOptions {
            cookie_cache: CookieCacheOptions {
                enabled: true,
                max_age: Some(time::Duration::seconds(300)),
                ..CookieCacheOptions::default()
            },
            ..SessionOptions::default()
        },
        ..RustAuthOptions::default()
    };
    let context = create_auth_context(super::with_test_defaults(RustAuthOptions {
        secret: Some(secret().to_owned()),
        ..options.clone()
    }))?;
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

fn change_password_user_field_options() -> RustAuthOptions {
    RustAuthOptions {
        user: UserOptions {
            additional_fields: BTreeMap::from([(
                "role".to_owned(),
                UserAdditionalField::new(DbFieldType::String),
            )]),
            ..UserOptions::default()
        },
        ..RustAuthOptions::default()
    }
}

#[tokio::test]
async fn change_password_revoke_preserves_non_remembered_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &fast_hash_password("secret123")?,
            now,
        ))
        .await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router(adapter.clone())?;
    let cookie = signed_dont_remember_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-password",
            r#"{"currentPassword":"secret123","newPassword":"new-secret123","revokeOtherSessions":true}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    // The reissued session cookie must remain a browser-session cookie (no
    // Max-Age) and the dont_remember marker must be re-emitted.
    let set_cookies = set_cookie_values(&response);
    let session_cookie = set_cookies
        .iter()
        .find(|value| value.starts_with("rustauth.session_token="))
        .ok_or("missing session cookie")?;
    assert!(
        !session_cookie.contains("Max-Age"),
        "non-remembered session cookie must not set Max-Age: {session_cookie}"
    );
    assert!(
        set_cookies
            .iter()
            .any(|value| value.starts_with("rustauth.dont_remember=")),
        "dont_remember marker cookie must be re-emitted"
    );

    // The replacement session must expire on the non-remembered (1 day) window,
    // not the full session lifetime.
    let body: Value = serde_json::from_slice(response.body())?;
    let token = body["token"].as_str().ok_or("missing replacement token")?;
    let replacement = record_by_string(&adapter, "session", "token", token)
        .await?
        .ok_or("missing replacement session")?;
    let DbValue::Timestamp(expires_at) =
        replacement.get("expires_at").ok_or("missing expires_at")?
    else {
        return Err("expires_at is not a timestamp".into());
    };
    let lifetime = *expires_at - now;
    assert!(
        lifetime <= Duration::hours(25) && lifetime >= Duration::hours(23),
        "replacement session must expire ~1 day out, got {lifetime}"
    );
    Ok(())
}
