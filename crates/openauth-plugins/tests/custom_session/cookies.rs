use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use super::helpers::{
    cookie_header, json_request, router, secret, session, set_cookie_values, signed_session_cookie,
    user, AdapterSeed, TestAdapter,
};
use http::Method;
use openauth_core::context::create_auth_context;
use openauth_core::cookies::{set_session_cookie, SessionCookieOptions};
use openauth_core::options::{CookieCacheOptions, OpenAuthOptions, SessionOptions};
use openauth_plugins::custom_session::custom_session;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

#[tokio::test]
async fn get_session_preserves_set_cookie_headers_individually(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let cookie = signed_session_cookie("token_1")?;
    let plugin = custom_session(|input| {
        Box::pin(async move { Ok(json!({ "user": input.user, "session": input.session })) })
    });
    let router = router(
        adapter,
        plugin,
        OpenAuthOptions {
            session: SessionOptions {
                cookie_cache: CookieCacheOptions {
                    enabled: true,
                    max_age: Some(300),
                    ..CookieCacheOptions::default()
                },
                ..SessionOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;

    let set_cookies = set_cookie_values(&response);
    assert!(set_cookies.len() >= 2);
    assert!(set_cookies
        .iter()
        .any(|value| value.starts_with("better-auth.session_token=")));
    assert!(set_cookies
        .iter()
        .any(|value| value.starts_with("better-auth.session_data=")));
    assert!(set_cookies
        .iter()
        .filter(|value| value.starts_with("better-auth."))
        .all(|value| value.matches("better-auth.").count() == 1));
    Ok(())
}

#[tokio::test]
async fn get_session_refresh_cookies_keep_individual_max_age_and_partitioned(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let plugin = custom_session(|input| {
        Box::pin(async move { Ok(json!({ "user": input.user, "session": input.session })) })
    });
    let options = OpenAuthOptions {
        session: SessionOptions {
            expires_in: Some(60 * 60 * 24),
            update_age: Some(0),
            cookie_cache: CookieCacheOptions {
                enabled: true,
                max_age: Some(300),
                ..CookieCacheOptions::default()
            },
            ..SessionOptions::default()
        },
        advanced: openauth_core::options::AdvancedOptions {
            default_cookie_attributes: openauth_core::options::CookieAttributesOverride {
                secure: Some(true),
                same_site: Some("none".to_owned()),
                partitioned: Some(true),
                ..Default::default()
            },
            ..Default::default()
        },
        ..OpenAuthOptions::default()
    };
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..options.clone()
    })?;
    let cookie = cookie_header(&set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        "token_1",
        SessionCookieOptions::default(),
    )?);
    let router = router(adapter, plugin, options)?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;
    let set_cookies = set_cookie_values(&response);
    let session_cookie = set_cookies
        .iter()
        .find(|value| value.contains("session_token="))
        .ok_or("missing refreshed session cookie")?;
    let cache_cookie = set_cookies
        .iter()
        .find(|value| value.contains("session_data="))
        .ok_or("missing session data cookie")?;

    assert!(session_cookie.contains("Max-Age=86400") || session_cookie.contains("Max-Age=86399"));
    assert!(cache_cookie.contains("Max-Age=300"));
    assert!(session_cookie.contains("Partitioned"));
    assert!(cache_cookie.contains("Partitioned"));
    Ok(())
}

#[tokio::test]
async fn get_session_does_not_double_encode_session_token_after_refresh(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let cookie = signed_session_cookie("token_1")?;
    let plugin = custom_session(|input| {
        Box::pin(async move { Ok(json!({ "user": input.user, "session": input.session })) })
    });
    let router = router(adapter, plugin, OpenAuthOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;

    let original_value = cookie
        .strip_prefix("better-auth.session_token=")
        .ok_or("unexpected session cookie name")?;
    let refreshed = set_cookie_values(&response)
        .into_iter()
        .find(|value| value.starts_with("better-auth.session_token="))
        .ok_or("missing refreshed session cookie")?;
    let refreshed_value = refreshed
        .trim_start_matches("better-auth.session_token=")
        .split(';')
        .next()
        .ok_or("missing refreshed value")?;
    assert_eq!(refreshed_value, original_value);
    assert!(!refreshed_value.contains("%25"));
    Ok(())
}

#[tokio::test]
async fn get_session_null_preserves_delete_set_cookie_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let cookie = signed_session_cookie("missing_token")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_handler = Arc::clone(&calls);
    let plugin = custom_session(move |_input| {
        let calls = Arc::clone(&calls_for_handler);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "unexpected": true }))
        })
    });
    let router = router(adapter, plugin, OpenAuthOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body.is_null());
    let set_cookies = set_cookie_values(&response);
    assert!(set_cookies.iter().any(
        |value| value.starts_with("better-auth.session_token=;") && value.contains("Max-Age=0")
    ));
    assert!(set_cookies.iter().any(
        |value| value.starts_with("better-auth.session_data=;") && value.contains("Max-Age=0")
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
