use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use super::helpers::{
    cookie_header, json_request, json_request_with_header, router,
    router_with_extra_async_endpoints, secret, seed_authenticated_session, session, session_record,
    set_cookie_values, signed_session_cookie, synthetic_list_device_sessions_endpoint, user,
    user_record, AdapterSeed, TestAdapter,
};
use http::{Method, StatusCode};
use openauth_core::context::create_auth_context;
use openauth_core::cookies::{set_cookie_cache, CookieCachePayload};
use openauth_core::db::{DbFieldType, DbValue};
use openauth_core::options::{
    CookieCacheOptions, OpenAuthOptions, SessionAdditionalField, SessionOptions,
    UserAdditionalField, UserOptions,
};
use openauth_plugins::custom_session::{
    custom_session, custom_session_with, CustomSessionOptions, UPSTREAM_PLUGIN_ID,
};
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

#[test]
fn exposes_custom_session_plugin_id() {
    assert_eq!(UPSTREAM_PLUGIN_ID, "custom-session");
}

#[test]
fn custom_session_registers_plugin_metadata() {
    let plugin = custom_session(|input| Box::pin(async move { Ok(input.session) }));

    assert_eq!(plugin.id, "custom-session");
    assert_eq!(plugin.version.as_deref(), Some(env!("CARGO_PKG_VERSION")));
    assert_eq!(
        plugin.options,
        Some(json!({ "shouldMutateListDeviceSessionsEndpoint": false }))
    );
    assert_eq!(plugin.hooks.async_after.len(), 1);
    assert_eq!(plugin.hooks.async_after[0].matcher.path, "/get-session");
}

#[test]
fn custom_session_options_serialize_with_upstream_camel_case() {
    let plugin = custom_session_with(
        |input, _context| Box::pin(async move { Ok(input.session) }),
        CustomSessionOptions {
            should_mutate_list_device_sessions_endpoint: true,
        },
    );

    assert_eq!(
        plugin.options,
        Some(json!({ "shouldMutateListDeviceSessionsEndpoint": true }))
    );
}

#[tokio::test]
async fn get_session_returns_custom_json_for_authenticated_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let cookie = seed_authenticated_session(&adapter).await?;
    let plugin = custom_session(|input| {
        Box::pin(async move {
            Ok(json!({
                "id": input.user["id"],
                "token": input.session["token"],
                "kind": "custom"
            }))
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

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(
        body,
        json!({ "id": "user_1", "token": "token_1", "kind": "custom" })
    );
    Ok(())
}

#[tokio::test]
async fn get_session_returns_null_when_unauthenticated() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let plugin = custom_session(|_input| Box::pin(async { Ok(json!({ "unexpected": true })) }));
    let router = router(adapter, plugin, OpenAuthOptions::default())?;

    let response = router
        .handle_async(json_request(Method::GET, "/api/auth/get-session", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body.is_null());
    Ok(())
}

#[tokio::test]
async fn custom_handler_can_return_shape_without_user_or_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let cookie = seed_authenticated_session(&adapter).await?;
    let plugin = custom_session(|_input| Box::pin(async { Ok(json!({ "ok": true })) }));
    let router = router(adapter, plugin, OpenAuthOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(
        serde_json::from_slice::<Value>(response.body())?,
        json!({ "ok": true })
    );
    Ok(())
}

#[tokio::test]
async fn callback_receives_context_and_can_read_request() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    let cookie = seed_authenticated_session(&adapter).await?;
    let plugin = custom_session_with(
        |_input, context| {
            Box::pin(async move {
                Ok(json!({
                    "path": context.request.uri().path(),
                    "marker": context
                        .request
                        .headers()
                        .get("x-custom-marker")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or(""),
                    "base_path": context.auth_context.base_path
                }))
            })
        },
        CustomSessionOptions::default(),
    );
    let router = router(adapter, plugin, OpenAuthOptions::default())?;

    let response = router
        .handle_async(json_request_with_header(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
            "x-custom-marker",
            "seen",
        )?)
        .await?;

    assert_eq!(
        serde_json::from_slice::<Value>(response.body())?,
        json!({
            "path": "/api/auth/get-session",
            "marker": "seen",
            "base_path": "/api/auth"
        })
    );
    Ok(())
}

#[tokio::test]
async fn user_preserves_additional_fields() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut record = user_record(user(now));
    record.insert("role".to_owned(), DbValue::String("admin".to_owned()));
    adapter.insert_user_record(record).await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let plugin =
        custom_session(|input| Box::pin(async move { Ok(json!({ "role": input.user["role"] })) }));
    let router = router(
        adapter,
        plugin,
        OpenAuthOptions {
            user: UserOptions {
                additional_fields: BTreeMap::from([(
                    "role".to_owned(),
                    UserAdditionalField::new(DbFieldType::String),
                )]),
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&signed_session_cookie("token_1")?),
        )?)
        .await?;

    assert_eq!(
        serde_json::from_slice::<Value>(response.body())?,
        json!({ "role": "admin" })
    );
    Ok(())
}

#[tokio::test]
async fn session_preserves_additional_fields() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    let mut record = session_record(session(now, now + Duration::hours(1)));
    record.insert("device".to_owned(), DbValue::String("laptop".to_owned()));
    adapter.insert_session_record(record).await?;
    let plugin = custom_session(|input| {
        Box::pin(async move { Ok(json!({ "device": input.session["device"] })) })
    });
    let router = router(
        adapter,
        plugin,
        OpenAuthOptions {
            session: SessionOptions {
                additional_fields: BTreeMap::from([(
                    "device".to_owned(),
                    SessionAdditionalField::new(DbFieldType::String),
                )]),
                ..SessionOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&signed_session_cookie("token_1")?),
        )?)
        .await?;

    assert_eq!(
        serde_json::from_slice::<Value>(response.body())?,
        json!({ "device": "laptop" })
    );
    Ok(())
}

#[tokio::test]
async fn custom_session_does_not_cache_custom_fields() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let cookie = seed_authenticated_session(&adapter).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_handler = Arc::clone(&calls);
    let plugin = custom_session(move |_input| {
        let calls = Arc::clone(&calls_for_handler);
        Box::pin(async move {
            let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(json!({ "count": count }))
        })
    });
    let router = router(
        adapter,
        plugin,
        OpenAuthOptions {
            session: SessionOptions {
                cookie_cache: CookieCacheOptions {
                    enabled: true,
                    ..CookieCacheOptions::default()
                },
                ..SessionOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let first = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;
    let cache_cookies = set_cookie_values(&first)
        .into_iter()
        .filter_map(|value| value.split(';').next().map(str::to_owned))
        .collect::<Vec<_>>();
    let cached_cookie = format!("{cookie}; {}", cache_cookies.join("; "));
    let second = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cached_cookie),
        )?)
        .await?;

    assert_eq!(
        serde_json::from_slice::<Value>(first.body())?,
        json!({ "count": 1 })
    );
    assert_eq!(
        serde_json::from_slice::<Value>(second.body())?,
        json!({ "count": 2 })
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn disable_refresh_returns_custom_json_without_refresh_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let cookie = signed_session_cookie("token_1")?;
    let plugin = custom_session(|input| {
        Box::pin(async move {
            Ok(json!({
                "user_id": input.user["id"],
                "token": input.session["token"]
            }))
        })
    });
    let router = router(
        adapter,
        plugin,
        OpenAuthOptions {
            session: SessionOptions {
                expires_in: Some(60 * 60 * 24),
                update_age: Some(0),
                ..SessionOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session?disableRefresh=true",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(
        serde_json::from_slice::<Value>(response.body())?,
        json!({ "user_id": "user_1", "token": "token_1" })
    );
    assert!(set_cookie_values(&response)
        .iter()
        .all(|value| !value.contains("session_token=")));
    Ok(())
}

#[tokio::test]
async fn disable_cookie_cache_makes_handler_see_database_payload(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
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
    let plugin = custom_session(|input| {
        Box::pin(async move {
            Ok(json!({
                "name": input.user["name"],
                "token": input.session["token"]
            }))
        })
    });
    let router = router(adapter, plugin, options)?;

    let cached_response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(
        serde_json::from_slice::<Value>(cached_response.body())?,
        json!({ "name": "Cached", "token": "token_1" })
    );

    let db_response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session?disableCookieCache=true",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(
        serde_json::from_slice::<Value>(db_response.body())?,
        json!({ "name": "Ada", "token": "token_1" })
    );
    Ok(())
}

#[tokio::test]
async fn list_device_sessions_is_not_mutated_by_default() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    let plugin = custom_session(|_input| Box::pin(async { Ok(json!({ "mutated": true })) }));
    let router = router_with_extra_async_endpoints(
        adapter,
        plugin,
        OpenAuthOptions::default(),
        vec![synthetic_list_device_sessions_endpoint()],
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/multi-session/list-device-sessions",
            None,
        )?)
        .await?;

    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body[0]["session"]["token"], "token_1");
    assert!(body[0].get("mutated").is_none());
    Ok(())
}

#[tokio::test]
async fn list_device_sessions_is_mutated_when_option_is_true(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let plugin = custom_session_with(
        |input, _context| Box::pin(async move { Ok(json!({ "user_id": input.user["id"] })) }),
        CustomSessionOptions {
            should_mutate_list_device_sessions_endpoint: true,
        },
    );
    let router = router_with_extra_async_endpoints(
        adapter,
        plugin,
        OpenAuthOptions::default(),
        vec![synthetic_list_device_sessions_endpoint()],
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/multi-session/list-device-sessions",
            None,
        )?)
        .await?;

    assert_eq!(
        serde_json::from_slice::<Value>(response.body())?,
        json!([{ "user_id": "user_1" }])
    );
    Ok(())
}
