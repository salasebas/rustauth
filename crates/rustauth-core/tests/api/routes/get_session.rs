use time::Duration;

use super::*;
use std::collections::BTreeMap;

use rustauth_core::context::request_state::set_should_skip_session_refresh;
use rustauth_core::cookies::{set_cookie_cache, CookieCachePayload};
use rustauth_core::db::{DbField, DbFieldType, DbValue};
use rustauth_core::options::{
    CookieCacheOptions, SessionOptions, UserAdditionalField, UserOptions,
};
use rustauth_core::plugin::{PluginBeforeHookAction, PluginSchemaContribution};

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
    assert!(body["session"]["createdAt"].as_str().is_some());
    assert!(body["session"]["updatedAt"].as_str().is_some());
    assert!(body["session"]["expiresAt"].as_str().is_some());
    assert!(body["user"]["createdAt"].as_str().is_some());
    assert!(body["user"]["updatedAt"].as_str().is_some());
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
        RustAuthOptions {
            session: SessionOptions {
                expires_in: Some(time::Duration::seconds(60 * 60 * 24)),
                ..SessionOptions::default()
            },
            ..RustAuthOptions::default()
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
        .all(|value| !value.starts_with("rustauth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn get_session_route_global_disable_session_refresh_skips_refresh(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(10);
    adapter.insert_user(user(now)).await;
    adapter.insert_session(session(now, expires_at)).await;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            session: SessionOptions {
                expires_in: Some(time::Duration::seconds(60 * 60)),
                update_age: Some(time::Duration::seconds(1)),
                disable_session_refresh: true,
                ..SessionOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&signed_session_cookie("token_1")?),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookie_values(&response)
        .iter()
        .all(|value| !value.starts_with("rustauth.session_token=")));
    let stored = record_by_string(&adapter, "session", "token", "token_1")
        .await?
        .ok_or("missing session")?;
    assert_eq!(
        stored.get("expires_at"),
        Some(&DbValue::Timestamp(expires_at))
    );
    Ok(())
}

#[tokio::test]
async fn get_session_route_request_state_skip_refresh_skips_refresh(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(10);
    adapter.insert_user(user(now)).await;
    adapter.insert_session(session(now, expires_at)).await;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            session: SessionOptions {
                expires_in: Some(time::Duration::seconds(60 * 60)),
                update_age: Some(time::Duration::seconds(1)),
                ..SessionOptions::default()
            },
            plugins: vec![AuthPlugin::new("skip-refresh").with_before_hook(
                "/get-session",
                |_context, request| {
                    set_should_skip_session_refresh(true)?;
                    Ok(PluginBeforeHookAction::Continue(request))
                },
            )],
            ..RustAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&signed_session_cookie("token_1")?),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookie_values(&response)
        .iter()
        .all(|value| !value.starts_with("rustauth.session_token=")));
    let stored = record_by_string(&adapter, "session", "token", "token_1")
        .await?
        .ok_or("missing session")?;
    assert_eq!(
        stored.get("expires_at"),
        Some(&DbValue::Timestamp(expires_at))
    );
    Ok(())
}

#[tokio::test]
async fn get_session_route_deferred_request_state_skip_refresh_suppresses_needs_refresh(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(10);
    adapter.insert_user(user(now)).await;
    adapter.insert_session(session(now, expires_at)).await;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            session: SessionOptions {
                expires_in: Some(time::Duration::seconds(60 * 60)),
                update_age: Some(time::Duration::seconds(1)),
                defer_session_refresh: true,
                ..SessionOptions::default()
            },
            plugins: vec![AuthPlugin::new("skip-refresh").with_before_hook(
                "/get-session",
                |_context, request| {
                    set_should_skip_session_refresh(true)?;
                    Ok(PluginBeforeHookAction::Continue(request))
                },
            )],
            ..RustAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&signed_session_cookie("token_1")?),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["needsRefresh"], false);
    let stored = record_by_string(&adapter, "session", "token", "token_1")
        .await?
        .ok_or("missing session")?;
    assert_eq!(
        stored.get("expires_at"),
        Some(&DbValue::Timestamp(expires_at))
    );
    Ok(())
}

#[tokio::test]
async fn get_session_route_post_requires_deferred_refresh() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter)?;
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/get-session",
            "",
            Some(&signed_session_cookie("token_1")?),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "METHOD_NOT_ALLOWED");
    Ok(())
}

#[tokio::test]
async fn get_session_route_defer_refresh_get_marks_needs_refresh_without_writing(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(10);
    adapter.insert_user(user(now)).await;
    adapter.insert_session(session(now, expires_at)).await;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            session: SessionOptions {
                expires_in: Some(time::Duration::seconds(60 * 60)),
                update_age: Some(time::Duration::seconds(1)),
                defer_session_refresh: true,
                ..SessionOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&signed_session_cookie("token_1")?),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["needsRefresh"], true);
    assert!(set_cookie_values(&response)
        .iter()
        .all(|value| !value.starts_with("rustauth.session_token=")));
    let stored = record_by_string(&adapter, "session", "token", "token_1")
        .await?
        .ok_or("missing session")?;
    assert_eq!(
        stored.get("expires_at"),
        Some(&DbValue::Timestamp(expires_at))
    );
    Ok(())
}

#[tokio::test]
async fn get_session_route_defer_refresh_post_refreshes_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(10);
    adapter.insert_user(user(now)).await;
    adapter.insert_session(session(now, expires_at)).await;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            session: SessionOptions {
                expires_in: Some(time::Duration::seconds(60 * 60)),
                update_age: Some(time::Duration::seconds(1)),
                defer_session_refresh: true,
                ..SessionOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/get-session",
            "",
            Some(&signed_session_cookie("token_1")?),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body.get("needsRefresh").is_none());
    assert!(set_cookie_values(&response)
        .iter()
        .any(|value| value.starts_with("rustauth.session_token=")));
    let stored = record_by_string(&adapter, "session", "token", "token_1")
        .await?
        .ok_or("missing session")?;
    let Some(DbValue::Timestamp(refreshed)) = stored.get("expires_at") else {
        return Err("missing refreshed expires_at".into());
    };
    assert!(*refreshed > expires_at);
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
    let mut active_session = session(now, now + Duration::hours(1));
    active_session.user_agent = Some("x".repeat(9000));
    adapter.insert_user(db_user).await;
    adapter.insert_session(active_session.clone()).await;

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

#[tokio::test]
async fn get_session_route_reads_chunked_cookie_cache() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let db_user = user(now);
    let mut cached_user = db_user.clone();
    cached_user.name = "Cached".to_owned();
    let mut active_session = session(now, now + Duration::hours(1));
    active_session.user_agent = Some("x".repeat(9000));
    adapter.insert_user(db_user).await;
    adapter.insert_session(active_session.clone()).await;

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
            user: cached_user,
            updated_at: now.unix_timestamp(),
            version: "1".to_owned(),
        },
        context.options.session.cookie_cache.strategy,
        300,
    )?;
    assert!(cache_cookies
        .iter()
        .any(|cookie| cookie.name == "rustauth.session_data.1"));
    let cookie = format!(
        "{}; {}",
        signed_session_cookie("token_1")?,
        cookie_header(&cache_cookies)
    );
    let router = router_with_options(adapter, options)?;

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
    assert_eq!(body["user"]["name"], "Cached");
    assert_eq!(
        body["session"]["userAgent"].as_str().map(str::len),
        Some(9000)
    );
    Ok(())
}

#[tokio::test]
async fn get_session_route_cookie_cache_requires_authoritative_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let active_session = session(now, now + Duration::hours(1));
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
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body.is_null());
    assert!(set_cookie_values(&response)
        .iter()
        .any(|value| value.starts_with("rustauth.session_token=; Max-Age=0")));
    assert!(set_cookie_values(&response)
        .iter()
        .any(|value| value.starts_with("rustauth.session_data=; Max-Age=0")));
    Ok(())
}

fn user_field_options() -> RustAuthOptions {
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
async fn get_session_route_filters_hidden_plugin_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut record = user_record(user(now));
    record.insert(
        "tenant_id".to_owned(),
        DbValue::String("tenant_1".to_owned()),
    );
    adapter.create(create_query("user", record)).await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter.clone(), hidden_plugin_user_field_options())?;
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
    assert!(body["user"].get("tenantId").is_none());
    let stored = record_by_string(&adapter, "user", "id", "user_1")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        stored.get("tenant_id"),
        Some(&DbValue::String("tenant_1".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn get_session_route_returns_plugin_user_output_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut record = user_record(user(now));
    record.insert(
        "tenant_id".to_owned(),
        DbValue::String("tenant_1".to_owned()),
    );
    adapter.create(create_query("user", record)).await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter, plugin_user_field_options())?;
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
    assert_eq!(body["user"]["tenantId"], "tenant_1");
    Ok(())
}

fn hidden_plugin_user_field_options() -> RustAuthOptions {
    RustAuthOptions {
        plugins: vec![
            AuthPlugin::new("tenant").with_schema(PluginSchemaContribution::field(
                "user",
                "tenant_id",
                DbField::new("tenant_id", DbFieldType::String)
                    .optional()
                    .hidden(),
            )),
        ],
        ..RustAuthOptions::default()
    }
}

fn plugin_user_field_options() -> RustAuthOptions {
    RustAuthOptions {
        plugins: vec![
            AuthPlugin::new("tenant").with_schema(PluginSchemaContribution::field(
                "user",
                "tenant_id",
                DbField::new("tenant_id", DbFieldType::String).optional(),
            )),
        ],
        ..RustAuthOptions::default()
    }
}
