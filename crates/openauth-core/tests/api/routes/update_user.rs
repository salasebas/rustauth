use super::*;
use std::collections::BTreeMap;

use openauth_core::cookies::{get_cookie_cache, set_cookie_cache, CookieCachePayload};
use openauth_core::db::{DbField, DbFieldType};
use openauth_core::options::{
    CookieCacheOptions, SessionOptions, UserAdditionalField, UserOptions,
};
use openauth_core::plugin::{AuthPlugin, PluginSchemaContribution};

#[tokio::test]
async fn update_user_route_updates_name_and_image() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;
    let before_update = OffsetDateTime::now_utc();

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"name":"Grace","image":"https://example.com/grace.png"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    let updated = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        updated.get("name"),
        Some(&DbValue::String("Grace".to_owned()))
    );
    assert_eq!(
        updated.get("image"),
        Some(&DbValue::String("https://example.com/grace.png".to_owned()))
    );
    let refreshed_session = record_by_string(&adapter, "session", "token", "token_1")
        .await?
        .ok_or("missing refreshed session")?;
    assert!(
        matches!(refreshed_session.get("updated_at"), Some(DbValue::Timestamp(updated_at)) if *updated_at >= before_update)
    );
    Ok(())
}

#[tokio::test]
async fn update_user_route_refreshes_cookie_cache_with_updated_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let db_user = user(now);
    let active_session = session(now, now + Duration::hours(1));
    adapter.insert_user(db_user.clone()).await;
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
    let context = create_auth_context(super::with_test_defaults(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..options.clone()
    }))?;
    let cache_cookies = set_cookie_cache(
        &context.auth_cookies,
        &context.secret,
        &CookieCachePayload {
            session: active_session,
            user: db_user,
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
            "/api/auth/update-user",
            r#"{"name":"Grace"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookies = set_cookie_values(&response);
    let cache_cookie = set_cookies
        .iter()
        .find(|value| value.starts_with("open-auth.session_data="))
        .ok_or("missing refreshed session_data cookie")?;
    let decoded = get_cookie_cache::<Session, User>(
        cache_cookie,
        &context.auth_cookies.session_data.name,
        &context.secret,
        context.options.session.cookie_cache.strategy,
        context.options.session.cookie_cache.version.as_deref(),
    )?
    .ok_or("session_data did not decode")?;
    assert_eq!(decoded.user.name, "Grace");
    Ok(())
}

#[tokio::test]
async fn update_user_route_updates_username_fields() -> Result<(), Box<dyn std::error::Error>> {
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
            Method::POST,
            "/api/auth/update-user",
            r#"{"username":"ada_dev","displayUsername":"Ada Dev"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let updated = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        updated.get("username"),
        Some(&DbValue::String("ada_dev".to_owned()))
    );
    assert_eq!(
        updated.get("display_username"),
        Some(&DbValue::String("Ada Dev".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn update_user_route_rejects_email_updates() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router(adapter)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"email":"new@example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "EMAIL_CAN_NOT_BE_UPDATED");
    Ok(())
}

#[tokio::test]
async fn update_user_route_updates_additional_user_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut record = user_record(user(now));
    record.insert("role".to_owned(), DbValue::String("member".to_owned()));
    adapter.create(create_query("user", record)).await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter.clone(), user_field_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"role":"admin"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let updated = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        updated.get("role"),
        Some(&DbValue::String("admin".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn update_user_route_rejects_invalid_additional_user_field_type(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter, user_field_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"role":123}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

#[tokio::test]
async fn update_user_route_rejects_non_input_additional_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let mut options = user_field_options();
    options.user.additional_fields.insert(
        "internal_role".to_owned(),
        UserAdditionalField::new(DbFieldType::String).generated(),
    );
    let router = router_with_options(adapter, options)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"internal_role":"owner"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

#[tokio::test]
async fn update_user_route_rejects_generated_plugin_schema_role_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut record = user_record(user(now));
    record.insert("role".to_owned(), DbValue::String("member".to_owned()));
    adapter.create(create_query("user", record)).await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter.clone(), generated_role_plugin_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"role":"admin"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    let updated = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        updated.get("role"),
        Some(&DbValue::String("member".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn update_user_route_rejects_generated_plugin_schema_two_factor_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut record = user_record(user(now));
    record.insert("two_factor_enabled".to_owned(), DbValue::Boolean(false));
    adapter.create(create_query("user", record)).await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter.clone(), generated_two_factor_plugin_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"twoFactorEnabled":true}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    let updated = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        updated.get("two_factor_enabled"),
        Some(&DbValue::Boolean(false))
    );
    Ok(())
}

#[tokio::test]
async fn update_user_route_updates_input_enabled_plugin_schema_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter.clone(), input_plugin_user_field_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"tenantId":"tenant_1"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let updated = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        updated.get("tenant_id"),
        Some(&DbValue::String("tenant_1".to_owned()))
    );
    Ok(())
}

fn generated_role_plugin_options() -> OpenAuthOptions {
    OpenAuthOptions {
        plugins: vec![
            AuthPlugin::new("admin").with_schema(PluginSchemaContribution::field(
                "user",
                "role",
                DbField::new("role", DbFieldType::String)
                    .optional()
                    .generated(),
            )),
        ],
        ..OpenAuthOptions::default()
    }
}

fn generated_two_factor_plugin_options() -> OpenAuthOptions {
    OpenAuthOptions {
        plugins: vec![
            AuthPlugin::new("two-factor").with_schema(PluginSchemaContribution::field(
                "user",
                "two_factor_enabled",
                DbField::new("two_factor_enabled", DbFieldType::Boolean)
                    .optional()
                    .generated(),
            )),
        ],
        ..OpenAuthOptions::default()
    }
}

fn input_plugin_user_field_options() -> OpenAuthOptions {
    OpenAuthOptions {
        plugins: vec![
            AuthPlugin::new("tenant").with_schema(PluginSchemaContribution::field(
                "user",
                "tenant_id",
                DbField::new("tenant_id", DbFieldType::String).optional(),
            )),
        ],
        ..OpenAuthOptions::default()
    }
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
