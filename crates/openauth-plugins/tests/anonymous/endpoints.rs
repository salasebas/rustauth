use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::{DbFieldType, DbValue};
use openauth_core::options::{AdvancedOptions, CookieCacheOptions, OpenAuthOptions};
use openauth_plugins::additional_fields::{
    additional_fields, AdditionalField, AdditionalFieldsOptions,
};
use openauth_plugins::anonymous::{anonymous, AnonymousOptions};
use serde_json::Value;

use super::helpers::{
    anonymous_user, find_bool, json_request, request, response_cookie_header, router,
    router_with_options, router_with_plugins, secret, seed_session, seed_user, session,
    set_cookie_values, signed_session_cookie, TestAdapter,
};

#[test]
fn exposes_plugin_schema_and_error_codes() {
    let plugin = anonymous(AnonymousOptions::default());

    assert_eq!(openauth_plugins::anonymous::UPSTREAM_PLUGIN_ID, "anonymous");
    assert_eq!(plugin.id, "anonymous");
    assert!(plugin
        .schema
        .iter()
        .any(|schema| matches!(schema, openauth_core::plugin::PluginSchemaContribution::Field { table, logical_name, .. } if table == "user" && logical_name == "is_anonymous")));
    assert!(plugin
        .error_codes
        .iter()
        .any(|code| code.code == "INVALID_EMAIL_FORMAT"));
}

#[tokio::test]
async fn sign_in_anonymous_creates_user_session_and_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter.clone(), anonymous(AnonymousOptions::default()))?;

    let response = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert_eq!(body["user"]["name"], "Anonymous");
    assert_eq!(body["user"]["is_anonymous"], true);
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    let users = adapter.records("user").await;
    assert_eq!(find_bool(&users[0], "is_anonymous"), Some(true));
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("better-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn sign_in_anonymous_sets_cookie_cache_when_enabled() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![anonymous(AnonymousOptions::default())],
            secret: Some(secret().to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            session: openauth_core::options::SessionOptions {
                cookie_cache: CookieCacheOptions {
                    enabled: true,
                    ..CookieCacheOptions::default()
                },
                ..openauth_core::options::SessionOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;

    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("better-auth.session_data=")));
    Ok(())
}

#[tokio::test]
async fn get_session_after_anonymous_sign_in_returns_is_anonymous(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, anonymous(AnonymousOptions::default()))?;

    let sign_in = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let cookie = response_cookie_header(&sign_in);

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["is_anonymous"], true);
    Ok(())
}

#[tokio::test]
async fn custom_field_name_stores_physical_and_returns_logical(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter.clone(),
        anonymous(AnonymousOptions::default().field_name("is_anon")),
    )?;

    let sign_in = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let sign_in_body: Value = serde_json::from_slice(sign_in.body())?;
    let cookie = response_cookie_header(&sign_in);
    let users = adapter.records("user").await;

    assert_eq!(find_bool(&users[0], "is_anon"), Some(true));
    assert_eq!(find_bool(&users[0], "is_anonymous"), None);
    assert_eq!(sign_in_body["user"]["is_anonymous"], true);

    let session = router
        .handle_async(request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;
    let session_body: Value = serde_json::from_slice(session.body())?;
    assert_eq!(session_body["user"]["is_anonymous"], true);
    Ok(())
}

#[tokio::test]
async fn anonymous_sign_in_applies_additional_field_defaults(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router_with_plugins(
        adapter.clone(),
        vec![
            anonymous(AnonymousOptions::default().field_name("is_anon")),
            additional_fields(
                AdditionalFieldsOptions::new()
                    .user_field(
                        "role",
                        AdditionalField::new(DbFieldType::String)
                            .default_value(DbValue::String("guest".to_owned()))
                            .generated()
                            .db_name("user_role"),
                    )
                    .session_field(
                        "theme",
                        AdditionalField::new(DbFieldType::String)
                            .default_value(DbValue::String("dark".to_owned()))
                            .generated()
                            .db_name("session_theme"),
                    ),
            ),
        ],
    )?;

    let sign_in = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let cookie = response_cookie_header(&sign_in);
    let users = adapter.records("user").await;
    let sessions = adapter.records("session").await;

    assert_eq!(find_bool(&users[0], "is_anon"), Some(true));
    assert_eq!(
        users[0].get("user_role"),
        Some(&DbValue::String("guest".to_owned()))
    );
    assert_eq!(
        sessions[0].get("session_theme"),
        Some(&DbValue::String("dark".to_owned()))
    );

    let session = router
        .handle_async(request(
            Method::GET,
            "/api/auth/get-session",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(session.body())?;
    assert_eq!(body["user"]["is_anonymous"], true);
    assert_eq!(body["user"]["role"], "guest");
    assert_eq!(body["session"]["theme"], "dark");
    Ok(())
}

#[tokio::test]
async fn regular_user_returns_is_anonymous_false_when_plugin_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, anonymous(AnonymousOptions::default()))?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            serde_json::json!({
                "name": "Real User",
                "email": "real@example.test",
                "password": "password123"
            }),
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["is_anonymous"], false);
    Ok(())
}

#[tokio::test]
async fn sign_in_anonymous_uses_email_domain_name() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        anonymous(AnonymousOptions::default().email_domain_name("example.test")),
    )?;

    let response = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert!(body["user"]["email"]
        .as_str()
        .is_some_and(|email| email.starts_with("temp-") && email.ends_with("@example.test")));
    Ok(())
}

#[tokio::test]
async fn sign_in_anonymous_uses_custom_email_and_name() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        anonymous(
            AnonymousOptions::default()
                .generate_random_email(|| "guest@example.test".to_owned())
                .generate_name(|| "Guest User".to_owned()),
        ),
    )?;

    let response = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["user"]["email"], "guest@example.test");
    assert_eq!(body["user"]["name"], "Guest User");
    Ok(())
}

#[tokio::test]
async fn sign_in_anonymous_supports_async_email_and_name_callbacks(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        anonymous(
            AnonymousOptions::default()
                .generate_random_email_async(|| async { "async@example.test".to_owned() })
                .generate_name_async(|| async { "Async Guest".to_owned() }),
        ),
    )?;

    let response = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["user"]["email"], "async@example.test");
    assert_eq!(body["user"]["name"], "Async Guest");
    Ok(())
}

#[tokio::test]
async fn sign_in_anonymous_rejects_invalid_custom_email() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        anonymous(AnonymousOptions::default().generate_random_email(|| "not-an-email".to_owned())),
    )?;

    let response = router
        .handle_async(request(Method::POST, "/api/auth/sign-in/anonymous", None)?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_EMAIL_FORMAT");
    Ok(())
}

#[tokio::test]
async fn sign_in_anonymous_rejects_existing_anonymous_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let user = anonymous_user("anon_user", true);
    seed_user(&adapter, user).await?;
    seed_session(&adapter, session("session_1", "anon_user", "token_1")).await?;
    let router = router(adapter, anonymous(AnonymousOptions::default()))?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/sign-in/anonymous",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body["code"],
        "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"
    );
    Ok(())
}

#[tokio::test]
async fn delete_anonymous_user_deletes_user_and_expires_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    seed_user(&adapter, anonymous_user("anon_user", true)).await?;
    seed_session(&adapter, session("session_1", "anon_user", "token_1")).await?;
    let router = router(adapter.clone(), anonymous(AnonymousOptions::default()))?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/delete-anonymous-user",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(adapter.len("user").await, 0);
    assert_eq!(adapter.len("session").await, 0);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("better-auth.session_token=; Max-Age=0")));
    Ok(())
}

#[tokio::test]
async fn delete_anonymous_user_rejects_non_anonymous_user() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    seed_user(&adapter, anonymous_user("real_user", false)).await?;
    seed_session(&adapter, session("session_1", "real_user", "token_1")).await?;
    let router = router(adapter, anonymous(AnonymousOptions::default()))?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/delete-anonymous-user",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn delete_anonymous_user_respects_disabled_option() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    seed_user(&adapter, anonymous_user("anon_user", true)).await?;
    seed_session(&adapter, session("session_1", "anon_user", "token_1")).await?;
    let router = router(
        adapter,
        anonymous(AnonymousOptions::default().disable_delete_anonymous_user(true)),
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/delete-anonymous-user",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}
