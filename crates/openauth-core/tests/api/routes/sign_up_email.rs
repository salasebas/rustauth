use super::*;
use std::collections::BTreeMap;

use openauth_core::db::DbFieldType;
use openauth_core::options::{UserAdditionalField, UserOptions};

#[tokio::test]
async fn sign_up_email_route_creates_session_and_sets_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["session"].is_null());
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("better-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_accepts_username_fields() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"ada_lovelace","displayUsername":"Ada Lovelace"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["username"], "ada_lovelace");
    assert_eq!(body["user"]["display_username"], "Ada Lovelace");
    let created = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        created.get("username"),
        Some(&DbValue::String("ada_lovelace".to_owned()))
    );
    assert_eq!(
        created.get("display_username"),
        Some(&DbValue::String("Ada Lovelace".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_persists_and_returns_additional_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(adapter.clone(), user_field_options())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","role":"admin"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["role"], "admin");
    assert_eq!(body["user"]["timezone"], "UTC");
    assert!(body["user"]["nickname"].is_null());
    let record = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        record.get("role"),
        Some(&DbValue::String("admin".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_requires_additional_user_fields_without_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_options(adapter, user_field_options())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_rejects_non_input_additional_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let mut options = user_field_options();
    options.user.additional_fields.insert(
        "internal_role".to_owned(),
        UserAdditionalField::new(DbFieldType::String).generated(),
    );
    let router = router_with_options(adapter, options)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","role":"admin","internal_role":"owner"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

fn user_field_options() -> OpenAuthOptions {
    OpenAuthOptions {
        user: UserOptions {
            additional_fields: BTreeMap::from([
                (
                    "role".to_owned(),
                    UserAdditionalField::new(DbFieldType::String),
                ),
                (
                    "nickname".to_owned(),
                    UserAdditionalField::new(DbFieldType::String).optional(),
                ),
                (
                    "timezone".to_owned(),
                    UserAdditionalField::new(DbFieldType::String)
                        .default_value(DbValue::String("UTC".to_owned())),
                ),
            ]),
            ..UserOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}
