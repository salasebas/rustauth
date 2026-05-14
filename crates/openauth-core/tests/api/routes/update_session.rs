use std::collections::BTreeMap;

use openauth_core::db::DbFieldType;
use openauth_core::options::{SessionAdditionalField, SessionOptions};

use super::*;

#[tokio::test]
async fn update_session_route_updates_allowed_custom_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    let mut record = session_record(session(now, now + Duration::hours(1)));
    record.insert("theme".to_owned(), DbValue::String("light".to_owned()));
    adapter.create(create_query("session", record)).await?;
    let router = router_with_options(adapter.clone(), session_field_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{"theme":"dark"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["session"]["theme"], "dark");
    let updated = record_by_string(&adapter, "session", "token", "token_1")
        .await?
        .ok_or("missing session")?;
    assert_eq!(
        updated.get("theme"),
        Some(&DbValue::String("dark".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn update_session_route_exposes_updated_fields_on_get_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    let mut record = session_record(session(now, now + Duration::hours(1)));
    record.insert("theme".to_owned(), DbValue::String("light".to_owned()));
    adapter.create(create_query("session", record)).await?;
    let router = router_with_options(adapter, session_field_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{"theme":"dark"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

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
    assert_eq!(body["session"]["theme"], "dark");
    Ok(())
}

#[tokio::test]
async fn update_session_route_rejects_core_only_updates() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter.clone(), session_field_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{"token":"malicious-token"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "NO_FIELDS_TO_UPDATE");
    assert!(contains_record_string(&adapter, "session", "token", "token_1").await?);
    Ok(())
}

#[tokio::test]
async fn update_session_route_rejects_non_input_fields() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let mut options = session_field_options();
    options.session.additional_fields.insert(
        "internal_note".to_owned(),
        SessionAdditionalField::new(DbFieldType::String).generated(),
    );
    let router = router_with_options(adapter, options)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{"internal_note":"blocked"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

#[tokio::test]
async fn update_session_route_rejects_invalid_field_type() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(adapter, session_field_options())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{"theme":123}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

#[tokio::test]
async fn sign_up_email_route_applies_additional_session_field_defaults(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let mut options = session_field_options();
    options.session.additional_fields.insert(
        "mode".to_owned(),
        SessionAdditionalField::new(DbFieldType::String)
            .default_value(DbValue::String("standard".to_owned())),
    );
    let router = router_with_options(adapter, options)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = cookie_header_from_response(&response)?;

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
    assert_eq!(body["session"]["mode"], "standard");
    Ok(())
}

fn session_field_options() -> OpenAuthOptions {
    OpenAuthOptions {
        session: SessionOptions {
            additional_fields: BTreeMap::from([(
                "theme".to_owned(),
                SessionAdditionalField::new(DbFieldType::String),
            )]),
            ..SessionOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}

fn cookie_header_from_response(
    response: &http::Response<Vec<u8>>,
) -> Result<String, OpenAuthError> {
    let cookies = set_cookie_values(response);
    Ok(cookies
        .iter()
        .filter_map(|cookie| cookie.split_once(';').map(|(value, _)| value.to_owned()))
        .collect::<Vec<_>>()
        .join("; "))
}
