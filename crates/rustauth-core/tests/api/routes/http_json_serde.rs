//! Pilot HTTP JSON serde and wire-format tests for plan 010.

use super::*;
use serde_json::Value;

#[tokio::test]
async fn sign_in_email_pilot_emits_camel_case_user_fields() -> Result<(), Box<dyn std::error::Error>>
{
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
    let router = router(adapter)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            include_str!("../../fixtures/http_json/sign_in_email_request.json"),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert_eq!(body["user"]["emailVerified"], true);
    assert!(body["user"]["createdAt"].as_str().is_some());
    assert!(body["user"]["updatedAt"].as_str().is_some());
    assert!(body["user"].get("email_verified").is_none());
    assert_eq!(body["redirect"], true);
    assert_eq!(body["url"], "/dashboard");
    Ok(())
}

#[tokio::test]
async fn get_session_pilot_emits_camel_case_session_and_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + time::Duration::hours(1)))
        .await;
    let router = router(adapter)?;
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
    assert!(body["session"]["createdAt"].as_str().is_some());
    assert!(body["session"]["expiresAt"].as_str().is_some());
    assert_eq!(body["user"]["id"], "user_1");
    assert_eq!(body["user"]["emailVerified"], true);
    assert!(body["session"].get("created_at").is_none());
    assert!(body["user"].get("email_verified").is_none());
    Ok(())
}
