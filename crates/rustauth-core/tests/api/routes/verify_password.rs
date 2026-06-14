use super::*;
use time::Duration;

#[tokio::test]
async fn verify_password_route_rejects_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
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
    let router = router(adapter)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/verify-password",
            r#"{"password":"wrong"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_PASSWORD");
    Ok(())
}
