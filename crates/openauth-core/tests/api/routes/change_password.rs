use super::*;

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
    let router = router(adapter.clone())?;
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
    assert!(!openauth_core::crypto::password::verify_password(
        hash,
        "secret123"
    )?);
    assert!(openauth_core::crypto::password::verify_password(
        hash,
        "new-secret123"
    )?);
    Ok(())
}
