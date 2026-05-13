use super::*;

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
