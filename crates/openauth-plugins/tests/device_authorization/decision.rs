use super::*;

#[tokio::test]
async fn approve_route_marks_pending_device_code_as_approved(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter.clone(), DeviceAuthorizationOptions::default())?;
    let code = create_device_code(&router, "test-client", None).await?;
    let (user_id, cookie) = create_user_session(&adapter).await?;

    let response = decide(
        &router,
        "/api/auth/device/approve",
        string_field(&code, "user_code"),
        Some(&cookie),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let record = device_record(&adapter)
        .await
        .ok_or("missing device record")?;
    assert_eq!(
        record.get("status"),
        Some(&DbValue::String("approved".to_owned()))
    );
    assert_eq!(record.get("userId"), Some(&DbValue::String(user_id)));
    Ok(())
}

#[tokio::test]
async fn deny_route_marks_pending_device_code_as_denied() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter.clone(), DeviceAuthorizationOptions::default())?;
    let code = create_device_code(&router, "test-client", None).await?;
    let (user_id, cookie) = create_user_session(&adapter).await?;

    let response = decide(
        &router,
        "/api/auth/device/deny",
        string_field(&code, "user_code"),
        Some(&cookie),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let record = device_record(&adapter)
        .await
        .ok_or("missing device record")?;
    assert_eq!(
        record.get("status"),
        Some(&DbValue::String("denied".to_owned()))
    );
    assert_eq!(record.get("userId"), Some(&DbValue::String(user_id)));
    Ok(())
}

#[tokio::test]
async fn approve_and_deny_require_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, DeviceAuthorizationOptions::default())?;
    let code = create_device_code(&router, "test-client", None).await?;

    for path in ["/api/auth/device/approve", "/api/auth/device/deny"] {
        let response = decide(&router, path, string_field(&code, "user_code"), None).await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: Value = serde_json::from_slice(response.body())?;
        assert_eq!(body["error"], "unauthorized");
        assert_eq!(body["error_description"], "Authentication required");
    }
    Ok(())
}

#[tokio::test]
async fn approve_route_rejects_already_processed_code() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter.clone(), DeviceAuthorizationOptions::default())?;
    let code = create_device_code(&router, "test-client", None).await?;
    let (_user_id, cookie) = create_user_session(&adapter).await?;
    let user_code = string_field(&code, "user_code");
    let first = decide(
        &router,
        "/api/auth/device/approve",
        user_code,
        Some(&cookie),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = decide(
        &router,
        "/api/auth/device/approve",
        user_code,
        Some(&cookie),
    )
    .await?;

    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(second.body())?;
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Device code already processed");
    Ok(())
}

#[tokio::test]
async fn approve_route_accepts_user_code_with_dashes_removed(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter.clone(),
        DeviceAuthorizationOptions::new().generate_user_code(|| "ABC12345".to_owned()),
    )?;
    create_device_code(&router, "test-client", None).await?;
    let (_user_id, cookie) = create_user_session(&adapter).await?;

    let response = decide(
        &router,
        "/api/auth/device/approve",
        "ABC-12345",
        Some(&cookie),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

async fn decide(
    router: &AuthRouter,
    path: &str,
    user_code: &str,
    cookie: Option<&str>,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(router
        .handle_async(json_request(
            Method::POST,
            path,
            &format!(r#"{{"userCode":"{user_code}"}}"#),
            cookie,
        )?)
        .await?)
}
