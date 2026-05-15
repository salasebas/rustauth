use super::*;

#[tokio::test]
async fn verify_route_returns_status_for_valid_user_code() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new().generate_user_code(|| "ABC-123".to_owned()),
    )?;
    let code = create_device_code(&router, "test-client", None).await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "/api/auth/device?user_code={}",
                string_field(&code, "user_code")
            ),
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user_code"], "ABC-123");
    assert_eq!(body["status"], "pending");
    Ok(())
}

#[tokio::test]
async fn verify_route_accepts_user_code_without_dashes() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new().generate_user_code(|| "ABC12345".to_owned()),
    )?;
    create_device_code(&router, "test-client", None).await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/device?user_code=ABC-12345",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], "pending");
    Ok(())
}

#[tokio::test]
async fn verify_route_rejects_invalid_user_code() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, DeviceAuthorizationOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/device?user_code=INVALID",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Invalid user code");
    Ok(())
}
