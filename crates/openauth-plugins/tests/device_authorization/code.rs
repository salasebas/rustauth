use super::*;

use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn device_code_route_generates_codes_and_persists_record(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter.clone(),
        DeviceAuthorizationOptions::new()
            .expires_in(Duration::minutes(5))
            .interval(Duration::seconds(2)),
    )?;

    let response = create_device_code(&router, "test-client", Some("read write")).await?;

    assert!(string_field(&response, "device_code").len() >= 40);
    assert_eq!(string_field(&response, "user_code").len(), 8);
    assert_eq!(response["expires_in"], 300);
    assert_eq!(response["interval"], 2);
    assert!(string_field(&response, "verification_uri").contains("/device"));
    assert!(
        string_field(&response, "verification_uri_complete").contains(&format!(
            "user_code={}",
            string_field(&response, "user_code")
        ))
    );

    let record = device_record(&adapter)
        .await
        .ok_or("missing device record")?;
    assert_eq!(
        record.get("clientId"),
        Some(&DbValue::String("test-client".to_owned()))
    );
    assert_eq!(
        record.get("scope"),
        Some(&DbValue::String("read write".to_owned()))
    );
    assert_eq!(record.get("pollingInterval"), Some(&DbValue::Number(2000)));
    Ok(())
}

#[tokio::test]
async fn device_code_route_rejects_invalid_client() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new()
            .validate_client(|client_id| async move { Ok(client_id == "valid-client") }),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/device/code",
            r#"{"client_id":"invalid-client"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["error"], "invalid_client");
    assert_eq!(body["error_description"], "Invalid client ID");
    Ok(())
}

#[tokio::test]
async fn device_code_route_uses_custom_generators() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new()
            .generate_device_code(|| "custom-device-code".to_owned())
            .generate_user_code(|| "CUSTOM12".to_owned()),
    )?;

    let response = create_device_code(&router, "test-client", None).await?;

    assert_eq!(response["device_code"], "custom-device-code");
    assert_eq!(response["user_code"], "CUSTOM12");
    Ok(())
}

#[tokio::test]
async fn device_code_route_uses_async_custom_generators() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new()
            .generate_device_code_async(|| async { "async-device-code".to_owned() })
            .generate_user_code_async(|| async { "ASYNC123".to_owned() }),
    )?;

    let response = create_device_code(&router, "test-client", None).await?;

    assert_eq!(response["device_code"], "async-device-code");
    assert_eq!(response["user_code"], "ASYNC123");
    Ok(())
}

#[tokio::test]
async fn device_code_route_accepts_valid_client() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new()
            .validate_client(|client_id| async move { Ok(client_id == "valid-client") }),
    )?;

    let response = create_device_code(&router, "valid-client", None).await?;

    assert_eq!(response["interval"], 5);
    Ok(())
}

#[tokio::test]
async fn device_code_route_runs_auth_request_hook() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let called = Arc::new(AtomicBool::new(false));
    let hook_called = Arc::clone(&called);
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new().on_device_auth_request(move |client_id, scope| {
            let hook_called = Arc::clone(&hook_called);
            async move {
                hook_called.store(
                    client_id == "test-client" && scope.as_deref() == Some("read"),
                    Ordering::SeqCst,
                );
                Ok(())
            }
        }),
    )?;

    create_device_code(&router, "test-client", Some("read")).await?;

    assert!(called.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn verification_uri_complete_encodes_user_code_with_dashes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new().generate_user_code(|| "ABC-123".to_owned()),
    )?;

    let response = create_device_code(&router, "test-client", None).await?;

    assert_eq!(response["user_code"], "ABC-123");
    assert!(string_field(&response, "verification_uri_complete").contains("ABC-123"));
    Ok(())
}

#[tokio::test]
async fn verification_uri_supports_relative_absolute_and_existing_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            "/auth/device-verify",
            "http://localhost:3000/auth/device-verify",
            "http://localhost:3000/auth/device-verify?user_code=ABC12345",
        ),
        (
            "https://myapp.com/device",
            "https://myapp.com/device",
            "https://myapp.com/device?user_code=ABC12345",
        ),
        (
            "/device?lang=en",
            "http://localhost:3000/device?lang=en",
            "http://localhost:3000/device?lang=en&user_code=ABC12345",
        ),
    ];

    for (input, expected_uri, expected_complete) in cases {
        let adapter = Arc::new(TestAdapter::default());
        let router = router(
            adapter,
            DeviceAuthorizationOptions::new()
                .verification_uri(input)
                .generate_user_code(|| "ABC12345".to_owned()),
        )?;

        let response = create_device_code(&router, "test-client", None).await?;

        assert_eq!(response["verification_uri"], expected_uri);
        assert_eq!(response["verification_uri_complete"], expected_complete);
    }
    Ok(())
}

#[tokio::test]
async fn device_code_route_accepts_form_body() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, DeviceAuthorizationOptions::default())?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/device/code",
            "client_id=test-client&scope=read+write",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&http::HeaderValue::from_static("no-store"))
    );
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["interval"], 5);
    Ok(())
}
