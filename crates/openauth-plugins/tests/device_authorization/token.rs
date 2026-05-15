use super::*;

use std::sync::atomic::{AtomicBool, Ordering};

use openauth_core::context::request_state;
use openauth_core::options::SessionAdditionalField;
use openauth_core::plugin::{AuthPlugin, PluginAfterHookAction};

#[tokio::test]
async fn token_route_returns_authorization_pending_before_approval(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, DeviceAuthorizationOptions::default())?;
    let code = create_device_code(&router, "test-client", None).await?;

    let response = poll_token(&router, string_field(&code, "device_code"), "test-client").await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_token_cache_headers(&response);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["error"], "authorization_pending");
    assert_eq!(body["error_description"], "Authorization pending");
    Ok(())
}

#[tokio::test]
async fn token_route_enforces_polling_interval() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new().interval(Duration::seconds(30)),
    )?;
    let code = create_device_code(&router, "test-client", None).await?;
    let device_code = string_field(&code, "device_code");
    let _ = poll_token(&router, device_code, "test-client").await?;

    let response = poll_token(&router, device_code, "test-client").await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_token_cache_headers(&response);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["error"], "slow_down");
    assert_eq!(body["error_description"], "Polling too frequently");
    Ok(())
}

#[tokio::test]
async fn token_route_rejects_invalid_device_code_and_grant_type(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, DeviceAuthorizationOptions::default())?;

    let bad_grant = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/device/token",
            r#"{"grant_type":"bad","device_code":"missing","client_id":"test-client"}"#,
            None,
        )?)
        .await?;
    assert_eq!(bad_grant.status(), StatusCode::BAD_REQUEST);
    assert_token_cache_headers(&bad_grant);
    let body: Value = serde_json::from_slice(bad_grant.body())?;
    assert_eq!(body["error"], "invalid_request");

    let invalid_code = poll_token(&router, "missing", "test-client").await?;
    assert_eq!(invalid_code.status(), StatusCode::BAD_REQUEST);
    assert_token_cache_headers(&invalid_code);
    let body: Value = serde_json::from_slice(invalid_code.body())?;
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "Invalid device code");
    Ok(())
}

#[tokio::test]
async fn token_route_rejects_invalid_and_mismatched_client(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter,
        DeviceAuthorizationOptions::new().validate_client(|client_id| async move {
            Ok(client_id == "valid-client-1" || client_id == "valid-client-2")
        }),
    )?;
    let code = create_device_code(&router, "valid-client-1", None).await?;
    let device_code = string_field(&code, "device_code");

    let invalid_client = poll_token(&router, device_code, "invalid-client").await?;
    assert_token_cache_headers(&invalid_client);
    let body: Value = serde_json::from_slice(invalid_client.body())?;
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "Invalid client ID");

    let mismatched_client = poll_token(&router, device_code, "valid-client-2").await?;
    assert_token_cache_headers(&mismatched_client);
    let body: Value = serde_json::from_slice(mismatched_client.body())?;
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "Client ID mismatch");
    Ok(())
}

#[tokio::test]
async fn token_route_returns_expired_token_and_deletes_record(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(
        adapter.clone(),
        DeviceAuthorizationOptions::new().expires_in(Duration::milliseconds(1)),
    )?;
    let code = create_device_code(&router, "test-client", None).await?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let response = poll_token(&router, string_field(&code, "device_code"), "test-client").await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_token_cache_headers(&response);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["error"], "expired_token");
    assert_eq!(body["error_description"], "Device code has expired");
    assert_eq!(adapter.len("deviceCode").await, 0);
    Ok(())
}

#[tokio::test]
async fn token_route_exchanges_approved_code_for_bearer_token_and_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter.clone(), DeviceAuthorizationOptions::default())?;
    let code = create_device_code(&router, "test-client", Some("read write")).await?;
    let (_user_id, cookie) = create_user_session(&adapter).await?;
    approve(&router, string_field(&code, "user_code"), &cookie).await?;

    let response = poll_token(&router, string_field(&code, "device_code"), "test-client").await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_token_cache_headers(&response);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(!string_field(&body, "access_token").is_empty());
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "read write");
    assert_eq!(adapter.len("deviceCode").await, 0);
    assert_eq!(adapter.len("session").await, 2);
    Ok(())
}

#[tokio::test]
async fn token_route_returns_access_denied_after_denial() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter.clone(), DeviceAuthorizationOptions::default())?;
    let code = create_device_code(&router, "test-client", None).await?;
    let (_user_id, cookie) = create_user_session(&adapter).await?;
    deny(&router, string_field(&code, "user_code"), &cookie).await?;

    let response = poll_token(&router, string_field(&code, "device_code"), "test-client").await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_token_cache_headers(&response);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], "Access denied");
    assert_eq!(adapter.len("deviceCode").await, 0);
    Ok(())
}

#[tokio::test]
async fn token_route_accepts_form_body() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter.clone(), DeviceAuthorizationOptions::default())?;
    let code = create_device_code(&router, "test-client", None).await?;
    let (_user_id, cookie) = create_user_session(&adapter).await?;
    approve(&router, string_field(&code, "user_code"), &cookie).await?;

    let response =
        poll_token_form(&router, string_field(&code, "device_code"), "test-client").await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_token_cache_headers(&response);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["token_type"], "Bearer");
    Ok(())
}

#[tokio::test]
async fn approved_token_session_records_request_metadata_and_additional_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let mut auth_options = OpenAuthOptions::default();
    auth_options.session.additional_fields.insert(
        "device_origin".to_owned(),
        SessionAdditionalField::new(DbFieldType::String)
            .generated()
            .default_value(DbValue::String("device-flow".to_owned())),
    );
    let router = router_with_openauth_options(
        adapter.clone(),
        DeviceAuthorizationOptions::default(),
        auth_options,
    )?;
    let code = create_device_code(&router, "test-client", None).await?;
    let (_user_id, cookie) = create_user_session(&adapter).await?;
    approve(&router, string_field(&code, "user_code"), &cookie).await?;

    let response = poll_token_with_headers(
        &router,
        string_field(&code, "device_code"),
        "test-client",
        "203.0.113.7, 10.0.0.1",
        "DeviceTest/1.0",
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let token = string_field(&body, "access_token");
    let session = adapter
        .records("session")
        .await
        .into_iter()
        .find(|record| record.get("token") == Some(&DbValue::String(token.to_owned())))
        .ok_or("missing token-created session")?;
    assert_eq!(
        session.get("ip_address"),
        Some(&DbValue::String("203.0.113.7".to_owned()))
    );
    assert_eq!(
        session.get("user_agent"),
        Some(&DbValue::String("DeviceTest/1.0".to_owned()))
    );
    assert_eq!(
        session.get("device_origin"),
        Some(&DbValue::String("device-flow".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn approved_token_records_new_session_for_after_hooks(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let observed = Arc::new(AtomicBool::new(false));
    let observed_hook = Arc::clone(&observed);
    let observer = AuthPlugin::new("device-session-observer").with_after_hook(
        "/device/token",
        move |_context, _request, response| {
            if request_state::current_new_session()?.is_some() {
                observed_hook.store(true, Ordering::SeqCst);
            }
            Ok(PluginAfterHookAction::Continue(response))
        },
    );
    let auth_options = OpenAuthOptions {
        plugins: vec![
            device_authorization_with_options(DeviceAuthorizationOptions::default()),
            observer,
        ],
        secret: Some(secret().to_owned()),
        base_url: Some("http://localhost:3000".to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    };
    let context = create_auth_context_with_adapter(auth_options, adapter.clone())?;
    let router = AuthRouter::with_async_endpoints(context, Vec::new(), Vec::new())?;
    let code = create_device_code(&router, "test-client", None).await?;
    let (_user_id, cookie) = create_user_session(&adapter).await?;
    approve(&router, string_field(&code, "user_code"), &cookie).await?;

    let response = poll_token(&router, string_field(&code, "device_code"), "test-client").await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(observed.load(Ordering::SeqCst));
    Ok(())
}

async fn poll_token(
    router: &AuthRouter,
    device_code: &str,
    client_id: &str,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let body = format!(
        r#"{{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"{device_code}","client_id":"{client_id}"}}"#
    );
    Ok(router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/device/token",
            &body,
            None,
        )?)
        .await?)
}

async fn poll_token_form(
    router: &AuthRouter,
    device_code: &str,
    client_id: &str,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code={device_code}&client_id={client_id}"
    );
    Ok(router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/device/token",
            &body,
            None,
        )?)
        .await?)
}

async fn poll_token_with_headers(
    router: &AuthRouter,
    device_code: &str,
    client_id: &str,
    ip_address: &str,
    user_agent: &str,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let body = format!(
        r#"{{"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"{device_code}","client_id":"{client_id}"}}"#
    );
    Ok(router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("http://localhost:3000/api/auth/device/token")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", ip_address)
                .header(header::USER_AGENT, user_agent)
                .body(body.into_bytes())?,
        )
        .await?)
}

fn assert_token_cache_headers(response: &http::Response<Vec<u8>>) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&http::HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        response.headers().get(header::PRAGMA),
        Some(&http::HeaderValue::from_static("no-cache"))
    );
}

async fn approve(
    router: &AuthRouter,
    user_code: &str,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/device/approve",
            &format!(r#"{{"userCode":"{user_code}"}}"#),
            Some(cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

async fn deny(
    router: &AuthRouter,
    user_code: &str,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/device/deny",
            &format!(r#"{{"userCode":"{user_code}"}}"#),
            Some(cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}
