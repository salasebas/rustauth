use super::*;
use std::net::IpAddr;

use openauth_core::options::{IpAddressOptions, RateLimitOptions};
use openauth_core::rate_limit::RequestClientIp;

const SPOOFED_FORWARDED_FOR: &str = "203.0.113.99";

/// Production mode suppresses the dev `127.0.0.1` fallback; rate limiting is
/// disabled so a single request is never throttled while asserting metadata.
fn ip_test_options() -> OpenAuthOptions {
    OpenAuthOptions::default()
        .production(true)
        .rate_limit(RateLimitOptions::default().enabled(false))
}

fn email_request(
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
    client_ip: Option<IpAddr>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    if let Some(ip) = client_ip {
        builder = builder.extension(RequestClientIp(ip));
    }
    builder.body(body.as_bytes().to_vec())
}

async fn stored_session_ip(
    adapter: &RouteAdapter,
    response: &http::Response<Vec<u8>>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let body: Value = serde_json::from_slice(response.body())?;
    let user_id = body["user"]["id"].as_str().ok_or("missing user id")?;
    let record = record_by_string(adapter, "session", "user_id", user_id)
        .await?
        .ok_or("session not stored")?;
    Ok(match record.get("ip_address") {
        Some(DbValue::String(value)) => Some(value.clone()),
        _ => None,
    })
}

async fn seed_credential_user(adapter: &RouteAdapter) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
    Ok(())
}

#[tokio::test]
async fn sign_up_email_uses_allow_listed_header_and_ignores_spoofed_forwarded_for(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_advanced(
        adapter.clone(),
        ip_test_options(),
        AdvancedOptions::default().ip_address(IpAddressOptions::new().header("x-real-ip")),
    )?;

    let response = router
        .handle_async(email_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            &[
                ("x-forwarded-for", SPOOFED_FORWARDED_FOR),
                ("x-real-ip", "198.51.100.4"),
            ],
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        stored_session_ip(&adapter, &response).await?.as_deref(),
        Some("198.51.100.4")
    );
    Ok(())
}

#[tokio::test]
async fn sign_in_email_uses_injected_client_ip_and_ignores_spoofed_forwarded_for(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    seed_credential_user(&adapter).await?;
    let router = router_with_advanced(
        adapter.clone(),
        ip_test_options(),
        AdvancedOptions::default(),
    )?;

    let response = router
        .handle_async(email_request(
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            &[("x-forwarded-for", SPOOFED_FORWARDED_FOR)],
            Some("192.0.2.55".parse()?),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        stored_session_ip(&adapter, &response).await?.as_deref(),
        Some("192.0.2.55")
    );
    Ok(())
}

#[tokio::test]
async fn sign_up_email_stores_no_ip_when_tracking_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_advanced(
        adapter.clone(),
        ip_test_options(),
        AdvancedOptions::default().ip_address(IpAddressOptions::new().disable_ip_tracking(true)),
    )?;

    let response = router
        .handle_async(email_request(
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            &[("x-forwarded-for", SPOOFED_FORWARDED_FOR)],
            Some("192.0.2.55".parse()?),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(stored_session_ip(&adapter, &response).await?, None);
    Ok(())
}

#[tokio::test]
async fn sign_in_email_stores_no_ip_for_invalid_allow_listed_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    seed_credential_user(&adapter).await?;
    let router = router_with_advanced(
        adapter.clone(),
        ip_test_options(),
        AdvancedOptions::default().ip_address(IpAddressOptions::new().header("x-real-ip")),
    )?;

    let response = router
        .handle_async(email_request(
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            &[
                ("x-forwarded-for", SPOOFED_FORWARDED_FOR),
                ("x-real-ip", "not-an-ip"),
            ],
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(stored_session_ip(&adapter, &response).await?, None);
    Ok(())
}
