use super::*;

#[tokio::test]
async fn sign_up_email_route_creates_session_and_sets_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["session"].is_null());
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("better-auth.session_token=")));
    Ok(())
}
