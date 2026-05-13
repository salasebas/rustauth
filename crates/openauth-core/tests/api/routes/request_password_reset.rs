use super::*;

#[tokio::test]
async fn request_password_reset_route_does_not_reveal_user_existence(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"missing@example.com","redirectTo":"/reset"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(
        body["message"],
        "If this email exists in our system, check your email for the reset link"
    );
    assert!(adapter.is_empty("verification").await);
    Ok(())
}
