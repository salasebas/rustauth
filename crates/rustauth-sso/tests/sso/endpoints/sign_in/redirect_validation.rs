use super::*;

#[tokio::test]
async fn sign_in_sso_rejects_untrusted_absolute_callback_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"https://evil.example.com/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["code"], "INVALID_CALLBACK_URL");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_rejects_callback_url_loop_to_sso_callback(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/sso/callback/okta"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["code"], "INVALID_CALLBACK_URL");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_rejects_protocol_relative_error_callback_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"//evil.example.com/login"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["code"], "INVALID_ERROR_CALLBACK_URL");

    Ok(())
}
