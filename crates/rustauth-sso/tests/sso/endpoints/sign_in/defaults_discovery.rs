use super::*;

#[tokio::test]
async fn sign_in_sso_uses_default_sso_oidc_by_provider_id() -> Result<(), Box<dyn std::error::Error>>
{
    let oidc = MockOidcServer::start().await?;
    let (_adapter, router) = router_with_options(default_oidc_sso_options(&oidc.base_url))?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some(format!("{}/authorize", oidc.base_url).as_str())
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("scope").map(|value| value.as_ref()),
        Some("openid email profile offline_access"),
        "missing configured scopes should use the default SSO OIDC request scopes"
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_discovers_default_sso_oidc_endpoints_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (_adapter, router) = router_with_options_and_trusted_origins(
        default_oidc_sso_options_requiring_discovery(&oidc.base_url),
        vec![oidc.base_url.clone()],
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some(format!("{}/authorize", oidc.base_url).as_str())
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("scope").map(|value| value.as_ref()),
        Some("openid email profile offline_access"),
        "runtime discovery should not replace default requested scopes with discovered scopes_supported"
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_returns_stable_discovery_error_code() -> Result<(), Box<dyn std::error::Error>>
{
    let oidc = MockOidcServer::start().await?;
    let mut options = default_oidc_sso_options_requiring_discovery(&oidc.base_url);
    if let Some(config) = options
        .default_sso
        .first_mut()
        .and_then(|provider| provider.oidc_config.as_mut())
    {
        config.discovery_endpoint = format!("{}/missing-openid-configuration", oidc.base_url);
    }
    let (_adapter, router) =
        router_with_options_and_trusted_origins(options, vec![oidc.base_url.clone()])?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "discovery_not_found");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_rejects_untrusted_default_sso_manual_oidc_endpoint_when_strict_policy_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = default_oidc_sso_options("https://trusted-idp.example.com");
    options.oidc.strict_manual_endpoint_origins = true;
    if let Some(config) = options
        .default_sso
        .first_mut()
        .and_then(|provider| provider.oidc_config.as_mut())
    {
        config.token_endpoint = Some("https://evil.example.com/token".to_owned());
    }
    let (_adapter, router) = router_with_options_and_trusted_origins(
        options,
        vec!["https://trusted-idp.example.com".to_owned()],
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "discovery_untrusted_origin");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_discovers_stored_oidc_provider_endpoints_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    seed_runtime_discovery_oidc_provider(&adapter, &oidc.base_url).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"runtime-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some(format!("{}/authorize", oidc.base_url).as_str())
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_uses_default_sso_oidc_by_email_domain(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (_adapter, router) = router_with_options(default_oidc_sso_options(&oidc.base_url))?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"email":"ada@example.com","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("client_id").map(|value| value.as_ref()),
        Some("client_123456")
    );

    Ok(())
}
