use super::*;

#[tokio::test]
async fn sign_in_sso_with_oidc_provider_returns_authorization_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true,
                    "pkce":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","loginHint":"user@example.com"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["redirect"], true);
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/oauth2/v1/authorize")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("client_id").map(|value| value.as_ref()),
        Some("client_123456")
    );
    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://app.example.com/sso/callback/okta")
    );
    assert_eq!(
        query.get("scope").map(|value| value.as_ref()),
        Some("openid email profile offline_access")
    );
    assert_eq!(
        query.get("login_hint").map(|value| value.as_ref()),
        Some("user@example.com")
    );
    assert!(query.contains_key("state"));
    assert!(query.get("nonce").is_some_and(|value| value.len() >= 32));
    assert_eq!(
        query
            .get("code_challenge_method")
            .map(|value| value.as_ref()),
        Some("S256")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_rejects_unknown_provider_type() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","providerType":"oauth","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_PROVIDER_TYPE");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_accepts_form_urlencoded_body() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/sign-in/sso",
            "providerId=okta&callbackURL=%2Fdashboard&loginHint=user%40example.com",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/oauth2/v1/authorize")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_request_scopes_override_provider_scopes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true,
                    "pkce":false,
                    "scopes":["openid","email","groups"]
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","scopes":["openid","profile"]}"#,
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
        query.get("scope").map(|value| value.as_ref()),
        Some("openid profile")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_uses_provider_for_organization_slug() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    seed_organization(&adapter, "org_1", "acme").await?;
    let oidc_config = OidcConfig {
        issuer: "https://idp.example.com".to_owned(),
        pkce: true,
        client_id: "client_123456".to_owned(),
        client_secret: "super-secret".into(),
        discovery_endpoint: "https://idp.example.com/.well-known/openid-configuration".to_owned(),
        authorization_endpoint: Some("https://idp.example.com/oauth2/v1/authorize".to_owned()),
        token_endpoint: Some("https://idp.example.com/oauth2/v1/token".to_owned()),
        user_info_endpoint: Some("https://idp.example.com/oauth2/v1/userinfo".to_owned()),
        jwks_endpoint: Some("https://idp.example.com/oauth2/v1/keys".to_owned()),
        revocation_endpoint: None,
        end_session_endpoint: None,
        introspection_endpoint: None,
        token_endpoint_authentication: Some(TokenEndpointAuthentication::ClientSecretBasic),
        scopes: None,
        mapping: None,
        override_user_info: false,
    };
    SsoProviderStore::new(adapter.as_ref())
        .create(CreateSsoProviderInput {
            provider_id: "acme-okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "acme.example.com".to_owned(),
            user_id: "other_user".to_owned(),
            organization_id: Some("org_1".to_owned()),
            oidc_config: Some(serde_json::to_string(&oidc_config)?),
            saml_config: None,
            domain_verified: None,
        })
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"organizationSlug":"acme","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/oauth2/v1/authorize")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("client_id").map(|value| value.as_ref()),
        Some("client_123456")
    );
    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://app.example.com/sso/callback/acme-okta")
    );

    Ok(())
}
