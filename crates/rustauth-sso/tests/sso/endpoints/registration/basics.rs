use super::*;

#[tokio::test]
#[cfg(feature = "oidc")]
async fn register_persists_and_sanitizes_oidc_config() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
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
                    "scopes":["openid","email"]
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["oidcConfig"]["clientIdLastFour"], "****3456");
    assert!(body["oidcConfig"].get("clientSecret").is_none());
    assert_eq!(body["providerType"], "oidc");
    assert_eq!(body["type"], "oidc");
    assert_eq!(
        body["redirectURI"],
        "https://app.example.com/sso/callback/okta"
    );
    assert_eq!(
        body["oidcConfig"]["authorizationEndpoint"],
        "https://idp.example.com/oauth2/v1/authorize"
    );

    let records = adapter.records("sso_provider").await;
    let Some(DbValue::String(config)) = records[0].get("oidc_config") else {
        return Err("missing stored OIDC config".into());
    };
    assert!(config.contains(r#""clientSecret":"super-secret""#));
    assert!(config.contains(
        r#""discoveryEndpoint":"https://idp.example.com/.well-known/openid-configuration""#
    ));

    Ok(())
}

#[tokio::test]
async fn register_accepts_form_urlencoded_body() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/sso/register",
            "providerId=form-okta&issuer=https%3A%2F%2Fidp.example.com&domain=example.com",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["providerId"], "form-okta");

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn register_returns_shared_oidc_redirect_uri_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().redirect_uri("/sso/callback"))?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"shared-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["type"], "oidc");
    assert_eq!(body["redirectURI"], "https://app.example.com/sso/callback");

    Ok(())
}

#[tokio::test]
#[cfg(all(feature = "oidc", feature = "saml"))]
async fn register_allows_provider_with_oidc_and_saml_configs(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"hybrid",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                },
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/hybrid",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["providerType"], "saml");
    assert_eq!(body["type"], "saml");
    assert!(body["oidcConfig"].is_object());
    assert!(body["samlConfig"].is_object());
    assert_eq!(
        body["redirectURI"],
        "https://app.example.com/sso/callback/hybrid"
    );

    let records = adapter.records("sso_provider").await;
    assert!(matches!(
        records[0].get("oidc_config"),
        Some(DbValue::String(_))
    ));
    assert!(matches!(
        records[0].get("saml_config"),
        Some(DbValue::String(_))
    ));

    Ok(())
}
