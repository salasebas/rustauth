use super::*;

#[tokio::test]
async fn sign_in_sso_with_dual_provider_defaults_to_oidc() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_dual_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"hybrid","callbackURL":"/dashboard"}"#,
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
async fn sign_in_sso_with_dual_provider_can_select_saml() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_dual_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"hybrid","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/saml/sso")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_signed_saml_authn_request_requires_private_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "SAML_AUTHN_REQUEST_PRIVATE_KEY_REQUIRED"
    );

    Ok(())
}

async fn register_dual_provider(
    router: &rustauth_core::api::AuthRouter,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
            Some(cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}
