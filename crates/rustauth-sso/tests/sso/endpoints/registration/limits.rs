use super::*;

#[tokio::test]
#[cfg(feature = "oidc")]
async fn register_uses_dynamic_provider_limit_callback() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default().providers_limit_callback(
        |user: User| async move {
            Ok(if user.email == "user@example.com" {
                1
            } else {
                2
            })
        },
    ))?;
    let cookie = seed_session(&adapter).await?;

    let first = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta-one",
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
    assert_eq!(first.status(), StatusCode::OK);

    let second = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta-two",
                "issuer":"https://idp2.example.com",
                "domain":"example.org",
                "oidcConfig":{
                    "clientId":"client_654321",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp2.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp2.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp2.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(second)?["code"], "SSO_PROVIDERS_LIMIT_REACHED");
    assert_eq!(adapter.records("sso_provider").await.len(), 1);

    Ok(())
}

#[tokio::test]
async fn register_dynamic_provider_limit_zero_disables_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(
        SsoOptions::default().providers_limit_callback(|_user: User| async move { Ok(0) }),
    )?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com"
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(response)?["code"],
        "SSO_PROVIDER_REGISTRATION_DISABLED"
    );
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}
