use super::*;

#[cfg(feature = "saml")]
const SAML_REGISTER_BODY: &str = r#"{
    "providerId":"saml-limit-test",
    "issuer":"https://idp.example.com",
    "domain":"example.com",
    "samlConfig":{
        "issuer":"https://app.example.com/sso/saml2/sp/metadata",
        "entryPoint":"https://idp.example.com/saml/sso",
        "cert":"CERTIFICATE",
        "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-limit-test",
        "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
        "wantAssertionsSigned":false,
        "authnRequestsSigned":false
    }
}"#;

#[tokio::test]
#[cfg(feature = "saml")]
async fn register_saml_honors_providers_limit_callback() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(
        SsoOptions::default().providers_limit_callback(|_user: User| async move { Ok(1) }),
    )?;
    let cookie = seed_session(&adapter).await?;

    let first = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            SAML_REGISTER_BODY,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-limit-second",
                "issuer":"https://idp2.example.com",
                "domain":"example.org",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp2.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-limit-second",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
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
#[cfg(feature = "saml")]
async fn register_saml_rejects_duplicate_provider_id() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let first = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            SAML_REGISTER_BODY,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-limit-test",
                "issuer":"https://idp2.example.com",
                "domain":"example.org",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp2.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-limit-test",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(second.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_body(second)?["code"], "PROVIDER_EXISTS");
    assert_eq!(adapter.records("sso_provider").await.len(), 1);

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn register_saml_dynamic_provider_limit_zero_disables_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(
        SsoOptions::default().providers_limit_callback(|_user: User| async move { Ok(0) }),
    )?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            SAML_REGISTER_BODY,
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
