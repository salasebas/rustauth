use super::*;

#[tokio::test]
async fn register_rejects_public_suffix_domain() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_DOMAIN");
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_empty_comma_separated_domain_segment(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com, ,corp.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_DOMAIN");
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_provider_id_that_cannot_be_used_in_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    for provider_id in [
        "../okta",
        "okta/example",
        "okta?x=1",
        " okta",
        "okta#fragment",
    ] {
        let response = router
            .handle_async(json_request(
                Method::POST,
                "/sso/register",
                &serde_json::json!({
                    "providerId": provider_id,
                    "issuer": "https://idp.example.com",
                    "domain": "example.com"
                })
                .to_string(),
                Some(&cookie),
            )?)
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{provider_id}");
        assert_eq!(json_body(response)?["code"], "INVALID_PROVIDER_ID");
    }
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn register_rejects_invalid_oidc_endpoint_url_when_discovery_is_skipped(
) -> Result<(), Box<dyn std::error::Error>> {
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
                    "authorizationEndpoint":"/relative/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_OIDC_CONFIG");
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn register_rejects_saml_config_with_invalid_entry_point(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"broken-saml",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"not-a-url",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/broken-saml",
                    "spMetadata":{},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response)?;
    assert_eq!(body["code"], "INVALID_SAML_CONFIG");
    assert!(body["message"]
        .as_str()
        .is_some_and(|message| message.contains("entryPoint")));
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn register_rejects_saml_config_with_non_http_entry_point(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"broken-saml",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"javascript:alert(1)",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/broken-saml",
                    "spMetadata":{},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_SAML_CONFIG");
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn register_rejects_saml_config_with_unknown_signature_algorithm(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"broken-saml",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/broken-saml",
                    "spMetadata":{},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false,
                    "signatureAlgorithm":"rsa-sha257"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_UNKNOWN_ALGORITHM");
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn register_rejects_deprecated_saml_algorithm_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.algorithms.on_deprecated = DeprecatedAlgorithmBehavior::Reject;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"broken-saml",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/broken-saml",
                    "spMetadata":{},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false,
                    "signatureAlgorithm":"rsa-sha1"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "SAML_DEPRECATED_CONFIG_ALGORITHM"
    );
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}
