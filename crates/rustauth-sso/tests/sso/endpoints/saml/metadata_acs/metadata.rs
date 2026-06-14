use super::*;

#[tokio::test]
async fn saml_metadata_endpoint_returns_provider_sp_metadata(
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
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/saml2/sp/metadata?providerId=saml-okta",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/xml"))
    );
    let body = String::from_utf8(response.body().clone())?;
    assert!(body.contains(r#"entityID="https://app.example.com/saml/sp""#));
    assert!(body.contains(r#"Location="https://app.example.com/sso/saml2/sp/acs/saml-okta""#));

    Ok(())
}

#[tokio::test]
async fn saml_metadata_endpoint_prefers_explicit_acs_url() -> Result<(), Box<dyn std::error::Error>>
{
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
                    "callbackUrl":"https://app.example.com/post-auth-callback",
                    "acsUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/saml2/sp/metadata?providerId=saml-okta",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(response.body().clone())?;
    assert!(body.contains(r#"Location="https://app.example.com/sso/saml2/sp/acs/saml-okta""#));
    assert!(!body.contains("https://app.example.com/post-auth-callback"));

    Ok(())
}

#[tokio::test]
async fn saml_metadata_endpoint_passthroughs_configured_sp_metadata(
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
                    "spMetadata":{
                        "metadata":"<EntityDescriptor entityID=\"custom-sp\"><SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"/></EntityDescriptor>"
                    },
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/saml2/sp/metadata?providerId=saml-okta",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(response.body().clone())?;
    assert_eq!(
        body,
        r#"<EntityDescriptor entityID="custom-sp"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>"#
    );

    Ok(())
}

#[tokio::test]
async fn saml_metadata_endpoint_enriches_generated_sp_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
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
                    "authnRequestsSigned":true,
                    "identifierFormat":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/saml2/sp/metadata?providerId=saml-okta",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(response.body().clone())?;
    assert!(body.contains(r#"AuthnRequestsSigned="true""#));
    assert!(body.contains(r#"WantAssertionsSigned="true""#));
    assert!(body.contains(
        "<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>"
    ));
    assert!(body.contains(r#"<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://app.example.com/sso/saml2/sp/slo/saml-okta"/>"#));
    assert!(body.contains(r#"<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://app.example.com/sso/saml2/sp/slo/saml-okta"/>"#));

    Ok(())
}

#[tokio::test]
async fn saml_metadata_endpoint_accepts_json_format_like_upstream(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/saml2/sp/metadata?providerId=saml-okta&format=json",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/xml"))
    );
    let body = String::from_utf8(response.body().clone())?;
    assert!(body.contains("<EntityDescriptor"));

    Ok(())
}
