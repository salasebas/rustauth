use super::*;

#[tokio::test]
async fn saml_acs_rejects_unsigned_assertion_when_provider_requires_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-unsigned")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing redirect location")?;
    assert!(
        location.contains("saml_assertion_signature_required")
            || location.contains("saml_signature_invalid"),
        "unexpected redirect: {location}"
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_forged_unsigned_response_when_want_assertions_signed_defaults_true(
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
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-forged-unsigned")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing redirect location")?;
    assert!(
        location.contains("saml_assertion_signature_required")
            || location.contains("saml_signature_invalid"),
        "unexpected redirect: {location}"
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_signed_response_with_invalid_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = signed_marker_saml_response(&relay_state, "assertion-signed-marker")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=saml_signature_invalid"
        ))
    );

    Ok(())
}
