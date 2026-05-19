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
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=saml_assertion_signature_required"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_signed_response_until_crypto_validation_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = signed_marker_saml_response(&relay_state, "assertion-signed-marker")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "SAML_SIGNATURE_VALIDATION_NOT_IMPLEMENTED"
    );

    Ok(())
}
