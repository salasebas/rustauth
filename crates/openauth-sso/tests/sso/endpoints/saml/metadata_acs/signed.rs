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

#[cfg(not(feature = "saml-signed"))]
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

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn saml_acs_accepts_valid_signed_assertion_when_crypto_validation_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let idp = signed_saml_idp()?;
    register_saml_provider_with_cert(&router, &cookie, &idp.cert, true).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = signed_assertion_saml_response(&idp, &relay_state)?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );

    Ok(())
}

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn saml_acs_rejects_response_only_signature_when_assertion_signature_is_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let idp = signed_saml_idp()?;
    register_saml_provider_with_cert(&router, &cookie, &idp.cert, true).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = signed_response_saml_response(&idp, &relay_state)?;

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

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn saml_acs_rejects_tampered_signed_assertion_before_creating_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let idp = signed_saml_idp()?;
    register_saml_provider_with_cert(&router, &cookie, &idp.cert, true).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = tamper_base64_xml(
        &signed_assertion_saml_response(&idp, &relay_state)?,
        "saml-user@example.com",
        "attacker@example.com",
    )?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_SIGNATURE_INVALID");
    assert_eq!(adapter.records("session").await.len(), 1);

    Ok(())
}

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn saml_acs_decrypts_encrypted_assertion_when_private_key_is_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.clock_skew = time::Duration::days(800);
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    let encrypted_xml = samael_test_vector("response_encrypted_valid.xml")?;
    let decryption_key = samael_test_vector("sp_private.pem")?;
    let parsed = openauth_sso::saml::assertions::parse_saml_response_with_decryption(
        &base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            encrypted_xml.as_bytes(),
        ),
        Some(&decryption_key),
    )?;
    let email = parsed
        .assertion
        .attributes
        .get("email")
        .or(parsed.assertion.name_id.as_ref())
        .ok_or("decrypted assertion missing email/nameID")?
        .to_owned();
    let domain = email
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or("example.com");
    let issuer = parsed.response_issuer.as_deref().unwrap_or("saml-mock");
    let acs_url = parsed
        .response_destination
        .as_deref()
        .unwrap_or("http://localhost:8080/saml/acs");

    let register_body = serde_json::json!({
        "providerId": "saml-okta",
        "issuer": "https://idp.example.com",
        "domain": domain,
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "entryPoint": "https://idp.example.com/saml/sso",
            "cert": "CERTIFICATE",
            "callbackUrl": "/dashboard",
            "acsUrl": acs_url,
            "idpMetadata": {"entityID": issuer},
            "spMetadata": {"entityId": "https://app.example.com/saml/sp"},
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "decryptionPvk": decryption_key
        }
    });
    let register = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_body.to_string(),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(
        register.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(register.body())
    );

    let encrypted_response = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        encrypted_xml.as_bytes(),
    );
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &serde_json::json!({ "SAMLResponse": encrypted_response }).to_string(),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("https://app.example.com"))
    );
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String(email.to_ascii_lowercase()))
    }));

    Ok(())
}
