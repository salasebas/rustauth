#[cfg(feature = "saml-signed")]
use super::*;

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn saml_slo_accepts_signed_post_logout_response_and_deletes_pending_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    options.saml.want_logout_response_signed = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    let idp = signed_saml_idp()?;
    register_saml_provider_with_cert(&router, &cookie, &idp.cert, false).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = signed_assertion_saml_response(&idp, &relay_state)?;
    let acs = post_saml_acs(&router, &saml_response, &relay_state).await?;
    let saml_cookie = set_cookie_header(&acs)?;
    let logout = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/logout/saml-okta",
            r#"{"callbackURL":"/logged-out"}"#,
            Some(&saml_cookie),
        )?)
        .await?;
    let logout_location = logout
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing logout Location")?;
    let request_id = logout_request_id_from_location(logout_location)?;
    let logout_response = signed_logout_response_xml(&idp, &request_id)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/slo/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":"/logged-out"}}"#,
                serde_json::to_string(&logout_response)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(adapter.records("verification").await.iter().all(|record| {
        record.get("identifier")
            != Some(&DbValue::String(format!(
                "saml-logout-request:{request_id}"
            )))
    }));

    Ok(())
}

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn saml_slo_rejects_tampered_signed_post_logout_request_without_deleting_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    options.saml.want_logout_request_signed = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    let idp = signed_saml_idp()?;
    register_saml_provider_with_cert(&router, &cookie, &idp.cert, false).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = signed_assertion_saml_response(&idp, &relay_state)?;
    let acs = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(acs.status(), StatusCode::FOUND);
    let logout_request = tamper_base64_xml(
        &signed_logout_request_xml(&idp, "signed-idp-logout")?,
        "saml-subject-123",
        "other-user",
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/slo/saml-okta",
            &format!(
                r#"{{"SAMLRequest":{},"RelayState":"/logged-out"}}"#,
                serde_json::to_string(&logout_request)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_SIGNATURE_INVALID");
    assert_eq!(adapter.records("session").await.len(), 2);

    Ok(())
}
