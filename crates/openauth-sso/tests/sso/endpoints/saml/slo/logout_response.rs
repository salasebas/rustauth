use super::*;

#[tokio::test]
async fn saml_slo_uses_post_form_for_post_logout_response() -> Result<(), Box<dyn std::error::Error>>
{
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_with_post_single_logout_service(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-post-slo-response")?;
    let acs = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(acs.status(), StatusCode::FOUND);
    let logout_request = logout_request_xml("idp-post-logout")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/slo/saml-okta",
            &format!(
                r#"{{"SAMLRequest":{},"RelayState":"/after-idp-logout"}}"#,
                serde_json::to_string(&logout_request)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(response.body().clone())?;
    assert!(body.contains(
        r#"<form method="post" action="https://idp.example.com/saml/slo-post?tenant=acme&amp;mode=logout">"#
    ));
    assert!(body.contains(r#"name="SAMLResponse""#));
    assert!(body.contains(r#"name="RelayState" value="/after-idp-logout""#));
    assert!(body.contains("<noscript>"));

    Ok(())
}

#[tokio::test]
async fn saml_logout_without_saml_session_lookup_signs_out_locally(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;

    let logout = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/logout/saml-okta",
            "{}",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(logout.status(), StatusCode::OK);
    assert_eq!(json_body(logout)?["success"], true);
    assert_eq!(adapter.records("session").await.len(), 0);

    Ok(())
}

#[tokio::test]
async fn saml_slo_logout_response_deletes_pending_request_and_redirects(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-slo-response")?;
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
    let logout_response = logout_response_xml(&request_id)?;

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
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/logged-out"))
    );
    assert!(adapter.records("verification").await.iter().all(|record| {
        record.get("identifier")
            != Some(&DbValue::String(format!(
                "saml-logout-request:{request_id}"
            )))
    }));

    Ok(())
}

#[tokio::test]
async fn saml_slo_logout_response_falls_back_for_untrusted_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-slo-relay-state")?;
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
    let logout_response = logout_response_xml(&request_id)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/slo/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":"https://evil.example.com/after-logout"}}"#,
                serde_json::to_string(&logout_response)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("https://app.example.com"))
    );

    Ok(())
}
