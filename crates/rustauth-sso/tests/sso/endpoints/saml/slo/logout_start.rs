use super::*;

#[tokio::test]
async fn saml_logout_generates_logout_request_redirect_and_cleans_local_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-slo-logout")?;
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

    assert_eq!(logout.status(), StatusCode::FOUND);
    let location = logout
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing Location")?;
    let url = url::Url::parse(location)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/saml/sso")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("RelayState").map(|value| value.as_ref()),
        Some("/logged-out")
    );
    let saml_request = query.get("SAMLRequest").ok_or("missing SAMLRequest")?;
    let xml = inflate_redirect_binding(saml_request)?;
    assert!(xml.contains("<samlp:LogoutRequest"));
    assert!(xml.contains(r#"Destination="https://idp.example.com/saml/sso""#));
    assert!(xml.contains("<saml:Issuer>https://app.example.com/saml/sp</saml:Issuer>"));
    assert!(xml.contains("<saml:NameID>saml-subject-123</saml:NameID>"));
    assert!(xml.contains("<samlp:SessionIndex>session-index-1</samlp:SessionIndex>"));

    let request_id = xml
        .split(r#"ID=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or("missing logout request ID")?;
    assert!(adapter.records("verification").await.iter().any(|record| {
        record.get("identifier")
            == Some(&DbValue::String(format!(
                "saml-logout-request:{request_id}"
            )))
    }));
    assert!(adapter.records("verification").await.iter().all(|record| {
        !record.get("identifier").is_some_and(|value| {
            matches!(
                value,
                DbValue::String(identifier)
                    if identifier.starts_with("saml-session:saml-okta:")
                        || identifier.starts_with("saml-session-by-id:")
            )
        })
    }));
    assert_eq!(adapter.records("session").await.len(), 1);

    Ok(())
}
