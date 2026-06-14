use super::*;

#[tokio::test]
async fn saml_slo_allows_cross_site_idp_post_when_origin_checks_are_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options_and_origin_security(
        options,
        vec!["https://app.example.com".to_owned()],
    )?;
    seed_saml_provider_record(&adapter).await?;

    let request = http::Request::builder()
        .method(Method::POST)
        .uri("https://app.example.com/sso/saml2/sp/slo/saml-okta")
        .header(header::CONTENT_TYPE, "application/json")
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "navigate")
        .body(br#"{}"#.to_vec())?;

    let response = router.handle_async(request).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing Location")?;
    assert_eq!(
        location,
        "https://app.example.com/sso/saml2/sp/slo/saml-okta?error=missing_logout_data"
    );

    Ok(())
}

#[tokio::test]
async fn saml_core_sign_out_clears_saml_session_lookup_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-core-signout")?;
    let acs = post_saml_acs(&router, &saml_response, &relay_state).await?;
    let saml_cookie = set_cookie_header(&acs)?;
    let other_relay_state = saml_sign_in_relay_state(&router).await?;
    let other_saml_response = valid_saml_response(&other_relay_state, "assertion-other-session")?;
    let other_acs = post_saml_acs(&router, &other_saml_response, &other_relay_state).await?;
    assert_eq!(other_acs.status(), StatusCode::FOUND);
    let saml_state_records = adapter.records("verification").await;
    assert_eq!(
        saml_state_records
            .iter()
            .filter(|record| {
                record.get("identifier").is_some_and(|value| {
                    matches!(
                        value,
                        DbValue::String(identifier)
                            if identifier.starts_with("saml-session:saml-okta:")
                                || identifier.starts_with("saml-session-by-id:")
                    )
                })
            })
            .count(),
        4
    );
    assert!(saml_state_records.iter().any(|record| {
        record.get("identifier").is_some_and(|value| {
            matches!(
                value,
                DbValue::String(identifier)
                    if identifier.starts_with("saml-session:saml-okta:")
                        || identifier.starts_with("saml-session-by-id:")
            )
        })
    }));

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-out",
            "{}",
            Some(&saml_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let saml_state_records = adapter.records("verification").await;
    assert_eq!(
        saml_state_records
            .iter()
            .filter(|record| {
                record.get("identifier").is_some_and(|value| {
                    matches!(
                        value,
                        DbValue::String(identifier)
                            if identifier.starts_with("saml-session:saml-okta:")
                                || identifier.starts_with("saml-session-by-id:")
                    )
                })
            })
            .count(),
        2
    );
    assert!(saml_state_records.iter().any(|record| {
        record.get("identifier").is_some_and(|value| {
            matches!(value, DbValue::String(identifier) if identifier.starts_with("saml-session:saml-okta:"))
        })
    }));
    assert!(saml_state_records.iter().any(|record| {
        record.get("identifier").is_some_and(|value| {
            matches!(value, DbValue::String(identifier) if identifier.starts_with("saml-session-by-id:"))
        })
    }));

    Ok(())
}
