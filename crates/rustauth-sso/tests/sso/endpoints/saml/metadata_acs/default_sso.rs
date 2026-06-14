use super::*;

#[tokio::test]
async fn sign_in_sso_uses_default_saml_provider_from_array_without_database_record(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router) = router_with_options(default_saml_sso_options())?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-saml","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert!(url.as_str().contains("https://idp.example.com/saml/sso"));

    Ok(())
}

#[tokio::test]
async fn saml_acs_uses_second_default_sso_provider_by_provider_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(multi_default_saml_sso_options())?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-saml-b","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let relay_state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then(|| value.into_owned()))
        .ok_or("missing RelayState")?;
    let saml_response = valid_saml_response(&relay_state, "assertion-default-saml-b")?;
    let saml_response = tamper_base64_xml(
        &saml_response,
        "/sso/saml2/sp/acs/saml-okta",
        "/sso/saml2/sp/acs/default-saml-b",
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/default-saml-b",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":{}}}"#,
                serde_json::to_string(&saml_response)?,
                serde_json::to_string(&relay_state)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("default-saml-b".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn saml_acs_returns_not_found_for_unknown_default_sso_provider_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router) = router_with_options(multi_default_saml_sso_options())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/unknown-id",
            r#"{"SAMLResponse":"dGVzdA==","RelayState":"relay"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(response)?["code"], "PROVIDER_NOT_FOUND");

    Ok(())
}

#[tokio::test]
async fn saml_default_sso_takes_precedence_over_db_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(default_saml_sso_options())?;
    seed_invalid_default_saml_db_provider(&adapter).await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-saml","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let relay_state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then(|| value.into_owned()))
        .ok_or("missing RelayState")?;
    let saml_response = valid_saml_response(&relay_state, "assertion-default-precedence")?;
    let saml_response = tamper_base64_xml(
        &saml_response,
        "/sso/saml2/sp/acs/saml-okta",
        "/sso/saml2/sp/acs/default-saml",
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/default-saml",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":{}}}"#,
                serde_json::to_string(&saml_response)?,
                serde_json::to_string(&relay_state)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );

    Ok(())
}
