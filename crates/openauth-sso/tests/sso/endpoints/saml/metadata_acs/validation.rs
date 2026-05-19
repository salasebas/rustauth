use super::*;

#[tokio::test]
async fn saml_acs_rejects_missing_saml_response() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            "{}",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "MISSING_SAML_RESPONSE");

    Ok(())
}

#[tokio::test]
async fn saml_acs_allows_cross_site_idp_post_when_origin_checks_are_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.allow_idp_initiated = true;
    let (adapter, router) = router_with_options_and_origin_security(
        options,
        vec!["https://app.example.com".to_owned()],
    )?;
    seed_saml_provider_record(&adapter).await?;

    let request = http::Request::builder()
        .method(Method::POST)
        .uri("https://app.example.com/sso/saml2/sp/acs/saml-okta")
        .header(header::CONTENT_TYPE, "application/json")
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "navigate")
        .body(br#"{"SAMLResponse":"not-base64"}"#.to_vec())?;

    let response = router.handle_async(request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_SAML_RESPONSE");

    Ok(())
}

#[tokio::test]
async fn sso_register_still_blocks_untrusted_origin_when_origin_checks_are_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_origin_security(
        SsoOptions::default(),
        vec!["https://app.example.com".to_owned()],
    )?;
    let cookie = seed_session(&adapter).await?;
    let request = http::Request::builder()
        .method(Method::POST)
        .uri("https://app.example.com/sso/register")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, "https://evil.example.com")
        .body(
            br#"{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com"
            }"#
            .to_vec(),
        )?;

    let response = router.handle_async(request).await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["code"], "INVALID_ORIGIN");

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_response_over_configured_size_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.max_response_size = 8;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            r#"{"SAMLResponse":"123456789"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json_body(response)?["code"], "SAML_RESPONSE_TOO_LARGE");

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_unknown_relay_state_when_request_validation_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            r#"{"SAMLResponse":"abc","RelayState":"missing-request"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "UNKNOWN_AUTHN_REQUEST");

    Ok(())
}

#[tokio::test]
async fn saml_acs_redirects_missing_response_to_relay_state_error_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let relay_state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then(|| value.into_owned()))
        .ok_or("missing RelayState")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &format!(
                r#"{{"RelayState":{}}}"#,
                serde_json::to_string(&relay_state)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=missing_saml_response"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_redirects_invalid_response_to_relay_state_error_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let relay_state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then(|| value.into_owned()))
        .ok_or("missing RelayState")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &format!(
                r#"{{"SAMLResponse":"not-base64","RelayState":{}}}"#,
                serde_json::to_string(&relay_state)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=invalid_saml_response"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_deprecated_runtime_signature_algorithm(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.algorithms.on_deprecated = DeprecatedAlgorithmBehavior::Reject;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-runtime-algorithm")?;
    let saml_response = tamper_base64_xml(
        &saml_response,
        "<saml:Subject>",
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference></ds:SignedInfo></ds:Signature><saml:Subject>"#,
    )?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=saml_deprecated_runtime_algorithm"
        ))
    );

    Ok(())
}
