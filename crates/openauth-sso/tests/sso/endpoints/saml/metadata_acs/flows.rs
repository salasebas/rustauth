use super::*;

#[tokio::test]
async fn saml_acs_creates_session_from_valid_unsigned_response_when_allowed(
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
    let saml_response = valid_saml_response(&relay_state, "assertion-okta-1")?;

    let callback = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":{}}}"#,
                serde_json::to_string(&saml_response)?,
                serde_json::to_string(&relay_state)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(callback.headers().get(header::SET_COOKIE).is_some());
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("saml-user@example.com".to_owned()))
            && record.get("name") == Some(&DbValue::String("Saml User".to_owned()))
    }));
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("saml-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("saml-subject-123".to_owned()))
    }));
    assert!(adapter.records("verification").await.iter().any(|record| {
        record.get("identifier")
            == Some(&DbValue::String(
                "saml-used-assertion:assertion-okta-1".to_owned(),
            ))
    }));

    Ok(())
}

#[tokio::test]
async fn saml_acs_validates_explicit_acs_url_destination() -> Result<(), Box<dyn std::error::Error>>
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
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-explicit-acs")?;
    let saml_response = tamper_base64_xml(
        &saml_response,
        r#"Destination="https://app.example.com/sso/saml2/sp/acs/saml-okta""#,
        r#"Destination="https://app.example.com/sso/saml2/sp/acs/saml-okta""#,
    )?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_accepts_form_urlencoded_body() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-form-acs")?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("SAMLResponse", &saml_response)
        .append_pair("RelayState", &relay_state)
        .finish();

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &body,
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

#[tokio::test]
async fn saml_get_callback_redirects_to_safe_relay_state_with_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/saml2/callback/saml-okta?RelayState=/dashboard/settings",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard/settings"))
    );

    Ok(())
}

#[tokio::test]
async fn saml_get_callback_requires_session() -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router) = router_with_options(SsoOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/saml2/callback/saml-okta?RelayState=/dashboard",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "https://app.example.com/error?error=invalid_request"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn saml_get_callback_falls_back_for_unsafe_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/saml2/callback/saml-okta?RelayState=https%3A%2F%2Fevil.example.com%2Fsteal",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("https://app.example.com"))
    );

    Ok(())
}
