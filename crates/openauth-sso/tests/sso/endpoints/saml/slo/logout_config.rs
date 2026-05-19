use super::*;

#[tokio::test]
async fn saml_logout_uses_default_sso_saml_provider() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = default_saml_sso_options();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
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
    let saml_response = valid_saml_response(&relay_state, "assertion-default-slo")?;
    let saml_response = tamper_base64_xml(
        &saml_response,
        "/sso/saml2/sp/acs/saml-okta",
        "/sso/saml2/sp/acs/default-saml",
    )?;
    let acs = router
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
    let saml_cookie = set_cookie_header(&acs)?;

    let logout = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/logout/default-saml",
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
    assert!(adapter.records("verification").await.iter().any(|record| {
        record.get("identifier").is_some_and(|value| {
            matches!(
                value,
                DbValue::String(identifier)
                    if identifier.starts_with("saml-logout-request:")
            )
        })
    }));

    Ok(())
}

#[tokio::test]
async fn saml_logout_uses_configured_single_logout_service(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
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
                    "idpMetadata":{
                        "singleLogoutService":[{
                            "Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                            "Location":"https://idp.example.com/saml/slo-post"
                        },{
                            "Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                            "Location":"https://idp.example.com/saml/slo-redirect"
                        }]
                    },
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-configured-slo")?;
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
        Some("https://idp.example.com/saml/slo-redirect")
    );
    let saml_request = url
        .query_pairs()
        .find_map(|(key, value)| (key == "SAMLRequest").then(|| value.into_owned()))
        .ok_or("missing SAMLRequest")?;
    let xml = inflate_redirect_binding(&saml_request)?;
    assert!(xml.contains(r#"Destination="https://idp.example.com/saml/slo-redirect""#));

    Ok(())
}

#[tokio::test]
async fn saml_logout_uses_single_logout_service_from_idp_metadata_xml(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    let metadata = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><md:IDPSSODescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/slo-from-metadata"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "idpMetadata":{{"metadata":{}}},
                    "spMetadata":{{"entityId":"https://app.example.com/saml/sp"}},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }}
            }}"#,
                serde_json::to_string(metadata)?
            ),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-metadata-slo")?;
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
        Some("https://idp.example.com/saml/slo-from-metadata")
    );

    Ok(())
}

#[tokio::test]
async fn saml_logout_uses_post_form_for_post_single_logout_service(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_with_post_single_logout_service(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-post-slo-request")?;
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

    assert_eq!(logout.status(), StatusCode::OK);
    assert_eq!(
        logout.headers().get(header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("text/html; charset=utf-8"))
    );
    let body = String::from_utf8(logout.body().clone())?;
    assert!(body.contains(
        r#"<form method="post" action="https://idp.example.com/saml/slo-post?tenant=acme&amp;mode=logout">"#
    ));
    assert!(body.contains(r#"name="SAMLRequest""#));
    assert!(body.contains(r#"name="RelayState" value="/logged-out""#));
    assert!(body.contains("<noscript>"));

    Ok(())
}
