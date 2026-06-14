use super::*;

#[tokio::test]
async fn sign_in_sso_uses_saml_provider_for_organization_slug(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    let cookie = seed_session(&adapter).await?;
    seed_organization(&adapter, "org_1", "acme").await?;
    SsoProviderStore::new(adapter.as_ref())
        .create(CreateSsoProviderInput {
            provider_id: "acme-saml".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "acme.example.com".to_owned(),
            user_id: "other_user".to_owned(),
            organization_id: Some("org_1".to_owned()),
            oidc_config: None,
            saml_config: Some(serde_json::to_string(&SamlConfig {
                issuer: "https://app.example.com/sso/saml2/sp/metadata".to_owned(),
                entry_point: "https://idp.example.com/saml/sso".to_owned(),
                cert: "CERTIFICATE".to_owned(),
                callback_url: "https://app.example.com/sso/saml2/sp/acs/acme-saml".to_owned(),
                acs_url: None,
                audience: None,
                idp_metadata: None,
                sp_metadata: SamlSpMetadata {
                    entity_id: Some("https://app.example.com/saml/sp".to_owned()),
                    ..SamlSpMetadata::default()
                },
                mapping: None,
                want_assertions_signed: false,
                authn_requests_signed: false,
                signature_algorithm: None,
                digest_algorithm: None,
                identifier_format: None,
                private_key: None,
                decryption_pvk: None,
                additional_params: None,
            })?),
            domain_verified: None,
        })
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"organizationSlug":"acme","providerType":"saml","callbackURL":"/dashboard"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/saml/sso")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    let saml_request = query.get("SAMLRequest").ok_or("missing SAMLRequest")?;
    let xml = inflate_redirect_binding(saml_request)?;
    assert!(xml.contains(
        r#"AssertionConsumerServiceURL="https://app.example.com/sso/saml2/sp/acs/acme-saml""#
    ));

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_omits_redirect_signature_when_authn_requests_are_unsigned(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(query.contains_key("SAMLRequest"));
    assert!(query.contains_key("RelayState"));
    assert!(!query.contains_key("Signature"));
    assert!(!query.contains_key("SigAlg"));

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_saml_provider_returns_authn_request_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["redirect"], true);
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/saml/sso")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    let relay_state = query.get("RelayState").ok_or("missing RelayState")?;
    let saml_request = query.get("SAMLRequest").ok_or("missing SAMLRequest")?;
    let xml = inflate_redirect_binding(saml_request)?;
    assert!(xml.contains("<samlp:AuthnRequest"));
    assert!(xml.contains(
        r#"AssertionConsumerServiceURL="https://app.example.com/sso/saml2/sp/acs/saml-okta""#
    ));
    assert!(xml.contains(r#"Destination="https://idp.example.com/saml/sso""#));

    let verification_records = adapter.records("verification").await;
    assert!(verification_records.iter().any(|record| {
        record.get("identifier")
            == Some(&DbValue::String(format!(
                "saml-authn-request:{relay_state}"
            )))
    }));

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_saml_provider_stores_five_minute_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    let relay_state = query.get("RelayState").ok_or("missing RelayState")?;
    let verification_records = adapter.records("verification").await;
    let record = verification_records
        .iter()
        .find(|record| {
            record.get("identifier")
                == Some(&DbValue::String(format!(
                    "saml-authn-request:{relay_state}"
                )))
        })
        .ok_or("missing SAML AuthnRequest state record")?;
    let Some(DbValue::String(value)) = record.get("value") else {
        return Err("missing SAML AuthnRequest state payload".into());
    };
    let payload: serde_json::Value = serde_json::from_str(value)?;
    let created_at = payload["createdAt"].as_i64().ok_or("missing createdAt")?;
    let expires_at = payload["expiresAt"].as_i64().ok_or("missing expiresAt")?;

    assert_eq!(expires_at - created_at, 300);

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_saml_provider_prefers_explicit_acs_url(
) -> Result<(), Box<dyn std::error::Error>> {
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
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    let saml_request = query.get("SAMLRequest").ok_or("missing SAMLRequest")?;
    let xml = inflate_redirect_binding(saml_request)?;
    assert!(xml.contains(
        r#"AssertionConsumerServiceURL="https://app.example.com/sso/saml2/sp/acs/saml-okta""#
    ));
    assert!(!xml.contains("https://app.example.com/post-auth-callback"));

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_configured_saml_services_prefers_redirect_binding(
) -> Result<(), Box<dyn std::error::Error>> {
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
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false,
                    "idpMetadata":{
                        "singleSignOnService":[{
                            "Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                            "Location":"https://idp.example.com/saml/post"
                        },{
                            "Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                            "Location":"https://idp.example.com/saml/redirect"
                        }]
                    }
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let records = adapter.records("sso_provider").await;
    let Some(DbValue::String(config)) = records[0].get("saml_config") else {
        return Err("missing stored SAML config".into());
    };
    assert!(config.contains(r#""entryPoint":"https://idp.example.com/saml/redirect""#));

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/saml/redirect")
    );

    Ok(())
}
