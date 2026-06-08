use super::*;

#[path = "../../../fixtures/saml_crypto.rs"]
mod saml_crypto_helpers;

use saml_crypto_helpers::{register_saml_crypto_provider_body, signed_idp_logout_response_post};

#[tokio::test]
async fn saml_slo_logout_response_requires_signature_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    options.saml.want_logout_response_signed = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, false, false, false),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-slo-signed-response")?;
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
    let unsigned_response = logout_response_xml(&request_id)?;

    let unsigned = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/slo/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":"/logged-out"}}"#,
                serde_json::to_string(&unsigned_response)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(unsigned.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(unsigned)?["code"],
        "SAML_LOGOUT_RESPONSE_SIGNATURE_REQUIRED"
    );

    let signed_response = signed_idp_logout_response_post(&request_id)?;
    let signed = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/slo/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":"/logged-out"}}"#,
                serde_json::to_string(&signed_response)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(signed.status(), StatusCode::FOUND);
    assert_eq!(
        signed.headers().get(header::LOCATION),
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
    assert!(body.contains(r#"<form method="post" action="https://idp.example.com/saml/slo-post">"#));
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
        Some(&http::HeaderValue::from_static("/logged-out"))
    );

    Ok(())
}

#[tokio::test]
async fn saml_slo_logout_response_rejects_in_response_to_state_for_another_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    SsoProviderStore::new(adapter.as_ref())
        .create(CreateSsoProviderInput {
            provider_id: "saml-other".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "user_1".to_owned(),
            organization_id: None,
            oidc_config: None,
            saml_config: Some(serde_json::to_string(&SamlConfig {
                issuer: "https://app.example.com/sso/saml2/sp/metadata".to_owned(),
                entry_point: "https://idp.example.com/saml/sso".to_owned(),
                cert: "CERTIFICATE".to_owned(),
                callback_url: "https://app.example.com/sso/saml2/sp/acs/saml-other".to_owned(),
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
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-slo-provider-mismatch")?;
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
    let record_key = format!("saml-logout-request:{request_id}");

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/slo/saml-other",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":"/logged-out"}}"#,
                serde_json::to_string(&logout_response)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH"
    );
    assert!(adapter
        .records("verification")
        .await
        .iter()
        .any(|record| { record.get("identifier") == Some(&DbValue::String(record_key.clone())) }));

    Ok(())
}

#[tokio::test]
async fn saml_slo_logout_response_uses_stored_callback_over_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-slo-callback-binding")?;
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
                r#"{{"SAMLResponse":{},"RelayState":"/different"}}"#,
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

    Ok(())
}
