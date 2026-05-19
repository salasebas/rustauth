use super::*;

#[tokio::test]
async fn saml_callback_endpoint_uses_acs_pipeline() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-callback-alias")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/callback/saml-okta",
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

#[tokio::test]
async fn saml_authn_request_state_uses_secondary_storage_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = std::sync::Arc::new(TestSecondaryStorage::default());
    let (adapter, router) =
        router_with_options_and_secondary_storage(SsoOptions::default(), storage.clone())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;

    let relay_state = saml_sign_in_relay_state(&router).await?;
    let authn_key = format!("saml-authn-request:{relay_state}");

    assert!(adapter.records("verification").await.is_empty());
    assert!(storage
        .value_for(&authn_key)
        .is_some_and(|value| value.contains(&relay_state)));
    assert!(storage
        .ttl_for(&authn_key)
        .flatten()
        .is_some_and(|ttl| ttl > 0));

    let saml_response = valid_saml_response(&relay_state, "assertion-secondary-state")?;
    let callback = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert!(storage.deleted_keys().contains(&authn_key));
    assert!(storage
        .value_for("saml-used-assertion:assertion-secondary-state")
        .is_some());
    assert!(adapter.records("verification").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn saml_acs_uses_in_response_to_state_when_relay_state_is_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = std::sync::Arc::new(TestSecondaryStorage::default());
    let (adapter, router) =
        router_with_options_and_secondary_storage(SsoOptions::default(), storage.clone())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;

    let relay_state = saml_sign_in_relay_state(&router).await?;
    let authn_key = format!("saml-authn-request:{relay_state}");
    let saml_response = valid_saml_response(&relay_state, "assertion-in-response-to-only")?;

    let callback = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{}}}"#,
                serde_json::to_string(&saml_response)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(storage.deleted_keys().contains(&authn_key));

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_unknown_in_response_to_without_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let saml_response = valid_saml_response("missing-request", "assertion-unknown-in-response-to")?;

    let callback = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{}}}"#,
                serde_json::to_string(&saml_response)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(callback)?["code"], "UNKNOWN_AUTHN_REQUEST");

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_in_response_to_state_for_another_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
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
    let saml_response = valid_saml_response(&relay_state, "assertion-provider-mismatch")?;
    let saml_response = tamper_base64_xml(&saml_response, "saml-okta", "saml-other")?;

    let callback = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-other",
            &format!(
                r#"{{"SAMLResponse":{}}}"#,
                serde_json::to_string(&saml_response)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(callback)?["code"],
        "SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH"
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_replayed_assertion_id() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;

    let first_relay = saml_sign_in_relay_state(&router).await?;
    let first_response = valid_saml_response(&first_relay, "assertion-replay")?;
    let first = post_saml_acs(&router, &first_response, &first_relay).await?;
    assert_eq!(first.status(), StatusCode::FOUND);

    let second_relay = saml_sign_in_relay_state(&router).await?;
    let second_response = valid_saml_response(&second_relay, "assertion-replay")?;
    let second = post_saml_acs(&router, &second_response, &second_relay).await?;

    assert_eq!(second.status(), StatusCode::FOUND);
    assert_eq!(
        second.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=replayed_saml_assertion"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn saml_replay_key_ttl_uses_assertion_expiration_not_request_ttl(
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = std::sync::Arc::new(TestSecondaryStorage::default());
    let mut options = SsoOptions::default();
    options.saml.request_ttl = time::Duration::seconds(5);
    let (adapter, router) = router_with_options_and_secondary_storage(options, storage.clone())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;

    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-replay-ttl")?;
    let callback = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    let ttl = storage
        .ttl_for("saml-used-assertion:assertion-replay-ttl")
        .flatten()
        .ok_or("missing replay TTL")?;
    assert!(
        ttl > 60,
        "replay TTL should follow assertion expiration, got {ttl}"
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_assertion_without_id() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let response = valid_saml_response(&relay_state, "assertion-missing-id")?;
    let response = tamper_base64_xml(
        &response,
        r#"Assertion ID="assertion-missing-id""#,
        "Assertion",
    )?;

    let callback = post_saml_acs(&router, &response, &relay_state).await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=invalid_saml_response"
        ))
    );
    assert!(adapter.records("user").await.iter().all(|record| {
        record.get("email") != Some(&DbValue::String("saml-user@example.com".to_owned()))
    }));
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_encrypted_assertion_until_decryption_is_supported(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let response = encrypted_saml_response(&relay_state)?;

    let callback = post_saml_acs(&router, &response, &relay_state).await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=encrypted_saml_assertion_unsupported"
        ))
    );
    assert!(adapter.records("user").await.iter().all(|record| {
        record.get("email") != Some(&DbValue::String("saml-user@example.com".to_owned()))
    }));
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_encrypted_assertion_with_key_without_crypto_feature(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let body = serde_json::json!({
        "providerId": "saml-okta",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "entryPoint": "https://idp.example.com/saml/sso",
            "cert": "CERTIFICATE",
            "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/saml-okta",
            "spMetadata": {"entityId": "https://app.example.com/saml/sp"},
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "decryptionPvk": "-----BEGIN PRIVATE KEY-----\nunsupported\n-----END PRIVATE KEY-----"
        }
    });
    let register = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &body.to_string(),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(register.status(), StatusCode::OK);
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let response = encrypted_saml_response(&relay_state)?;

    let callback = post_saml_acs(&router, &response, &relay_state).await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=encrypted_saml_assertion_unsupported"
        ))
    );
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}
