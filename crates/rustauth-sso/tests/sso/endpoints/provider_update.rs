use super::*;

#[tokio::test]
async fn update_provider_applies_owner_scope_and_resets_domain_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{"providerId":"okta","issuer":"https://login.example.com","domain":"corp.example.com","organizationId":"org_1"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["providerId"], "okta");
    assert_eq!(body["issuer"], "https://login.example.com");
    assert_eq!(body["domain"], "corp.example.com");
    assert_eq!(body["organizationId"], "org_1");
    assert_eq!(body["domainVerified"], false);

    let records = adapter.records("sso_provider").await;
    assert_eq!(
        records[0].get("domain"),
        Some(&DbValue::String("corp.example.com".to_owned()))
    );
    assert_eq!(
        records[0].get("organization_id"),
        Some(&DbValue::String("org_1".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn update_provider_rejects_organization_id_without_membership(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    let cookie = seed_session(&adapter).await?;
    seed_organization(&adapter, "org_1", "acme").await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "ORGANIZATION_MEMBERSHIP_REQUIRED"
    );
    let records = adapter.records("sso_provider").await;
    assert_eq!(records[0].get("organization_id"), Some(&DbValue::Null));

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn update_provider_rejects_saml_config_with_unknown_digest_algorithm(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"saml-okta",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false,
                    "digestAlgorithm":"sha257"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_UNKNOWN_ALGORITHM");

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn update_provider_rejects_empty_update_body() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "NO_UPDATE_FIELDS");

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn update_provider_merges_partial_saml_config() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"saml-okta",
                "samlConfig":{
                    "entryPoint":"https://idp.example.com/saml/updated",
                    "wantAssertionsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(
        body["samlConfig"]["entryPoint"],
        "https://idp.example.com/saml/updated"
    );
    assert_eq!(body["samlConfig"]["wantAssertionsSigned"], false);
    assert!(body["samlConfig"].get("cert").is_none());

    let records = adapter.records("sso_provider").await;
    let Some(DbValue::String(config)) = records[0].get("saml_config") else {
        return Err("missing stored SAML config".into());
    };
    assert!(config.contains(r#""cert":"CERTIFICATE""#));
    assert!(config.contains(r#""entryPoint":"https://idp.example.com/saml/updated""#));

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn update_provider_merges_partial_oidc_config_and_keeps_secret(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"okta",
                "oidcConfig":{
                    "pkce":false,
                    "revocationEndpoint":"https://idp.example.com/revoke",
                    "endSessionEndpoint":"https://idp.example.com/endsession",
                    "introspectionEndpoint":"https://idp.example.com/introspection",
                    "scopes":["openid","profile"]
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["oidcConfig"]["pkce"], false);
    assert_eq!(
        body["oidcConfig"]["revocationEndpoint"],
        "https://idp.example.com/revoke"
    );
    assert_eq!(
        body["oidcConfig"]["endSessionEndpoint"],
        "https://idp.example.com/endsession"
    );
    assert_eq!(
        body["oidcConfig"]["introspectionEndpoint"],
        "https://idp.example.com/introspection"
    );
    assert_eq!(body["oidcConfig"]["scopes"], json!(["openid", "profile"]));
    assert_eq!(body["oidcConfig"]["clientIdLastFour"], "****3456");

    let records = adapter.records("sso_provider").await;
    let Some(DbValue::String(config)) = records[0].get("oidc_config") else {
        return Err("missing stored OIDC config".into());
    };
    assert!(config.contains(r#""clientSecret":"super-secret""#));
    assert!(config.contains(r#""pkce":false"#));
    assert!(config.contains(r#""revocationEndpoint":"https://idp.example.com/revoke""#));
    assert!(config.contains(r#""endSessionEndpoint":"https://idp.example.com/endsession""#));
    assert!(config.contains(r#""introspectionEndpoint":"https://idp.example.com/introspection""#));

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn update_provider_empty_authorization_endpoint_triggers_runtime_discovery_on_sign_in(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let cookie = seed_session(&adapter).await?;

    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                "providerId":"okta",
                "issuer":"{}",
                "domain":"example.com",
                "oidcConfig":{{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "pkce":true
                }}
            }}"#,
                oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"okta",
                "oidcConfig":{
                    "authorizationEndpoint":""
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(json_body(response)?["oidcConfig"]["authorizationEndpoint"].is_null());

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let sign_in_body = json_body(sign_in)?;
    assert!(sign_in_body["url"]
        .as_str()
        .is_some_and(|url| url.starts_with(&format!("{}/authorize?", oidc.base_url))));

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn update_provider_rejects_untrusted_manual_oidc_endpoint_when_strict_policy_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.oidc.strict_manual_endpoint_origins = true;
    let (adapter, router) = router_with_options_and_trusted_origins(
        options,
        vec!["https://idp.example.com".to_owned()],
    )?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"okta",
                "oidcConfig":{
                    "tokenEndpoint":"https://evil.example.com/token"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "discovery_untrusted_origin");

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn update_provider_rejects_oversized_saml_idp_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.max_metadata_size = 16;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"saml-okta",
                "samlConfig":{
                    "idpMetadata":{
                        "metadata":"<EntityDescriptor><IDPSSODescriptor /></EntityDescriptor>"
                    }
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_METADATA_TOO_LARGE");

    Ok(())
}

#[tokio::test]
#[cfg(all(feature = "oidc", feature = "saml"))]
async fn update_provider_rejects_config_update_for_wrong_provider_type(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"saml-okta",
                "oidcConfig":{"pkce":false}
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "OIDC_CONFIG_NOT_CONFIGURED");

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn update_provider_rejects_invalid_oidc_endpoint_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"okta",
                "oidcConfig":{
                    "authorizationEndpoint":"/relative/authorize"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_OIDC_CONFIG");

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn update_provider_rejects_public_suffix_domain() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{"providerId":"okta","domain":"com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_DOMAIN");
    let records = adapter.records("sso_provider").await;
    assert_eq!(
        records[0].get("domain"),
        Some(&DbValue::String("example.com".to_owned()))
    );

    Ok(())
}

async fn mark_provider_domain_verified(
    adapter: &MemoryAdapter,
    provider_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    SsoProviderStore::new(adapter)
        .update_domain_verified(provider_id, true)
        .await?
        .ok_or_else(|| format!("provider {provider_id} not found"))?;
    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn update_provider_oidc_trust_boundary_change_resets_domain_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;
    mark_provider_domain_verified(&adapter, "okta").await?;

    for payload in [
        r#"{"providerId":"okta","oidcConfig":{"jwksEndpoint":"https://evil.example.com/keys"}}"#,
        r#"{"providerId":"okta","oidcConfig":{"issuer":"https://evil.example.com"}}"#,
        r#"{"providerId":"okta","oidcConfig":{"userInfoEndpoint":"https://evil.example.com/userinfo"}}"#,
    ] {
        mark_provider_domain_verified(&adapter, "okta").await?;
        let response = router
            .handle_async(json_request(
                Method::POST,
                "/sso/update-provider",
                payload,
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "payload: {payload}");
        let body = json_body(response)?;
        assert_eq!(body["domainVerified"], false, "payload: {payload}");
        assert_eq!(
            adapter.records("sso_provider").await[0].get("domain_verified"),
            Some(&DbValue::Boolean(false)),
            "payload: {payload}"
        );
    }

    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn update_provider_oidc_safe_metadata_preserves_domain_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;
    mark_provider_domain_verified(&adapter, "okta").await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"okta",
                "oidcConfig":{
                    "pkce":false,
                    "scopes":["openid","profile"],
                    "revocationEndpoint":"https://idp.example.com/revoke"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["domainVerified"], true);
    assert_eq!(
        adapter.records("sso_provider").await[0].get("domain_verified"),
        Some(&DbValue::Boolean(true))
    );

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn update_provider_saml_trust_boundary_change_resets_domain_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;
    mark_provider_domain_verified(&adapter, "saml-okta").await?;

    for payload in [
        r#"{"providerId":"saml-okta","samlConfig":{"cert":"ROTATED-CERTIFICATE"}}"#,
        r#"{"providerId":"saml-okta","samlConfig":{"entryPoint":"https://evil.example.com/saml/sso"}}"#,
        r#"{"providerId":"saml-okta","samlConfig":{"idpMetadata":{"entityId":"https://evil.example.com"}}}"#,
    ] {
        mark_provider_domain_verified(&adapter, "saml-okta").await?;
        let response = router
            .handle_async(json_request(
                Method::POST,
                "/sso/update-provider",
                payload,
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "payload: {payload}");
        let body = json_body(response)?;
        assert_eq!(body["domainVerified"], false, "payload: {payload}");
        assert_eq!(
            adapter.records("sso_provider").await[0].get("domain_verified"),
            Some(&DbValue::Boolean(false)),
            "payload: {payload}"
        );
    }

    Ok(())
}

#[tokio::test]
#[cfg(feature = "saml")]
async fn update_provider_saml_callback_url_preserves_domain_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;
    mark_provider_domain_verified(&adapter, "saml-okta").await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{
                "providerId":"saml-okta",
                "samlConfig":{
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta-v2"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["domainVerified"], true);
    assert_eq!(
        adapter.records("sso_provider").await[0].get("domain_verified"),
        Some(&DbValue::Boolean(true))
    );

    Ok(())
}
