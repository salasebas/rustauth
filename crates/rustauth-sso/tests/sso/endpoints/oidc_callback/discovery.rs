use super::*;

#[tokio::test]
async fn oidc_callback_blocks_token_exchange_to_private_ip_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    // The mock provider listens on a loopback address. With the default SSRF
    // guard active (no `allow_private_endpoint_ips` opt-out), the token request
    // to that private IP must be refused, surfacing a stable error instead of
    // completing the login.
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) =
        router_with_options_blocking_private_endpoints(default_oidc_sso_options(&oidc.base_url))?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=invalid_oidc_config"
        ))
    );
    assert!(
        adapter.records("account").await.is_empty(),
        "no account should be linked when the SSRF guard blocks the token request"
    );

    Ok(())
}

#[tokio::test]
async fn oidc_callback_uses_default_sso_provider_from_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(default_oidc_sso_options(&oidc.base_url))?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback?state={state}&code=valid-id-token-code.{nonce}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("default-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_path_uses_default_sso_provider_by_provider_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(default_oidc_sso_options(&oidc.base_url))?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/default-okta?state={state}&code=valid-id-token-code.{nonce}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("default-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_discovers_default_sso_oidc_endpoints_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        default_oidc_sso_options_requiring_discovery(&oidc.base_url),
        vec![oidc.base_url.clone()],
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "/sso/callback/default-okta?state={state}&code=self-issued-id-token-code.{nonce}"
            ),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("default-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_redirects_stable_discovery_error_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let mut config = OidcConfig {
        issuer: oidc.base_url.clone(),
        pkce: true,
        client_id: "client_123456".to_owned(),
        client_secret: "super-secret".into(),
        discovery_endpoint: format!("{}/.well-known/openid-configuration", oidc.base_url),
        authorization_endpoint: Some(format!("{}/authorize", oidc.base_url)),
        token_endpoint: Some(format!("{}/token", oidc.base_url)),
        user_info_endpoint: None,
        jwks_endpoint: Some(format!("{}/keys", oidc.base_url)),
        revocation_endpoint: None,
        end_session_endpoint: None,
        introspection_endpoint: None,
        token_endpoint_authentication: None,
        scopes: None,
        mapping: None,
        override_user_info: false,
    };
    SsoProviderStore::new(&adapter)
        .create(CreateSsoProviderInput {
            provider_id: "stable-error-okta".to_owned(),
            issuer: oidc.base_url.clone(),
            domain: "example.com".to_owned(),
            user_id: "default".to_owned(),
            organization_id: None,
            oidc_config: Some(serde_json::to_string(&config)?),
            saml_config: None,
            domain_verified: None,
        })
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"stable-error-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;
    config.discovery_endpoint = format!("{}/missing-openid-configuration", oidc.base_url);
    config.token_endpoint = None;
    config.jwks_endpoint = None;
    adapter
        .update(
            Update::new("sso_provider")
                .where_clause(Where::new(
                    "provider_id",
                    DbValue::String("stable-error-okta".to_owned()),
                ))
                .data(
                    "oidc_config",
                    DbValue::String(serde_json::to_string(&config)?),
                ),
        )
        .await?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/stable-error-okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=discovery_not_found"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn oidc_callback_discovers_stored_oidc_provider_endpoints_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    seed_runtime_discovery_oidc_provider(&adapter, &oidc.base_url).await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"runtime-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "/sso/callback/runtime-okta?state={state}&code=self-issued-id-token-code.{nonce}"
            ),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("runtime-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_discovers_missing_jwks_even_when_userinfo_endpoint_exists(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let config = OidcConfig {
        issuer: oidc.base_url.clone(),
        pkce: true,
        client_id: "client_123456".to_owned(),
        client_secret: "super-secret".into(),
        discovery_endpoint: format!("{}/.well-known/openid-configuration", oidc.base_url),
        authorization_endpoint: Some(format!("{}/authorize", oidc.base_url)),
        token_endpoint: Some(format!("{}/token", oidc.base_url)),
        user_info_endpoint: Some(format!("{}/userinfo", oidc.base_url)),
        jwks_endpoint: Some(format!("{}/keys", oidc.base_url)),
        revocation_endpoint: None,
        end_session_endpoint: None,
        introspection_endpoint: None,
        token_endpoint_authentication: None,
        scopes: None,
        mapping: None,
        override_user_info: false,
    };
    SsoProviderStore::new(&adapter)
        .create(CreateSsoProviderInput {
            provider_id: "missing-jwks-okta".to_owned(),
            issuer: oidc.base_url.clone(),
            domain: "example.com".to_owned(),
            user_id: "default".to_owned(),
            organization_id: None,
            oidc_config: Some(serde_json::to_string(&config)?),
            saml_config: None,
            domain_verified: None,
        })
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"missing-jwks-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;
    let mut callback_config = config;
    callback_config.jwks_endpoint = None;
    adapter
        .update(
            Update::new("sso_provider")
                .where_clause(Where::new(
                    "provider_id",
                    DbValue::String("missing-jwks-okta".to_owned()),
                ))
                .data(
                    "oidc_config",
                    DbValue::String(serde_json::to_string(&callback_config)?),
                ),
        )
        .await?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/missing-jwks-okta?state={state}&code=self-issued-id-token-code.{nonce}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("missing-jwks-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_redirects_discovery_error_when_jwks_missing_and_discovery_unavailable(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let config = OidcConfig {
        issuer: oidc.base_url.clone(),
        pkce: true,
        client_id: "client_123456".to_owned(),
        client_secret: "super-secret".into(),
        discovery_endpoint: format!("{}/.well-known/openid-configuration", oidc.base_url),
        authorization_endpoint: Some(format!("{}/authorize", oidc.base_url)),
        token_endpoint: Some(format!("{}/token", oidc.base_url)),
        user_info_endpoint: Some(format!("{}/userinfo", oidc.base_url)),
        jwks_endpoint: Some(format!("{}/keys", oidc.base_url)),
        revocation_endpoint: None,
        end_session_endpoint: None,
        introspection_endpoint: None,
        token_endpoint_authentication: None,
        scopes: None,
        mapping: None,
        override_user_info: false,
    };
    SsoProviderStore::new(&adapter)
        .create(CreateSsoProviderInput {
            provider_id: "bad-discovery-jwks-okta".to_owned(),
            issuer: oidc.base_url.clone(),
            domain: "example.com".to_owned(),
            user_id: "default".to_owned(),
            organization_id: None,
            oidc_config: Some(serde_json::to_string(&config)?),
            saml_config: None,
            domain_verified: None,
        })
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"bad-discovery-jwks-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;
    let mut callback_config = config;
    callback_config.discovery_endpoint = format!("{}/missing-openid-configuration", oidc.base_url);
    callback_config.jwks_endpoint = None;
    adapter
        .update(
            Update::new("sso_provider")
                .where_clause(Where::new(
                    "provider_id",
                    DbValue::String("bad-discovery-jwks-okta".to_owned()),
                ))
                .data(
                    "oidc_config",
                    DbValue::String(serde_json::to_string(&callback_config)?),
                ),
        )
        .await?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/bad-discovery-jwks-okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=discovery_not_found"
        ))
    );
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}
