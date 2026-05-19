use super::*;

#[tokio::test]
async fn verify_domain_returns_stable_error_when_dns_resolver_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(|_| async {
            Err(openauth_core::error::OpenAuthError::Api(
                "dns transport failed".to_owned(),
            ))
        });
    let (adapter, router) = router_with_options(options)?;
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
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = json_body(response)?;
    assert_eq!(body["code"], "DOMAIN_VERIFICATION_FAILED");
    assert_eq!(body["reason"], "resolver_error");
    assert_eq!(
        adapter.records("ssoProvider").await[0].get("domainVerified"),
        Some(&DbValue::Boolean(false))
    );

    Ok(())
}

#[tokio::test]
async fn verify_domain_returns_stable_error_when_txt_records_are_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(|_| async { Ok(Vec::new()) });
    let (adapter, router) = router_with_options(options)?;
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
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = json_body(response)?;
    assert_eq!(body["code"], "DOMAIN_VERIFICATION_FAILED");
    assert_eq!(body["reason"], "no_txt_records");
    assert_eq!(
        adapter.records("ssoProvider").await[0].get("domainVerified"),
        Some(&DbValue::Boolean(false))
    );

    Ok(())
}

#[tokio::test]
async fn verify_domain_returns_stable_error_when_txt_value_does_not_match(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(|_| async { Ok(vec!["wrong-token=value".to_owned()]) });
    let (adapter, router) = router_with_options(options)?;
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
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = json_body(response)?;
    assert_eq!(body["code"], "DOMAIN_VERIFICATION_FAILED");
    assert_eq!(body["reason"], "txt_value_mismatch");
    assert_eq!(
        adapter.records("ssoProvider").await[0].get("domainVerified"),
        Some(&DbValue::Boolean(false))
    );

    Ok(())
}

#[tokio::test]
async fn verify_domain_rejects_txt_value_that_only_contains_expected_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let captured_token = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let resolver_token = std::sync::Arc::clone(&captured_token);
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(move |_| {
            let resolver_token = std::sync::Arc::clone(&resolver_token);
            async move {
                let token = resolver_token
                    .lock()
                    .map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(format!(
                            "token lock poisoned: {error}"
                        ))
                    })?
                    .clone()
                    .unwrap_or_default();
                Ok(vec![format!(
                    "prefix-_better-auth-token-okta={token}-suffix"
                )])
            }
        });
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;
    let token_response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    let token = json_body(token_response)?["domainVerificationToken"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    *captured_token
        .lock()
        .map_err(|error| std::io::Error::other(format!("token lock poisoned: {error}")))? =
        Some(token);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = json_body(response)?;
    assert_eq!(body["code"], "DOMAIN_VERIFICATION_FAILED");
    assert_eq!(body["reason"], "txt_value_mismatch");
    Ok(())
}

#[tokio::test]
async fn verify_domain_returns_stable_error_for_invalid_stored_hostname(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;
    SsoProviderStore::new(adapter.as_ref())
        .create(CreateSsoProviderInput {
            provider_id: "okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "https://".to_owned(),
            user_id: "user_1".to_owned(),
            organization_id: None,
            oidc_config: None,
            saml_config: None,
            domain_verified: Some(false),
        })
        .await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response)?;
    assert_eq!(body["code"], "INVALID_DOMAIN");
    assert_eq!(body["message"], "Invalid domain");
    assert_eq!(
        adapter.records("ssoProvider").await[0].get("domainVerified"),
        Some(&DbValue::Boolean(false))
    );

    Ok(())
}
