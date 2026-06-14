use super::*;

#[tokio::test]
async fn verify_domain_requires_pending_verification() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;
    SsoProviderStore::new(adapter.as_ref())
        .create(CreateSsoProviderInput {
            provider_id: "okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "user_1".to_owned(),
            organization_id: None,
            oidc_config: None,
            saml_config: None,
            domain_verified: Some(false),
        })
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(response)?["code"], "NO_PENDING_VERIFICATION");

    Ok(())
}

#[tokio::test]
async fn verify_domain_marks_provider_verified_when_txt_record_matches(
) -> Result<(), Box<dyn std::error::Error>> {
    let txt_records = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        Vec<String>,
    >::new()));
    let queries = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let resolver_records = std::sync::Arc::clone(&txt_records);
    let resolver_queries = std::sync::Arc::clone(&queries);
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(move |name| {
            let resolver_records = std::sync::Arc::clone(&resolver_records);
            let resolver_queries = std::sync::Arc::clone(&resolver_queries);
            async move {
                resolver_queries
                    .lock()
                    .map_err(|error| {
                        rustauth_core::error::RustAuthError::Api(format!(
                            "queries lock poisoned: {error}"
                        ))
                    })?
                    .push(name.clone());
                Ok(resolver_records
                    .lock()
                    .map_err(|error| {
                        rustauth_core::error::RustAuthError::Api(format!(
                            "records lock poisoned: {error}"
                        ))
                    })?
                    .get(&name)
                    .cloned()
                    .unwrap_or_default())
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
    txt_records
        .lock()
        .map_err(|error| std::io::Error::other(format!("records lock poisoned: {error}")))?
        .insert(
            "_better-auth-token-okta.example.com".to_owned(),
            vec![format!("_better-auth-token-okta={token}")],
        );

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        queries
            .lock()
            .map_err(|error| std::io::Error::other(format!("queries lock poisoned: {error}")))?
            .as_slice(),
        ["_better-auth-token-okta.example.com"]
    );
    let records = adapter.records("sso_provider").await;
    assert_eq!(
        records[0].get("domain_verified"),
        Some(&DbValue::Boolean(true))
    );

    Ok(())
}

#[tokio::test]
async fn verify_domain_uses_first_hostname_for_multi_domain_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let txt_records = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        Vec<String>,
    >::new()));
    let queries = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let resolver_records = std::sync::Arc::clone(&txt_records);
    let resolver_queries = std::sync::Arc::clone(&queries);
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(move |name| {
            let resolver_records = std::sync::Arc::clone(&resolver_records);
            let resolver_queries = std::sync::Arc::clone(&resolver_queries);
            async move {
                resolver_queries
                    .lock()
                    .map_err(|error| {
                        rustauth_core::error::RustAuthError::Api(format!(
                            "queries lock poisoned: {error}"
                        ))
                    })?
                    .push(name.clone());
                Ok(resolver_records
                    .lock()
                    .map_err(|error| {
                        rustauth_core::error::RustAuthError::Api(format!(
                            "records lock poisoned: {error}"
                        ))
                    })?
                    .get(&name)
                    .cloned()
                    .unwrap_or_default())
            }
        });
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com, secondary.example.com"}"#,
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
    txt_records
        .lock()
        .map_err(|error| std::io::Error::other(format!("records lock poisoned: {error}")))?
        .insert(
            "_better-auth-token-okta.example.com".to_owned(),
            vec![format!("_better-auth-token-okta={token}")],
        );

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        queries
            .lock()
            .map_err(|error| std::io::Error::other(format!("queries lock poisoned: {error}")))?
            .as_slice(),
        ["_better-auth-token-okta.example.com"]
    );

    Ok(())
}
