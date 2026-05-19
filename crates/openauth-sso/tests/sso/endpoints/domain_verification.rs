use super::*;

#[path = "domain_verification/dns_failures.rs"]
mod dns_failures;

#[tokio::test]
async fn register_provider_with_organization_id_requires_membership(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com","organizationId":"org_1"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "ORGANIZATION_MEMBERSHIP_REQUIRED"
    );
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_provider_with_organization_id_allows_org_member(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    let cookie = seed_session(&adapter).await?;
    seed_org_member(&adapter, "member_register", "org_1", "user_1", "member").await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com","organizationId":"org_1"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["organizationId"], "org_1");

    Ok(())
}

#[tokio::test]
async fn request_domain_verification_creates_reusable_verification_token(
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

    let first = router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = json_body(first)?;
    let token = first_body["domainVerificationToken"]
        .as_str()
        .ok_or("missing token")?;

    let verification_records = adapter.records("verification").await;
    assert_eq!(
        verification_records[0].get("identifier"),
        Some(&DbValue::String("_better-auth-token-okta".to_owned()))
    );
    assert_eq!(
        verification_records[0].get("value"),
        Some(&DbValue::String(token.to_owned()))
    );

    let second = router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(json_body(second)?["domainVerificationToken"], token);

    Ok(())
}

#[tokio::test]
async fn register_returns_initial_domain_verification_token_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;

    let register = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(register.status(), StatusCode::OK);
    let register_body = json_body(register)?;
    assert_eq!(register_body["domainVerified"], false);
    let token = register_body["domainVerificationToken"]
        .as_str()
        .ok_or("missing token")?;

    let verification_records = adapter.records("verification").await;
    assert_eq!(
        verification_records[0].get("identifier"),
        Some(&DbValue::String("_better-auth-token-okta".to_owned()))
    );
    assert_eq!(
        verification_records[0].get("value"),
        Some(&DbValue::String(token.to_owned()))
    );

    let request = router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(request.status(), StatusCode::CREATED);
    assert_eq!(json_body(request)?["domainVerificationToken"], token);

    Ok(())
}

#[tokio::test]
async fn domain_verification_allows_organization_member_for_org_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let txt_records = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        Vec<String>,
    >::new()));
    let resolver_records = std::sync::Arc::clone(&txt_records);
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(move |name| {
            let resolver_records = std::sync::Arc::clone(&resolver_records);
            async move {
                Ok(resolver_records
                    .lock()
                    .map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(format!(
                            "records lock poisoned: {error}"
                        ))
                    })?
                    .get(&name)
                    .cloned()
                    .unwrap_or_default())
            }
        });
    let (adapter, router) =
        router_with_options_and_extra_plugins(options, vec![AuthPlugin::new("organization")])?;
    let cookie = seed_session(&adapter).await?;
    seed_org_member(&adapter, "member_domain", "org_1", "user_1", "member").await?;
    SsoProviderStore::new(adapter.as_ref())
        .create(CreateSsoProviderInput {
            provider_id: "org-okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "other_user".to_owned(),
            organization_id: Some("org_1".to_owned()),
            oidc_config: None,
            saml_config: None,
            domain_verified: Some(false),
        })
        .await?;

    let token_response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"org-okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(token_response.status(), StatusCode::CREATED);
    let token = json_body(token_response)?["domainVerificationToken"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    txt_records
        .lock()
        .map_err(|error| std::io::Error::other(format!("records lock poisoned: {error}")))?
        .insert(
            "_better-auth-token-org-okta.example.com".to_owned(),
            vec![format!("_better-auth-token-org-okta={token}")],
        );

    let verify_response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"org-okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(verify_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        adapter.records("ssoProvider").await[0].get("domainVerified"),
        Some(&DbValue::Boolean(true))
    );

    Ok(())
}

#[tokio::test]
async fn domain_verification_rejects_non_org_member_for_org_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default().domain_verification_enabled(true),
        vec![AuthPlugin::new("organization")],
    )?;
    let cookie = seed_session(&adapter).await?;
    SsoProviderStore::new(adapter.as_ref())
        .create(CreateSsoProviderInput {
            provider_id: "org-okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "other_user".to_owned(),
            organization_id: Some("org_1".to_owned()),
            oidc_config: None,
            saml_config: None,
            domain_verified: Some(false),
        })
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"org-okta"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["code"], "FORBIDDEN");

    Ok(())
}

#[tokio::test]
async fn domain_verification_uses_secondary_storage_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let txt_records = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        Vec<String>,
    >::new()));
    let resolver_records = std::sync::Arc::clone(&txt_records);
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(move |name| {
            let resolver_records = std::sync::Arc::clone(&resolver_records);
            async move {
                Ok(resolver_records
                    .lock()
                    .map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(format!(
                            "records lock poisoned: {error}"
                        ))
                    })?
                    .get(&name)
                    .cloned()
                    .unwrap_or_default())
            }
        });
    let storage = std::sync::Arc::new(TestSecondaryStorage::default());
    let (adapter, router) = router_with_options_and_secondary_storage(options, storage.clone())?;
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
    assert_eq!(token_response.status(), StatusCode::CREATED);
    let token = json_body(token_response)?["domainVerificationToken"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();

    assert!(adapter.records("verification").await.is_empty());
    let stored = storage
        .value_for("_better-auth-token-okta")
        .ok_or("missing secondary state")?;
    assert!(stored.contains(&token));
    assert!(storage
        .ttl_for("_better-auth-token-okta")
        .flatten()
        .is_some_and(|ttl| ttl > 0));

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
        adapter.records("ssoProvider").await[0].get("domainVerified"),
        Some(&DbValue::Boolean(true))
    );

    Ok(())
}

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
                        openauth_core::error::OpenAuthError::Api(format!(
                            "queries lock poisoned: {error}"
                        ))
                    })?
                    .push(name.clone());
                Ok(resolver_records
                    .lock()
                    .map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(format!(
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
    let records = adapter.records("ssoProvider").await;
    assert_eq!(
        records[0].get("domainVerified"),
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
                        openauth_core::error::OpenAuthError::Api(format!(
                            "queries lock poisoned: {error}"
                        ))
                    })?
                    .push(name.clone());
                Ok(resolver_records
                    .lock()
                    .map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(format!(
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

#[tokio::test]
async fn domain_verification_uses_custom_token_prefix_and_url_hostname(
) -> Result<(), Box<dyn std::error::Error>> {
    let txt_records = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        Vec<String>,
    >::new()));
    let queries = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let resolver_records = std::sync::Arc::clone(&txt_records);
    let resolver_queries = std::sync::Arc::clone(&queries);
    let mut options = SsoOptions::default().domain_verification_enabled(true);
    options.domain_verification.token_prefix = "openauth-proof".to_owned();
    let options = options.domain_txt_resolver(move |name| {
        let resolver_records = std::sync::Arc::clone(&resolver_records);
        let resolver_queries = std::sync::Arc::clone(&resolver_queries);
        async move {
            resolver_queries
                .lock()
                .map_err(|error| {
                    openauth_core::error::OpenAuthError::Api(format!(
                        "queries lock poisoned: {error}"
                    ))
                })?
                .push(name.clone());
            Ok(resolver_records
                .lock()
                .map_err(|error| {
                    openauth_core::error::OpenAuthError::Api(format!(
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
    let register = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"https://Example.COM/sso"}"#,
            Some(&cookie),
        )?)
        .await?;
    let token = json_body(register)?["domainVerificationToken"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();
    txt_records
        .lock()
        .map_err(|error| std::io::Error::other(format!("records lock poisoned: {error}")))?
        .insert(
            "_openauth-proof-okta.example.com".to_owned(),
            vec![format!("_openauth-proof-okta={token}")],
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
        ["_openauth-proof-okta.example.com"]
    );

    Ok(())
}

#[tokio::test]
async fn domain_verification_rejects_already_verified_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let txt_records = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        Vec<String>,
    >::new()));
    let resolver_records = std::sync::Arc::clone(&txt_records);
    let options = SsoOptions::default()
        .domain_verification_enabled(true)
        .domain_txt_resolver(move |name| {
            let resolver_records = std::sync::Arc::clone(&resolver_records);
            async move {
                Ok(resolver_records
                    .lock()
                    .map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(format!(
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
    let register = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;
    let token = json_body(register)?["domainVerificationToken"]
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
    let verified = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(verified.status(), StatusCode::NO_CONTENT);

    let request_again = router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(request_again.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(request_again)?["code"], "DOMAIN_VERIFIED");

    let verify_again = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(verify_again.status(), StatusCode::CONFLICT);
    assert_eq!(json_body(verify_again)?["code"], "DOMAIN_VERIFIED");

    Ok(())
}

#[tokio::test]
async fn verify_domain_rejects_too_long_dns_label() -> Result<(), Box<dyn std::error::Error>> {
    let long_provider_id = "provider-id-that-makes-the-domain-verification-dns-label-too-long";
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{"providerId":"{long_provider_id}","issuer":"https://idp.example.com","domain":"example.com"}}"#
            ),
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            &format!(r#"{{"providerId":"{long_provider_id}"}}"#),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "IDENTIFIER_TOO_LONG");

    Ok(())
}
