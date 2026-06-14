use super::*;

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
                        rustauth_core::error::RustAuthError::Api(format!(
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
        adapter.records("sso_provider").await[0].get("domain_verified"),
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
