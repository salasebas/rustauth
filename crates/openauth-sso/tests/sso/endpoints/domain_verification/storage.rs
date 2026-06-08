use super::*;

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
    let storage = std::sync::Arc::new(crate::support::test_secondary_storage());
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
