use super::*;

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
    options.domain_verification.token_prefix = "rustauth-proof".to_owned();
    let options = options.domain_txt_resolver(move |name| {
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
            "_rustauth-proof-okta.example.com".to_owned(),
            vec![format!("_rustauth-proof-okta={token}")],
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
        ["_rustauth-proof-okta.example.com"]
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
