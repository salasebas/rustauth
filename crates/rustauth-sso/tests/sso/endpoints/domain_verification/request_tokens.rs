use super::*;

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
