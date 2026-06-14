use super::*;

#[tokio::test]
async fn register_persists_provider_for_session_user() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["providerId"], "okta");
    assert_eq!(body["domainVerified"], false);

    let records = adapter.records("sso_provider").await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("provider_id"),
        Some(&rustauth_core::db::DbValue::String("okta".to_owned()))
    );
    assert_eq!(
        records[0].get("user_id"),
        Some(&rustauth_core::db::DbValue::String("user_1".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn register_uses_custom_sso_provider_model_name() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions {
        model_name: "enterpriseSsoProvider".to_owned(),
        ..SsoOptions::default()
    })?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(adapter.records("sso_provider").await.is_empty());
    let records = adapter.records("enterpriseSsoProvider").await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("provider_id"),
        Some(&rustauth_core::db::DbValue::String("okta".to_owned()))
    );

    Ok(())
}
