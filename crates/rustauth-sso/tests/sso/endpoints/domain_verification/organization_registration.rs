use super::*;

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
    assert!(adapter.records("sso_provider").await.is_empty());

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
