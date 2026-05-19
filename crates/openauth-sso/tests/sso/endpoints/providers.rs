use super::*;

#[tokio::test]
async fn register_requires_authenticated_session() -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router) = router_with_options(SsoOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn get_and_delete_provider_apply_authenticated_user_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let get_response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/get-provider",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(get_response.status(), StatusCode::OK);
    assert_eq!(json_body(get_response)?["providerId"], "okta");

    let delete_response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/delete-provider",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(delete_response.status(), StatusCode::OK);
    assert_eq!(adapter.records("ssoProvider").await.len(), 0);

    Ok(())
}

#[tokio::test]
async fn organization_admin_can_list_get_update_and_delete_org_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    let cookie = seed_session(&adapter).await?;
    seed_org_member(&adapter, "member_admin", "org_1", "user_1", "admin").await?;
    seed_org_member(&adapter, "member_plain", "org_2", "user_1", "member").await?;
    let store = SsoProviderStore::new(adapter.as_ref());
    store
        .create(CreateSsoProviderInput {
            provider_id: "org-admin-provider".to_owned(),
            issuer: "https://idp.example.com/admin".to_owned(),
            domain: "admin.example.com".to_owned(),
            user_id: "other_user".to_owned(),
            organization_id: Some("org_1".to_owned()),
            oidc_config: None,
            saml_config: None,
            domain_verified: None,
        })
        .await?;
    store
        .create(CreateSsoProviderInput {
            provider_id: "org-member-provider".to_owned(),
            issuer: "https://idp.example.com/member".to_owned(),
            domain: "member.example.com".to_owned(),
            user_id: "other_user".to_owned(),
            organization_id: Some("org_2".to_owned()),
            oidc_config: None,
            saml_config: None,
            domain_verified: None,
        })
        .await?;

    let list = router
        .handle_async(json_request(
            Method::GET,
            "/sso/providers",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = json_body(list)?;
    let providers = list_body["providers"]
        .as_array()
        .ok_or("missing providers")?
        .iter()
        .filter_map(|provider| provider["providerId"].as_str())
        .collect::<Vec<_>>();
    assert!(providers.contains(&"org-admin-provider"));
    assert!(!providers.contains(&"org-member-provider"));

    let get = router
        .handle_async(json_request(
            Method::GET,
            "/sso/get-provider",
            r#"{"providerId":"org-admin-provider"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(get.status(), StatusCode::OK);

    let get_member_provider = router
        .handle_async(json_request(
            Method::GET,
            "/sso/get-provider",
            r#"{"providerId":"org-member-provider"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(get_member_provider.status(), StatusCode::FORBIDDEN);

    let update = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{"providerId":"org-admin-provider","domain":"updated.example.com"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(update.status(), StatusCode::OK);
    assert_eq!(json_body(update)?["domain"], "updated.example.com");

    let update_member_provider = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{"providerId":"org-member-provider","domain":"blocked.example.com"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(update_member_provider.status(), StatusCode::FORBIDDEN);

    let delete = router
        .handle_async(json_request(
            Method::POST,
            "/sso/delete-provider",
            r#"{"providerId":"org-admin-provider"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(delete.status(), StatusCode::OK);

    let delete_member_provider = router
        .handle_async(json_request(
            Method::POST,
            "/sso/delete-provider",
            r#"{"providerId":"org-member-provider"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(delete_member_provider.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
async fn list_providers_returns_only_session_user_providers(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/providers",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["providers"][0]["providerId"], "okta");
    assert_eq!(body["providers"][0]["providerType"], "oidc");
    assert_eq!(body["providers"][0]["type"], "oidc");
    assert_eq!(
        body["providers"][0]["redirectURI"],
        "https://app.example.com/sso/callback/okta"
    );
    assert_eq!(
        body["providers"][0]["spMetadataUrl"],
        "https://app.example.com/sso/saml2/sp/metadata?providerId=okta"
    );

    Ok(())
}

#[tokio::test]
async fn list_providers_returns_saml_certificate_parse_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/sso/providers",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let saml_config = &body["providers"][0]["samlConfig"];
    assert_eq!(
        saml_config["certificateError"],
        "Failed to parse certificate"
    );
    assert!(saml_config.get("cert").is_none());
    assert!(!body.to_string().contains("CERTIFICATE"));

    Ok(())
}
