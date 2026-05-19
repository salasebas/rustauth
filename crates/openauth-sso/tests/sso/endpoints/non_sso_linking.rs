use super::*;

#[tokio::test]
async fn sign_up_email_assigns_user_to_verified_sso_domain_organization(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default().domain_verification_enabled(true),
        vec![AuthPlugin::new("organization")],
    )?;
    seed_organization(&adapter, "org_1", "acme").await?;
    create_domain_provider(&adapter, "okta", "org_1", "example.com", true).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let users = adapter.records("user").await;
    let user_id = user_id_by_email(&users, "ada@example.com")?;
    let members = adapter.records("member").await;
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].get("organization_id"),
        Some(&DbValue::String("org_1".to_owned()))
    );
    assert_eq!(members[0].get("user_id"), Some(user_id));

    Ok(())
}

#[tokio::test]
async fn sign_in_email_assigns_existing_user_to_verified_sso_domain_organization(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default().domain_verification_enabled(true),
        vec![AuthPlugin::new("organization")],
    )?;
    seed_organization(&adapter, "org_1", "acme").await?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    assert!(adapter.records("member").await.is_empty());

    create_domain_provider(&adapter, "okta", "org_1", "example.com", true).await?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let users = adapter.records("user").await;
    let user_id = user_id_by_email(&users, "ada@example.com")?;
    let members = adapter.records("member").await;
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].get("organization_id"),
        Some(&DbValue::String("org_1".to_owned()))
    );
    assert_eq!(members[0].get("user_id"), Some(user_id));

    Ok(())
}

async fn create_domain_provider(
    adapter: &MemoryAdapter,
    provider_id: &str,
    organization_id: &str,
    domain: &str,
    verified: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    SsoProviderStore::new(adapter)
        .create(CreateSsoProviderInput {
            provider_id: provider_id.to_owned(),
            issuer: format!("https://idp.example.com/{provider_id}"),
            domain: domain.to_owned(),
            user_id: "owner_user".to_owned(),
            organization_id: Some(organization_id.to_owned()),
            oidc_config: None,
            saml_config: None,
            domain_verified: Some(verified),
        })
        .await?;
    Ok(())
}

fn user_id_by_email<'a>(
    users: &'a [openauth_core::db::DbRecord],
    email: &str,
) -> Result<&'a DbValue, Box<dyn std::error::Error>> {
    users
        .iter()
        .find(|record| record.get("email") == Some(&DbValue::String(email.to_owned())))
        .and_then(|record| record.get("id"))
        .ok_or_else(|| format!("user with email {email} was not persisted").into())
}
