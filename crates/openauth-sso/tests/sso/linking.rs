use openauth_core::context::create_auth_context;
use openauth_core::db::{Create, DbAdapter, DbValue, MemoryAdapter, User};
use openauth_core::options::OpenAuthOptions;
use openauth_core::plugin::AuthPlugin;
use openauth_sso::linking::{
    assign_organization_by_domain, assign_organization_from_provider,
    provider_matches_email_domain, validate_provider_domains, NormalizedSsoProfile,
};
use openauth_sso::{
    CreateSsoProviderInput, DomainVerificationOptions, OrganizationProvisioningOptions,
    SsoProviderRecord, SsoProviderStore,
};
use time::OffsetDateTime;

#[test]
fn provider_domain_matching_rejects_public_suffix_catchalls() {
    let provider = provider("com");

    assert!(!provider_matches_email_domain(
        &provider,
        "user@example.com"
    ));
}

#[test]
fn provider_domain_matching_accepts_exact_and_subdomain_matches() {
    let provider = provider("example.com,subsidiary.co.uk");

    assert!(provider_matches_email_domain(&provider, "user@example.com"));
    assert!(provider_matches_email_domain(
        &provider,
        "user@team.subsidiary.co.uk"
    ));
    assert!(!provider_matches_email_domain(
        &provider,
        "user@attacker-example.com"
    ));
}

#[test]
fn provider_domain_matching_normalizes_url_case_and_trailing_dot() {
    let provider = provider("https://Example.COM/sso., https://Subsidiary.example.org/path");

    assert!(provider_matches_email_domain(
        &provider,
        "USER@TEAM.EXAMPLE.COM"
    ));
    assert!(provider_matches_email_domain(
        &provider,
        "user@subsidiary.example.org"
    ));
}

#[test]
fn provider_domain_matching_rejects_invalid_email_or_empty_segments() {
    let provider = provider("example.com,,https:///");

    assert!(!provider_matches_email_domain(&provider, "not-an-email"));
    assert!(!provider_matches_email_domain(&provider, "user@"));
    assert!(provider_matches_email_domain(&provider, "user@example.com"));
}

#[test]
fn validate_provider_domains_rejects_empty_segments_and_public_suffixes() {
    assert!(validate_provider_domains(
        "https://Example.COM/sso, subsidiary.example.org."
    ));
    assert!(!validate_provider_domains(""));
    assert!(!validate_provider_domains("example.com,"));
    assert!(!validate_provider_domains("example.com,,example.org"));
    assert!(!validate_provider_domains("example.com,com"));
}

#[tokio::test]
async fn assign_organization_from_provider_uses_default_member_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = organization_context()?;
    let adapter = MemoryAdapter::new();
    let user = user("user_1", "sso-user@example.com");
    let mut provider = provider("example.com");
    provider.organization_id = Some("org_1".to_owned());

    assign_organization_from_provider(
        &context,
        &adapter,
        &OrganizationProvisioningOptions::default(),
        &user,
        &profile("oidc", "okta", "account_1", "sso-user@example.com"),
        &provider,
        None,
    )
    .await?;

    let members = adapter.records("member").await;
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].get("organization_id"),
        Some(&DbValue::String("org_1".to_owned()))
    );
    assert_eq!(
        members[0].get("user_id"),
        Some(&DbValue::String("user_1".to_owned()))
    );
    assert_eq!(
        members[0].get("role"),
        Some(&DbValue::String("member".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn assign_organization_from_provider_skips_when_disabled_or_already_member(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = organization_context()?;
    let adapter = MemoryAdapter::new();
    let user = user("user_1", "sso-user@example.com");
    let mut provider = provider("example.com");
    provider.organization_id = Some("org_1".to_owned());
    seed_member(&adapter, "member_existing", "org_1", "user_1", "admin").await?;

    assign_organization_from_provider(
        &context,
        &adapter,
        &OrganizationProvisioningOptions {
            disabled: true,
            ..OrganizationProvisioningOptions::default()
        },
        &user,
        &profile("oidc", "okta", "account_1", "sso-user@example.com"),
        &provider,
        None,
    )
    .await?;
    assign_organization_from_provider(
        &context,
        &adapter,
        &OrganizationProvisioningOptions::default(),
        &user,
        &profile("oidc", "okta", "account_1", "sso-user@example.com"),
        &provider,
        None,
    )
    .await?;

    let members = adapter.records("member").await;
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].get("role"),
        Some(&DbValue::String("admin".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn assign_organization_from_provider_skips_without_org_plugin_or_provider_org(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let adapter = MemoryAdapter::new();
    let user = user("user_1", "sso-user@example.com");
    let no_org_provider = provider("example.com");

    assign_organization_from_provider(
        &context,
        &adapter,
        &OrganizationProvisioningOptions::default(),
        &user,
        &profile("oidc", "okta", "account_1", "sso-user@example.com"),
        &no_org_provider,
        None,
    )
    .await?;

    let mut org_provider = provider("example.com");
    org_provider.organization_id = Some("org_1".to_owned());
    assign_organization_from_provider(
        &context,
        &adapter,
        &OrganizationProvisioningOptions::default(),
        &user,
        &profile("oidc", "okta", "account_1", "sso-user@example.com"),
        &org_provider,
        None,
    )
    .await?;

    assert!(adapter.records("member").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn assign_organization_from_provider_uses_configured_default_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = organization_context()?;
    let adapter = MemoryAdapter::new();
    let user = user("user_1", "sso-user@example.com");
    let mut provider = provider("example.com");
    provider.organization_id = Some("org_1".to_owned());

    assign_organization_from_provider(
        &context,
        &adapter,
        &OrganizationProvisioningOptions::default().default_role("admin"),
        &user,
        &profile("oidc", "okta", "account_1", "sso-user@example.com"),
        &provider,
        None,
    )
    .await?;

    let members = adapter.records("member").await;
    assert_eq!(
        members[0].get("role"),
        Some(&DbValue::String("admin".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn assign_organization_from_provider_uses_configured_role_callback(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = organization_context()?;
    let adapter = MemoryAdapter::new();
    let user = user("user_1", "sso-user@example.com");
    let mut provider = provider("example.com");
    provider.organization_id = Some("org_1".to_owned());
    let provisioning = OrganizationProvisioningOptions::default().get_role(|input| async move {
        if input.profile.provider_type == "saml" {
            Ok("admin".to_owned())
        } else {
            Ok("member".to_owned())
        }
    });

    assign_organization_from_provider(
        &context,
        &adapter,
        &provisioning,
        &user,
        &profile("saml", "okta", "account_1", "sso-user@example.com"),
        &provider,
        None,
    )
    .await?;

    let members = adapter.records("member").await;
    assert_eq!(
        members[0].get("role"),
        Some(&DbValue::String("admin".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn assign_organization_by_domain_prefers_verified_duplicate_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = organization_context()?;
    let adapter = MemoryAdapter::new();
    create_provider(
        &adapter,
        "unverified",
        "org_unverified",
        "example.com",
        false,
    )
    .await?;
    create_provider(&adapter, "verified", "org_verified", "example.com", true).await?;
    let user = user("user_1", "sso-user@example.com");

    assign_organization_by_domain(
        &context,
        &adapter,
        &OrganizationProvisioningOptions::default(),
        &DomainVerificationOptions {
            enabled: true,
            ..DomainVerificationOptions::default()
        },
        &user,
    )
    .await?;

    let members = adapter.records("member").await;
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].get("organization_id"),
        Some(&DbValue::String("org_verified".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn assign_organization_by_domain_skips_unverified_provider_when_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = organization_context()?;
    let adapter = MemoryAdapter::new();
    create_provider(
        &adapter,
        "unverified",
        "org_unverified",
        "example.com",
        false,
    )
    .await?;
    let user = user("user_1", "sso-user@example.com");

    assign_organization_by_domain(
        &context,
        &adapter,
        &OrganizationProvisioningOptions::default(),
        &DomainVerificationOptions {
            enabled: true,
            ..DomainVerificationOptions::default()
        },
        &user,
    )
    .await?;

    assert!(adapter.records("member").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn assign_organization_by_domain_allows_unverified_provider_when_verification_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = organization_context()?;
    let adapter = MemoryAdapter::new();
    create_provider(
        &adapter,
        "unverified",
        "org_unverified",
        "example.com",
        false,
    )
    .await?;
    let user = user("user_1", "sso-user@example.com");

    assign_organization_by_domain(
        &context,
        &adapter,
        &OrganizationProvisioningOptions::default(),
        &DomainVerificationOptions::default(),
        &user,
    )
    .await?;

    let members = adapter.records("member").await;
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0].get("organization_id"),
        Some(&DbValue::String("org_unverified".to_owned()))
    );

    Ok(())
}

fn provider(domain: &str) -> SsoProviderRecord {
    SsoProviderRecord {
        id: "provider_1".to_owned(),
        issuer: "https://idp.example.com".to_owned(),
        oidc_config: None,
        saml_config: None,
        user_id: "user_1".to_owned(),
        provider_id: "okta".to_owned(),
        organization_id: None,
        domain: domain.to_owned(),
        domain_verified: Some(true),
        created_at: None,
    }
}

fn profile(
    provider_type: &str,
    provider_id: &str,
    account_id: &str,
    email: &str,
) -> NormalizedSsoProfile {
    NormalizedSsoProfile {
        provider_type: provider_type.to_owned(),
        provider_id: provider_id.to_owned(),
        account_id: account_id.to_owned(),
        email: email.to_owned(),
        email_verified: true,
        name: Some("SSO User".to_owned()),
        image: None,
        raw_attributes: None,
        token_data: None,
    }
}

fn user(id: &str, email: &str) -> User {
    let now = OffsetDateTime::now_utc();
    User {
        id: id.to_owned(),
        name: "SSO User".to_owned(),
        email: email.to_owned(),
        email_verified: true,
        image: None,
        username: None,
        display_username: None,
        created_at: now,
        updated_at: now,
    }
}

fn organization_context() -> Result<openauth_core::context::AuthContext, Box<dyn std::error::Error>>
{
    Ok(create_auth_context(OpenAuthOptions {
        plugins: vec![AuthPlugin::new("organization")],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?)
}

async fn seed_member(
    adapter: &MemoryAdapter,
    id: &str,
    organization_id: &str,
    user_id: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String(id.to_owned()))
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("role", DbValue::String(role.to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

async fn create_provider(
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
