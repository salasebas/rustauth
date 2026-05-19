use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{Create, DbAdapter, DbValue, FindOne, User, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::oauth::oauth2::OAuth2Tokens;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::options::{
    DomainVerificationOptions, OrganizationProvisioningOptions, OrganizationRoleInput,
    ProvisionUserInput, SsoOptions,
};
use crate::store::{SsoProviderRecord, SsoProviderStore};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Normalized identity profile produced by an OIDC or SAML SSO login.
pub struct NormalizedSsoProfile {
    /// Provider protocol, such as `oidc` or `saml`.
    pub provider_type: String,
    /// Stable OpenAuth SSO provider id.
    pub provider_id: String,
    /// External account id from the identity provider.
    pub account_id: String,
    /// Normalized email address.
    pub email: String,
    /// Whether the identity provider marked the email as verified.
    pub email_verified: bool,
    /// Display name, when available.
    pub name: Option<String>,
    /// Avatar URL, when available.
    pub image: Option<String>,
    /// Extra mapped claims or attributes requested by provider mapping.
    pub raw_attributes: Option<Value>,
    /// OIDC token data; `None` for SAML.
    pub token_data: Option<OAuth2Tokens>,
}

pub fn provider_matches_email_domain(provider: &SsoProviderRecord, email: &str) -> bool {
    let Some((_, email_domain)) = email.rsplit_once('@') else {
        return false;
    };
    let email_domain = normalize_domain(email_domain);
    if email_domain.is_empty() {
        return false;
    }
    provider.domain.split(',').any(|domain| {
        let domain = normalize_domain(domain);
        if domain.is_empty() || is_public_suffix(&domain) {
            return false;
        }
        email_domain == domain || email_domain.ends_with(&format!(".{domain}"))
    })
}

pub fn validate_provider_domains(domains: &str) -> bool {
    let mut has_domain = false;
    for domain in domains.split(',') {
        let domain = normalize_domain(domain);
        if domain.is_empty() || is_public_suffix(&domain) {
            return false;
        }
        has_domain = true;
    }
    has_domain
}

pub async fn assign_organization_from_provider(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    provisioning_options: &OrganizationProvisioningOptions,
    user: &User,
    profile: &NormalizedSsoProfile,
    provider: &SsoProviderRecord,
    token: Option<OAuth2Tokens>,
) -> Result<(), OpenAuthError> {
    let Some(organization_id) = provider.organization_id.as_deref() else {
        return Ok(());
    };
    if provisioning_options.disabled || !context.has_plugin("organization") {
        return Ok(());
    }
    if organization_member(adapter, organization_id, &user.id)
        .await?
        .is_some()
    {
        return Ok(());
    }

    let role = provisioning_options
        .resolve_role(OrganizationRoleInput {
            user: user.clone(),
            profile: profile.clone(),
            provider: provider.clone(),
            token,
        })
        .await?;
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String(generate_random_string(32)))
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("user_id", DbValue::String(user.id.clone()))
                .data("role", DbValue::String(role))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub async fn provision_sso_user(
    options: &SsoOptions,
    user: &User,
    profile: &NormalizedSsoProfile,
    provider: &SsoProviderRecord,
    token: Option<OAuth2Tokens>,
    is_register: bool,
) -> Result<(), OpenAuthError> {
    let Some(provision_user) = &options.provision_user else {
        return Ok(());
    };
    if !is_register && !options.provision_user_on_every_login {
        return Ok(());
    }
    provision_user
        .resolve(ProvisionUserInput {
            user: user.clone(),
            profile: profile.clone(),
            provider: provider.clone(),
            token,
            is_register,
        })
        .await
}

pub async fn assign_organization_by_domain(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    provisioning_options: &OrganizationProvisioningOptions,
    domain_verification: &DomainVerificationOptions,
    user: &User,
) -> Result<(), OpenAuthError> {
    if provisioning_options.disabled || !context.has_plugin("organization") {
        return Ok(());
    }

    let Some((_, email_domain)) = user.email.rsplit_once('@') else {
        return Ok(());
    };
    let email_domain = normalize_domain(email_domain);
    if email_domain.is_empty() {
        return Ok(());
    }

    let providers = SsoProviderStore::new(adapter).list().await?;
    let provider = providers.into_iter().find(|provider| {
        provider.organization_id.is_some()
            && provider_matches_email_domain(provider, &user.email)
            && (!domain_verification.enabled || provider.domain_verified.unwrap_or(false))
    });
    let Some(provider) = provider else {
        return Ok(());
    };

    let provider_type = if provider.saml_config.is_some() {
        "saml"
    } else {
        "oidc"
    };
    assign_organization_from_provider(
        context,
        adapter,
        provisioning_options,
        user,
        &NormalizedSsoProfile {
            provider_type: provider_type.to_owned(),
            provider_id: provider.provider_id.clone(),
            account_id: user.id.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            name: Some(user.name.clone()),
            image: user.image.clone(),
            raw_attributes: None,
            token_data: None,
        },
        &provider,
        None,
    )
    .await
}

async fn organization_member(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
) -> Result<Option<openauth_core::db::DbRecord>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
        )
        .await
}

fn normalize_domain(value: &str) -> String {
    let trimmed = value
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('.');
    trimmed
        .split('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn is_public_suffix(domain: &str) -> bool {
    publicsuffix2::List::global()
        .tld(domain, publicsuffix2::MatchOpts::default())
        .is_some_and(|suffix| suffix == domain)
}
