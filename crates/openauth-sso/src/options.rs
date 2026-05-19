use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use time::Duration;

use openauth_core::db::User;
use openauth_core::error::OpenAuthError;
use openauth_core::oauth::oauth2::OAuth2Tokens;
use openauth_core::options::RateLimitRule;

use crate::linking::NormalizedSsoProfile;
use crate::saml::DeprecatedAlgorithmBehavior;
use crate::secrets::SecretString;
use crate::store::SsoProviderRecord;

type TxtResolverFuture = Pin<Box<dyn Future<Output = Result<Vec<String>, OpenAuthError>> + Send>>;
type ProvidersLimitFuture = Pin<Box<dyn Future<Output = Result<usize, OpenAuthError>> + Send>>;
type OrganizationRoleFuture = Pin<Box<dyn Future<Output = Result<String, OpenAuthError>> + Send>>;
type ProvisionUserFuture = Pin<Box<dyn Future<Output = Result<(), OpenAuthError>> + Send>>;
type AuditEventFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Clone)]
pub struct DnsTxtResolver {
    resolver: Arc<dyn Fn(String) -> TxtResolverFuture + Send + Sync>,
}

impl DnsTxtResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<String>, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |name| Box::pin(resolver(name))),
        }
    }

    pub async fn resolve(&self, name: &str) -> Result<Vec<String>, OpenAuthError> {
        (self.resolver)(name.to_owned()).await
    }
}

impl std::fmt::Debug for DnsTxtResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DnsTxtResolver(..)")
    }
}

impl PartialEq for DnsTxtResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for DnsTxtResolver {}

#[derive(Clone)]
pub struct ProvidersLimitResolver {
    resolver: Arc<dyn Fn(User) -> ProvidersLimitFuture + Send + Sync>,
}

impl ProvidersLimitResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(User) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<usize, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |user| Box::pin(resolver(user))),
        }
    }

    pub async fn resolve(&self, user: User) -> Result<usize, OpenAuthError> {
        (self.resolver)(user).await
    }
}

impl std::fmt::Debug for ProvidersLimitResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProvidersLimitResolver(..)")
    }
}

impl PartialEq for ProvidersLimitResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ProvidersLimitResolver {}

#[derive(Debug, Clone, PartialEq)]
pub struct OrganizationRoleInput {
    pub user: User,
    pub profile: NormalizedSsoProfile,
    pub provider: SsoProviderRecord,
    pub token: Option<OAuth2Tokens>,
}

#[derive(Clone)]
pub struct OrganizationRoleResolver {
    resolver: Arc<dyn Fn(OrganizationRoleInput) -> OrganizationRoleFuture + Send + Sync>,
}

impl OrganizationRoleResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(OrganizationRoleInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(&self, input: OrganizationRoleInput) -> Result<String, OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for OrganizationRoleResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OrganizationRoleResolver(..)")
    }
}

impl PartialEq for OrganizationRoleResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for OrganizationRoleResolver {}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionUserInput {
    pub user: User,
    pub profile: NormalizedSsoProfile,
    pub provider: SsoProviderRecord,
    pub token: Option<OAuth2Tokens>,
    pub is_register: bool,
}

#[derive(Clone)]
pub struct ProvisionUserResolver {
    resolver: Arc<dyn Fn(ProvisionUserInput) -> ProvisionUserFuture + Send + Sync>,
}

impl ProvisionUserResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(ProvisionUserInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    pub async fn resolve(&self, input: ProvisionUserInput) -> Result<(), OpenAuthError> {
        (self.resolver)(input).await
    }
}

impl std::fmt::Debug for ProvisionUserResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProvisionUserResolver(..)")
    }
}

impl PartialEq for ProvisionUserResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for ProvisionUserResolver {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SsoAuditSeverity {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SsoAuditEventKind {
    ProviderRegistered,
    ProviderUpdated,
    ProviderDeleted,
    DomainVerificationRequested,
    DomainVerificationSucceeded,
    DomainVerificationFailed,
    SamlReplayRejected,
    SamlSignatureFailed,
    SamlSloSessionDeleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoAuditEvent {
    pub kind: SsoAuditEventKind,
    pub severity: SsoAuditSeverity,
    pub provider_id: Option<String>,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub reason: Option<String>,
}

impl SsoAuditEvent {
    pub fn new(kind: SsoAuditEventKind, severity: SsoAuditSeverity) -> Self {
        Self {
            kind,
            severity,
            provider_id: None,
            user_id: None,
            organization_id: None,
            reason: None,
        }
    }

    #[must_use]
    pub fn provider_id(mut self, provider_id: impl Into<String>) -> Self {
        self.provider_id = Some(provider_id.into());
        self
    }

    #[must_use]
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    #[must_use]
    pub fn organization_id(mut self, organization_id: impl Into<String>) -> Self {
        self.organization_id = Some(organization_id.into());
        self
    }

    #[must_use]
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[derive(Clone)]
pub struct SsoAuditEventResolver {
    resolver: Arc<dyn Fn(SsoAuditEvent) -> AuditEventFuture + Send + Sync>,
}

impl SsoAuditEventResolver {
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(SsoAuditEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |event| Box::pin(resolver(event))),
        }
    }

    pub async fn resolve(&self, event: SsoAuditEvent) {
        (self.resolver)(event).await;
    }
}

impl std::fmt::Debug for SsoAuditEventResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SsoAuditEventResolver(..)")
    }
}

impl PartialEq for SsoAuditEventResolver {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for SsoAuditEventResolver {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationProvisioningOptions {
    pub disabled: bool,
    pub default_role: String,
    #[serde(skip)]
    pub get_role: Option<OrganizationRoleResolver>,
}

impl Default for OrganizationProvisioningOptions {
    fn default() -> Self {
        Self {
            disabled: false,
            default_role: "member".to_owned(),
            get_role: None,
        }
    }
}

impl OrganizationProvisioningOptions {
    #[must_use]
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    #[must_use]
    pub fn default_role(mut self, role: impl Into<String>) -> Self {
        self.default_role = role.into();
        self
    }

    #[must_use]
    pub fn get_role<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(OrganizationRoleInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, OpenAuthError>> + Send + 'static,
    {
        self.get_role = Some(OrganizationRoleResolver::new(resolver));
        self
    }

    pub async fn resolve_role(
        &self,
        input: OrganizationRoleInput,
    ) -> Result<String, OpenAuthError> {
        match &self.get_role {
            Some(resolver) => resolver.resolve(input).await,
            None => Ok(self.default_role.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoOptions {
    pub model_name: String,
    pub provider_table: String,
    pub providers_limit: usize,
    #[serde(skip)]
    pub providers_limit_callback: Option<ProvidersLimitResolver>,
    pub domain_verification: DomainVerificationOptions,
    pub redirect_uri: Option<String>,
    pub disable_implicit_sign_up: bool,
    pub trust_email_verified: bool,
    pub default_override_user_info: bool,
    #[serde(skip)]
    pub provision_user: Option<ProvisionUserResolver>,
    pub provision_user_on_every_login: bool,
    pub organization_provisioning: OrganizationProvisioningOptions,
    pub saml: SamlOptions,
    #[serde(skip)]
    pub rate_limit: SsoRateLimitOptions,
    #[serde(skip)]
    pub audit_event: Option<SsoAuditEventResolver>,
    pub default_sso: Vec<SsoProvider>,
}

impl Default for SsoOptions {
    fn default() -> Self {
        Self {
            model_name: "ssoProvider".to_owned(),
            provider_table: "sso_providers".to_owned(),
            providers_limit: 10,
            providers_limit_callback: None,
            domain_verification: DomainVerificationOptions::default(),
            redirect_uri: None,
            disable_implicit_sign_up: false,
            trust_email_verified: false,
            default_override_user_info: false,
            provision_user: None,
            provision_user_on_every_login: false,
            organization_provisioning: OrganizationProvisioningOptions::default(),
            saml: SamlOptions::default(),
            rate_limit: SsoRateLimitOptions::default(),
            audit_event: None,
            default_sso: Vec::new(),
        }
    }
}

impl SsoOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn provider_table(mut self, table: impl Into<String>) -> Self {
        self.provider_table = table.into();
        self
    }

    #[must_use]
    pub fn providers_limit(mut self, limit: usize) -> Self {
        self.providers_limit = limit;
        self
    }

    #[must_use]
    pub fn providers_limit_callback<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(User) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<usize, OpenAuthError>> + Send + 'static,
    {
        self.providers_limit_callback = Some(ProvidersLimitResolver::new(resolver));
        self
    }

    pub async fn resolve_providers_limit(&self, user: User) -> Result<usize, OpenAuthError> {
        match &self.providers_limit_callback {
            Some(resolver) => resolver.resolve(user).await,
            None => Ok(self.providers_limit),
        }
    }

    #[must_use]
    pub fn domain_verification_enabled(mut self, enabled: bool) -> Self {
        self.domain_verification.enabled = enabled;
        self
    }

    #[must_use]
    pub fn domain_txt_resolver<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<String>, OpenAuthError>> + Send + 'static,
    {
        self.domain_verification.txt_resolver = Some(DnsTxtResolver::new(resolver));
        self
    }

    #[must_use]
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    #[must_use]
    pub fn organization_provisioning(
        mut self,
        provisioning: OrganizationProvisioningOptions,
    ) -> Self {
        self.organization_provisioning = provisioning;
        self
    }

    #[must_use]
    pub fn provision_user<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(ProvisionUserInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.provision_user = Some(ProvisionUserResolver::new(resolver));
        self
    }

    #[must_use]
    pub fn provision_user_on_every_login(mut self, enabled: bool) -> Self {
        self.provision_user_on_every_login = enabled;
        self
    }

    #[must_use]
    pub fn rate_limit(mut self, rate_limit: SsoRateLimitOptions) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    #[must_use]
    pub fn rate_limit_enabled(mut self, enabled: bool) -> Self {
        self.rate_limit.enabled = enabled;
        self
    }

    #[must_use]
    pub fn audit_event<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(SsoAuditEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.audit_event = Some(SsoAuditEventResolver::new(resolver));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoRateLimitOptions {
    pub enabled: bool,
    pub registration: RateLimitRule,
    pub domain_verification: RateLimitRule,
    pub oidc_callback: RateLimitRule,
    pub saml: RateLimitRule,
}

impl Default for SsoRateLimitOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            registration: RateLimitRule::new(60, 10),
            domain_verification: RateLimitRule::new(60, 5),
            oidc_callback: RateLimitRule::new(60, 30),
            saml: RateLimitRule::new(60, 30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainVerificationOptions {
    pub enabled: bool,
    pub token_prefix: String,
    pub token_ttl_seconds: u64,
    #[serde(skip)]
    pub txt_resolver: Option<DnsTxtResolver>,
}

impl Default for DomainVerificationOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            token_prefix: "better-auth-token".to_owned(),
            token_ttl_seconds: 60 * 60 * 24 * 7,
            txt_resolver: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlOptions {
    pub enable_in_response_to_validation: bool,
    pub allow_idp_initiated: bool,
    pub request_ttl: Duration,
    pub clock_skew: Duration,
    pub require_timestamps: bool,
    pub max_response_size: usize,
    pub max_metadata_size: usize,
    pub enable_single_logout: bool,
    pub logout_request_ttl: Duration,
    pub want_logout_request_signed: bool,
    pub want_logout_response_signed: bool,
    pub algorithms: SamlAlgorithmOptions,
}

impl Default for SamlOptions {
    fn default() -> Self {
        Self {
            enable_in_response_to_validation: true,
            allow_idp_initiated: true,
            request_ttl: Duration::minutes(10),
            clock_skew: Duration::minutes(5),
            require_timestamps: false,
            max_response_size: 256 * 1024,
            max_metadata_size: 100 * 1024,
            enable_single_logout: false,
            logout_request_ttl: Duration::minutes(5),
            want_logout_request_signed: false,
            want_logout_response_signed: false,
            algorithms: SamlAlgorithmOptions::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlAlgorithmOptions {
    pub on_deprecated: DeprecatedAlgorithmBehavior,
    pub allowed_signature_algorithms: Option<Vec<String>>,
    pub allowed_digest_algorithms: Option<Vec<String>>,
    pub allowed_key_encryption_algorithms: Option<Vec<String>>,
    pub allowed_data_encryption_algorithms: Option<Vec<String>>,
}

impl Default for SamlAlgorithmOptions {
    fn default() -> Self {
        Self {
            on_deprecated: DeprecatedAlgorithmBehavior::Warn,
            allowed_signature_algorithms: None,
            allowed_digest_algorithms: None,
            allowed_key_encryption_algorithms: None,
            allowed_data_encryption_algorithms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoProvider {
    pub provider_id: String,
    pub issuer: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_config: Option<OidcConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_config: Option<SamlConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcConfig {
    pub issuer: String,
    pub pkce: bool,
    pub client_id: String,
    pub client_secret: SecretString,
    pub discovery_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_info_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_authentication: Option<TokenEndpointAuthentication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping: Option<OidcMapping>,
    pub override_user_info: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthentication {
    ClientSecretBasic,
    ClientSecretPost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcMapping {
    pub id: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub extra_fields: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlConfig {
    pub issuer: String,
    #[serde(default)]
    pub entry_point: String,
    pub cert: String,
    pub callback_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_metadata: Option<SamlIdpMetadata>,
    pub sp_metadata: SamlSpMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping: Option<SamlMapping>,
    pub want_assertions_signed: bool,
    pub authn_requests_signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decryption_pvk: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_params: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlIdpMetadata {
    pub metadata: Option<String>,
    #[serde(alias = "entityID")]
    pub entity_id: Option<String>,
    pub entity_url: Option<String>,
    pub redirect_url: Option<String>,
    pub cert: Option<String>,
    pub private_key: Option<SecretString>,
    pub private_key_pass: Option<SecretString>,
    pub is_assertion_encrypted: Option<bool>,
    pub enc_private_key: Option<SecretString>,
    pub enc_private_key_pass: Option<SecretString>,
    pub single_sign_on_service: Option<Vec<SamlService>>,
    pub single_logout_service: Option<Vec<SamlService>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlService {
    #[serde(rename = "Binding")]
    pub binding: String,
    #[serde(rename = "Location")]
    pub location: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlSpMetadata {
    pub metadata: Option<String>,
    #[serde(alias = "entityID")]
    pub entity_id: Option<String>,
    pub binding: Option<String>,
    pub private_key: Option<SecretString>,
    pub private_key_pass: Option<SecretString>,
    pub is_assertion_encrypted: Option<bool>,
    pub enc_private_key: Option<SecretString>,
    pub enc_private_key_pass: Option<SecretString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlMapping {
    pub id: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<String>,
    pub name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub extra_fields: Option<BTreeMap<String, String>>,
}
