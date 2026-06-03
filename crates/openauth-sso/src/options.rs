use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use time::Duration;

use openauth_core::db::User;
use openauth_core::error::OpenAuthError;
use openauth_core::options::RateLimitRule;
use openauth_core::secret::SecretString;

#[cfg(feature = "saml")]
pub use openauth_saml::{
    DeprecatedAlgorithmBehavior, SamlConfig, SamlIdpMetadata, SamlMapping, SamlService,
    SamlSpMetadata,
};

#[path = "options/audit.rs"]
mod audit;
#[path = "options/callbacks.rs"]
mod callbacks;

pub use audit::*;
pub use callbacks::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Controls automatic organization membership assignment for SSO users.
pub struct OrganizationProvisioningOptions {
    /// Disable organization assignment from provider configuration.
    pub disabled: bool,
    /// Role assigned when no custom role resolver is configured.
    pub default_role: String,
    #[serde(skip)]
    /// Optional async resolver for per-login organization roles.
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
    /// Enable or disable organization provisioning.
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    #[must_use]
    /// Set the default role assigned to provisioned organization members.
    pub fn default_role(mut self, role: impl Into<String>) -> Self {
        self.default_role = role.into();
        self
    }

    #[must_use]
    /// Set a custom async role resolver.
    pub fn get_role<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(OrganizationRoleInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, OpenAuthError>> + Send + 'static,
    {
        self.get_role = Some(OrganizationRoleResolver::new(resolver));
        self
    }

    /// Resolve the organization role for a completed SSO login.
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
/// Configuration for the OpenAuth SSO plugin.
pub struct SsoOptions {
    /// Logical schema model name contributed by the plugin.
    pub model_name: String,
    /// Physical database table name for SSO providers.
    pub provider_table: String,
    /// Static maximum number of providers a user may register.
    pub providers_limit: usize,
    #[serde(skip)]
    /// Optional dynamic provider limit resolver.
    pub providers_limit_callback: Option<ProvidersLimitResolver>,
    /// Domain verification settings.
    pub domain_verification: DomainVerificationOptions,
    /// Shared OIDC redirect URI override.
    pub redirect_uri: Option<String>,
    /// Disable implicit user creation during SSO login.
    pub disable_implicit_sign_up: bool,
    /// Trust IdP email verification for implicit account linking.
    pub trust_email_verified: bool,
    /// Default value for provider-level user info override behavior.
    pub default_override_user_info: bool,
    /// OIDC runtime and security settings.
    #[serde(default)]
    pub oidc: OidcOptions,
    #[serde(skip)]
    /// Optional hook for application-specific user provisioning.
    pub provision_user: Option<ProvisionUserResolver>,
    /// Run `provision_user` for existing users on every login.
    pub provision_user_on_every_login: bool,
    /// Organization provisioning settings.
    pub organization_provisioning: OrganizationProvisioningOptions,
    /// SAML runtime and security settings.
    pub saml: SamlOptions,
    #[serde(skip)]
    /// Plugin rate limit settings.
    pub rate_limit: SsoRateLimitOptions,
    #[serde(skip)]
    /// Optional audit event sink.
    pub audit_event: Option<SsoAuditEventResolver>,
    /// Statically configured SSO providers.
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
            oidc: OidcOptions::default(),
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
    /// Create default SSO plugin options.
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Override the physical provider table name.
    pub fn provider_table(mut self, table: impl Into<String>) -> Self {
        self.provider_table = table.into();
        self
    }

    #[must_use]
    /// Set the static maximum provider count per user.
    pub fn providers_limit(mut self, limit: usize) -> Self {
        self.providers_limit = limit;
        self
    }

    #[must_use]
    /// Set a dynamic provider limit callback.
    pub fn providers_limit_callback<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(User) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<usize, OpenAuthError>> + Send + 'static,
    {
        self.providers_limit_callback = Some(ProvidersLimitResolver::new(resolver));
        self
    }

    /// Resolve the effective provider limit for a user.
    pub async fn resolve_providers_limit(&self, user: User) -> Result<usize, OpenAuthError> {
        match &self.providers_limit_callback {
            Some(resolver) => resolver.resolve(user).await,
            None => Ok(self.providers_limit),
        }
    }

    #[must_use]
    /// Enable or disable DNS domain verification.
    pub fn domain_verification_enabled(mut self, enabled: bool) -> Self {
        self.domain_verification.enabled = enabled;
        self
    }

    #[must_use]
    /// Set a custom DNS TXT resolver for domain verification.
    pub fn domain_txt_resolver<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<String>, OpenAuthError>> + Send + 'static,
    {
        self.domain_verification.txt_resolver = Some(DnsTxtResolver::new(resolver));
        self
    }

    #[must_use]
    /// Override the OIDC redirect URI used in authorization requests.
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    #[must_use]
    /// Configure organization provisioning.
    pub fn organization_provisioning(
        mut self,
        provisioning: OrganizationProvisioningOptions,
    ) -> Self {
        self.organization_provisioning = provisioning;
        self
    }

    #[must_use]
    /// Set a user provisioning hook.
    pub fn provision_user<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(ProvisionUserInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.provision_user = Some(ProvisionUserResolver::new(resolver));
        self
    }

    #[must_use]
    /// Run the provisioning hook for existing users on every login.
    pub fn provision_user_on_every_login(mut self, enabled: bool) -> Self {
        self.provision_user_on_every_login = enabled;
        self
    }

    #[must_use]
    /// Replace all SSO rate limit settings.
    pub fn rate_limit(mut self, rate_limit: SsoRateLimitOptions) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    #[must_use]
    /// Enable or disable SSO rate limit rule contributions.
    pub fn rate_limit_enabled(mut self, enabled: bool) -> Self {
        self.rate_limit.enabled = enabled;
        self
    }

    #[must_use]
    /// Set an async audit event sink.
    pub fn audit_event<F, Fut>(mut self, resolver: F) -> Self
    where
        F: Fn(SsoAuditEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.audit_event = Some(SsoAuditEventResolver::new(resolver));
        self
    }

    #[must_use]
    /// Require manually configured OIDC endpoints to match trusted origins.
    pub fn strict_oidc_manual_endpoint_origins(mut self, enabled: bool) -> Self {
        self.oidc.strict_manual_endpoint_origins = enabled;
        self
    }

    #[must_use]
    /// Allow OIDC outbound requests to resolve to private or internal IPs.
    ///
    /// Leave disabled (the default) to keep SSRF protection active. Enable only
    /// when identity providers are intentionally hosted on a private network.
    pub fn allow_private_endpoint_ips(mut self, enabled: bool) -> Self {
        self.oidc.allow_private_endpoint_ips = enabled;
        self
    }
}

#[cfg(feature = "oidc")]
impl openauth_oidc::OidcFlowOptions for SsoOptions {
    fn redirect_uri(&self) -> Option<&str> {
        self.redirect_uri.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
/// OIDC runtime and security behavior for SSO providers.
pub struct OidcOptions {
    /// Validate manually configured OIDC endpoint origins against OpenAuth trusted origins.
    ///
    /// Disabled by default for compatibility with existing manual `skipDiscovery`
    /// configurations. Enable this for stricter SSRF/configuration hardening.
    pub strict_manual_endpoint_origins: bool,
    /// Allow OIDC discovery, JWKS, userinfo, and token requests to reach
    /// private, loopback, or otherwise non-public IP addresses.
    ///
    /// Disabled by default: outbound requests are blocked at DNS resolution
    /// when a hostname resolves only to internal addresses, mitigating SSRF
    /// against cloud metadata services and internal infrastructure. Enable this
    /// only for deployments that intentionally talk to identity providers on a
    /// private network.
    #[serde(default)]
    pub allow_private_endpoint_ips: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Rate limit rules contributed by the SSO plugin.
pub struct SsoRateLimitOptions {
    /// Whether SSO rate limit rules are registered.
    pub enabled: bool,
    /// Provider registration rate limit.
    pub registration: RateLimitRule,
    /// Domain verification request and check rate limit.
    pub domain_verification: RateLimitRule,
    /// OIDC callback rate limit.
    pub oidc_callback: RateLimitRule,
    /// SAML ACS and logout rate limit.
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
/// Domain verification behavior for registered SSO providers.
pub struct DomainVerificationOptions {
    /// Require providers to verify domains before domain matching.
    pub enabled: bool,
    /// Prefix used in generated DNS TXT verification tokens.
    pub token_prefix: String,
    /// Token lifetime in seconds.
    pub token_ttl_seconds: u64,
    #[serde(skip)]
    /// Optional custom DNS TXT resolver.
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

/// Default maximum accepted base64 SAML response size (256 KiB).
pub const DEFAULT_MAX_SAML_RESPONSE_SIZE: usize = 256 * 1024;
/// Default maximum accepted IdP metadata XML size (100 KiB).
pub const DEFAULT_MAX_SAML_METADATA_SIZE: usize = 100 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Runtime and security options for SAML flows.
pub struct SamlOptions {
    /// Validate `InResponseTo` against stored AuthnRequest state.
    pub enable_in_response_to_validation: bool,
    /// Allow IdP-initiated SAML responses without stored request state.
    pub allow_idp_initiated: bool,
    /// AuthnRequest state lifetime.
    pub request_ttl: Duration,
    /// Allowed timestamp clock skew.
    pub clock_skew: Duration,
    /// Require SAML assertions to include timestamp conditions.
    pub require_timestamps: bool,
    /// Maximum accepted base64 SAML response size.
    pub max_response_size: usize,
    /// Maximum accepted IdP metadata XML size.
    pub max_metadata_size: usize,
    /// Enable SAML single logout endpoints and session lookup state.
    pub enable_single_logout: bool,
    /// Pending logout request lifetime.
    pub logout_request_ttl: Duration,
    /// Require signed inbound LogoutRequest messages.
    pub want_logout_request_signed: bool,
    /// Require signed inbound LogoutResponse messages.
    pub want_logout_response_signed: bool,
    /// SAML algorithm validation policy.
    pub algorithms: SamlAlgorithmOptions,
}

impl Default for SamlOptions {
    fn default() -> Self {
        Self {
            enable_in_response_to_validation: true,
            allow_idp_initiated: true,
            request_ttl: Duration::minutes(5),
            clock_skew: Duration::minutes(5),
            require_timestamps: false,
            max_response_size: DEFAULT_MAX_SAML_RESPONSE_SIZE,
            max_metadata_size: DEFAULT_MAX_SAML_METADATA_SIZE,
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
/// SAML algorithm allow lists and deprecated algorithm behavior.
pub struct SamlAlgorithmOptions {
    /// How deprecated algorithms are handled.
    pub on_deprecated: DeprecatedAlgorithmBehavior,
    /// Optional allow list for signature algorithm URIs or short names.
    pub allowed_signature_algorithms: Option<Vec<String>>,
    /// Optional allow list for digest algorithm URIs or short names.
    pub allowed_digest_algorithms: Option<Vec<String>>,
    /// Optional allow list for encrypted-key algorithm URIs or short names.
    pub allowed_key_encryption_algorithms: Option<Vec<String>>,
    /// Optional allow list for encrypted-data algorithm URIs or short names.
    pub allowed_data_encryption_algorithms: Option<Vec<String>>,
}

#[cfg(not(feature = "saml"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Behavior used when SAML algorithms are deprecated.
pub enum DeprecatedAlgorithmBehavior {
    /// Accept deprecated algorithms while allowing callers to audit them.
    Warn,
    /// Reject deprecated algorithms.
    Reject,
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
/// Static SSO provider definition used by `SsoOptions::default_sso`.
pub struct SsoProvider {
    /// Stable provider id used in API paths and sign-in requests.
    pub provider_id: String,
    /// Provider issuer URL or identifier.
    pub issuer: String,
    /// Comma-separated domains owned by the provider.
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional organization assigned to users authenticated by this provider.
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// OIDC configuration, when the provider supports OIDC.
    pub oidc_config: Option<OidcConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// SAML configuration, when the provider supports SAML.
    pub saml_config: Option<SamlConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// OIDC configuration for an SSO provider.
pub struct OidcConfig {
    /// OIDC issuer URL.
    pub issuer: String,
    /// Whether authorization requests should use PKCE.
    pub pkce: bool,
    /// OAuth/OIDC client id.
    pub client_id: String,
    /// OAuth/OIDC client secret. Debug output is redacted.
    pub client_secret: SecretString,
    /// OIDC discovery document URL.
    pub discovery_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit authorization endpoint override.
    pub authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit token endpoint override.
    pub token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit UserInfo endpoint override.
    pub user_info_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit JWKS endpoint override.
    pub jwks_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional OAuth token revocation endpoint discovered from the IdP.
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional OIDC end-session endpoint discovered from the IdP.
    pub end_session_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional OAuth token introspection endpoint discovered from the IdP.
    pub introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Token endpoint authentication method.
    pub token_endpoint_authentication: Option<TokenEndpointAuthentication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Authorization request scopes.
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Provider claim mapping.
    pub mapping: Option<OidcMapping>,
    /// Override existing OpenAuth user fields with mapped OIDC values on login.
    pub override_user_info: bool,
}

#[allow(dead_code)]
pub type OidcProviderConfig = OidcConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Supported OAuth token endpoint authentication methods.
pub enum TokenEndpointAuthentication {
    /// Send client credentials through HTTP Basic authentication.
    ClientSecretBasic,
    /// Send client credentials in the token request body.
    ClientSecretPost,
}

#[cfg(feature = "oidc")]
impl From<TokenEndpointAuthentication> for openauth_oidc::TokenEndpointAuthentication {
    fn from(value: TokenEndpointAuthentication) -> Self {
        match value {
            TokenEndpointAuthentication::ClientSecretBasic => Self::ClientSecretBasic,
            TokenEndpointAuthentication::ClientSecretPost => Self::ClientSecretPost,
        }
    }
}

#[cfg(feature = "oidc")]
impl From<openauth_oidc::TokenEndpointAuthentication> for TokenEndpointAuthentication {
    fn from(value: openauth_oidc::TokenEndpointAuthentication) -> Self {
        match value {
            openauth_oidc::TokenEndpointAuthentication::ClientSecretBasic => {
                Self::ClientSecretBasic
            }
            openauth_oidc::TokenEndpointAuthentication::ClientSecretPost => Self::ClientSecretPost,
        }
    }
}

#[cfg(feature = "oidc")]
impl openauth_oidc::OidcEndpointConfig for OidcConfig {
    fn discovery_endpoint(&self) -> &str {
        &self.discovery_endpoint
    }

    fn authorization_endpoint(&self) -> Option<&str> {
        self.authorization_endpoint.as_deref()
    }

    fn token_endpoint(&self) -> Option<&str> {
        self.token_endpoint.as_deref()
    }

    fn user_info_endpoint(&self) -> Option<&str> {
        self.user_info_endpoint.as_deref()
    }

    fn jwks_endpoint(&self) -> Option<&str> {
        self.jwks_endpoint.as_deref()
    }

    fn revocation_endpoint(&self) -> Option<&str> {
        self.revocation_endpoint.as_deref()
    }

    fn end_session_endpoint(&self) -> Option<&str> {
        self.end_session_endpoint.as_deref()
    }

    fn introspection_endpoint(&self) -> Option<&str> {
        self.introspection_endpoint.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Mapping from OIDC claims to OpenAuth profile fields.
pub struct OidcMapping {
    /// Claim used as the external account id.
    pub id: Option<String>,
    /// Claim used as email.
    pub email: Option<String>,
    /// Claim used as email verification status.
    pub email_verified: Option<String>,
    /// Claim used as display name.
    pub name: Option<String>,
    /// Claim used as avatar URL.
    pub image: Option<String>,
    /// Additional claim mappings exposed to hooks as raw attributes.
    pub extra_fields: Option<BTreeMap<String, String>>,
}

#[allow(dead_code)]
pub type OidcProfileMapping = OidcMapping;

#[cfg(feature = "saml")]
#[allow(dead_code)]
pub type SamlProviderConfig = SamlConfig;

#[cfg(not(feature = "saml"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// SAML configuration for an SSO provider.
pub struct SamlConfig {
    /// Service provider issuer/entity id expected by the IdP.
    pub issuer: String,
    #[serde(default)]
    /// IdP SSO entry point for AuthnRequest redirects.
    pub entry_point: String,
    /// IdP signing certificate, either PEM or base64 body.
    pub cert: String,
    /// OpenAuth callback URL used after SAML login.
    pub callback_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit assertion consumer service URL.
    pub acs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Expected SAML audience. Defaults to issuer semantics when omitted.
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Parsed or configured IdP metadata.
    pub idp_metadata: Option<SamlIdpMetadata>,
    /// Service provider metadata configuration.
    pub sp_metadata: SamlSpMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Provider attribute mapping.
    pub mapping: Option<SamlMapping>,
    /// Require valid XMLDSig over the SAML Assertion.
    pub want_assertions_signed: bool,
    /// Sign outbound AuthnRequest messages.
    pub authn_requests_signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Signature algorithm URI or short name for outbound signed requests.
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Digest algorithm URI or short name for outbound signed requests.
    pub digest_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// SAML NameID format requested from the IdP.
    pub identifier_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Service provider signing private key. Debug output is redacted.
    pub private_key: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Service provider decryption private key for encrypted assertions.
    pub decryption_pvk: Option<SecretString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Additional AuthnRequest parameters sent to the IdP.
    pub additional_params: Option<BTreeMap<String, serde_json::Value>>,
}

#[cfg(not(feature = "saml"))]
#[allow(dead_code)]
pub type SamlProviderConfig = SamlConfig;

#[cfg(not(feature = "saml"))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// IdP metadata fields accepted by SAML provider configuration.
pub struct SamlIdpMetadata {
    /// Raw IdP metadata XML.
    pub metadata: Option<String>,
    #[serde(rename = "entityID", alias = "entityId")]
    /// IdP entity id.
    pub entity_id: Option<String>,
    #[serde(rename = "entityURL", alias = "entityUrl")]
    /// URL where metadata can be fetched.
    pub entity_url: Option<String>,
    #[serde(rename = "redirectURL", alias = "redirectUrl")]
    /// IdP redirect binding SSO URL.
    pub redirect_url: Option<String>,
    /// IdP signing certificate.
    pub cert: Option<String>,
    /// IdP private key field retained for upstream compatibility.
    pub private_key: Option<SecretString>,
    /// Passphrase for `private_key`.
    pub private_key_pass: Option<SecretString>,
    /// Whether the IdP encrypts assertions.
    pub is_assertion_encrypted: Option<bool>,
    /// Encrypted assertion private key field retained for upstream compatibility.
    pub enc_private_key: Option<SecretString>,
    /// Passphrase for `enc_private_key`.
    pub enc_private_key_pass: Option<SecretString>,
    /// Single sign-on services advertised by the IdP.
    pub single_sign_on_service: Option<Vec<SamlService>>,
    /// Single logout services advertised by the IdP.
    pub single_logout_service: Option<Vec<SamlService>>,
}

#[cfg(not(feature = "saml"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// SAML metadata service endpoint.
pub struct SamlService {
    #[serde(rename = "Binding")]
    /// SAML binding URI.
    pub binding: String,
    #[serde(rename = "Location")]
    /// Service endpoint URL.
    pub location: String,
}

#[cfg(not(feature = "saml"))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Service provider metadata overrides.
pub struct SamlSpMetadata {
    /// Raw service provider metadata XML returned as-is when configured.
    pub metadata: Option<String>,
    #[serde(rename = "entityID", alias = "entityId")]
    /// Service provider entity id.
    pub entity_id: Option<String>,
    /// Preferred SAML binding URI.
    pub binding: Option<String>,
    /// Service provider signing private key.
    pub private_key: Option<SecretString>,
    /// Passphrase for `private_key`.
    pub private_key_pass: Option<SecretString>,
    /// Whether assertions should be encrypted for this SP.
    pub is_assertion_encrypted: Option<bool>,
    /// Service provider decryption private key.
    pub enc_private_key: Option<SecretString>,
    /// Passphrase for `enc_private_key`.
    pub enc_private_key_pass: Option<SecretString>,
}

#[cfg(not(feature = "saml"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Mapping from SAML attributes to OpenAuth profile fields.
pub struct SamlMapping {
    /// Attribute used as the external account id.
    pub id: Option<String>,
    /// Attribute used as email.
    pub email: Option<String>,
    /// Attribute used as email verification status.
    pub email_verified: Option<String>,
    /// Attribute used as display name.
    pub name: Option<String>,
    /// Attribute used as first name.
    pub first_name: Option<String>,
    /// Attribute used as last name.
    pub last_name: Option<String>,
    /// Additional attribute mappings exposed to hooks as raw attributes.
    pub extra_fields: Option<BTreeMap<String, String>>,
}

#[cfg(all(test, not(feature = "saml")))]
mod fallback_saml_tests {
    use super::*;

    #[test]
    fn fallback_saml_config_uses_upstream_acronym_wire_names_and_accepts_legacy_aliases(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config: SamlConfig = serde_json::from_value(serde_json::json!({
            "issuer": "https://sp.example.com/metadata",
            "entryPoint": "https://idp.example.com/sso",
            "cert": "CERTIFICATE",
            "callbackUrl": "https://sp.example.com/acs",
            "spMetadata": {
                "entityId": "https://sp.example.com/legacy"
            },
            "idpMetadata": {
                "entityId": "https://idp.example.com/legacy",
                "entityUrl": "https://idp.example.com/legacy-metadata",
                "redirectUrl": "https://idp.example.com/legacy-redirect"
            },
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false
        }))?;

        let serialized = serde_json::to_value(&config)?;

        assert_eq!(
            serialized["spMetadata"]["entityID"],
            "https://sp.example.com/legacy"
        );
        assert_eq!(
            serialized["idpMetadata"]["entityID"],
            "https://idp.example.com/legacy"
        );
        assert_eq!(
            serialized["idpMetadata"]["entityURL"],
            "https://idp.example.com/legacy-metadata"
        );
        assert_eq!(
            serialized["idpMetadata"]["redirectURL"],
            "https://idp.example.com/legacy-redirect"
        );
        Ok(())
    }
}
