use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_core::db::User;
use rustauth_core::error::RustAuthError;
use rustauth_oauth::oauth2::OAuth2Tokens;

use crate::linking_impl::NormalizedSsoProfile;
use crate::store::SsoProviderRecord;

type TxtResolverFuture = Pin<Box<dyn Future<Output = Result<Vec<String>, RustAuthError>> + Send>>;
type ProvidersLimitFuture = Pin<Box<dyn Future<Output = Result<usize, RustAuthError>> + Send>>;
type OrganizationRoleFuture = Pin<Box<dyn Future<Output = Result<String, RustAuthError>> + Send>>;
type ProvisionUserFuture = Pin<Box<dyn Future<Output = Result<(), RustAuthError>> + Send>>;

#[derive(Clone)]
/// Async resolver used to verify domain ownership through DNS TXT records.
pub struct DnsTxtResolver {
    resolver: Arc<dyn Fn(String) -> TxtResolverFuture + Send + Sync>,
}

impl DnsTxtResolver {
    /// Create a resolver from an async function receiving the DNS name to query.
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<String>, RustAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |name| Box::pin(resolver(name))),
        }
    }

    /// Resolve TXT values for the provided DNS name.
    pub async fn resolve(&self, name: &str) -> Result<Vec<String>, RustAuthError> {
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
/// Async resolver used to compute a per-user dynamic provider limit.
pub struct ProvidersLimitResolver {
    resolver: Arc<dyn Fn(User) -> ProvidersLimitFuture + Send + Sync>,
}

impl ProvidersLimitResolver {
    /// Create a provider-limit resolver from an async function.
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(User) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<usize, RustAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |user| Box::pin(resolver(user))),
        }
    }

    /// Resolve the maximum number of providers the user may register.
    pub async fn resolve(&self, user: User) -> Result<usize, RustAuthError> {
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
/// Input passed to organization role resolution after a successful SSO login.
pub struct OrganizationRoleInput {
    /// User created or linked by the SSO flow.
    pub user: User,
    /// Normalized profile extracted from OIDC UserInfo or SAML attributes.
    pub profile: NormalizedSsoProfile,
    /// SSO provider that authenticated the user.
    pub provider: SsoProviderRecord,
    /// OAuth tokens for OIDC flows; `None` for SAML flows.
    pub token: Option<OAuth2Tokens>,
}

#[derive(Clone)]
/// Async callback that maps an SSO login to an organization role.
pub struct OrganizationRoleResolver {
    resolver: Arc<dyn Fn(OrganizationRoleInput) -> OrganizationRoleFuture + Send + Sync>,
}

impl OrganizationRoleResolver {
    /// Create a role resolver from an async function.
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(OrganizationRoleInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, RustAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    /// Resolve the organization role for the login.
    pub async fn resolve(&self, input: OrganizationRoleInput) -> Result<String, RustAuthError> {
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
/// Input passed to the `provision_user` hook.
pub struct ProvisionUserInput {
    /// User created or linked by the SSO flow.
    pub user: User,
    /// Normalized identity profile from the identity provider.
    pub profile: NormalizedSsoProfile,
    /// SSO provider that authenticated the user.
    pub provider: SsoProviderRecord,
    /// OAuth tokens for OIDC flows; `None` for SAML flows.
    pub token: Option<OAuth2Tokens>,
    /// Whether this login came from an explicit SSO registration request.
    pub is_register: bool,
}

#[derive(Clone)]
/// Async hook invoked after an SSO user is created or linked.
pub struct ProvisionUserResolver {
    resolver: Arc<dyn Fn(ProvisionUserInput) -> ProvisionUserFuture + Send + Sync>,
}

impl ProvisionUserResolver {
    /// Create a provisioning resolver from an async function.
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(ProvisionUserInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), RustAuthError>> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |input| Box::pin(resolver(input))),
        }
    }

    /// Run user provisioning for the completed SSO login.
    pub async fn resolve(&self, input: ProvisionUserInput) -> Result<(), RustAuthError> {
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
