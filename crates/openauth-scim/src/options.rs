//! SCIM plugin configuration.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::StatusCode;
use openauth_core::db::User;
use openauth_core::error::OpenAuthError;

use crate::store::ScimProviderRecord;

/// Boxed future returned by SCIM hooks.
pub type ScimHookFuture = Pin<Box<dyn Future<Output = Result<(), ScimHookError>> + Send>>;

/// Boxed future returned by custom token storage callbacks.
pub type ScimTokenStorageFuture =
    Pin<Box<dyn Future<Output = Result<String, OpenAuthError>> + Send>>;

/// Custom token transformation callback.
pub type ScimTokenTransform = Arc<dyn Fn(String) -> ScimTokenStorageFuture + Send + Sync>;

/// Hook invoked before a SCIM token provider is persisted.
pub type BeforeScimTokenGeneratedHook =
    Arc<dyn Fn(BeforeScimTokenGeneratedInput) -> ScimHookFuture + Send + Sync>;

/// Hook invoked after a SCIM token provider is persisted.
pub type AfterScimTokenGeneratedHook =
    Arc<dyn Fn(AfterScimTokenGeneratedInput) -> ScimHookFuture + Send + Sync>;

/// SCIM plugin options.
///
/// ```
/// use openauth_scim::{ScimOptions, ScimTokenStorage};
///
/// let options = ScimOptions {
///     token_storage: ScimTokenStorage::Hashed,
///     ..ScimOptions::default()
/// };
/// ```
#[derive(Clone)]
pub struct ScimOptions {
    /// Whether provider connections are tied to the user who generated them.
    pub provider_ownership: ProviderOwnershipOptions,
    /// Organization roles allowed to manage org-scoped SCIM providers.
    pub required_role: Option<Vec<String>>,
    /// Static SCIM providers checked before database-backed providers.
    pub default_scim: Vec<DefaultScimProvider>,
    /// How generated SCIM tokens are stored.
    pub token_storage: ScimTokenStorage,
    /// Callback invoked after built-in authorization and before persistence.
    pub before_token_generated: Option<BeforeScimTokenGeneratedHook>,
    /// Callback invoked after a provider has been persisted.
    pub after_token_generated: Option<AfterScimTokenGeneratedHook>,
}

impl Default for ScimOptions {
    fn default() -> Self {
        Self {
            provider_ownership: ProviderOwnershipOptions::default(),
            required_role: None,
            default_scim: Vec::new(),
            token_storage: ScimTokenStorage::Plain,
            before_token_generated: None,
            after_token_generated: None,
        }
    }
}

impl std::fmt::Debug for ScimOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScimOptions")
            .field("provider_ownership", &self.provider_ownership)
            .field("required_role", &self.required_role)
            .field("default_scim", &self.default_scim)
            .field("token_storage", &self.token_storage)
            .field(
                "before_token_generated",
                &self.before_token_generated.as_ref().map(|_| "<hook>"),
            )
            .field(
                "after_token_generated",
                &self.after_token_generated.as_ref().map(|_| "<hook>"),
            )
            .finish()
    }
}

/// Organization member details passed to SCIM hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimOrganizationMember {
    /// Organization identifier.
    pub organization_id: String,
    /// User identifier.
    pub user_id: String,
    /// Persisted organization role string.
    pub role: String,
}

/// Payload for `before_token_generated`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeforeScimTokenGeneratedInput {
    /// Authenticated user generating the token.
    pub user: User,
    /// Organization member row when the token is org-scoped.
    pub member: Option<ScimOrganizationMember>,
    /// Returned bearer token.
    pub scim_token: String,
}

/// Payload for `after_token_generated`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfterScimTokenGeneratedInput {
    /// Authenticated user generating the token.
    pub user: User,
    /// Organization member row when the token is org-scoped.
    pub member: Option<ScimOrganizationMember>,
    /// Returned bearer token.
    pub scim_token: String,
    /// Persisted provider record.
    pub provider: ScimProviderRecord,
}

/// Error returned by SCIM hooks to abort a management request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimHookError {
    /// HTTP status returned to the caller.
    pub status: StatusCode,
    /// Stable API error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
}

impl ScimHookError {
    /// Create a hook error with an explicit HTTP status and API code.
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    /// Create a forbidden hook error.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "FORBIDDEN", message)
    }
}

/// Provider ownership configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderOwnershipOptions {
    /// Enable user ownership for personal SCIM provider connections.
    pub enabled: bool,
}

/// A statically configured SCIM provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultScimProvider {
    /// Stable provider identifier.
    pub provider_id: String,
    /// Plain base token for the provider.
    pub scim_token: String,
    /// Optional organization scope.
    pub organization_id: Option<String>,
}

/// Built-in SCIM token storage modes.
#[derive(Clone)]
pub enum ScimTokenStorage {
    /// Store the base token directly.
    Plain,
    /// Store a SHA-256 digest of the base token.
    Hashed,
    /// Store the base token encrypted with OpenAuth secret material.
    Encrypted,
    /// Store a custom hash of the base token.
    CustomHash { hash: ScimTokenTransform },
    /// Store a custom encrypted token and decrypt it during verification.
    CustomEncryption {
        encrypt: ScimTokenTransform,
        decrypt: ScimTokenTransform,
    },
}

impl ScimTokenStorage {
    /// Create a custom hash token storage mode.
    ///
    /// ```
    /// use openauth_scim::ScimTokenStorage;
    ///
    /// let storage = ScimTokenStorage::custom_hash(|token| {
    ///     Box::pin(async move { Ok(format!("{token}:hashed")) })
    /// });
    /// ```
    pub fn custom_hash(
        hash: impl Fn(String) -> ScimTokenStorageFuture + Send + Sync + 'static,
    ) -> Self {
        Self::CustomHash {
            hash: Arc::new(hash),
        }
    }

    /// Create a custom encrypt/decrypt token storage mode.
    ///
    /// ```
    /// use openauth_scim::ScimTokenStorage;
    ///
    /// let storage = ScimTokenStorage::custom_encryption(
    ///     |token| Box::pin(async move { Ok(token.chars().rev().collect()) }),
    ///     |token| Box::pin(async move { Ok(token.chars().rev().collect()) }),
    /// );
    /// ```
    pub fn custom_encryption(
        encrypt: impl Fn(String) -> ScimTokenStorageFuture + Send + Sync + 'static,
        decrypt: impl Fn(String) -> ScimTokenStorageFuture + Send + Sync + 'static,
    ) -> Self {
        Self::CustomEncryption {
            encrypt: Arc::new(encrypt),
            decrypt: Arc::new(decrypt),
        }
    }
}

impl std::fmt::Debug for ScimTokenStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => formatter.write_str("Plain"),
            Self::Hashed => formatter.write_str("Hashed"),
            Self::Encrypted => formatter.write_str("Encrypted"),
            Self::CustomHash { .. } => formatter.write_str("CustomHash"),
            Self::CustomEncryption { .. } => formatter.write_str("CustomEncryption"),
        }
    }
}
