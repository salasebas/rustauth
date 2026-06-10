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

/// How `POST /scim/v2/Bulk` applies database changes.
///
/// Better Auth **1.6.9** does not implement Bulk (`bulk.supported: false`). OpenAuth
/// implements RFC 7644 bulk with two modes:
///
/// - [`ScimBulkMode::Independent`] (default): each operation commits on its own,
///   matching typical SCIM deployments and `failOnErrors` stop semantics.
/// - [`ScimBulkMode::Atomic`]: all mutating operations run in one adapter
///   transaction; the first error rolls back earlier mutations in the same request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScimBulkMode {
    /// Sequential operations; each mutation uses its own transaction (default).
    #[default]
    Independent,
    /// One transaction for the whole bulk request; rollback on first failing op.
    Atomic,
}

/// How `DELETE /scim/v2/Users/:id` (and bulk user delete) deprovisions users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScimDeprovisionMode {
    /// Delete the OpenAuth user when they have no linked accounts besides the
    /// current SCIM provider; otherwise unlink (see [`ScimDeprovisionMode::UnlinkAccount`]).
    DeleteUser,
    /// Remove only the current provider account link and SCIM profile.
    #[default]
    UnlinkAccount,
}

/// Severity level for SCIM audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimAuditSeverity {
    /// Informational audit event.
    Info,
    /// Warning-level audit event.
    Warn,
    /// Error-level audit event.
    Error,
}

/// SCIM audit event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimAuditEventKind {
    /// Management token generated or rotated.
    TokenGenerated,
    /// User created or linked via SCIM.
    UserProvisioned,
    /// User deleted or unlinked via SCIM.
    UserDeprovisioned,
    /// A bulk operation returned an error status.
    BulkFailed,
    /// An atomic bulk request rolled back prior operations.
    BulkRolledBack,
}

/// Audit event emitted by the SCIM plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimAuditEvent {
    /// Event kind.
    pub kind: ScimAuditEventKind,
    /// Severity.
    pub severity: ScimAuditSeverity,
    /// SCIM provider id when known.
    pub provider_id: Option<String>,
    /// OpenAuth user id when known.
    pub user_id: Option<String>,
    /// Organization id when the provider is org-scoped.
    pub organization_id: Option<String>,
    /// Optional detail (error message, rollback reason, etc.).
    pub reason: Option<String>,
}

impl ScimAuditEvent {
    /// Create an audit event with no optional context.
    pub fn new(kind: ScimAuditEventKind, severity: ScimAuditSeverity) -> Self {
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
    pub fn with_provider_id(mut self, provider_id: impl Into<String>) -> Self {
        self.provider_id = Some(provider_id.into());
        self
    }

    #[must_use]
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    #[must_use]
    pub fn with_organization_id(mut self, organization_id: impl Into<String>) -> Self {
        self.organization_id = Some(organization_id.into());
        self
    }

    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// SCIM plugin options.
///
/// ```
/// use openauth_scim::{ScimOptions, ScimTokenStorage};
///
/// let options = ScimOptions::default();
/// assert!(matches!(options.token_storage, ScimTokenStorage::Hashed));
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
    /// Bulk commit strategy ([`ScimBulkMode::Independent`] by default).
    pub bulk_mode: ScimBulkMode,
    /// User delete semantics for SCIM deprovision.
    pub deprovision_mode: ScimDeprovisionMode,
    /// Optional async audit sink (also logged through `AuthContext::logger`).
    pub audit_event: Option<crate::audit::ScimAuditEventResolver>,
}

impl Default for ScimOptions {
    fn default() -> Self {
        Self {
            provider_ownership: ProviderOwnershipOptions::default(),
            required_role: None,
            default_scim: Vec::new(),
            token_storage: ScimTokenStorage::Hashed,
            before_token_generated: None,
            after_token_generated: None,
            bulk_mode: ScimBulkMode::default(),
            deprovision_mode: ScimDeprovisionMode::default(),
            audit_event: None,
        }
    }
}

impl ScimOptions {
    /// Create default SCIM plugin options.
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Configure provider ownership rules.
    pub fn provider_ownership(mut self, ownership: ProviderOwnershipOptions) -> Self {
        self.provider_ownership = ownership;
        self
    }

    #[must_use]
    /// Set organization roles allowed to manage org-scoped SCIM providers.
    pub fn required_role(mut self, roles: Vec<String>) -> Self {
        self.required_role = Some(roles);
        self
    }

    #[must_use]
    /// Add statically configured SCIM providers.
    pub fn default_scim(mut self, providers: Vec<DefaultScimProvider>) -> Self {
        self.default_scim = providers;
        self
    }

    #[must_use]
    /// Set how generated SCIM tokens are stored.
    pub fn token_storage(mut self, storage: ScimTokenStorage) -> Self {
        self.token_storage = storage;
        self
    }

    #[must_use]
    /// Set the hook invoked before a SCIM token is persisted.
    pub fn before_token_generated(mut self, hook: BeforeScimTokenGeneratedHook) -> Self {
        self.before_token_generated = Some(hook);
        self
    }

    #[must_use]
    /// Set the hook invoked after a SCIM token is persisted.
    pub fn after_token_generated(mut self, hook: AfterScimTokenGeneratedHook) -> Self {
        self.after_token_generated = Some(hook);
        self
    }

    #[must_use]
    /// Set bulk commit strategy.
    pub fn bulk_mode(mut self, mode: ScimBulkMode) -> Self {
        self.bulk_mode = mode;
        self
    }

    #[must_use]
    /// Set user delete semantics for SCIM deprovision.
    pub fn deprovision_mode(mut self, mode: ScimDeprovisionMode) -> Self {
        self.deprovision_mode = mode;
        self
    }

    #[must_use]
    /// Set an async audit event sink.
    pub fn audit_event(mut self, resolver: crate::audit::ScimAuditEventResolver) -> Self {
        self.audit_event = Some(resolver);
        self
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
            .field("bulk_mode", &self.bulk_mode)
            .field("deprovision_mode", &self.deprovision_mode)
            .field(
                "audit_event",
                &self.audit_event.as_ref().map(|_| "<resolver>"),
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
    /// Enable user ownership for global SCIM provider connections.
    ///
    /// When disabled, management routes reject requests without `organizationId`.
    /// Organization-scoped providers still use [`ScimOptions::required_role`].
    pub enabled: bool,
}

/// A statically configured SCIM provider.
///
/// `provider_id` is globally unique in storage, like Better Auth: it names one SCIM
/// connection, not one organization. Pair it with `organization_id` when the token
/// should only provision members of that organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultScimProvider {
    /// Stable provider identifier (one persisted SCIM connection per value).
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
