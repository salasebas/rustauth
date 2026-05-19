use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

type AuditEventFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Severity level for SSO audit events.
pub enum SsoAuditSeverity {
    /// Informational event.
    Info,
    /// Suspicious or recoverable condition.
    Warn,
    /// Failed security-sensitive operation.
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// SSO audit event kind emitted by provider, domain, SAML, and SLO flows.
pub enum SsoAuditEventKind {
    /// A provider was registered.
    ProviderRegistered,
    /// A provider was updated.
    ProviderUpdated,
    /// A provider was deleted.
    ProviderDeleted,
    /// A domain verification token was requested.
    DomainVerificationRequested,
    /// Domain verification succeeded.
    DomainVerificationSucceeded,
    /// Domain verification failed.
    DomainVerificationFailed,
    /// A replayed SAML assertion was rejected.
    SamlReplayRejected,
    /// SAML signature validation failed.
    SamlSignatureFailed,
    /// A SAML SLO flow deleted a local session.
    SamlSloSessionDeleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Audit event emitted by the SSO plugin.
pub struct SsoAuditEvent {
    /// Event kind.
    pub kind: SsoAuditEventKind,
    /// Event severity.
    pub severity: SsoAuditSeverity,
    /// Provider id related to the event, when available.
    pub provider_id: Option<String>,
    /// User id related to the event, when available.
    pub user_id: Option<String>,
    /// Organization id related to the event, when available.
    pub organization_id: Option<String>,
    /// Human-readable reason or stable error code.
    pub reason: Option<String>,
}

impl SsoAuditEvent {
    /// Create an audit event with no optional context.
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
    /// Attach a provider id to the event.
    pub fn provider_id(mut self, provider_id: impl Into<String>) -> Self {
        self.provider_id = Some(provider_id.into());
        self
    }

    #[must_use]
    /// Attach a user id to the event.
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    #[must_use]
    /// Attach an organization id to the event.
    pub fn organization_id(mut self, organization_id: impl Into<String>) -> Self {
        self.organization_id = Some(organization_id.into());
        self
    }

    #[must_use]
    /// Attach a reason or stable error code to the event.
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[derive(Clone)]
/// Async sink for SSO audit events.
pub struct SsoAuditEventResolver {
    resolver: Arc<dyn Fn(SsoAuditEvent) -> AuditEventFuture + Send + Sync>,
}

impl SsoAuditEventResolver {
    /// Create an audit event sink from an async function.
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(SsoAuditEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |event| Box::pin(resolver(event))),
        }
    }

    /// Emit an audit event.
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
