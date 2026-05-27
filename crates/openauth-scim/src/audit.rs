//! Optional SCIM audit hooks (structured logging + integrator callback).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_core::context::AuthContext;

use crate::options::{ScimAuditEvent, ScimAuditEventKind, ScimAuditSeverity, ScimOptions};

type AuditEventFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Async sink for SCIM audit events.
#[derive(Clone)]
pub struct ScimAuditEventResolver {
    resolver: Arc<dyn Fn(ScimAuditEvent) -> AuditEventFuture + Send + Sync>,
}

impl ScimAuditEventResolver {
    /// Create an audit event sink from an async function.
    pub fn new<F, Fut>(resolver: F) -> Self
    where
        F: Fn(ScimAuditEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            resolver: Arc::new(move |event| Box::pin(resolver(event))),
        }
    }

    /// Emit an audit event.
    pub async fn resolve(&self, event: ScimAuditEvent) {
        (self.resolver)(event).await;
    }
}

impl std::fmt::Debug for ScimAuditEventResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScimAuditEventResolver(..)")
    }
}

impl PartialEq for ScimAuditEventResolver {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

pub(crate) async fn emit(context: &AuthContext, options: &ScimOptions, event: ScimAuditEvent) {
    log(context, &event);
    if let Some(resolver) = &options.audit_event {
        resolver.resolve(event).await;
    }
}

fn log(context: &AuthContext, event: &ScimAuditEvent) {
    let message = match event.kind {
        ScimAuditEventKind::TokenGenerated => "scim token generated",
        ScimAuditEventKind::UserProvisioned => "scim user provisioned",
        ScimAuditEventKind::UserDeprovisioned => "scim user deprovisioned",
        ScimAuditEventKind::BulkFailed => "scim bulk operation failed",
        ScimAuditEventKind::BulkRolledBack => "scim atomic bulk rolled back",
    };
    let mut args = Vec::new();
    if let Some(provider_id) = event.provider_id.as_deref() {
        args.push(provider_id);
    }
    if let Some(user_id) = event.user_id.as_deref() {
        args.push(user_id);
    }
    if let Some(organization_id) = event.organization_id.as_deref() {
        args.push(organization_id);
    }
    if let Some(reason) = event.reason.as_deref() {
        args.push(reason);
    }
    match event.severity {
        ScimAuditSeverity::Info => context.logger.info(message, &args),
        ScimAuditSeverity::Warn => context.logger.warn(message, &args),
        ScimAuditSeverity::Error => context.logger.error(message, &args),
    }
}
