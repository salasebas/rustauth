use openauth_core::context::AuthContext;

use crate::options::{SsoAuditEvent, SsoAuditSeverity, SsoOptions};

pub(crate) async fn emit(context: &AuthContext, options: &SsoOptions, event: SsoAuditEvent) {
    log(context, &event);
    if let Some(resolver) = &options.audit_event {
        resolver.resolve(event).await;
    }
}

fn log(context: &AuthContext, event: &SsoAuditEvent) {
    let message = match event.kind {
        crate::options::SsoAuditEventKind::ProviderRegistered => "sso provider registered",
        crate::options::SsoAuditEventKind::ProviderUpdated => "sso provider updated",
        crate::options::SsoAuditEventKind::ProviderDeleted => "sso provider deleted",
        crate::options::SsoAuditEventKind::DomainVerificationRequested => {
            "sso domain verification requested"
        }
        crate::options::SsoAuditEventKind::DomainVerificationSucceeded => {
            "sso domain verification succeeded"
        }
        crate::options::SsoAuditEventKind::DomainVerificationFailed => {
            "sso domain verification failed"
        }
        crate::options::SsoAuditEventKind::SamlReplayRejected => "saml replay rejected",
        crate::options::SsoAuditEventKind::SamlSignatureFailed => "saml signature failed",
        crate::options::SsoAuditEventKind::SamlSloSessionDeleted => "saml slo session deleted",
    };
    let mut args = Vec::new();
    if let Some(provider_id) = event.provider_id.as_deref() {
        args.push(provider_id);
    }
    if let Some(user_id) = event.user_id.as_deref() {
        args.push(user_id);
    }
    if let Some(reason) = event.reason.as_deref() {
        args.push(reason);
    }
    match event.severity {
        SsoAuditSeverity::Info => context.logger.info(message, &args),
        SsoAuditSeverity::Warn => context.logger.warn(message, &args),
        SsoAuditSeverity::Error => context.logger.error(message, &args),
    }
}
