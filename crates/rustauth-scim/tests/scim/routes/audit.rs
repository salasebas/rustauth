//! SCIM audit hook integration.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn management_token_generation_emits_audit_event() {
    let seen = Arc::new(AtomicUsize::new(0));
    let seen_for_hook = Arc::clone(&seen);
    let (adapter, router, context) = router_with_context(ScimOptions {
        audit_event: Some(ScimAuditEventResolver::new(move |event| {
            let seen = Arc::clone(&seen_for_hook);
            async move {
                if event.kind == ScimAuditEventKind::TokenGenerated {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            }
        })),
        ..crate::scim_options_for_global_management()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "audit-owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"audit-okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}
