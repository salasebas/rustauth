use std::sync::{Arc, Mutex};

use openauth_sso::{SsoAuditEvent, SsoAuditEventKind};

use super::*;

#[tokio::test]
async fn provider_lifecycle_emits_audit_events() -> Result<(), Box<dyn std::error::Error>> {
    let events = Arc::new(Mutex::new(Vec::<SsoAuditEvent>::new()));
    let (adapter, router) = router_with_options(audit_options(Arc::clone(&events)))?;
    let cookie = seed_session(&adapter).await?;

    let register = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(register.status(), StatusCode::OK);

    let update = router
        .handle_async(json_request(
            Method::POST,
            "/sso/update-provider",
            r#"{"providerId":"okta","domain":"login.example.com"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(update.status(), StatusCode::OK);

    let delete = router
        .handle_async(json_request(
            Method::POST,
            "/sso/delete-provider",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(delete.status(), StatusCode::OK);

    let kinds = event_kinds(&events);
    assert!(kinds.contains(&SsoAuditEventKind::ProviderRegistered));
    assert!(kinds.contains(&SsoAuditEventKind::ProviderUpdated));
    assert!(kinds.contains(&SsoAuditEventKind::ProviderDeleted));

    Ok(())
}

#[tokio::test]
async fn domain_verification_emits_audit_events() -> Result<(), Box<dyn std::error::Error>> {
    let events = Arc::new(Mutex::new(Vec::<SsoAuditEvent>::new()));
    let expected_txt = Arc::new(Mutex::new(String::new()));
    let resolver_txt = Arc::clone(&expected_txt);
    let options = audit_options(Arc::clone(&events))
        .domain_verification_enabled(true)
        .domain_txt_resolver(move |_name| {
            let resolver_txt = Arc::clone(&resolver_txt);
            async move {
                let value = resolver_txt
                    .lock()
                    .map(|value| value.clone())
                    .unwrap_or_default();
                Ok(vec![value])
            }
        });
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;

    let register = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(register.status(), StatusCode::OK);

    let request = router
        .handle_async(json_request(
            Method::POST,
            "/sso/request-domain-verification",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(request.status(), StatusCode::CREATED);
    let token = json_body(request)?["domainVerificationToken"]
        .as_str()
        .ok_or("domain verification token missing")?
        .to_owned();
    if let Ok(mut value) = expected_txt.lock() {
        *value = format!("_better-auth-token-okta={token}");
    }

    let verify = router
        .handle_async(json_request(
            Method::POST,
            "/sso/verify-domain",
            r#"{"providerId":"okta"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(verify.status(), StatusCode::NO_CONTENT);

    let kinds = event_kinds(&events);
    assert!(kinds.contains(&SsoAuditEventKind::DomainVerificationRequested));
    assert!(kinds.contains(&SsoAuditEventKind::DomainVerificationSucceeded));

    Ok(())
}

fn audit_options(events: Arc<Mutex<Vec<SsoAuditEvent>>>) -> SsoOptions {
    SsoOptions::default().audit_event(move |event| {
        let events = Arc::clone(&events);
        async move {
            if let Ok(mut events) = events.lock() {
                events.push(event);
            }
        }
    })
}

fn event_kinds(events: &Arc<Mutex<Vec<SsoAuditEvent>>>) -> Vec<SsoAuditEventKind> {
    events
        .lock()
        .map(|events| events.iter().map(|event| event.kind).collect())
        .unwrap_or_default()
}
