use super::*;
use std::sync::Mutex;

use openauth_core::options::{PasswordOptions, PasswordResetEmail};
use openauth_core::test_utils::MemorySecondaryStorage as TestSecondaryStorage;

#[tokio::test]
async fn request_password_reset_route_does_not_reveal_user_existence(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"missing@example.com","redirectTo":"/reset"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(
        body["message"],
        "If this email exists in our system, check your email for the reset link"
    );
    assert!(adapter.is_empty("verification").await);
    Ok(())
}

#[tokio::test]
async fn password_reset_flow_uses_secondary_storage_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(TestSecondaryStorage::default());
    let sent = Arc::new(Mutex::new(Vec::<String>::new()));
    let sent_for_hook = Arc::clone(&sent);
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions::default()
            .secondary_storage(storage.clone())
            .password(PasswordOptions::new().send_reset_password(
                move |payload: PasswordResetEmail, _request: Option<&http::Request<Vec<u8>>>| {
                    sent_for_hook
                        .lock()
                        .map_err(|_| {
                            OpenAuthError::Api("password reset sink lock poisoned".to_owned())
                        })?
                        .push(payload.token);
                    Ok(())
                },
            )),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let token = sent
        .lock()
        .map_err(|_| "password reset sink poisoned")?
        .first()
        .cloned()
        .ok_or("missing password reset email")?;
    assert!(adapter.is_empty("verification").await);
    let key = format!("verification:reset-password:{token}");
    assert!(storage.value(&key)?.is_some());

    let reset = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/reset-password",
            &format!(r#"{{"newPassword":"new-secret123","token":"{token}"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(reset.status(), StatusCode::OK);
    assert!(storage.value(&key)?.is_none());
    assert!(contains_record_string(&adapter, "account", "user_id", "user_1").await?);
    Ok(())
}

#[tokio::test]
async fn request_password_reset_route_sends_reset_link_for_existing_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let sent_for_hook = Arc::clone(&sent);
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions::default().password(PasswordOptions::new().send_reset_password(
            move |payload: PasswordResetEmail, _request: Option<&http::Request<Vec<u8>>>| {
                sent_for_hook
                    .lock()
                    .map_err(|_| {
                        OpenAuthError::Api("password reset sink lock poisoned".to_owned())
                    })?
                    .push((payload.token, payload.url));
                Ok(())
            },
        )),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(
        body["message"],
        "If this email exists in our system, check your email for the reset link"
    );
    let (token, url) = sent
        .lock()
        .map_err(|_| "password reset sink poisoned")?
        .first()
        .cloned()
        .ok_or("missing password reset email")?;
    assert_eq!(token.len(), 24);
    assert!(url.contains("/reset-password/"));
    assert!(url.contains("callbackURL=%2Freset"));
    assert!(
        contains_record_string(
            &adapter,
            "verification",
            "identifier",
            &format!("reset-password:{token}")
        )
        .await?
    );
    Ok(())
}
