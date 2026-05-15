use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use openauth_core::options::{OnPasswordReset, PasswordOptions, PasswordResetPayload};

struct CountReset(Arc<AtomicUsize>);

impl OnPasswordReset for CountReset {
    fn on_password_reset(
        &self,
        _payload: PasswordResetPayload,
        _request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn reset_password_route_updates_password_and_consumes_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
    let router = router(adapter.clone())?;

    let request_response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
            None,
        )?)
        .await?;
    assert_eq!(request_response.status(), StatusCode::OK);
    let identifier = adapter
        .records("verification")
        .await
        .into_iter()
        .find_map(|record| string_field(&record, "identifier").ok().map(str::to_owned))
        .ok_or("missing verification")?;
    let token = identifier
        .strip_prefix("reset-password:")
        .ok_or("bad identifier")?
        .to_owned();

    let reset_response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/reset-password",
            &format!(r#"{{"newPassword":"new-secret123","token":"{token}"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(reset_response.status(), StatusCode::OK);
    assert!(adapter.is_empty("verification").await);
    let account = record_by_string(&adapter, "account", "id", "account_1")
        .await?
        .ok_or("missing account")?;
    let hash = string_field(&account, "password")?;
    assert!(openauth_core::crypto::password::verify_password(
        hash,
        "new-secret123"
    )?);

    let reused_response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/reset-password",
            &format!(r#"{{"newPassword":"another-secret123","token":"{token}"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(reused_response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn reset_password_route_invokes_callback_and_revokes_sessions(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let reset_count = Arc::new(AtomicUsize::new(0));
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            password: PasswordOptions {
                on_password_reset: Some(Arc::new(CountReset(Arc::clone(&reset_count)))),
                revoke_sessions_on_password_reset: true,
                ..PasswordOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com"}"#,
            None,
        )?)
        .await?;
    let identifier = adapter
        .records("verification")
        .await
        .into_iter()
        .find_map(|record| string_field(&record, "identifier").ok().map(str::to_owned))
        .ok_or("missing verification")?;
    let token = identifier
        .strip_prefix("reset-password:")
        .ok_or("bad identifier")?
        .to_owned();

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/reset-password",
            &format!(r#"{{"newPassword":"new-secret123","token":"{token}"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(reset_count.load(Ordering::SeqCst), 1);
    assert!(adapter.is_empty("session").await);
    Ok(())
}
