use super::*;
use time::Duration;

use rustauth_core::options::{ChangeEmailOptions, UserOptions};

#[tokio::test]
async fn change_email_route_updates_unverified_user_when_allowed(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            user: UserOptions {
                change_email: ChangeEmailOptions {
                    enabled: true,
                    update_email_without_verification: true,
                    ..Default::default()
                },
                ..UserOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-email",
            r#"{"newEmail":"new@example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    assert_eq!(body["message"], "Email updated");
    assert!(!contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    let updated = record_by_string(&adapter, "user", "email", "new@example.com")
        .await?
        .ok_or("missing updated user")?;
    assert_eq!(
        updated.get("email"),
        Some(&DbValue::String("new@example.com".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn change_email_route_hides_existing_email() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    adapter
        .insert_user(User {
            id: "user_2".to_owned(),
            email: "taken@example.com".to_owned(),
            ..user(now)
        })
        .await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            user: UserOptions {
                change_email: ChangeEmailOptions {
                    enabled: true,
                    update_email_without_verification: true,
                    ..Default::default()
                },
                ..UserOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-email",
            r#"{"newEmail":"taken@example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    assert!(contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    Ok(())
}

#[tokio::test]
async fn change_email_immediate_update_preserves_non_remembered_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            user: UserOptions {
                change_email: ChangeEmailOptions {
                    enabled: true,
                    update_email_without_verification: true,
                    ..Default::default()
                },
                ..UserOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;
    let cookie = signed_dont_remember_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-email",
            r#"{"newEmail":"new@example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookies = set_cookie_values(&response);
    let session_cookie = set_cookies
        .iter()
        .find(|value| value.starts_with("rustauth.session_token="))
        .ok_or("missing session cookie")?;
    assert!(
        !session_cookie.contains("Max-Age"),
        "non-remembered session cookie must not set Max-Age: {session_cookie}"
    );
    assert!(
        set_cookies
            .iter()
            .any(|value| value.starts_with("rustauth.dont_remember=")),
        "dont_remember marker cookie must be re-emitted"
    );
    Ok(())
}

#[tokio::test]
async fn change_email_route_notifies_current_email_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    use rustauth_core::options::{
        ChangeEmailConfirmation, EmailVerificationOptions, SendChangeEmailConfirmation,
        SendVerificationEmail, VerificationEmail,
    };
    use rustauth_core::OutboundSendFuture;
    use std::sync::{Arc, Mutex};

    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: true,
            ..user(now)
        })
        .await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;

    let notified = Arc::new(Mutex::new(Vec::<String>::new()));
    struct NotifyCurrent(Arc<Mutex<Vec<String>>>);
    impl SendChangeEmailConfirmation for NotifyCurrent {
        fn send_change_email_confirmation(
            &self,
            payload: ChangeEmailConfirmation,
            _: Option<&http::Request<Vec<u8>>>,
        ) -> Result<(), rustauth_core::error::RustAuthError> {
            self.0
                .lock()
                .map_err(|_| rustauth_core::error::RustAuthError::Api("lock".into()))?
                .push(payload.new_email);
            Ok(())
        }
    }
    struct SendNew;
    impl SendVerificationEmail for SendNew {
        fn send_verification_email(
            &self,
            _payload: VerificationEmail,
            _: Option<&http::Request<Vec<u8>>>,
        ) -> OutboundSendFuture {
            Box::pin(async { Ok(()) })
        }
    }

    let router = router_with_options(
        adapter.clone(),
        RustAuthOptions {
            user: UserOptions {
                change_email: ChangeEmailOptions::new()
                    .enabled(true)
                    .send_change_email_confirmation(NotifyCurrent(Arc::clone(&notified))),
                ..UserOptions::default()
            },
            email_verification: EmailVerificationOptions {
                send_verification_email: Some(Arc::new(SendNew)),
                ..EmailVerificationOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/change-email",
            r#"{"newEmail":"new@example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let seen = notified.lock().map_err(|_| "lock")?;
    assert_eq!(seen.as_slice(), ["new@example.com"]);
    Ok(())
}
