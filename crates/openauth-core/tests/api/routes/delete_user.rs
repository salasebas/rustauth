use super::*;

use openauth_core::options::{DeleteUserOptions, UserOptions};

#[tokio::test]
async fn delete_user_route_deletes_user_accounts_and_sessions_with_password(
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
    adapter
        .insert_session(Session {
            id: "session_2".to_owned(),
            token: "token_2".to_owned(),
            ..session(now, now + Duration::hours(1))
        })
        .await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            user: UserOptions {
                delete_user: DeleteUserOptions::builder().enabled(true),
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/delete-user",
            r#"{"password":"secret123"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["success"], true);
    assert_eq!(body["message"], "User deleted");
    assert!(adapter.is_empty("user").await);
    assert!(adapter.is_empty("account").await);
    assert!(adapter.is_empty("session").await);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=;")
            && cookie.contains("Max-Age=0")));
    Ok(())
}

#[tokio::test]
async fn delete_user_route_rejects_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
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
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            user: UserOptions {
                delete_user: DeleteUserOptions::builder().enabled(true),
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/delete-user",
            r#"{"password":"wrong-password"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_PASSWORD");
    assert!(contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    Ok(())
}

#[tokio::test]
async fn delete_user_route_rejects_stale_session_without_password(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now - Duration::hours(48), now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            session: openauth_core::options::SessionOptions {
                fresh_age: Some(60 * 60),
                ..Default::default()
            },
            user: UserOptions {
                delete_user: DeleteUserOptions::builder().enabled(true),
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/delete-user",
            "{}",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SESSION_EXPIRED");
    Ok(())
}

#[tokio::test]
async fn delete_user_route_sends_verification_instead_of_immediate_delete(
) -> Result<(), Box<dyn std::error::Error>> {
    use openauth_core::options::DeleteAccountVerificationEmail;
    use std::sync::{Arc, Mutex};

    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let sent = Arc::new(Mutex::new(false));
    struct RecordingSender(Arc<Mutex<bool>>);
    impl openauth_core::options::SendDeleteAccountVerification for RecordingSender {
        fn send_delete_account_verification(
            &self,
            payload: DeleteAccountVerificationEmail,
            _: Option<&http::Request<Vec<u8>>>,
        ) -> Result<(), openauth_core::error::OpenAuthError> {
            assert!(payload.url.contains("/delete-user/callback?token="));
            assert!(payload.url.contains("callbackURL=%2Fdone"));
            *self
                .0
                .lock()
                .map_err(|_| openauth_core::error::OpenAuthError::Api("lock".into()))? = true;
            Ok(())
        }
    }
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            user: UserOptions {
                delete_user: DeleteUserOptions::builder()
                    .enabled(true)
                    .send_delete_account_verification(RecordingSender(Arc::clone(&sent))),
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/delete-user",
            r#"{"callbackURL":"/done"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["message"], "Verification email sent");
    assert!(*sent.lock().map_err(|_| "lock")?);
    assert!(contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    Ok(())
}

#[tokio::test]
async fn delete_user_route_rejects_expired_token() -> Result<(), Box<dyn std::error::Error>> {
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
    adapter
        .create(
            Create::new("verification")
                .data("id", DbValue::String("verification_1".to_owned()))
                .data(
                    "identifier",
                    DbValue::String("delete-account-delete_token".to_owned()),
                )
                .data("value", DbValue::String("user_1".to_owned()))
                .data("expires_at", DbValue::Timestamp(now - Duration::hours(1)))
                .data("created_at", DbValue::Timestamp(now - Duration::hours(2)))
                .data("updated_at", DbValue::Timestamp(now - Duration::hours(2))),
        )
        .await?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            user: UserOptions {
                delete_user: DeleteUserOptions::builder().enabled(true),
                ..UserOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/delete-user",
            r#"{"token":"delete_token"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_TOKEN");
    assert!(contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    assert!(contains_record_string(&adapter, "account", "user_id", "user_1").await?);
    assert!(contains_record_string(&adapter, "session", "token", "token_1").await?);
    Ok(())
}
