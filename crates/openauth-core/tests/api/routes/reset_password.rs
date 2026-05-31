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

#[tokio::test]
async fn reset_password_token_callback_redirects_with_token_or_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
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

    let valid = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/reset-password/{token}?callbackURL=/reset"),
            "",
            None,
        )?)
        .await?;
    let invalid = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/reset-password/missing?callbackURL=/reset",
            "",
            None,
        )?)
        .await?;

    assert_eq!(valid.status(), StatusCode::FOUND);
    assert_eq!(
        valid
            .headers()
            .get(header::LOCATION)
            .and_then(|h| h.to_str().ok()),
        Some(format!("/reset?token={token}").as_str())
    );
    assert_eq!(invalid.status(), StatusCode::FOUND);
    assert_eq!(
        invalid
            .headers()
            .get(header::LOCATION)
            .and_then(|h| h.to_str().ok()),
        Some("/reset?error=INVALID_TOKEN")
    );
    Ok(())
}

#[tokio::test]
async fn reset_password_token_callback_rejects_untrusted_callback_urls(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
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

    let location = |response: &http::Response<Vec<u8>>| {
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let callback = |segment: &str, callback_url: &str| {
        json_request(
            Method::GET,
            &format!("/api/auth/reset-password/{segment}?callbackURL={callback_url}"),
            "",
            None,
        )
    };

    // Both the valid-token and invalid-token branches must reject unsafe targets and
    // fall back to /error without leaking the token.
    for segment in [token.as_str(), "missing"] {
        for unsafe_url in [
            "https://evil.example/phish",
            "//evil.example",
            "/\\evil.example",
            "%2F%2Fevil.example",
        ] {
            let response = router.handle_async(callback(segment, unsafe_url)?).await?;
            assert_eq!(response.status(), StatusCode::FOUND);
            assert_eq!(
                location(&response).as_deref(),
                Some("/error?error=INVALID_TOKEN"),
                "callback {unsafe_url} for token {segment} must fall back to /error"
            );
        }
    }

    // Safe relative paths and trusted absolute origins still work with a valid token.
    let relative = router.handle_async(callback(&token, "/reset")?).await?;
    assert_eq!(
        location(&relative).as_deref(),
        Some(format!("/reset?token={token}").as_str())
    );
    let trusted = router
        .handle_async(callback(&token, "https://app.example.com/reset")?)
        .await?;
    assert_eq!(
        location(&trusted).as_deref(),
        Some(format!("https://app.example.com/reset?token={token}").as_str())
    );

    Ok(())
}
