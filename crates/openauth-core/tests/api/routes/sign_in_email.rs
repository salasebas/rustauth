use super::*;
use std::sync::Mutex;

use openauth_core::options::{EmailPasswordOptions, EmailVerificationOptions, VerificationEmail};

#[tokio::test]
async fn sign_in_email_route_rejects_invalid_credentials() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("other-password")?,
            now,
        ))
        .await?;
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_EMAIL_OR_PASSWORD");
    assert!(adapter.is_empty("session").await);
    Ok(())
}

#[tokio::test]
async fn sign_in_email_route_returns_token_user_and_sets_cookie(
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

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["session"].is_null());
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert_eq!(body["user"]["id"], "user_1");
    assert_eq!(body["redirect"], false);
    assert!(body["url"].is_null());
    assert_eq!(adapter.len("session").await, 1);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn sign_in_email_route_returns_redirect_url_when_callback_url_is_provided(
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

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["redirect"], true);
    assert_eq!(body["url"], "/dashboard");
    assert_eq!(
        response
            .headers()
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/dashboard")
    );
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert_eq!(body["user"]["id"], "user_1");
    assert_eq!(adapter.len("session").await, 1);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn sign_in_email_route_rejects_by_default_without_explicit_opt_in(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_bare_options(adapter, OpenAuthOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "EMAIL_PASSWORD_DISABLED");
    Ok(())
}

#[tokio::test]
async fn sign_in_email_route_rejects_when_email_password_is_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let router = router_with_bare_options(
        adapter,
        OpenAuthOptions::default().email_password(EmailPasswordOptions::new().enabled(false)),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "EMAIL_PASSWORD_DISABLED");
    Ok(())
}

#[tokio::test]
async fn sign_in_email_route_requires_verified_email_after_password_is_valid(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = Arc::new(Mutex::new(0usize));
    let sent_for_hook = Arc::clone(&sent);
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    let mut unverified = user(now);
    unverified.email_verified = false;
    adapter.insert_user(unverified).await;
    adapter
        .insert_account(credential_account_record(
            "user_1",
            &hash_password("secret123")?,
            now,
        ))
        .await?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions::default()
            .email_password(
                EmailPasswordOptions::new()
                    .enabled(true)
                    .require_email_verification(true),
            )
            .email_verification(
                EmailVerificationOptions::new()
                    .send_on_sign_in(true)
                    .send_verification_email(
                        move |_email: VerificationEmail,
                              _request: Option<&http::Request<Vec<u8>>>| {
                            *sent_for_hook.lock().map_err(|_| {
                                OpenAuthError::Api("verification sink lock poisoned".to_owned())
                            })? += 1;
                            Ok(())
                        },
                    ),
            ),
    )?;

    let wrong_password = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrong"}"#,
            None,
        )?)
        .await?;
    assert_eq!(wrong_password.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(*sent.lock().map_err(|_| "verification sink poisoned")?, 0);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "EMAIL_NOT_VERIFIED");
    assert_eq!(*sent.lock().map_err(|_| "verification sink poisoned")?, 1);
    assert!(adapter.is_empty("session").await);
    Ok(())
}
