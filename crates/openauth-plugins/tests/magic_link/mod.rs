use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, MemoryAdapter, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions, TrustedOriginOptions};
use openauth_plugins::magic_link::{
    default_key_hasher, magic_link_with, MagicLinkEmail, MagicLinkOptions, TokenStorage,
};

mod failure_redirects;
mod rate_limit;
mod support;
mod token_generation;
mod upstream_parity;

use support::{
    build_router, get, json_body, options, post_json, seed_user, sender, sent_messages,
    set_cookie_values, SECRET,
};

#[tokio::test]
async fn exposes_magic_link_plugin_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let plugin = magic_link_with(options(sent.clone()));

    assert_eq!(
        openauth_plugins::magic_link::UPSTREAM_PLUGIN_ID,
        "magic-link"
    );
    assert_eq!(plugin.id, "magic-link");
    assert_eq!(plugin.version.as_deref(), Some(openauth_plugins::VERSION));
    assert_eq!(plugin.endpoints.len(), 2);
    assert_eq!(plugin.rate_limit.len(), 2);
    Ok(())
}

#[tokio::test]
async fn sends_magic_link_with_url_and_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, _adapter) =
        build_router(sent.clone(), MagicLinkOptions::new(sender(sent.clone())))?;

    let response = post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"Ada@Example.COM","metadata":{"inviteId":"123"}}"#,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(&response)?["status"], true);
    let message = last_message(&sent)?;
    assert_eq!(message.email, "Ada@Example.COM");
    assert!(message
        .url
        .starts_with("http://localhost:3000/api/auth/magic-link/verify?"));
    let metadata = message.metadata.as_ref().ok_or("missing metadata")?;
    assert_eq!(metadata["inviteId"], "123");
    Ok(())
}

#[tokio::test]
async fn verifies_magic_link_creates_session_and_sets_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, adapter) = build_router(sent.clone(), options(sent.clone()))?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(&response)?;
    assert!(body["token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn rejects_reused_expired_and_invalid_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, adapter) = build_router(sent.clone(), options(sent.clone()))?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let first = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let reused = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;
    assert_redirect_error(&reused, "ATTEMPTS_EXCEEDED")?;

    let invalid = get(&router, "/api/auth/magic-link/verify?token=missing").await?;
    assert_redirect_error(&invalid, "INVALID_TOKEN")?;

    let short_lived = MagicLinkOptions::new(sender(sent.clone())).expires_in(1);
    let (router, _adapter) = build_router(sent.clone(), short_lived)?;
    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let expired_token = token_from_last_message(&sent)?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let expired = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={expired_token}"),
    )
    .await?;
    assert_redirect_error(&expired, "EXPIRED_TOKEN")?;
    Ok(())
}

#[tokio::test]
async fn missing_or_empty_verify_token_redirects_with_invalid_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, _adapter) = build_router(sent.clone(), options(sent))?;

    let missing = get(&router, "/api/auth/magic-link/verify").await?;
    assert_redirect_error(&missing, "INVALID_TOKEN")?;

    let empty = get(&router, "/api/auth/magic-link/verify?token=").await?;
    assert_redirect_error(&empty, "INVALID_TOKEN")?;
    Ok(())
}

#[tokio::test]
async fn signs_up_new_users_and_can_disable_sign_up() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, adapter) = build_router(sent.clone(), options(sent.clone()))?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"new@example.com","name":"New User"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let user = find_user(&adapter, "new@example.com")
        .await?
        .ok_or("missing new user")?;
    assert_eq!(
        user.get("name"),
        Some(&DbValue::String("New User".to_owned()))
    );
    assert_eq!(user.get("email_verified"), Some(&DbValue::Boolean(true)));

    let disabled = MagicLinkOptions::new(sender(sent.clone())).disable_sign_up(true);
    let (router, _adapter) = build_router(sent.clone(), disabled)?;
    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"blocked@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;
    assert_redirect_error(&response, "new_user_signup_disabled")?;
    Ok(())
}

#[tokio::test]
async fn verified_unverified_user_session_persists_through_get_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, adapter) = build_router(sent.clone(), options(sent.clone()))?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", false).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let verify = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;
    assert_eq!(verify.status(), StatusCode::OK);
    let cookies = set_cookie_values(&verify);
    let cookie = cookies
        .iter()
        .find_map(|value| value.split(';').next())
        .ok_or("missing session cookie")?;

    let session = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/get-session")
                .header(header::COOKIE, cookie)
                .body(Vec::new())?,
        )
        .await?;
    let body = json_body(&session)?;

    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(body["user"]["email_verified"], true);
    assert_eq!(body["user"]["email"], "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn verifies_existing_unverified_user() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, adapter) = build_router(sent.clone(), options(sent.clone()))?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", false).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(&response)?["user"]["email_verified"], true);
    let user = find_user(&adapter, "ada@example.com")
        .await?
        .ok_or("missing verified user")?;
    assert_eq!(user.get("email_verified"), Some(&DbValue::Boolean(true)));
    Ok(())
}

#[tokio::test]
async fn concurrent_verify_mints_only_one_session() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, adapter) = build_router(sent.clone(), options(sent.clone()))?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let path = format!("/api/auth/magic-link/verify?token={token}");
    let sessions_before = adapter.len("session").await;

    let (first, second) = tokio::join!(get(&router, &path), get(&router, &path));
    let responses = [first?, second?];
    let ok = responses
        .iter()
        .filter(|response| response.status() == StatusCode::OK)
        .count();
    let rejected = responses
        .iter()
        .filter(|response| response.status() == StatusCode::FOUND)
        .count();

    assert_eq!(
        ok, 1,
        "only one concurrent verify should mint a session for the default single attempt"
    );
    assert_eq!(
        rejected, 1,
        "the losing concurrent verify should redirect with an error"
    );
    let rejected_location = responses
        .iter()
        .find(|response| response.status() == StatusCode::FOUND)
        .and_then(|response| response.headers().get(header::LOCATION))
        .and_then(|value| value.to_str().ok())
        .ok_or("missing rejected redirect location")?;
    assert!(
        rejected_location.contains("error=ATTEMPTS_EXCEEDED")
            || rejected_location.contains("error=INVALID_TOKEN"),
        "{rejected_location}"
    );
    assert_eq!(
        adapter.len("session").await,
        sessions_before + 1,
        "only one new session row should be created by concurrent verification"
    );
    Ok(())
}

#[tokio::test]
async fn respects_allowed_attempts_and_unlimited_attempts() -> Result<(), Box<dyn std::error::Error>>
{
    let sent = sent_messages();
    let opts = MagicLinkOptions::new(sender(sent.clone())).allowed_attempts(3);
    let (router, adapter) = build_router(sent.clone(), opts)?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    for _ in 0..3 {
        let response = get(
            &router,
            &format!("/api/auth/magic-link/verify?token={token}"),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let fourth = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;
    assert_redirect_error(&fourth, "ATTEMPTS_EXCEEDED")?;

    let opts = MagicLinkOptions::new(sender(sent.clone())).unlimited_attempts();
    let (router, adapter) = build_router(sent.clone(), opts)?;
    seed_user(&adapter, "user_2", "Grace", "grace@example.com", true).await?;
    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"grace@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    for _ in 0..5 {
        let response = get(
            &router,
            &format!("/api/auth/magic-link/verify?token={token}"),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn supports_token_storage_modes() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let hashed_opts = MagicLinkOptions::new(sender(sent.clone())).store_token(TokenStorage::Hashed);
    let (router, adapter) = build_router(sent.clone(), hashed_opts)?;
    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let hashed = default_key_hasher(&token);
    assert!(find_verification(&adapter, &hashed).await?.is_some());

    let custom_opts =
        MagicLinkOptions::new(sender(sent.clone())).store_token(TokenStorage::custom(|token| {
            Box::pin(async move { Ok(format!("{token}:hashed")) })
        }));
    let (router, adapter) = build_router(sent.clone(), custom_opts)?;
    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    assert!(find_verification(&adapter, &format!("{token}:hashed"))
        .await?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn rejects_untrusted_verify_callback_urls() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let adapter = Arc::new(MemoryAdapter::new());
    let plugin = magic_link_with(options(sent.clone()));
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            trusted_origins: TrustedOriginOptions::Static(vec!["http://localhost:3000".to_owned()]),
            secret: Some(SECRET.to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: false,
                ..AdvancedOptions::default()
            },
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = token_from_last_message(&sent)?;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}&callbackURL=http://evil.example"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(&response)?["code"], "INVALID_CALLBACK_URL");
    Ok(())
}

fn last_message(
    sent: &Arc<Mutex<Vec<MagicLinkEmail>>>,
) -> Result<MagicLinkEmail, Box<dyn std::error::Error>> {
    sent.lock()
        .map_err(|_| "sent messages lock poisoned")?
        .last()
        .cloned()
        .ok_or_else(|| "missing sent magic link".into())
}

fn token_from_last_message(
    sent: &Arc<Mutex<Vec<MagicLinkEmail>>>,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(last_message(sent)?.token)
}

fn assert_redirect_error(
    response: &http::Response<Vec<u8>>,
    error: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing location header")?;
    assert!(location.contains(&format!("error={error}")), "{location}");
    Ok(())
}

async fn find_user(
    adapter: &MemoryAdapter,
    email: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("email", DbValue::String(email.to_owned()))),
        )
        .await
}

async fn find_verification(
    adapter: &MemoryAdapter,
    identifier: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(FindOne::new("verification").where_clause(Where::new(
            "identifier",
            DbValue::String(identifier.to_owned()),
        )))
        .await
}
