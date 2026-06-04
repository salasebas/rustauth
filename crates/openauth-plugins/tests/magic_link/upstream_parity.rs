use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, DbFieldType, DbValue, MemoryAdapter, Update, Where};
use openauth_core::options::{
    AdvancedOptions, CookieCacheOptions, IpAddressOptions, OpenAuthOptions, RateLimitOptions,
    SessionOptions, TrustedOriginOptions,
};
use openauth_plugins::additional_fields::{
    additional_fields, AdditionalField, AdditionalFieldsOptions,
};
use openauth_plugins::magic_link::{
    magic_link, MagicLinkEmail, MagicLinkFuture, MagicLinkOptions, MagicLinkSendContext,
};

use super::support::{
    build_router, build_router_with_adapter, build_router_with_plugins, get, json_body, location,
    post_json, seed_user, sent_messages, set_cookie_values, test_advanced_options, SECRET,
};

#[tokio::test]
async fn error_callback_preserves_query_params_when_appending_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, _adapter) = build_router(sent.clone(), MagicLinkOptions::new(sender(sent)))?;

    let response = get(
        &router,
        "/api/auth/magic-link/verify?token=missing&errorCallbackURL=http%3A%2F%2Flocalhost%3A3000%2Ferror-page%3Ffoo%3Dbar",
    )
    .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("http://localhost:3000/error-page?foo=bar&error=INVALID_TOKEN")
    );
    Ok(())
}

#[tokio::test]
async fn error_callback_replaces_existing_error_param() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, _adapter) = build_router(sent.clone(), MagicLinkOptions::new(sender(sent)))?;

    let response = get(
        &router,
        "/api/auth/magic-link/verify?token=missing&errorCallbackURL=http%3A%2F%2Flocalhost%3A3000%2Ferror-page%3Ffoo%3Dbar%26error%3Dold",
    )
    .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        Some("http://localhost:3000/error-page?foo=bar&error=INVALID_TOKEN")
    );
    Ok(())
}

#[tokio::test]
async fn verify_url_uses_base_url_path_without_appending_base_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, _adapter) = build_router_with_plugins(
        MagicLinkOptions::new(sender(sent.clone())),
        Vec::new(),
        OpenAuthOptions {
            base_url: Some("http://localhost:3000/custom/auth".to_owned()),
            base_path: Some("/api/auth".to_owned()),
            secret: Some(SECRET.to_owned()),
            advanced: test_advanced_options(),
            rate_limit: RateLimitOptions {
                enabled: Some(false),
                ..RateLimitOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;

    assert!(last_message(&sent)?
        .url
        .starts_with("http://localhost:3000/custom/auth/magic-link/verify?"));
    Ok(())
}

#[tokio::test]
async fn context_sender_receives_request_data() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_sender = Arc::clone(&seen);
    let sent_sender = Arc::clone(&sent);
    let options = MagicLinkOptions::new_with_context(
        move |email: MagicLinkEmail, ctx: MagicLinkSendContext<'_>| {
            let seen = Arc::clone(&seen_sender);
            let sent = Arc::clone(&sent_sender);
            Box::pin(async move {
                let request_id = ctx
                    .request
                    .headers()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                seen.lock()
                    .map_err(|_| {
                        openauth_core::error::OpenAuthError::Api("seen lock poisoned".to_owned())
                    })?
                    .push(format!("{}:{request_id}", ctx.context.base_path));
                sent.lock()
                    .map_err(|_| {
                        openauth_core::error::OpenAuthError::Api("sent lock poisoned".to_owned())
                    })?
                    .push(email);
                Ok(())
            })
        },
    );
    let (router, _adapter) = build_router(sent, options)?;

    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/sign-in/magic-link")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-request-id", "req_123")
        .body(br#"{"email":"ada@example.com"}"#.to_vec())?;
    let response = router.handle_async(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        seen.lock().map_err(|_| "seen lock poisoned")?.as_slice(),
        ["/api/auth:req_123"]
    );
    Ok(())
}

#[tokio::test]
async fn latest_sent_magic_link_token_verifies_correctly() -> Result<(), Box<dyn std::error::Error>>
{
    let sent = sent_messages();
    let (router, adapter) =
        build_router(sent.clone(), MagicLinkOptions::new(sender(sent.clone())))?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    for _ in 0..3 {
        post_json(
            &router,
            "/api/auth/sign-in/magic-link",
            r#"{"email":"ada@example.com"}"#,
        )
        .await?;
    }
    let token = last_message(&sent)?.token;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn verify_returns_returned_additional_user_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let sent = sent_messages();
    let field = AdditionalField::new(DbFieldType::String)
        .optional()
        .default_value(DbValue::String("pro".to_owned()));
    let plugin = additional_fields(AdditionalFieldsOptions::new().user_field("plan", field));
    let (router, _adapter) = build_router_with_plugins(
        MagicLinkOptions::new(sender(sent.clone())),
        vec![plugin],
        OpenAuthOptions::default(),
    )?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"new@example.com","name":"New User"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert_eq!(json_body(&response)?["user"]["plan"], "pro");
    Ok(())
}

#[tokio::test]
async fn verify_returns_persisted_additional_user_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let sent = sent_messages();
    let field = AdditionalField::new(DbFieldType::String)
        .optional()
        .default_value(DbValue::String("free".to_owned()));
    let plugin = additional_fields(AdditionalFieldsOptions::new().user_field("plan", field));
    let (router, adapter) = build_router_with_plugins(
        MagicLinkOptions::new(sender(sent.clone())),
        vec![plugin],
        OpenAuthOptions::default(),
    )?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"member@example.com","name":"Member"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;
    assert_eq!(json_body(&response)?["user"]["plan"], "free");

    adapter
        .update(
            Update::new("user")
                .where_clause(Where::new(
                    "email",
                    DbValue::String("member@example.com".to_owned()),
                ))
                .data("plan", DbValue::String("enterprise".to_owned())),
        )
        .await?;
    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"member@example.com"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert_eq!(json_body(&response)?["user"]["plan"], "enterprise");
    Ok(())
}

#[tokio::test]
async fn verify_returns_returned_additional_session_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let field = AdditionalField::new(DbFieldType::String)
        .optional()
        .default_value(DbValue::String("magic".to_owned()));
    let plugin =
        additional_fields(AdditionalFieldsOptions::new().session_field("loginKind", field));
    let (router, adapter) = build_router_with_plugins(
        MagicLinkOptions::new(sender(sent.clone())),
        vec![plugin],
        OpenAuthOptions::default(),
    )?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;
    let sessions = adapter.records("session").await;

    assert_eq!(json_body(&response)?["session"]["loginKind"], "magic");
    assert_eq!(
        sessions.first().and_then(|record| record.get("loginKind")),
        Some(&DbValue::String("magic".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn verify_persists_request_metadata_on_session() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let adapter = Arc::new(MemoryAdapter::new());
    let router = build_router_with_adapter(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some(SECRET.to_owned()),
            advanced: test_advanced_options()
                .ip_address(IpAddressOptions::new().header("x-forwarded-for")),
            plugins: vec![magic_link(MagicLinkOptions::new(sender(sent.clone())))],
            rate_limit: RateLimitOptions {
                enabled: Some(false),
                ..RateLimitOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "http://localhost:3000/api/auth/magic-link/verify?token={token}"
        ))
        .header(header::USER_AGENT, "MagicLinkTest/1.0")
        .header("x-forwarded-for", "203.0.113.7, 10.0.0.1")
        .body(Vec::new())?;
    let response = router.handle_async(request).await?;
    let sessions = adapter.records("session").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        sessions.first().and_then(|record| record.get("ip_address")),
        Some(&DbValue::String("203.0.113.7".to_owned()))
    );
    assert_eq!(
        sessions.first().and_then(|record| record.get("user_agent")),
        Some(&DbValue::String("MagicLinkTest/1.0".to_owned()))
    );
    Ok(())
}

/// Magic-link verify must persist the client IP from the configured resolver, not
/// a spoofed `x-forwarded-for` an attacker can prepend (OPE-67).
#[tokio::test]
async fn verify_session_ip_uses_resolver_not_spoofed_forwarded_for(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let adapter = Arc::new(MemoryAdapter::new());
    let router = build_router_with_adapter(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some(SECRET.to_owned()),
            advanced: test_advanced_options()
                .ip_address(IpAddressOptions::new().header("x-real-ip")),
            plugins: vec![magic_link(MagicLinkOptions::new(sender(sent.clone())))],
            rate_limit: RateLimitOptions {
                enabled: Some(false),
                ..RateLimitOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "http://localhost:3000/api/auth/magic-link/verify?token={token}"
        ))
        .header("x-real-ip", "198.51.100.4")
        .header("x-forwarded-for", "203.0.113.99")
        .body(Vec::new())?;
    let response = router.handle_async(request).await?;
    let sessions = adapter.records("session").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        sessions.first().and_then(|record| record.get("ip_address")),
        Some(&DbValue::String("198.51.100.4".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_in_rejects_untrusted_callback_urls() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let adapter = Arc::new(MemoryAdapter::new());
    let plugin = magic_link(MagicLinkOptions::new(sender(sent)));
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
            rate_limit: RateLimitOptions {
                enabled: Some(false),
                ..RateLimitOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;

    let response = post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com","callbackURL":"http://evil.example"}"#,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(&response)?["code"], "INVALID_CALLBACK_URL");
    Ok(())
}

#[tokio::test]
async fn verify_sets_cookie_cache_when_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, adapter) = build_router_with_plugins(
        MagicLinkOptions::new(sender(sent.clone())),
        Vec::new(),
        OpenAuthOptions {
            session: SessionOptions {
                cookie_cache: CookieCacheOptions {
                    enabled: true,
                    ..CookieCacheOptions::default()
                },
                ..SessionOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_data=")));
    Ok(())
}

#[tokio::test]
async fn default_token_charset_is_letters_only() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, _adapter) =
        build_router(sent.clone(), MagicLinkOptions::new(sender(sent.clone())))?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;

    assert_eq!(token.len(), 32);
    assert!(token.chars().all(|ch| ch.is_ascii_alphabetic()), "{token}");
    Ok(())
}

#[tokio::test]
async fn expires_in_zero_uses_default_expiry() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let (router, adapter) = build_router(
        sent.clone(),
        MagicLinkOptions::new(sender(sent.clone())).expires_in(0),
    )?;
    seed_user(&adapter, "user_1", "Ada", "ada@example.com", true).await?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = last_message(&sent)?.token;
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

fn sender(
    sent: Arc<Mutex<Vec<MagicLinkEmail>>>,
) -> impl Fn(MagicLinkEmail) -> MagicLinkFuture<'static, ()> + Send + Sync + 'static {
    move |email| {
        let sent = Arc::clone(&sent);
        Box::pin(async move {
            sent.lock()
                .map_err(|_| {
                    openauth_core::error::OpenAuthError::Api("sent lock poisoned".to_owned())
                })?
                .push(email);
            Ok(())
        })
    }
}

fn last_message(
    sent: &Arc<Mutex<Vec<MagicLinkEmail>>>,
) -> Result<MagicLinkEmail, Box<dyn std::error::Error>> {
    sent.lock()
        .map_err(|_| "sent lock poisoned")?
        .last()
        .cloned()
        .ok_or_else(|| "missing sent magic link".into())
}
