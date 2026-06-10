use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::MemoryAdapter;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions, RateLimitOptions};
use openauth_plugins::magic_link::{magic_link_with, MagicLinkRateLimit};

use super::support::{json_body, options, sent_messages, SECRET};

#[tokio::test]
async fn applies_magic_link_rate_limit_rule() -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let adapter = Arc::new(MemoryAdapter::new());
    let plugin = magic_link_with(
        options(sent.clone()).rate_limit(MagicLinkRateLimit { window: 60, max: 1 }),
    );
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some(SECRET.to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![plugin],
            rate_limit: RateLimitOptions {
                enabled: Some(true),
                ..RateLimitOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))?;

    let first = request(&router).await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = request(&router).await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_body(&second)?["code"], "TOO_MANY_REQUESTS");
    Ok(())
}

async fn request(
    router: &AuthRouter,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/sign-in/magic-link")
        .header(header::CONTENT_TYPE, "application/json")
        .body(br#"{"email":"ada@example.com"}"#.to_vec())?;
    Ok(router.handle_async(request).await?)
}
