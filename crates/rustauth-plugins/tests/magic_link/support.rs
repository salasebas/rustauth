use std::sync::{Arc, Mutex};

use http::{header, Method, Request};
use rustauth_core::api::{core_auth_async_endpoints, AuthRouter};
use rustauth_core::context::create_auth_context_with_adapter;
use rustauth_core::db::{Create, DbAdapter, DbValue, MemoryAdapter};
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{AdvancedOptions, RateLimitOptions, RustAuthOptions};
use rustauth_core::plugin::AuthPlugin;
use rustauth_plugins::magic_link::{magic_link, MagicLinkEmail, MagicLinkFuture, MagicLinkOptions};
use serde_json::Value;
use time::OffsetDateTime;

pub(super) const SECRET: &str = "test-secret-123456789012345678901234";

pub(super) fn options(sent: Arc<Mutex<Vec<MagicLinkEmail>>>) -> MagicLinkOptions {
    MagicLinkOptions::new(sender(sent))
}

pub(super) fn sender(
    sent: Arc<Mutex<Vec<MagicLinkEmail>>>,
) -> impl Fn(MagicLinkEmail) -> MagicLinkFuture<'static, ()> + Send + Sync + 'static {
    move |email| {
        let result = sent
            .lock()
            .map_err(|_| RustAuthError::Api("sent messages lock poisoned".to_owned()))
            .map(|mut messages| messages.push(email));
        Box::pin(async move { result.map(|_| ()) })
    }
}

pub(super) fn sent_messages() -> Arc<Mutex<Vec<MagicLinkEmail>>> {
    Arc::new(Mutex::new(Vec::new()))
}

pub(super) async fn last_sent_token(
    sent: &Arc<Mutex<Vec<MagicLinkEmail>>>,
) -> Result<String, RustAuthError> {
    for _ in 0..200 {
        if let Ok(messages) = sent.lock() {
            if let Some(message) = messages.last() {
                return Ok(message.token.clone());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    Err(RustAuthError::Api("missing sent magic link".to_owned()))
}

pub(super) fn build_router(
    sent: Arc<Mutex<Vec<MagicLinkEmail>>>,
    options: MagicLinkOptions,
) -> Result<(AuthRouter, Arc<MemoryAdapter>), RustAuthError> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = build_router_with_adapter(
        adapter.clone(),
        RustAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some(SECRET.to_owned()),
            advanced: test_advanced_options(),
            plugins: vec![magic_link(options)],
            rate_limit: RateLimitOptions {
                enabled: Some(false),
                ..RateLimitOptions::default()
            },
            ..RustAuthOptions::default()
        },
    )?;
    let _ = sent;
    Ok((router, adapter))
}

pub(super) fn build_router_with_plugins(
    options: MagicLinkOptions,
    mut plugins: Vec<AuthPlugin>,
    mut auth_options: RustAuthOptions,
) -> Result<(AuthRouter, Arc<MemoryAdapter>), RustAuthError> {
    let adapter = Arc::new(MemoryAdapter::new());
    if auth_options.base_url.is_none() {
        auth_options.base_url = Some("http://localhost:3000".to_owned());
    }
    if auth_options.secret.is_none() {
        auth_options.secret = Some(SECRET.to_owned());
    }
    auth_options.advanced.disable_csrf_check = true;
    auth_options.advanced.disable_origin_check = true;
    if auth_options.rate_limit.enabled.is_none() {
        auth_options.rate_limit = RateLimitOptions {
            enabled: Some(false),
            ..auth_options.rate_limit
        };
    }
    plugins.push(magic_link(options));
    auth_options.plugins = plugins;
    let router = build_router_with_adapter(adapter.clone(), auth_options)?;
    Ok((router, adapter))
}

pub(super) fn build_router_with_adapter<A>(
    adapter: Arc<A>,
    options: RustAuthOptions,
) -> Result<AuthRouter, RustAuthError>
where
    A: DbAdapter + 'static,
{
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints())
}

pub(super) fn test_advanced_options() -> AdvancedOptions {
    AdvancedOptions {
        disable_csrf_check: true,
        disable_origin_check: true,
        ..AdvancedOptions::default()
    }
}

pub(super) async fn post_json(
    router: &AuthRouter,
    path: &str,
    body: &str,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.as_bytes().to_vec())?;
    Ok(router.handle_async(request).await?)
}

pub(super) async fn get(
    router: &AuthRouter,
    path: &str,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://localhost:3000{path}"))
        .body(Vec::new())?;
    Ok(router.handle_async(request).await?)
}

pub(super) fn json_body(response: &http::Response<Vec<u8>>) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(response.body())
}

pub(super) fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

pub(super) fn location(response: &http::Response<Vec<u8>>) -> Option<&str> {
    response.headers().get(header::LOCATION)?.to_str().ok()
}

pub(super) async fn seed_user(
    adapter: &MemoryAdapter,
    id: &str,
    name: &str,
    email: &str,
    email_verified: bool,
) -> Result<(), RustAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String(name.to_owned()))
                .data("email", DbValue::String(email.to_owned()))
                .data("email_verified", DbValue::Boolean(email_verified))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await?;
    Ok(())
}
