use std::sync::Arc;

use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbValue, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AccountLinkingOptions, AccountOptions, AdvancedOptions, EmailPasswordOptions, OpenAuthOptions,
    SecondaryStorage, SessionOptions, TrustedOriginOptions,
};
use openauth_core::test_utils::MemorySecondaryStorage;

fn with_test_defaults(mut options: OpenAuthOptions) -> OpenAuthOptions {
    if !options.production {
        options.development = true;
    }
    if !options.email_password.enabled {
        options.email_password = EmailPasswordOptions::new().enabled(true);
    }
    options
}
use openauth_core::plugin::AuthPlugin;
use openauth_sso::{sso, SsoOptions};
use time::{Duration, OffsetDateTime};

const SECRET: &str = "secret-a-at-least-32-chars-long!!";

/// Opt out of the OIDC SSRF guard for tests.
///
/// SSO integration tests run mock OIDC providers on loopback addresses, which
/// the default SSRF guard blocks. The shared router helpers enable the
/// documented `allow_private_endpoint_ips` opt-out so these tests can reach the
/// mock servers. Tests that specifically assert the guard's blocking behavior
/// build their router through [`router_with_options_blocking_private_endpoints`]
/// instead, which leaves the guard active.
fn allow_loopback_oidc(mut options: SsoOptions) -> SsoOptions {
    options.oidc.allow_private_endpoint_ips = true;
    options
}

pub fn router_with_options(
    options: SsoOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    router_with_options_and_trusted_origins(options, Vec::new())
}

pub fn router_with_options_and_account_linking(
    options: SsoOptions,
    account_linking: AccountLinkingOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        with_test_defaults(OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            secret: Some(SECRET.to_owned()),
            plugins: vec![sso(allow_loopback_oidc(options))],
            account: AccountOptions::default().account_linking(account_linking),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    );
    Ok((adapter, router?))
}

/// Builds a router that keeps the OIDC SSRF guard active (no opt-out), for
/// tests that assert outbound requests to private/loopback hosts are blocked.
pub fn router_with_options_blocking_private_endpoints(
    options: SsoOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    router_with_options_storage_trusted_origins_extra_plugins_and_advanced(
        options,
        None,
        Vec::new(),
        Vec::new(),
        AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
    )
}

pub fn router_with_adapter_and_options(
    adapter: Arc<dyn DbAdapter>,
    options: SsoOptions,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        with_test_defaults(OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            secret: Some(SECRET.to_owned()),
            plugins: vec![sso(allow_loopback_oidc(options))],
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

pub fn router_with_options_and_trusted_origins(
    options: SsoOptions,
    trusted_origins: Vec<String>,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    router_with_options_storage_and_trusted_origins(options, None, trusted_origins)
}

#[cfg(feature = "saml")]
pub fn router_with_options_and_origin_security(
    options: SsoOptions,
    trusted_origins: Vec<String>,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    router_with_options_storage_trusted_origins_extra_plugins_and_advanced(
        options,
        None,
        trusted_origins,
        Vec::new(),
        AdvancedOptions::default(),
    )
}

pub fn router_with_options_and_secondary_storage(
    options: SsoOptions,
    secondary_storage: Arc<dyn SecondaryStorage>,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    router_with_options_storage_and_trusted_origins(options, Some(secondary_storage), Vec::new())
}

pub fn router_with_options_and_extra_plugins(
    options: SsoOptions,
    extra_plugins: Vec<AuthPlugin>,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    router_with_options_storage_trusted_origins_and_extra_plugins(
        options,
        None,
        Vec::new(),
        extra_plugins,
    )
}

fn router_with_options_storage_and_trusted_origins(
    options: SsoOptions,
    secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    trusted_origins: Vec<String>,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    router_with_options_storage_trusted_origins_and_extra_plugins(
        options,
        secondary_storage,
        trusted_origins,
        Vec::new(),
    )
}

fn router_with_options_storage_trusted_origins_and_extra_plugins(
    options: SsoOptions,
    secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    trusted_origins: Vec<String>,
    extra_plugins: Vec<AuthPlugin>,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    router_with_options_storage_trusted_origins_extra_plugins_and_advanced(
        allow_loopback_oidc(options),
        secondary_storage,
        trusted_origins,
        extra_plugins,
        AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
    )
}

fn router_with_options_storage_trusted_origins_extra_plugins_and_advanced(
    options: SsoOptions,
    secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    trusted_origins: Vec<String>,
    extra_plugins: Vec<AuthPlugin>,
    advanced: AdvancedOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter), OpenAuthError> {
    let adapter = Arc::new(MemoryAdapter::new());
    let mut plugins = vec![sso(options)];
    plugins.extend(extra_plugins);
    let context = create_auth_context_with_adapter(
        with_test_defaults(OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            secret: Some(SECRET.to_owned()),
            plugins,
            trusted_origins: TrustedOriginOptions::Static(trusted_origins),
            session: SessionOptions {
                store_session_in_database: secondary_storage.is_some(),
                ..SessionOptions::default()
            },
            secondary_storage,
            advanced,
            ..OpenAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router))
}

pub type TestSecondaryStorage = MemorySecondaryStorage;

pub fn test_secondary_storage() -> TestSecondaryStorage {
    TestSecondaryStorage::tracking_deletes()
}

pub fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://app.example.com{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub fn form_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://app.example.com{path}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub async fn seed_session(adapter: &MemoryAdapter) -> Result<String, Box<dyn std::error::Error>> {
    seed_session_for_adapter(adapter).await
}

pub async fn seed_session_for_adapter(
    adapter: &dyn DbAdapter,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("User One".to_owned()))
                .data("email", DbValue::String("user@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("session")
                .data("id", DbValue::String("session_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .data("token", DbValue::String("session-token".to_owned()))
                .data("expires_at", DbValue::Timestamp(now + Duration::hours(1)))
                .data("ip_address", DbValue::Null)
                .data("user_agent", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    signed_session_cookie("session-token")
}

fn signed_session_cookie(token: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Match the router's HTTPS base_url so the cookie is emitted under the
    // `__Secure-` prefixed name. In secure mode the server only accepts the
    // secure name, so signing under the plain context would produce a cookie
    // the router ignores.
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            secret: Some(SECRET.to_owned()),
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn json_body(
    response: http::Response<Vec<u8>>,
) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_slice(response.body())
}
