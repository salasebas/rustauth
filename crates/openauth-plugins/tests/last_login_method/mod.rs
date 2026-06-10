use std::sync::Arc;

use http::{header, HeaderValue, Method, Response, StatusCode};
use openauth_core::context::create_auth_context;
use openauth_core::db::{DbValue, MemoryAdapter};
use openauth_core::options::{AdvancedOptions, CookieConfig, OpenAuthOptions};
use openauth_plugins::last_login_method::{
    last_login_method, last_login_method_with, LastLoginMethodOptions, LoginMethodContext,
    DEFAULT_COOKIE_MAX_AGE, DEFAULT_COOKIE_NAME, UPSTREAM_PLUGIN_ID,
};

mod helpers;
mod oauth;
use helpers::{
    find_user_by_email, json_request, request, response_with_set_cookie, router_with_plugin,
    router_with_plugin_options, run_last_login_after_hook, secret, set_cookie_values,
    signed_session_cookie,
};

#[test]
fn exposes_last_login_method_plugin_metadata() {
    let plugin = last_login_method();

    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);
    assert_eq!(plugin.version.as_deref(), Some(openauth_plugins::VERSION));
    assert!(plugin.on_response.is_none());
    assert_eq!(plugin.hooks.async_after.len(), 1);
}

#[test]
fn default_resolver_matches_upstream_login_routes() {
    let cases = [
        ("/callback/google", Some("google")),
        ("/oauth2/callback/my-provider-id", Some("my-provider-id")),
        ("/sign-in/email", Some("email")),
        ("/sign-up/email", Some("email")),
        ("/siwe/verify", Some("siwe")),
        ("/passkey/verify-authentication", Some("passkey")),
        ("/magic-link/verify", Some("magic-link")),
        ("/unknown", None),
    ];

    for (path, expected) in cases {
        let context = LoginMethodContext::new(path);
        assert_eq!(
            openauth_plugins::last_login_method::default_login_method(&context).as_deref(),
            expected
        );
    }
}

#[test]
fn custom_resolver_takes_precedence_over_default_resolver() {
    let options = LastLoginMethodOptions::default().with_resolver(|context| {
        (context.path() == "/sign-in/email").then(|| "custom-email".to_owned())
    });

    assert_eq!(
        options.resolve_login_method(&LoginMethodContext::new("/sign-in/email")),
        Some("custom-email".to_owned())
    );
}

#[test]
fn custom_resolver_falls_back_to_default_when_it_returns_none() {
    let options = LastLoginMethodOptions::default().with_resolver(|_context| None);

    assert_eq!(
        options.resolve_login_method(&LoginMethodContext::new("/sign-in/email")),
        Some("email".to_owned())
    );
}

#[test]
fn default_resolver_ignores_missing_or_unknown_path() {
    assert_eq!(
        openauth_plugins::last_login_method::default_login_method(&LoginMethodContext::new("")),
        None
    );
    assert_eq!(
        openauth_plugins::last_login_method::default_login_method(&LoginMethodContext::new(
            "/not-a-login"
        )),
        None
    );
}

#[tokio::test]
async fn async_after_hook_sets_last_method_cookie_when_session_cookie_is_created(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method();
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = request("/api/auth/sign-in/email")?;
    let response = response_with_set_cookie(&format!(
        "{}=signed; Path=/; HttpOnly",
        context.auth_cookies.session_token.name
    ))?;

    let response = run_last_login_after_hook(&plugin, &context, &request, response).await?;
    let cookies = set_cookie_values(&response);
    let last_method = cookies
        .iter()
        .find(|cookie| cookie.starts_with(DEFAULT_COOKIE_NAME))
        .ok_or("missing last login method cookie")?;

    assert!(last_method.starts_with("better-auth.last_used_login_method=email"));
    assert!(last_method.contains(&format!("Max-Age={DEFAULT_COOKIE_MAX_AGE}")));
    assert!(last_method.contains("Path=/"));
    assert!(!last_method.contains("HttpOnly"));
    Ok(())
}

#[tokio::test]
async fn async_after_hook_does_not_set_cookie_without_session_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method();
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = request("/api/auth/sign-in/email")?;
    let response = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Vec::new())?;

    let response = run_last_login_after_hook(&plugin, &context, &request, response).await?;

    assert!(set_cookie_values(&response)
        .iter()
        .all(|cookie| !cookie.starts_with(DEFAULT_COOKIE_NAME)));
    Ok(())
}

#[tokio::test]
async fn async_after_hook_does_not_set_cookie_when_method_is_unknown(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method();
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = request("/api/auth/not-a-login")?;
    let response = response_with_set_cookie(&format!(
        "{}=signed; Path=/; HttpOnly",
        context.auth_cookies.session_token.name
    ))?;

    let response = run_last_login_after_hook(&plugin, &context, &request, response).await?;

    assert!(set_cookie_values(&response)
        .iter()
        .all(|cookie| !cookie.starts_with(DEFAULT_COOKIE_NAME)));
    Ok(())
}

#[tokio::test]
async fn async_after_hook_uses_custom_cookie_name_max_age_and_session_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method_with(
        LastLoginMethodOptions::default()
            .cookie_name("my-app.last_method")
            .max_age(42),
    );
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        advanced: openauth_core::options::AdvancedOptions {
            default_cookie_attributes: openauth_core::options::CookieAttributesOverride {
                domain: Some(".example.com".to_owned()),
                same_site: Some("None".to_owned()),
                secure: Some(true),
                partitioned: Some(true),
                ..openauth_core::options::CookieAttributesOverride::default()
            },
            ..openauth_core::options::AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;
    let request = request("/api/auth/sign-in/email")?;
    let response = response_with_set_cookie(&format!(
        "{}=signed; Path=/; HttpOnly",
        context.auth_cookies.session_token.name
    ))?;

    let response = run_last_login_after_hook(&plugin, &context, &request, response).await?;
    let cookies = set_cookie_values(&response);
    let last_method = cookies
        .iter()
        .find(|cookie| cookie.starts_with("my-app.last_method"))
        .ok_or("missing custom last login method cookie")?;

    assert!(last_method.starts_with("my-app.last_method=email"));
    assert!(last_method.contains("Max-Age=42"));
    assert!(last_method.contains("Domain=.example.com"));
    assert!(last_method.contains("SameSite=None"));
    assert!(last_method.contains("Secure"));
    assert!(last_method.contains("Partitioned"));
    assert!(!last_method.contains("HttpOnly"));
    Ok(())
}

#[tokio::test]
async fn async_after_hook_handles_multiple_set_cookie_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method();
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = request("/api/auth/sign-in/email")?;
    let mut response = response_with_set_cookie("unrelated=value; Path=/")?;
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{}=signed; Path=/; HttpOnly",
            context.auth_cookies.session_token.name
        ))?,
    );

    let response = run_last_login_after_hook(&plugin, &context, &request, response).await?;

    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with(DEFAULT_COOKIE_NAME)));
    Ok(())
}

#[tokio::test]
async fn async_after_hook_handles_combined_set_cookie_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method();
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let request = request("/api/auth/sign-in/email")?;
    let response = response_with_set_cookie(&format!(
        "unrelated=value; Path=/, {}=signed; Path=/; HttpOnly",
        context.auth_cookies.session_token.name
    ))?;

    let response = run_last_login_after_hook(&plugin, &context, &request, response).await?;

    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with(DEFAULT_COOKIE_NAME)));
    Ok(())
}

#[test]
fn store_in_database_contributes_optional_generated_user_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method_with(LastLoginMethodOptions::default().store_in_database(true));
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let field = context.db_schema.field("user", "last_login_method")?;

    assert_eq!(field.name, "last_login_method");
    assert!(!field.required);
    assert!(!field.input);
    assert!(field.returned);
    Ok(())
}

#[test]
fn store_in_database_uses_custom_database_field_name() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = last_login_method_with(
        LastLoginMethodOptions::default()
            .store_in_database(true)
            .database_field_name("last_auth_method"),
    );
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert_eq!(
        context.db_schema.field_name("user", "last_login_method")?,
        "last_auth_method"
    );
    Ok(())
}

#[tokio::test]
async fn sign_in_email_persists_last_login_method_and_get_session_returns_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin(adapter.clone(), LastLoginMethodOptions::default())?;
    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(sign_in.body())?;
    let token = body["token"].as_str().ok_or("missing token")?;
    let user = find_user_by_email(adapter.as_ref(), "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("last_login_method"),
        Some(&DbValue::String("email".to_owned()))
    );

    let session = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&signed_session_cookie(token)?),
        )?)
        .await?;
    assert_eq!(session.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(session.body())?;
    assert_eq!(body["user"]["last_login_method"], "email");
    Ok(())
}

#[tokio::test]
async fn custom_database_field_name_persists_and_returns_logical_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin(
        adapter.clone(),
        LastLoginMethodOptions::default().database_field_name("last_auth_method"),
    )?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(sign_in.body())?;
    let token = body["token"].as_str().ok_or("missing token")?;

    let user = find_user_by_email(adapter.as_ref(), "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("last_login_method"),
        Some(&DbValue::String("email".to_owned()))
    );

    let session = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&signed_session_cookie(token)?),
        )?)
        .await?;
    assert_eq!(session.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(session.body())?;
    assert_eq!(body["user"]["last_login_method"], "email");
    Ok(())
}

#[tokio::test]
async fn sign_up_email_persists_last_login_method() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin(adapter.clone(), LastLoginMethodOptions::default())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let user = find_user_by_email(adapter.as_ref(), "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("last_login_method"),
        Some(&DbValue::String("email".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn failed_sign_in_does_not_persist_or_set_cookie() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin(adapter.clone(), LastLoginMethodOptions::default())?;
    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let user = find_user_by_email(adapter.as_ref(), "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("last_login_method"),
        Some(&DbValue::String("email".to_owned()))
    );

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"wrong-password"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(set_cookie_values(&response)
        .iter()
        .all(|cookie| !cookie.starts_with(DEFAULT_COOKIE_NAME)));
    Ok(())
}

#[tokio::test]
async fn subsequent_login_updates_existing_last_login_method(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin(
        adapter.clone(),
        LastLoginMethodOptions::default().with_resolver(|context| match context.path() {
            "/sign-up/email" => Some("signup-email".to_owned()),
            "/sign-in/email" => Some("signin-email".to_owned()),
            _ => None,
        }),
    )?;
    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let user = find_user_by_email(adapter.as_ref(), "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("last_login_method"),
        Some(&DbValue::String("signup-email".to_owned()))
    );

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let user = find_user_by_email(adapter.as_ref(), "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("last_login_method"),
        Some(&DbValue::String("signin-email".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_in_sets_last_method_cookie_with_cross_subdomain_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin_options(
        adapter,
        LastLoginMethodOptions::default(),
        OpenAuthOptions {
            base_url: Some("https://auth.example.com".to_owned()),
            advanced: AdvancedOptions {
                cookie_prefix: Some("custom-auth".to_owned()),
                cross_subdomain_cookies: Some(
                    CookieConfig::new()
                        .enabled(true)
                        .domain("example.com".to_owned()),
                ),
                default_cookie_attributes: openauth_core::options::CookieAttributesOverride {
                    same_site: Some("Lax".to_owned()),
                    ..openauth_core::options::CookieAttributesOverride::default()
                },
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let last_method = set_cookie_values(&sign_in)
        .into_iter()
        .find(|cookie| cookie.starts_with(DEFAULT_COOKIE_NAME))
        .ok_or("missing last login method cookie")?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    assert!(last_method.starts_with("better-auth.last_used_login_method=email"));
    assert!(last_method.contains("Domain=example.com"));
    assert!(last_method.contains("SameSite=Lax"));
    assert!(!last_method.contains("custom-auth.last_used_login_method"));
    Ok(())
}

#[tokio::test]
async fn sign_in_sets_last_method_cookie_with_cross_origin_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin_options(
        adapter,
        LastLoginMethodOptions::default(),
        OpenAuthOptions {
            base_url: Some("https://api.example.com".to_owned()),
            advanced: AdvancedOptions {
                use_secure_cookies: Some(true),
                default_cookie_attributes: openauth_core::options::CookieAttributesOverride {
                    same_site: Some("None".to_owned()),
                    secure: Some(true),
                    ..openauth_core::options::CookieAttributesOverride::default()
                },
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let last_method = set_cookie_values(&sign_in)
        .into_iter()
        .find(|cookie| cookie.starts_with(DEFAULT_COOKIE_NAME))
        .ok_or("missing last login method cookie")?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    assert!(last_method.contains("SameSite=None"));
    assert!(last_method.contains("Secure"));
    assert!(!last_method.contains("Domain="));
    assert!(last_method.starts_with("better-auth.last_used_login_method=email"));
    Ok(())
}

#[tokio::test]
async fn sign_in_sets_last_method_cookie_on_localhost_cross_origin_development(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_plugin_options(
        adapter,
        LastLoginMethodOptions::default(),
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            development: true,
            advanced: AdvancedOptions {
                use_secure_cookies: Some(false),
                default_cookie_attributes: openauth_core::options::CookieAttributesOverride {
                    same_site: Some("None".to_owned()),
                    secure: Some(false),
                    ..openauth_core::options::CookieAttributesOverride::default()
                },
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let last_method = set_cookie_values(&sign_in)
        .into_iter()
        .find(|cookie| cookie.starts_with(DEFAULT_COOKIE_NAME))
        .ok_or("missing last login method cookie")?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    assert!(last_method.contains("SameSite=None"));
    assert!(!last_method.contains("Secure"));
    assert!(!last_method.contains("Domain="));
    assert!(last_method.starts_with("better-auth.last_used_login_method=email"));
    Ok(())
}
