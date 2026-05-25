use std::sync::Arc;
use std::sync::OnceLock;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::crypto::{symmetric_decrypt, symmetric_encrypt};
use openauth_core::db::{Count, DbAdapter, MemoryAdapter};
use openauth_core::options::{
    AccountLinkingOptions, AccountOptions, AdvancedOptions, OAuthStateStoreStrategy,
    OpenAuthOptions,
};
use openauth_core::user::{CreateUserInput, DbUserStore};
use openauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
use openauth_plugins::oauth_proxy::{oauth_proxy, OAuthProxyOptions};
use serde_json::Value;
use tokio::sync::Mutex;
use url::Url;

const SECRET: &str = "test-secret-123456789012345678901234";

#[test]
fn exposes_oauth_proxy_plugin_id() {
    assert_eq!(
        openauth_plugins::oauth_proxy::UPSTREAM_PLUGIN_ID,
        "oauth-proxy"
    );
}

#[tokio::test]
async fn cross_origin_callback_redirects_to_preview_with_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router(
        adapter.clone(),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let provider_url = body["url"].as_str().ok_or("missing provider url")?;
    assert_eq!(
        query_value(provider_url, "redirect_uri").as_deref(),
        Some("https://login.example.com/api/auth/callback/google")
    );
    let state = query_value(provider_url, "state").ok_or("missing state")?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?code=ok&state={state}"),
            "",
        )?)
        .await?;
    let location = location(&callback)?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert!(location.starts_with("http://preview.example.com/api/auth/oauth-proxy-callback"));
    assert!(query_value(location, "profile").is_some());
    assert_eq!(adapter.count(Count::new("user")).await?, 0);
    Ok(())
}

#[tokio::test]
async fn openauth_url_sets_production_redirect_uri() -> Result<(), Box<dyn std::error::Error>> {
    let _env = TestEnv::set([("OPENAUTH_URL", "https://login.example.com")]).await;
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let provider_url = body["url"].as_str().ok_or("missing provider url")?;

    assert_eq!(
        query_value(provider_url, "redirect_uri").as_deref(),
        Some("https://login.example.com/api/auth/callback/google")
    );
    assert!(query_value(provider_url, "state").is_some());
    Ok(())
}

#[tokio::test]
async fn production_redirect_uri_falls_back_to_context_base_url_without_env(
) -> Result<(), Box<dyn std::error::Error>> {
    let _env = TestEnv::set([]).await;
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let provider_url = body["url"].as_str().ok_or("missing provider url")?;

    assert_eq!(
        query_value(provider_url, "redirect_uri").as_deref(),
        Some("https://login.example.com/api/auth/callback/google")
    );
    assert!(query_value(provider_url, "state").is_some());
    Ok(())
}

#[tokio::test]
async fn openauth_url_is_used_for_token_exchange_redirect_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    let _env = TestEnv::set([("OPENAUTH_URL", "https://login.example.com")]).await;
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?code=require-production-redirect&state={state}"),
            "",
        )?)
        .await?;

    assert!(location(&callback)?.contains("/oauth-proxy-callback"));
    assert!(query_value(location(&callback)?, "profile").is_some());
    Ok(())
}

#[tokio::test]
async fn oauth2_sign_in_route_uses_oauth_proxy() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/oauth2",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let provider_url = body["url"].as_str().ok_or("missing provider url")?;

    assert_eq!(
        query_value(provider_url, "redirect_uri").as_deref(),
        Some("https://login.example.com/api/auth/callback/google")
    );
    assert!(query_value(provider_url, "state").is_some());
    Ok(())
}

#[tokio::test]
async fn vendor_env_sets_current_preview_callback() -> Result<(), Box<dyn std::error::Error>> {
    let _env = TestEnv::set([
        ("OPENAUTH_URL", "https://login.example.com"),
        ("VERCEL_URL", "preview.example.com"),
    ])
    .await;
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "https://fallback.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?code=ok&state={state}"),
            "",
        )?)
        .await?;
    let location = location(&callback)?;

    assert!(location.starts_with("https://preview.example.com/api/auth/oauth-proxy-callback"));
    Ok(())
}

#[tokio::test]
async fn upstream_vendor_env_names_set_current_preview_callback(
) -> Result<(), Box<dyn std::error::Error>> {
    for (key, value, expected) in [
        (
            "AWS_LAMBDA_FUNCTION_NAME",
            "aws-preview.example.com",
            "https://aws-preview.example.com/api/auth/oauth-proxy-callback",
        ),
        (
            "GOOGLE_CLOUD_FUNCTION_NAME",
            "google-preview.example.com",
            "https://google-preview.example.com/api/auth/oauth-proxy-callback",
        ),
        (
            "AZURE_FUNCTION_NAME",
            "azure-preview.example.com",
            "https://azure-preview.example.com/api/auth/oauth-proxy-callback",
        ),
    ] {
        let _env =
            TestEnv::set([("OPENAUTH_URL", "https://login.example.com"), (key, value)]).await;
        let router = router(
            Arc::new(MemoryAdapter::default()),
            "https://fallback.example.com/api/auth",
            OAuthProxyOptions::new(),
        )?;
        let sign_in = router
            .handle_async(json_request(
                Method::POST,
                "/api/auth/sign-in/social",
                r#"{"provider":"google","callbackURL":"/dashboard"}"#,
            )?)
            .await?;
        let body: Value = serde_json::from_slice(sign_in.body())?;
        let state = query_value(body["url"].as_str().ok_or("missing url")?, "state")
            .ok_or("missing state")?;
        let callback = router
            .handle_async(json_request(
                Method::GET,
                &format!(
                    "https://login.example.com/api/auth/callback/google?code=ok&state={state}"
                ),
                "",
            )?)
            .await?;

        assert!(location(&callback)?.starts_with(expected));
    }
    Ok(())
}

#[tokio::test]
async fn preview_callback_creates_user_account_and_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let production = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;
    let preview_adapter = Arc::new(MemoryAdapter::default());
    let preview = router(
        preview_adapter.clone(),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;
    let sign_in = production
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let production_callback = production
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?code=ok&state={state}"),
            "",
        )?)
        .await?;
    let preview_location = location(&production_callback)?;
    let preview_callback = preview
        .handle_async(json_request(Method::GET, preview_location, "")?)
        .await?;

    assert_eq!(preview_callback.status(), StatusCode::FOUND);
    assert_eq!(location(&preview_callback)?, "/dashboard");
    assert_eq!(preview_adapter.count(Count::new("user")).await?, 1);
    assert_eq!(preview_adapter.count(Count::new("account")).await?, 1);
    assert_eq!(preview_adapter.count(Count::new("session")).await?, 1);
    assert!(preview_callback.headers().contains_key(header::SET_COOKIE));
    Ok(())
}

#[tokio::test]
async fn same_origin_does_not_proxy() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router(
        adapter,
        "http://localhost:3000/api/auth",
        OAuthProxyOptions::new().production_url("http://localhost:3000"),
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://localhost:3000/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("http://localhost:3000/api/auth/callback/google?code=ok&state={state}"),
            "",
        )?)
        .await?;
    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(location(&callback)?, "/dashboard");
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_and_expired_profiles() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new().max_age(5),
    )?;
    let invalid = router
        .handle_async(json_request(
            Method::GET,
            "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile=bad",
            "",
        )?)
        .await?;

    assert!(location(&invalid)?.contains("error=invalid_profile"));

    let expired_payload = serde_json::json!({
        "user_info": {
            "id": "google-user-1",
            "name": "Ada Lovelace",
            "email": "ada@example.com",
            "image": null,
            "email_verified": true
        },
        "account": {
            "provider_id": "google",
            "account_id": "google-user-1",
            "access_token": "access-token",
            "refresh_token": null,
            "id_token": null,
            "access_token_expires_at": null,
            "refresh_token_expires_at": null,
            "scope": null
        },
        "state": "state",
        "callback_url": "/dashboard",
        "new_user_url": null,
        "error_url": null,
        "disable_sign_up": false,
        "timestamp": time::OffsetDateTime::now_utc().unix_timestamp() - 10
    });
    let encrypted = symmetric_encrypt(SECRET, &expired_payload.to_string())?;
    let expired = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile={}",
                url_encode(&encrypted)
            ),
            "",
        )?)
        .await?;
    assert!(location(&expired)?.contains("error=payload_expired"));
    Ok(())
}

#[tokio::test]
async fn rejects_missing_malformed_and_future_profiles() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;

    let missing = router
        .handle_async(json_request(
            Method::GET,
            "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard",
            "",
        )?)
        .await?;
    assert!(location(&missing)?.contains("error=missing_profile"));

    let malformed = symmetric_encrypt(SECRET, "not-json")?;
    let malformed_response = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile={}",
                url_encode(&malformed)
            ),
            "",
        )?)
        .await?;
    assert!(location(&malformed_response)?.contains("error=invalid_payload"));

    let mut missing_fields = passthrough_payload_json();
    missing_fields["account"]["account_id"] = Value::String(String::new());
    let encrypted_missing = symmetric_encrypt(SECRET, &missing_fields.to_string())?;
    let missing_fields_response = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile={}",
                url_encode(&encrypted_missing)
            ),
            "",
        )?)
        .await?;
    assert!(location(&missing_fields_response)?.contains("error=invalid_payload"));

    let mut nonnumeric = passthrough_payload_json();
    nonnumeric["timestamp"] = Value::String("now".to_owned());
    let encrypted_nonnumeric = symmetric_encrypt(SECRET, &nonnumeric.to_string())?;
    let nonnumeric_response = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile={}",
                url_encode(&encrypted_nonnumeric)
            ),
            "",
        )?)
        .await?;
    assert!(location(&nonnumeric_response)?.contains("error=invalid_payload"));

    let mut future = passthrough_payload_json();
    future["timestamp"] =
        Value::Number((time::OffsetDateTime::now_utc().unix_timestamp() + 11).into());
    let encrypted_future = symmetric_encrypt(SECRET, &future.to_string())?;
    let future_response = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile={}",
                url_encode(&encrypted_future)
            ),
            "",
        )?)
        .await?;
    assert!(location(&future_response)?.contains("error=payload_expired"));
    Ok(())
}

#[tokio::test]
async fn proxy_callback_requires_callback_url_query() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;
    let encrypted = symmetric_encrypt(SECRET, &passthrough_payload_json().to_string())?;
    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?profile={}",
                url_encode(&encrypted)
            ),
            "",
        )?)
        .await?;

    assert!(location(&response)?.contains("error=missing_callback_url"));
    Ok(())
}

#[tokio::test]
async fn rejects_untrusted_callback_url() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;
    let mut payload = passthrough_payload_json();
    payload["callback_url"] = Value::String("https://evil.example/callback".to_owned());
    let encrypted = symmetric_encrypt(SECRET, &payload.to_string())?;
    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=https%3A%2F%2Fevil.example%2Fcallback&profile={}",
                url_encode(&encrypted)
            ),
            "",
        )?)
        .await?;

    assert!(location(&response)?.contains("error=invalid_callback_url"));
    Ok(())
}

#[tokio::test]
async fn callback_rejects_state_binding_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let decrypted = symmetric_decrypt(SECRET, &state)?;
    let mut package: Value = serde_json::from_str(&decrypted)?;
    package["state"] = Value::String("tampered-state".to_owned());
    let tampered_state = symmetric_encrypt(SECRET, &package.to_string())?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "https://login.example.com/api/auth/callback/google?code=ok&state={}",
                url_encode(&tampered_state)
            ),
            "",
        )?)
        .await?;

    assert!(location(&callback)?.contains("error=state_mismatch"));
    Ok(())
}

#[tokio::test]
async fn custom_secret_encrypts_profile_payload() -> Result<(), Box<dyn std::error::Error>> {
    let dedicated = "oauth-proxy-dedicated-secret-key";
    let production = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new()
            .current_url("http://preview.example.com")
            .secret(dedicated),
    )?;
    let sign_in = production
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let production_callback = production
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?code=ok&state={state}"),
            "",
        )?)
        .await?;
    let profile =
        query_value(location(&production_callback)?, "profile").ok_or("missing profile")?;

    assert!(symmetric_decrypt(dedicated, &profile)?.contains("ada@example.com"));
    assert!(symmetric_decrypt(SECRET, &profile).is_err());
    Ok(())
}

#[tokio::test]
async fn skip_header_bypasses_oauth_proxy() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router(
        adapter.clone(),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;
    let sign_in = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("http://preview.example.com/api/auth/sign-in/social")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-skip-oauth-proxy", "1")
                .body(
                    r#"{"provider":"google","callbackURL":"/dashboard"}"#
                        .as_bytes()
                        .to_vec(),
                )?,
        )
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    assert!(symmetric_decrypt(SECRET, &state).is_ok());

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?code=ok&state={state}"),
            "",
        )?)
        .await?;
    assert_eq!(location(&callback)?, "/dashboard");
    assert_eq!(adapter.count(Count::new("user")).await?, 1);
    Ok(())
}

#[tokio::test]
async fn callback_errors_match_upstream_cases() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;

    let provider_missing = router
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/github?code=ok&state={state}"),
            "",
        )?)
        .await?;
    assert!(location(&provider_missing)?.contains("error=oauth_provider_not_found"));

    let no_code = router
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?state={state}"),
            "",
        )?)
        .await?;
    assert!(location(&no_code)?.contains("error=no_code"));

    let invalid_code = router
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?code=bad&state={state}"),
            "",
        )?)
        .await?;
    assert!(location(&invalid_code)?.contains("error=invalid_code"));

    let no_user = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "https://login.example.com/api/auth/callback/google?code=no-user&state={state}"
            ),
            "",
        )?)
        .await?;
    assert!(location(&no_user)?.contains("error=unable_to_get_user_info"));

    let no_email = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "https://login.example.com/api/auth/callback/google?code=no-email&state={state}"
            ),
            "",
        )?)
        .await?;
    assert!(location(&no_email)?.contains("error=email_not_found"));
    Ok(())
}

#[tokio::test]
async fn existing_preview_user_links_account_without_duplicate(
) -> Result<(), Box<dyn std::error::Error>> {
    let production = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;
    let preview_adapter = Arc::new(MemoryAdapter::default());
    DbUserStore::new(preview_adapter.as_ref())
        .create_user(CreateUserInput::new("Existing Ada", "ada@example.com").id("user_1"))
        .await?;
    let preview = router(
        preview_adapter.clone(),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;
    let sign_in = production
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let production_callback = production
        .handle_async(json_request(
            Method::GET,
            &format!("https://login.example.com/api/auth/callback/google?code=ok&state={state}"),
            "",
        )?)
        .await?;
    let preview_callback = preview
        .handle_async(json_request(
            Method::GET,
            location(&production_callback)?,
            "",
        )?)
        .await?;

    assert_eq!(preview_callback.status(), StatusCode::FOUND);
    assert_eq!(preview_adapter.count(Count::new("user")).await?, 1);
    assert_eq!(preview_adapter.count(Count::new("account")).await?, 1);
    Ok(())
}

#[tokio::test]
async fn preview_callback_rejects_unverified_existing_user_when_google_is_not_trusted(
) -> Result<(), Box<dyn std::error::Error>> {
    let preview_adapter = Arc::new(MemoryAdapter::default());
    DbUserStore::new(preview_adapter.as_ref())
        .create_user(CreateUserInput::new("Existing Ada", "ada@example.com").id("user_1"))
        .await?;
    let preview = router(
        preview_adapter.clone(),
        "http://preview.example.com/api/auth",
        OAuthProxyOptions::new(),
    )?;
    let mut payload = passthrough_payload_json();
    payload["user_info"]["email_verified"] = Value::Bool(false);
    let encrypted = symmetric_encrypt(SECRET, &payload.to_string())?;

    let response = preview
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile={}",
                url_encode(&encrypted)
            ),
            "",
        )?)
        .await?;

    assert!(location(&response)?.contains("error=user_creation_failed"));
    assert_eq!(preview_adapter.count(Count::new("account")).await?, 0);
    assert_eq!(preview_adapter.count(Count::new("session")).await?, 0);
    Ok(())
}

#[tokio::test]
async fn preview_callback_links_unverified_existing_user_when_google_is_trusted(
) -> Result<(), Box<dyn std::error::Error>> {
    let preview_adapter = Arc::new(MemoryAdapter::default());
    DbUserStore::new(preview_adapter.as_ref())
        .create_user(CreateUserInput::new("Existing Ada", "ada@example.com").id("user_1"))
        .await?;
    let preview = router_with_options(
        preview_adapter.clone(),
        OpenAuthOptions {
            base_url: Some("http://preview.example.com/api/auth".to_owned()),
            account: AccountOptions {
                account_linking: AccountLinkingOptions::default().trusted_provider("google"),
                ..AccountOptions::default()
            },
            plugins: vec![oauth_proxy(OAuthProxyOptions::new())],
            ..test_options()
        },
    )?;
    let mut payload = passthrough_payload_json();
    payload["user_info"]["email_verified"] = Value::Bool(false);
    let encrypted = symmetric_encrypt(SECRET, &payload.to_string())?;

    let response = preview
        .handle_async(json_request(
            Method::GET,
            &format!(
                "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=/dashboard&profile={}",
                url_encode(&encrypted)
            ),
            "",
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response)?, "/dashboard");
    assert_eq!(preview_adapter.count(Count::new("account")).await?, 1);
    assert_eq!(preview_adapter.count(Count::new("session")).await?, 1);
    Ok(())
}

#[tokio::test]
async fn database_state_strategy_packages_proxy_state() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::default());
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            base_url: Some("https://login.example.com/api/auth".to_owned()),
            account: AccountOptions {
                store_state_strategy: OAuthStateStoreStrategy::Database,
                ..AccountOptions::default()
            },
            plugins: vec![oauth_proxy(
                OAuthProxyOptions::new().current_url("http://preview.example.com"),
            )],
            ..test_options()
        },
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;

    assert!(state.len() > 50);
    let decrypted = symmetric_decrypt(SECRET, &state)?;
    let package: Value = serde_json::from_str(&decrypted)?;
    assert_eq!(package["is_oauth_proxy"], Value::Bool(true));
    assert!(package["state"].as_str().is_some());
    let state_cookie = package["state_cookie"]
        .as_str()
        .ok_or("missing state_cookie")?;
    let state_data = symmetric_decrypt(SECRET, state_cookie)?;
    let state_cookie_package: Value = serde_json::from_str(&state_data)?;
    assert_eq!(state_cookie_package["state"], package["state"]);
    assert!(state_cookie_package["data"]["code_verifier"]
        .as_str()
        .is_some());
    Ok(())
}

#[tokio::test]
async fn form_post_callback_reads_code_and_state_from_body(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let callback = router
        .handle_async(form_request(
            Method::POST,
            "https://login.example.com/api/auth/callback/google",
            &format!("code=ok&state={}", url_encode(&state)),
        )?)
        .await?;

    assert!(location(&callback)?.contains("/oauth-proxy-callback"));
    assert!(location(&callback)?.contains("profile="));
    Ok(())
}

#[tokio::test]
async fn form_post_callback_reads_user_from_body() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        Arc::new(MemoryAdapter::default()),
        "https://login.example.com/api/auth",
        OAuthProxyOptions::new().current_url("http://preview.example.com"),
    )?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "http://preview.example.com/api/auth/sign-in/social",
            r#"{"provider":"google","callbackURL":"/dashboard"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sign_in.body())?;
    let state =
        query_value(body["url"].as_str().ok_or("missing url")?, "state").ok_or("missing state")?;
    let provider_user = url_encode(r#"{"email":"body-user@example.com"}"#);
    let callback = router
        .handle_async(form_request(
            Method::POST,
            "https://login.example.com/api/auth/callback/google",
            &format!(
                "code=use-provider-user&state={}&user={provider_user}",
                url_encode(&state)
            ),
        )?)
        .await?;
    let profile = query_value(location(&callback)?, "profile").ok_or("missing profile")?;
    let payload = symmetric_decrypt(SECRET, &profile)?;

    assert!(payload.contains("body-user@example.com"));
    Ok(())
}

fn router(
    adapter: Arc<MemoryAdapter>,
    base_url: &str,
    options: OAuthProxyOptions,
) -> Result<AuthRouter, openauth_core::error::OpenAuthError> {
    router_with_options(
        adapter,
        OpenAuthOptions {
            base_url: Some(base_url.to_owned()),
            plugins: vec![oauth_proxy(options)],
            ..test_options()
        },
    )
}

fn router_with_options(
    adapter: Arc<MemoryAdapter>,
    options: OpenAuthOptions,
) -> Result<AuthRouter, openauth_core::error::OpenAuthError> {
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn test_options() -> OpenAuthOptions {
    OpenAuthOptions {
        secret: Some(SECRET.to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        social_providers: vec![Arc::new(FakeProvider)],
        ..OpenAuthOptions::default()
    }
}

fn json_request(method: Method, uri: &str, body: &str) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    builder.body(body.as_bytes().to_vec())
}

fn form_request(method: Method, uri: &str, body: &str) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
}

fn location(response: &http::Response<Vec<u8>>) -> Result<&str, Box<dyn std::error::Error>> {
    Ok(response
        .headers()
        .get(header::LOCATION)
        .ok_or("missing location")?
        .to_str()?)
}

fn query_value(url: &str, key: &str) -> Option<String> {
    Url::parse(url)
        .ok()?
        .query_pairs()
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

struct TestEnv {
    _guard: tokio::sync::MutexGuard<'static, ()>,
    previous: Vec<(&'static str, Option<String>)>,
}

impl TestEnv {
    async fn set(values: impl IntoIterator<Item = (&'static str, &'static str)>) -> Self {
        let guard = env_lock().lock().await;
        let keys = [
            "OPENAUTH_URL",
            "VERCEL_URL",
            "NETLIFY_URL",
            "RENDER_URL",
            "AWS_LAMBDA_FUNCTION_URL",
            "AWS_LAMBDA_FUNCTION_NAME",
            "AWS_FUNCTION_URL",
            "GOOGLE_CLOUD_FUNCTION_URL",
            "GOOGLE_CLOUD_FUNCTION_NAME",
            "AZURE_FUNCTION_URL",
            "AZURE_FUNCTION_NAME",
            "FUNCTIONS_CUSTOMHANDLER_PORT",
        ];
        let previous = keys
            .into_iter()
            .map(|key| (key, std::env::var(key).ok()))
            .collect::<Vec<_>>();
        for key in keys {
            std::env::remove_var(key);
        }
        for (key, value) in values {
            std::env::set_var(key, value);
        }
        Self {
            _guard: guard,
            previous,
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn passthrough_payload_json() -> Value {
    serde_json::json!({
        "user_info": {
            "id": "google-user-1",
            "name": "Ada Lovelace",
            "email": "ada@example.com",
            "image": null,
            "email_verified": true
        },
        "account": {
            "provider_id": "google",
            "account_id": "google-user-1",
            "access_token": "access-token",
            "refresh_token": null,
            "id_token": null,
            "access_token_expires_at": null,
            "refresh_token_expires_at": null,
            "scope": null
        },
        "state": "state",
        "callback_url": "/dashboard",
        "new_user_url": null,
        "error_url": null,
        "disable_sign_up": false,
        "timestamp": time::OffsetDateTime::now_utc().unix_timestamp()
    })
}

#[derive(Debug)]
struct FakeProvider;

impl SocialOAuthProvider for FakeProvider {
    fn id(&self) -> &str {
        "google"
    }

    fn name(&self) -> &str {
        "Google"
    }

    fn provider_options(&self) -> ProviderOptions {
        ProviderOptions::default()
    }

    fn create_authorization_url(
        &self,
        input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        Url::parse_with_params(
            "https://provider.example.com/oauth",
            &[("state", input.state), ("redirect_uri", input.redirect_uri)],
        )
        .map_err(OAuthError::InvalidUrl)
    }

    fn validate_authorization_code(
        &self,
        input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async move {
            if input.code == "require-production-redirect"
                && input.redirect_uri != "https://login.example.com/api/auth/callback/google"
            {
                return Err(OAuthError::InvalidResponse(format!(
                    "wrong redirect uri: {}",
                    input.redirect_uri
                )));
            }
            if !matches!(
                input.code.as_str(),
                "ok" | "no-user" | "no-email" | "require-production-redirect" | "use-provider-user"
            ) {
                return Err(OAuthError::InvalidResponse("bad code".to_owned()));
            }
            Ok(OAuth2Tokens {
                access_token: Some(input.code),
                refresh_token: Some("refresh-token".to_owned()),
                scopes: vec!["profile".to_owned()],
                ..OAuth2Tokens::default()
            })
        })
    }

    fn get_user_info(
        &self,
        tokens: OAuth2Tokens,
        provider_user: Option<Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async move {
            if tokens.access_token.as_deref() == Some("no-user") {
                return Ok(None);
            }
            let email = if tokens.access_token.as_deref() == Some("use-provider-user") {
                provider_user.and_then(|value| {
                    value
                        .get("email")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
            } else {
                (tokens.access_token.as_deref() != Some("no-email"))
                    .then(|| "ada@example.com".to_owned())
            };
            Ok(Some(OAuth2UserInfo {
                id: "google-user-1".to_owned(),
                name: Some("Ada Lovelace".to_owned()),
                email,
                image: None,
                email_verified: true,
            }))
        })
    }

    fn verify_id_token(&self, _input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async { Ok(false) })
    }
}
