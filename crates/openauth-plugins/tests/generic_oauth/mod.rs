#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "plugin tests intentionally fail fast with contextual setup errors"
)]

use http::{Method, Request, StatusCode};
use openauth_core::api::AuthRouter;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, MemoryAdapter};
use openauth_core::options::OpenAuthOptions;
use openauth_oauth::oauth2::{
    ClientAuthentication, OAuthError, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialOAuthProvider,
};
use openauth_plugins::generic_oauth::{
    auth0, generic_oauth, gumroad, hubspot, keycloak, line, microsoft_entra_id, okta, patreon,
    slack, GenericOAuthConfig, GenericOAuthOptions, UPSTREAM_PLUGIN_ID,
};
use serde_json::Value;
use std::sync::Arc;

#[test]
fn generic_oauth_plugin_exposes_metadata_endpoints_and_errors() {
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config()],
    });

    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);
    assert_eq!(plugin.version.as_deref(), Some(openauth_plugins::VERSION));
    assert_eq!(plugin.endpoints.len(), 3);
    assert!(plugin
        .error_codes
        .iter()
        .any(|code| code.code == "ISSUER_MISMATCH"));
}

#[test]
fn generic_oauth_init_registers_configured_social_providers() {
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config()],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin.clone()],
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>,
    )
    .unwrap();

    assert!(context.social_provider("example").is_some());
}

#[test]
fn generic_oauth_duplicate_provider_ids_keep_first_provider() {
    let mut duplicate = example_config();
    duplicate.authorization_url = Some("https://other.example.com/oauth/authorize".to_owned());
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config(), duplicate],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin.clone()],
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>,
    )
    .unwrap();

    assert!(context.social_provider("example").is_some());
}

#[test]
fn provider_authorization_url_uses_better_auth_oauth2_callback_and_pkce() -> Result<(), OAuthError>
{
    let provider = provider(example_config());
    let url = provider.create_authorization_url(SocialAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["calendar".to_owned()],
        login_hint: Some("ada@example.com".to_owned()),
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/oauth/authorize")
    );
    assert_eq!(query_value(&url, "client_id"), Some("client-1".to_owned()));
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/oauth2/callback/example".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid email calendar".to_owned())
    );
    assert_eq!(query_value(&url, "prompt"), Some("consent".to_owned()));
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert_eq!(query_value(&url, "audience"), Some("api".to_owned()));
    Ok(())
}

#[test]
fn provider_authorization_code_request_uses_basic_auth_and_extra_params() -> Result<(), OAuthError>
{
    let mut config = example_config();
    config.authentication = ClientAuthentication::Basic;
    config
        .token_url_params
        .insert("resource".to_owned(), "https://api.example.com".to_owned());
    let provider = provider(config);
    let request = provider.authorization_code_request(SocialAuthorizationCodeRequest {
        code: "code-1".to_owned(),
        code_verifier: Some("verifier-1".to_owned()),
        redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
        device_id: None,
    })?;

    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("resource"),
        Some("https://api.example.com")
    );
    assert!(request.header("authorization").is_some());
    assert_eq!(request.form_value("client_secret"), None);
    Ok(())
}

#[test]
fn helper_providers_match_upstream_defaults() {
    assert_eq!(
        auth0("client", "secret", "https://tenant.auth0.com").discovery_url,
        Some("https://tenant.auth0.com/.well-known/openid-configuration".to_owned())
    );
    assert_eq!(
        okta("client", "secret", "https://dev.okta.com/oauth2/default/").discovery_url,
        Some("https://dev.okta.com/oauth2/default/.well-known/openid-configuration".to_owned())
    );
    assert_eq!(
        keycloak("client", "secret", "https://kc.example.com/realms/acme/").discovery_url,
        Some("https://kc.example.com/realms/acme/.well-known/openid-configuration".to_owned())
    );
    assert_eq!(gumroad("client", "secret").provider_id, "gumroad");
    assert_eq!(hubspot("client", "secret").scopes, vec!["oauth"]);
    assert_eq!(line("client", "secret").provider_id, "line");
    assert_eq!(
        microsoft_entra_id("client", "secret", "common").authorization_url,
        Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_owned())
    );
    assert_eq!(patreon("client", "secret").scopes, vec!["identity[email]"]);
    assert_eq!(slack("client", "secret").provider_id, "slack");
}

#[tokio::test]
async fn sign_in_oauth2_route_returns_redirect_url() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config()],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(
                    br#"{"providerId":"example","callbackURL":"/dashboard","disableRedirect":true}"#
                        .to_vec(),
                )
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["redirect"], false);
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/oauth2/callback/example".to_owned())
    );
}

#[tokio::test]
async fn sign_in_oauth2_route_rejects_unknown_provider() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config()],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header("content-type", "application/json")
                .body(br#"{"providerId":"missing"}"#.to_vec())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "PROVIDER_CONFIG_NOT_FOUND");
}

#[tokio::test]
async fn oauth2_callback_rejects_issuer_mismatch() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let mut config = example_config();
    config.issuer = Some("https://issuer.example.com".to_owned());
    config.require_issuer_validation = true;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![config],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let error = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("https://app.example.com/api/auth/oauth2/callback/example?code=code-1&iss=https%3A%2F%2Fwrong.example.com")
                .body(Vec::new())
                .unwrap(),
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("ISSUER_MISMATCH"));
}

#[tokio::test]
async fn oauth2_link_requires_session() {
    let adapter = Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>;
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![example_config()],
    });
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap();
    let router = AuthRouter::try_new(context, Vec::new()).unwrap();
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/oauth2/link")
                .header("content-type", "application/json")
                .body(br#"{"providerId":"example","callbackURL":"/settings"}"#.to_vec())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "SESSION_REQUIRED");
}

fn example_config() -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        "example",
        "client-1",
        Some("secret-1"),
        "https://idp.example.com/oauth/authorize",
        "https://idp.example.com/oauth/token",
    );
    config.user_info_url = Some("https://idp.example.com/oauth/userinfo".to_owned());
    config.scopes = vec!["openid".to_owned(), "email".to_owned()];
    config.pkce = true;
    config.prompt = Some("consent".to_owned());
    config
        .authorization_url_params
        .insert("audience".to_owned(), "api".to_owned());
    config
}

fn provider(config: GenericOAuthConfig) -> openauth_plugins::generic_oauth::GenericOAuthProvider {
    openauth_plugins::generic_oauth::GenericOAuthProvider::new(config)
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
