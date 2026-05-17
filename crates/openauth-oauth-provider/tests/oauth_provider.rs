use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, MemoryAdapter, Session};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_oauth_provider::mcp::{
    authorization_server_metadata as mcp_authorization_server_metadata,
    protected_resource_metadata as mcp_protected_resource_metadata, validate_bearer_token,
    www_authenticate_for_resources,
};
use openauth_oauth_provider::{
    delete_consent, find_consent, has_granted_scopes, oauth_provider, upsert_consent,
    ConsentGrantInput, GrantType, OAuthProviderConfigError, OAuthProviderOptions, SecretStorage,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const BASE_URL: &str = "http://localhost:3000";
const SECRET: &str = "test-secret-123456789012345678901234";

#[test]
fn oauth_provider_uses_upstream_default_scopes_grants_and_expirations(
) -> Result<(), OAuthProviderConfigError> {
    let plugin = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        ..OAuthProviderOptions::default()
    })?;

    assert_eq!(plugin.id, "oauth-provider");
    assert_eq!(
        plugin.options.scopes,
        ["openid", "profile", "email", "offline_access"]
    );
    assert_eq!(
        plugin.options.claims,
        [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "sid",
            "scope",
            "azp",
            "email",
            "email_verified",
            "name",
            "picture",
            "family_name",
            "given_name"
        ]
    );
    assert_eq!(plugin.options.code_expires_in, 600);
    assert_eq!(plugin.options.access_token_expires_in, 3600);
    assert_eq!(plugin.options.refresh_token_expires_in, 2_592_000);
    assert_eq!(
        plugin.options.grant_types,
        [
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken
        ]
    );
    assert_eq!(plugin.options.store_client_secret, SecretStorage::Hashed);
    Ok(())
}

#[test]
fn oauth_provider_contributes_plural_snake_case_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context =
        create_auth_context_with_adapter(options_with_provider(default_provider()?), adapter())?;
    let clients = context
        .db_schema
        .table("oauth_client")
        .ok_or_else(|| OpenAuthError::InvalidConfig("missing oauth client schema".to_owned()))?;
    let refresh_tokens = context
        .db_schema
        .table("oauth_refresh_token")
        .ok_or_else(|| OpenAuthError::InvalidConfig("missing refresh token schema".to_owned()))?;
    let access_tokens = context
        .db_schema
        .table("oauth_access_token")
        .ok_or_else(|| OpenAuthError::InvalidConfig("missing access token schema".to_owned()))?;
    let consents = context
        .db_schema
        .table("oauth_consent")
        .ok_or_else(|| OpenAuthError::InvalidConfig("missing consent schema".to_owned()))?;

    assert_eq!(clients.name, "oauth_clients");
    assert_eq!(refresh_tokens.name, "oauth_refresh_tokens");
    assert_eq!(access_tokens.name, "oauth_access_tokens");
    assert_eq!(consents.name, "oauth_consents");
    assert_eq!(
        clients.field("client_id").map(|field| field.name.as_str()),
        Some("client_id")
    );
    assert_eq!(
        clients
            .field("token_endpoint_auth_method")
            .map(|field| field.name.as_str()),
        Some("token_endpoint_auth_method")
    );
    assert_eq!(
        clients
            .field("redirect_uris")
            .map(|field| field.name.as_str()),
        Some("redirect_uris")
    );
    Ok(())
}

#[tokio::test]
async fn consent_helpers_persist_update_delete_and_match_scopes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    let consent = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: "client_1".to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: None,
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        },
    )
    .await?;

    assert!(has_granted_scopes(&consent, &["openid".to_owned()]));
    assert!(has_granted_scopes(
        &consent,
        &["openid".to_owned(), "email".to_owned()]
    ));
    assert!(!has_granted_scopes(&consent, &["profile".to_owned()]));

    let updated = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: "client_1".to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: Some("ref_1".to_owned()),
            scopes: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
        },
    )
    .await?;

    assert_eq!(adapter.len("oauth_consent").await, 1);
    assert_eq!(updated.reference_id.as_deref(), Some("ref_1"));
    assert!(has_granted_scopes(&updated, &["profile".to_owned()]));

    let found = find_consent(adapter.as_ref(), "user_1", "client_1")
        .await?
        .ok_or("missing consent")?;
    assert_eq!(found.id, updated.id);

    delete_consent(adapter.as_ref(), "user_1", "client_1").await?;
    assert!(find_consent(adapter.as_ref(), "user_1", "client_1")
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn metadata_endpoint_returns_oidc_server_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let router = router(default_provider()?, adapter())?;
    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/openid-configuration",
            "",
            None,
        )?)
        .await?;
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static(
            "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"
        ))
    );
    let body = json_body(response)?;

    assert_eq!(body["issuer"], BASE_URL);
    assert_eq!(
        body["authorization_endpoint"],
        format!("{BASE_URL}/oauth2/authorize")
    );
    assert_eq!(body["token_endpoint"], format!("{BASE_URL}/oauth2/token"));
    assert_eq!(
        body["userinfo_endpoint"],
        format!("{BASE_URL}/oauth2/userinfo")
    );
    assert_eq!(
        body["scopes_supported"],
        json!(["openid", "profile", "email", "offline_access"])
    );
    Ok(())
}

#[tokio::test]
async fn dynamic_registration_creates_confidential_client_and_hashes_secret(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            valid_audiences: vec!["https://api.example.com".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response)?;
    let client_id = body["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = body["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    assert_eq!(body["scope"], "openid email");

    let stored = adapter.records("oauth_client").await;
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].get("client_id"),
        Some(&DbValue::String(client_id.to_owned()))
    );
    assert_ne!(
        stored[0].get("client_secret"),
        Some(&DbValue::String(client_secret.to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn client_credentials_token_returns_bearer_token_and_persists_opaque_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"grant_types":["client_credentials"],"scope":"profile"}"#,
        Some(&cookie),
    )
    .await?;
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=profile",
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response)?;
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["scope"], "profile");
    assert!(token["access_token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(adapter.len("oauth_access_token").await, 1);
    Ok(())
}

#[tokio::test]
async fn authorization_code_flow_issues_access_and_refresh_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&state=abc"
    );

    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing location")?;
    let redirect = url::Url::parse(location)?;
    let code = redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then_some(value.into_owned()))
        .ok_or("missing code")?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let token = json_body(response)?;
    assert!(token["access_token"].as_str().is_some());
    assert!(token["refresh_token"].as_str().is_some());
    assert_eq!(adapter.len("oauth_access_token").await, 1);
    assert_eq!(adapter.len("oauth_refresh_token").await, 1);
    Ok(())
}

#[tokio::test]
async fn authorization_code_flow_enforces_pkce_s256_for_public_clients(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none","type":"native","scope":"openid","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let authorize_without_pkce = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_without_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_with_pkce = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_with_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let wrong_verifier_body = format!(
        "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&code_verifier=wrong"
    );
    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/token",
            &wrong_verifier_body,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .handle_async(request(
            Method::GET,
            &authorize_with_pkce,
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&code_verifier={verifier}"
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_none_returns_login_required_without_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid&state=login-state&prompt=none"
    );

    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.scheme(), "https");
    assert_eq!(redirect.host_str(), Some("rp.example"));
    assert_eq!(redirect.path(), "/callback");
    assert_eq!(
        redirect_query_value(&redirect, "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("login-state")
    );
    Ok(())
}

#[tokio::test]
async fn authorize_prompt_none_returns_consent_required_without_grant(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20email&state=consent-state&prompt=none"
    );

    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = redirect_url(&response)?;
    assert_eq!(redirect.scheme(), "https");
    assert_eq!(redirect.host_str(), Some("rp.example"));
    assert_eq!(redirect.path(), "/callback");
    assert_eq!(
        redirect_query_value(&redirect, "error").as_deref(),
        Some("consent_required")
    );
    assert_eq!(
        redirect_query_value(&redirect, "state").as_deref(),
        Some("consent-state")
    );
    Ok(())
}

#[tokio::test]
async fn consent_endpoint_accepts_rejects_and_continue_resumes_pending_authorization(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email offline_access"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20email&state=approve-state"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let consent_redirect = redirect_url(&response)?;
    assert_eq!(consent_redirect.path(), "/consent");
    let request_id =
        redirect_query_value(&consent_redirect, "request_id").ok_or("missing request_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/consent",
            &format!(r#"{{"request_id":"{}","accept":true}}"#, request_id),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let callback = redirect_url(&response)?;
    assert_eq!(callback.path(), "/callback");
    assert!(redirect_query_value(&callback, "code").is_some());
    assert_eq!(
        redirect_query_value(&callback, "state").as_deref(),
        Some("approve-state")
    );
    assert_eq!(adapter.len("oauth_consent").await, 1);

    let reject_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=profile&state=reject-state&prompt=consent"
    );
    let response = router
        .handle_async(request(Method::GET, &reject_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let reject_request_id = redirect_query_value(&redirect_url(&response)?, "request_id")
        .ok_or("missing request_id")?;
    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/consent",
            &format!(r#"{{"request_id":"{}","accept":false}}"#, reject_request_id),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let rejected = redirect_url(&response)?;
    assert_eq!(
        redirect_query_value(&rejected, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        redirect_query_value(&rejected, "state").as_deref(),
        Some("reject-state")
    );

    let continue_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=email&state=continue-state&prompt=consent"
    );
    let response = router
        .handle_async(request(Method::GET, &continue_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let continue_request_id = redirect_query_value(&redirect_url(&response)?, "request_id")
        .ok_or("missing request_id")?;
    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/continue?request_id={continue_request_id}"),
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let continued = redirect_url(&response)?;
    assert!(redirect_query_value(&continued, "code").is_some());
    assert_eq!(
        redirect_query_value(&continued, "state").as_deref(),
        Some("continue-state")
    );
    Ok(())
}

#[tokio::test]
async fn refresh_token_grant_rotates_and_revokes_previous_refresh_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let first = exchange_authorization_code(&router, &cookie, client_id, client_secret).await?;
    let refresh_token = first["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?;
    let body = format!(
        "grant_type=refresh_token&client_id={client_id}&client_secret={client_secret}&refresh_token={refresh_token}"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed = json_body(response)?;
    assert_ne!(
        refreshed["refresh_token"].as_str(),
        Some(refresh_token),
        "refresh grant must rotate refresh tokens"
    );
    let refresh_records = adapter.records("oauth_refresh_token").await;
    assert_eq!(refresh_records.len(), 2);
    assert!(refresh_records
        .iter()
        .any(|record| matches!(record.get("revoked"), Some(DbValue::Timestamp(_)))));
    Ok(())
}

#[tokio::test]
async fn introspect_and_revoke_require_valid_client_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let tokens = exchange_authorization_code(&router, &cookie, client_id, client_secret).await?;
    let access_token = tokens["access_token"]
        .as_str()
        .ok_or("missing access_token")?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!("token={}", query_encode(access_token)),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)?["error"], "invalid_client");

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/revoke",
            &format!(
                "token={}&token_type_hint=access_token&client_id={client_id}&client_secret=wrong",
                query_encode(access_token)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)?["error"], "invalid_client");

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&token_type_hint=access_token&client_id={client_id}&client_secret={}",
                query_encode(access_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["active"], true);

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/revoke",
            &format!(
                "token={}&token_type_hint=access_token&client_id={client_id}&client_secret={}",
                query_encode(access_token),
                query_encode(client_secret)
            ),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn openid_authorization_code_issues_signed_id_token_and_jwks(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            valid_audiences: vec!["https://api.example.com".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid profile email","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let tokens = exchange_authorization_code_with_scope(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        "openid profile email",
    )
    .await?;
    let id_token = tokens["id_token"].as_str().ok_or("missing id_token")?;
    let claims = decode_jwt_payload(id_token)?;

    assert_eq!(claims["iss"], BASE_URL);
    assert_eq!(claims["aud"], client["client_id"]);
    assert_eq!(claims["sub"], "user_1");
    assert_eq!(claims["email"], "ada@example.com");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["name"], "Ada Lovelace");

    let jwks_response = router
        .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
        .await?;
    assert_eq!(jwks_response.status(), StatusCode::OK);
    let jwks = json_body(jwks_response)?;
    assert!(jwks["keys"].as_array().is_some_and(|keys| !keys.is_empty()));
    Ok(())
}

#[tokio::test]
async fn resource_parameter_issues_jwt_access_token_with_oauth_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            valid_audiences: vec!["https://api.example.com".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let tokens = exchange_authorization_code_with_resource(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        Some("https://api.example.com"),
    )
    .await?;
    let access_token = tokens["access_token"]
        .as_str()
        .ok_or("missing access_token")?;
    let claims = decode_jwt_payload(access_token)?;

    assert_eq!(claims["iss"], BASE_URL);
    assert_eq!(claims["aud"], "https://api.example.com");
    assert_eq!(claims["azp"], client["client_id"]);
    assert_eq!(claims["sub"], "user_1");
    assert_eq!(claims["scope"], "openid offline_access");
    assert_eq!(adapter.len("oauth_access_token").await, 0);
    Ok(())
}

#[tokio::test]
async fn resource_parameter_rejects_unconfigured_audience() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            valid_audiences: vec!["https://api.example.com".to_owned()],
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let client_secret = client["client_secret"]
        .as_str()
        .ok_or("missing client_secret")?;
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(&cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&resource=https%3A%2F%2Fevil.example"
    );

    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_request");
    Ok(())
}

#[tokio::test]
async fn pairwise_subject_is_stable_by_sector_and_used_for_userinfo_and_introspection(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            pairwise_secret: Some("test-pairwise-secret-key-32chars!!".to_owned()),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client_a = register_client(
        &router,
        r#"{"redirect_uris":["https://rp-a.example/callback"],"scope":"openid email offline_access","subject_type":"pairwise","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let client_b = register_client(
        &router,
        r#"{"redirect_uris":["https://rp-b.example/callback"],"scope":"openid email offline_access","subject_type":"pairwise","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let tokens_a = exchange_authorization_code_with_redirect(
        &router,
        &cookie,
        client_a["client_id"].as_str().ok_or("missing client_id")?,
        client_a["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        "https://rp-a.example/callback",
    )
    .await?;
    let tokens_a_again = exchange_authorization_code_with_redirect(
        &router,
        &cookie,
        client_a["client_id"].as_str().ok_or("missing client_id")?,
        client_a["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        "https://rp-a.example/callback",
    )
    .await?;
    let tokens_b = exchange_authorization_code_with_redirect(
        &router,
        &cookie,
        client_b["client_id"].as_str().ok_or("missing client_id")?,
        client_b["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
        "https://rp-b.example/callback",
    )
    .await?;
    let sub_a = decode_jwt_payload(tokens_a["id_token"].as_str().ok_or("missing id_token")?)?
        ["sub"]
        .as_str()
        .ok_or("missing sub")?
        .to_owned();
    let sub_a_again = decode_jwt_payload(
        tokens_a_again["id_token"]
            .as_str()
            .ok_or("missing id_token")?,
    )?["sub"]
        .as_str()
        .ok_or("missing sub")?
        .to_owned();
    let sub_b = decode_jwt_payload(tokens_b["id_token"].as_str().ok_or("missing id_token")?)?
        ["sub"]
        .as_str()
        .ok_or("missing sub")?
        .to_owned();

    assert_eq!(sub_a, sub_a_again);
    assert_ne!(sub_a, sub_b);

    let access_token = tokens_a["access_token"]
        .as_str()
        .ok_or("missing access_token")?;
    let userinfo = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/oauth2/userinfo",
            access_token,
        )?)
        .await?;
    assert_eq!(userinfo.status(), StatusCode::OK);
    assert_eq!(json_body(userinfo)?["sub"], sub_a);

    let introspection = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/introspect",
            &format!(
                "token={}&client_id={}&client_secret={}",
                query_encode(access_token),
                client_a["client_id"].as_str().ok_or("missing client_id")?,
                query_encode(
                    client_a["client_secret"]
                        .as_str()
                        .ok_or("missing client_secret")?
                )
            ),
        )?)
        .await?;
    assert_eq!(introspection.status(), StatusCode::OK);
    assert_eq!(json_body(introspection)?["sub"], sub_a);

    let refresh_token = tokens_a["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?;
    let refresh_body = format!(
        "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={refresh_token}",
        client_a["client_id"].as_str().ok_or("missing client_id")?,
        client_a["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?
    );
    let refreshed = router
        .handle_async(form_request(
            Method::POST,
            "/api/auth/oauth2/token",
            &refresh_body,
        )?)
        .await?;
    assert_eq!(refreshed.status(), StatusCode::OK);
    let refreshed = json_body(refreshed)?;
    assert_eq!(
        decode_jwt_payload(refreshed["id_token"].as_str().ok_or("missing id_token")?)?["sub"],
        sub_a
    );
    Ok(())
}

#[tokio::test]
async fn pairwise_registration_requires_single_redirect_sector(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            pairwise_secret: Some("test-pairwise-secret-key-32chars!!".to_owned()),
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;

    let error = match router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example/callback","https://other.example/callback"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await
    {
        Ok(_) => return Err("registration should reject mixed pairwise hosts".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        OpenAuthError::Api(message) if message.starts_with("invalid_client_metadata:")
    ));

    let error = match router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example:443/callback","https://rp.example:8443/callback"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await
    {
        Ok(_) => return Err("registration should reject mixed pairwise ports".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        OpenAuthError::Api(message) if message.starts_with("invalid_client_metadata:")
    ));

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            r#"{"redirect_uris":["https://rp.example/callback","https://rp.example/alt"],"subject_type":"pairwise"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    Ok(())
}

#[tokio::test]
async fn dynamic_registration_cannot_enable_rp_initiated_logout(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;

    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"post_logout_redirect_uris":["https://rp.example/logout"],"enable_end_session":true}"#,
        Some(&cookie),
    )
    .await?;

    assert!(client.get("enable_end_session").is_none_or(Value::is_null));
    let stored = adapter.records("oauth_client").await;
    assert_eq!(stored[0].get("enable_end_session"), Some(&DbValue::Null));
    Ok(())
}

#[tokio::test]
async fn client_management_endpoints_reject_cross_user_ownership(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    seed_user_session_with(
        adapter.as_ref(),
        UserSeed {
            user_id: "user_2",
            session_id: "session_2",
            token: "token_2",
            name: "Grace Hopper",
            email: "grace@example.com",
        },
    )
    .await?;
    let owner_cookie = signed_session_cookie("token_1")?;
    let other_cookie = signed_session_cookie("token_2")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&owner_cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/get-client?client_id={client_id}"),
            "",
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["error"], "access_denied");

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-client",
            &format!(r#"{{"client_id":"{client_id}","update":{{"client_name":"stolen"}}}}"#),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/client/rotate-secret",
            &format!(r#"{{"client_id":"{client_id}"}}"#),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/delete-client",
            &format!(r#"{{"client_id":"{client_id}"}}"#),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/get-client?client_id={client_id}"),
            "",
            Some(&owner_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn rotate_secret_rejects_public_clients() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["http://127.0.0.1/callback"],"token_endpoint_auth_method":"none","type":"native","scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/client/rotate-secret",
            &format!(r#"{{"client_id":"{client_id}"}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_client");
    Ok(())
}

#[tokio::test]
async fn update_client_preserves_omitted_fields() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-client",
            &format!(r#"{{"client_id":"{client_id}","update":{{"client_name":"renamed"}}}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["client_name"], "renamed");
    assert_eq!(
        body["redirect_uris"],
        json!(["https://rp.example/callback"])
    );
    assert_eq!(body["scope"], "openid email");
    Ok(())
}

#[tokio::test]
async fn update_client_rejects_invalid_scope() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-client",
            &format!(r#"{{"client_id":"{client_id}","update":{{"scope":"admin"}}}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_scope");
    Ok(())
}

#[tokio::test]
async fn consent_management_endpoints_enforce_owner_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    seed_user_session_with(
        adapter.as_ref(),
        UserSeed {
            user_id: "user_2",
            session_id: "session_2",
            token: "token_2",
            name: "Grace Hopper",
            email: "grace@example.com",
        },
    )
    .await?;
    let owner_cookie = signed_session_cookie("token_1")?;
    let other_cookie = signed_session_cookie("token_2")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email"}"#,
        Some(&owner_cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let consent = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: client_id.to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: None,
            scopes: vec!["openid".to_owned()],
        },
    )
    .await?;

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/get-consent?id={}", consent.id),
            "",
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .handle_async(request(
            Method::GET,
            &format!("/api/auth/oauth2/get-consent?id={}", consent.id),
            "",
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-consent",
            &format!(
                r#"{{"id":"{}","update":{{"scopes":["openid","email"]}}}}"#,
                consent.id
            ),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/delete-consent",
            &format!(r#"{{"id":"{}"}}"#, consent.id),
            Some(&other_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-consent",
            &format!(
                r#"{{"id":"{}","update":{{"scopes":["openid","email"]}}}}"#,
                consent.id
            ),
            Some(&owner_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/delete-consent",
            &format!(r#"{{"id":"{}"}}"#, consent.id),
            Some(&owner_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(find_consent(adapter.as_ref(), "user_1", client_id)
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn update_consent_rejects_scopes_not_allowed_for_client(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let consent = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: client_id.to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: None,
            scopes: vec!["openid".to_owned()],
        },
    )
    .await?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-consent",
            &format!(
                r#"{{"id":"{}","update":{{"scopes":["email"]}}}}"#,
                consent.id
            ),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["error"], "invalid_scope");

    let stored = find_consent(adapter.as_ref(), "user_1", client_id)
        .await?
        .ok_or("missing consent")?;
    assert_eq!(stored.scopes, vec!["openid".to_owned()]);
    Ok(())
}

#[tokio::test]
async fn update_consent_without_scopes_preserves_existing_scopes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email"}"#,
        Some(&cookie),
    )
    .await?;
    let client_id = client["client_id"].as_str().ok_or("missing client_id")?;
    let consent = upsert_consent(
        adapter.as_ref(),
        ConsentGrantInput {
            client_id: client_id.to_owned(),
            user_id: Some("user_1".to_owned()),
            reference_id: None,
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        },
    )
    .await?;

    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/update-consent",
            &format!(r#"{{"id":"{}","update":{{}}}}"#, consent.id),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let stored = find_consent(adapter.as_ref(), "user_1", client_id)
        .await?
        .ok_or("missing consent")?;
    assert_eq!(stored.scopes, vec!["openid".to_owned(), "email".to_owned()]);
    Ok(())
}

#[tokio::test]
async fn mcp_helpers_return_metadata_challenge_and_validate_bearer_tokens(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let plugin = oauth_provider(OAuthProviderOptions {
        disable_jwt_plugin: true,
        allow_dynamic_client_registration: true,
        ..default_options()
    })?;
    let resolved = plugin.options.clone();
    let router = router(plugin, Arc::clone(&adapter))?;
    let context = create_auth_context_with_adapter(
        options_with_provider(oauth_provider(OAuthProviderOptions {
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            ..default_options()
        })?),
        adapter.clone(),
    )?;
    let auth_metadata = mcp_authorization_server_metadata(&context, &resolved);
    assert_eq!(auth_metadata["issuer"], BASE_URL);
    assert_eq!(
        auth_metadata["authorization_endpoint"],
        format!("{BASE_URL}/oauth2/authorize")
    );
    assert_eq!(
        auth_metadata["token_endpoint"],
        format!("{BASE_URL}/oauth2/token")
    );
    assert_eq!(
        auth_metadata["scopes_supported"],
        json!(["openid", "profile", "email", "offline_access"])
    );

    let resource_metadata =
        mcp_protected_resource_metadata(&context, &resolved, "https://mcp.example/sse")?;
    assert_eq!(resource_metadata["resource"], "https://mcp.example/sse");
    assert_eq!(
        resource_metadata["authorization_servers"],
        json!([BASE_URL])
    );
    assert_eq!(
        resource_metadata["scopes_supported"],
        json!(["openid", "profile", "email", "offline_access"])
    );

    let challenge = www_authenticate_for_resources(["https://mcp.example/sse"])?;
    assert!(challenge.contains(".well-known/oauth-protected-resource/sse"));

    let client = register_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"scope":"openid email offline_access","skip_consent":true}"#,
        Some(&cookie),
    )
    .await?;
    let tokens = exchange_authorization_code(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
    )
    .await?;
    let access_token = tokens["access_token"]
        .as_str()
        .ok_or("missing access_token")?;
    let active = validate_bearer_token(
        &context,
        adapter.as_ref(),
        &resolved,
        Some(&format!("Bearer {access_token}")),
    )
    .await?
    .ok_or("missing validated token")?;

    assert_eq!(active.subject.as_deref(), Some("user_1"));
    assert_eq!(active.client_id.as_deref(), client["client_id"].as_str());
    assert_eq!(active.scopes, ["openid", "offline_access"]);

    let invalid = validate_bearer_token(
        &context,
        adapter.as_ref(),
        &resolved,
        Some("Bearer invalid"),
    )
    .await?;
    assert!(invalid.is_none());
    Ok(())
}

#[tokio::test]
async fn rp_initiated_logout_rejects_invalid_id_token_hint(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(default_provider()?, adapter())?;
    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/oauth2/end-session?id_token_hint=not-a-jwt",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)?["error"], "invalid_token");
    Ok(())
}

#[tokio::test]
async fn rp_initiated_logout_deletes_session_and_redirects_to_registered_uri(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = adapter();
    seed_user_session(adapter.as_ref()).await?;
    let cookie = signed_session_cookie("token_1")?;
    let router = router(
        oauth_provider(OAuthProviderOptions {
            allow_dynamic_client_registration: true,
            ..default_options()
        })?,
        Arc::clone(&adapter),
    )?;
    let client = create_admin_client(
        &router,
        r#"{"redirect_uris":["https://rp.example/callback"],"post_logout_redirect_uris":["https://rp.example/logout"],"enable_end_session":true,"scope":"openid offline_access","skip_consent":true}"#,
        &cookie,
    )
    .await?;
    let tokens = exchange_authorization_code(
        &router,
        &cookie,
        client["client_id"].as_str().ok_or("missing client_id")?,
        client["client_secret"]
            .as_str()
            .ok_or("missing client_secret")?,
    )
    .await?;
    let id_token = tokens["id_token"].as_str().ok_or("missing id_token")?;
    assert_eq!(decode_jwt_payload(id_token)?["sid"], "session_1");

    let logout_path = format!(
        "/api/auth/oauth2/end-session?id_token_hint={}&post_logout_redirect_uri=https%3A%2F%2Frp.example%2Flogout&state=done",
        query_encode(id_token)
    );
    let response = router
        .handle_async(request(Method::GET, &logout_path, "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing location")?;
    assert_eq!(location, "https://rp.example/logout?state=done");
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[test]
fn oauth_provider_rejects_client_registration_scopes_not_in_server_scopes() {
    let result = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        client_registration_allowed_scopes: vec!["admin".into()],
        ..OAuthProviderOptions::default()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::UnknownClientRegistrationScope(
            "admin".into()
        ))
    );
}

#[test]
fn oauth_provider_rejects_refresh_token_without_authorization_code_grant() {
    let result = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        grant_types: vec![GrantType::RefreshToken],
        ..OAuthProviderOptions::default()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::RefreshTokenRequiresAuthorizationCode)
    );
}

#[test]
fn oauth_provider_rejects_short_pairwise_secret() {
    let result = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        pairwise_secret: Some("too-short".into()),
        ..OAuthProviderOptions::default()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::PairwiseSecretTooShort)
    );
}

#[test]
fn oauth_provider_rejects_hashed_client_secrets_without_jwt_plugin() {
    let result = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        disable_jwt_plugin: true,
        store_client_secret: SecretStorage::Hashed,
        ..OAuthProviderOptions::default()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::HashedClientSecretsRequireJwtPlugin)
    );
}

async fn register_client(
    router: &AuthRouter,
    body: &str,
    cookie: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/oauth2/register",
            body,
            cookie,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response)
}

async fn create_admin_client(
    router: &AuthRouter,
    body: &str,
    cookie: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/admin/oauth2/create-client",
            body,
            Some(cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response)
}

async fn exchange_authorization_code(
    router: &AuthRouter,
    cookie: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    exchange_authorization_code_with_scope(
        router,
        cookie,
        client_id,
        client_secret,
        "openid offline_access",
    )
    .await
}

async fn exchange_authorization_code_with_scope(
    router: &AuthRouter,
    cookie: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope={}",
        query_encode(scope)
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback"
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response)
}

async fn exchange_authorization_code_with_resource(
    router: &AuthRouter,
    cookie: &str,
    client_id: &str,
    client_secret: &str,
    resource: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    if resource.is_none() {
        return exchange_authorization_code(router, cookie, client_id, client_secret).await;
    }

    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&resource={}",
        query_encode(resource.unwrap_or_default())
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response)
}

async fn exchange_authorization_code_with_redirect(
    router: &AuthRouter,
    cookie: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid%20offline_access",
        query_encode(redirect_uri)
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri={}",
        query_encode(redirect_uri)
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response)
}

fn authorization_code_from_location(
    response: &http::Response<Vec<u8>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let redirect = redirect_url(response)?;
    redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then_some(value.into_owned()))
        .ok_or_else(|| "missing code".into())
}

fn redirect_url(
    response: &http::Response<Vec<u8>>,
) -> Result<url::Url, Box<dyn std::error::Error>> {
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing location")?;
    Ok(url::Url::parse(BASE_URL)?.join(location)?)
}

fn redirect_query_value(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then_some(value.into_owned()))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn decode_jwt_payload(token: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or("token does not contain a jwt payload")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

fn query_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn default_provider(
) -> Result<openauth_oauth_provider::OAuthProviderPlugin, OAuthProviderConfigError> {
    oauth_provider(default_options())
}

fn default_options() -> OAuthProviderOptions {
    OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        ..OAuthProviderOptions::default()
    }
}

fn options_with_provider(plugin: openauth_oauth_provider::OAuthProviderPlugin) -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: Some(BASE_URL.to_owned()),
        secret: Some(SECRET.to_owned()),
        plugins: vec![plugin.into_auth_plugin()],
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}

fn router(
    plugin: openauth_oauth_provider::OAuthProviderPlugin,
    adapter: Arc<MemoryAdapter>,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(options_with_provider(plugin), adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn adapter() -> Arc<MemoryAdapter> {
    Arc::new(MemoryAdapter::new())
}

fn request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{BASE_URL}{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

fn form_request(method: Method, path: &str, body: &str) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("{BASE_URL}{path}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
}

fn bearer_request(
    method: Method,
    path: &str,
    token: &str,
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("{BASE_URL}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Vec::new())
}

fn json_body(response: http::Response<Vec<u8>>) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(response.body())?)
}

async fn seed_user_session(adapter: &MemoryAdapter) -> Result<(), OpenAuthError> {
    seed_user_session_with(
        adapter,
        UserSeed {
            user_id: "user_1",
            session_id: "session_1",
            token: "token_1",
            name: "Ada Lovelace",
            email: "ada@example.com",
        },
    )
    .await
}

struct UserSeed<'a> {
    user_id: &'a str,
    session_id: &'a str,
    token: &'a str,
    name: &'a str,
    email: &'a str,
}

async fn seed_user_session_with(
    adapter: &MemoryAdapter,
    seed: UserSeed<'_>,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(create_query("user", user_record(now, &seed)))
        .await?;
    adapter
        .create(create_query("session", session_record(now, &seed)))
        .await?;
    Ok(())
}

fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(SECRET.to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter(),
    )?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookies
        .iter()
        .map(|cookie: &Cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; "))
}

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

fn user_record(now: OffsetDateTime, seed: &UserSeed<'_>) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(seed.user_id.to_owned()));
    record.insert("name".to_owned(), DbValue::String(seed.name.to_owned()));
    record.insert("email".to_owned(), DbValue::String(seed.email.to_owned()));
    record.insert("email_verified".to_owned(), DbValue::Boolean(true));
    record.insert("image".to_owned(), DbValue::Null);
    record.insert("created_at".to_owned(), DbValue::Timestamp(now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(now));
    record
}

fn session_record(now: OffsetDateTime, seed: &UserSeed<'_>) -> DbRecord {
    let mut record = DbRecord::new();
    let session = Session {
        id: seed.session_id.to_owned(),
        user_id: seed.user_id.to_owned(),
        expires_at: now + Duration::hours(1),
        token: seed.token.to_owned(),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
    };
    record.insert("id".to_owned(), DbValue::String(session.id));
    record.insert("user_id".to_owned(), DbValue::String(session.user_id));
    record.insert(
        "expires_at".to_owned(),
        DbValue::Timestamp(session.expires_at),
    );
    record.insert("token".to_owned(), DbValue::String(session.token));
    record.insert("ip_address".to_owned(), DbValue::Null);
    record.insert("user_agent".to_owned(), DbValue::Null);
    record.insert(
        "created_at".to_owned(),
        DbValue::Timestamp(session.created_at),
    );
    record.insert(
        "updated_at".to_owned(),
        DbValue::Timestamp(session.updated_at),
    );
    record
}
