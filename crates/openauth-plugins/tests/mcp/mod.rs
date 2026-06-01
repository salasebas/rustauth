use http::{header, Method, Request, StatusCode};
use openauth_plugins::mcp::{mcp, McpMetadataOverrides, McpOptions};
use serde_json::{json, Map, Value};

mod client_helpers;
mod consent;
mod login_resume;
mod metadata_userinfo;
mod options;
mod registration_validation;
mod support;
mod token_hardening;

use support::*;

#[test]
fn mcp_uses_upstream_defaults_and_schema_contributions() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = mcp(McpOptions {
        login_page: "/login".to_owned(),
        ..McpOptions::default()
    })?;

    assert_eq!(plugin.id, "mcp");
    assert_eq!(
        plugin.options.scopes,
        ["openid", "profile", "email", "offline_access"]
    );
    assert_eq!(plugin.options.code_expires_in, 600);
    assert_eq!(plugin.options.access_token_expires_in, 3600);
    assert_eq!(plugin.options.refresh_token_expires_in, 604800);
    assert!(plugin.options.allow_plain_code_challenge_method);
    assert_eq!(plugin.options.default_scope, ["openid"]);
    assert_eq!(plugin.as_auth_plugin().endpoints.len(), 9);
    assert_eq!(plugin.as_auth_plugin().schema.len(), 3);
    Ok(())
}

#[tokio::test]
async fn mcp_metadata_endpoints_return_provider_and_resource_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = router().await?;

    let provider = auth
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-authorization-server",
            "",
        )?)
        .await?;
    assert_eq!(provider.status(), StatusCode::OK);
    let body = json_body(&provider)?;
    assert_eq!(body["issuer"], "http://localhost:3000");
    assert_eq!(
        body["authorization_endpoint"],
        "http://localhost:3000/api/auth/mcp/authorize"
    );
    assert_eq!(
        body["token_endpoint"],
        "http://localhost:3000/api/auth/mcp/token"
    );
    assert_eq!(
        body["registration_endpoint"],
        "http://localhost:3000/api/auth/mcp/register"
    );

    let resource = auth
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-protected-resource",
            "",
        )?)
        .await?;
    assert_eq!(resource.status(), StatusCode::OK);
    let body = json_body(&resource)?;
    assert_eq!(body["resource"], "http://localhost:3000");
    assert_eq!(
        body["authorization_servers"],
        json!(["http://localhost:3000"])
    );
    assert_eq!(body["bearer_methods_supported"], json!(["header"]));
    Ok(())
}

#[tokio::test]
async fn mcp_metadata_supports_custom_overrides() -> Result<(), Box<dyn std::error::Error>> {
    let mut auth_metadata = Map::new();
    auth_metadata.insert(
        "service_documentation".to_owned(),
        json!("https://docs.example"),
    );
    let mut resource_metadata = Map::new();
    resource_metadata.insert("resource_name".to_owned(), json!("Example MCP"));
    let (auth, _) = seeded_router_with_options(McpOptions {
        login_page: "/login".to_owned(),
        metadata: McpMetadataOverrides {
            authorization_server: auth_metadata,
            protected_resource: resource_metadata,
        },
        ..McpOptions::default()
    })
    .await?;

    let provider = auth
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-authorization-server",
            "",
        )?)
        .await?;
    assert_eq!(
        json_body(&provider)?["service_documentation"],
        "https://docs.example"
    );

    let resource = auth
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-protected-resource",
            "",
        )?)
        .await?;
    assert_eq!(json_body(&resource)?["resource_name"], "Example MCP");
    Ok(())
}

#[tokio::test]
async fn mcp_register_creates_confidential_and_public_clients(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = router().await?;

    let confidential = auth
        .handle_async(json_request(
            Method::POST,
            "/api/auth/mcp/register",
            json!({
                "redirect_uris": ["https://client.example/callback"],
                "client_name": "Example MCP"
            }),
        )?)
        .await?;
    assert_eq!(confidential.status(), StatusCode::CREATED);
    let body = json_body(&confidential)?;
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
    assert!(body.get("client_secret").and_then(Value::as_str).is_some());

    let public = auth
        .handle_async(json_request(
            Method::POST,
            "/api/auth/mcp/register",
            json!({
                "redirect_uris": ["https://public.example/callback"],
                "token_endpoint_auth_method": "none"
            }),
        )?)
        .await?;
    assert_eq!(public.status(), StatusCode::CREATED);
    let body = json_body(&public)?;
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert!(body.get("client_secret").is_none());
    Ok(())
}

#[tokio::test]
async fn mcp_register_rejects_invalid_client_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let auth = router().await?;

    let missing_redirect = auth
        .handle_async(json_request(
            Method::POST,
            "/api/auth/mcp/register",
            json!({ "grant_types": ["authorization_code"] }),
        )?)
        .await?;
    assert_eq!(missing_redirect.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(&missing_redirect)?["error"],
        "invalid_redirect_uri"
    );

    let inconsistent = auth
        .handle_async(json_request(
            Method::POST,
            "/api/auth/mcp/register",
            json!({
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["token"]
            }),
        )?)
        .await?;
    assert_eq!(inconsistent.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(&inconsistent)?["error"],
        "invalid_client_metadata"
    );

    let invalid_method = auth
        .handle_async(json_request(
            Method::POST,
            "/api/auth/mcp/register",
            json!({
                "redirect_uris": ["https://client.example/callback"],
                "token_endpoint_auth_method": "client_secret_jwt"
            }),
        )?)
        .await?;
    assert_eq!(invalid_method.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(&invalid_method)?["error"],
        "invalid_client_metadata"
    );

    let invalid_grant = auth
        .handle_async(json_request(
            Method::POST,
            "/api/auth/mcp/register",
            json!({
                "redirect_uris": ["https://client.example/callback"],
                "grant_types": ["device_code"]
            }),
        )?)
        .await?;
    assert_eq!(invalid_grant.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(&invalid_grant)?["error"],
        "invalid_client_metadata"
    );
    Ok(())
}

#[tokio::test]
async fn mcp_authorize_unauthenticated_sets_login_prompt_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let (auth, adapter) = seeded_router().await?;
    seed_client(
        &adapter,
        "client_1",
        "secret_1",
        "https://client.example/callback",
        "web",
    )
    .await?;

    let response = auth
        .handle_async(request(
            Method::GET,
            "/api/auth/mcp/authorize?client_id=client_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&prompt=login",
            "",
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(response.headers()[header::LOCATION]
        .to_str()?
        .starts_with("/login?"));
    assert!(response.headers()[header::SET_COOKIE]
        .to_str()?
        .contains("oidc_login_prompt="));
    Ok(())
}

#[tokio::test]
async fn mcp_authorize_creates_code_and_redirects() -> Result<(), Box<dyn std::error::Error>> {
    let (auth, adapter) = seeded_router().await?;
    seed_client(
        &adapter,
        "client_1",
        "secret_1",
        "https://client.example/callback",
        "web",
    )
    .await?;
    let verifier = "verifier_123456789";
    let challenge = pkce_challenge(verifier);
    let cookie = signed_session_cookie("session_token_1")?;

    let response = auth
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "http://localhost:3000/api/auth/mcp/authorize?client_id=client_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid%20email&state=state_1&code_challenge={challenge}&code_challenge_method=S256"
                ))
                .header(header::COOKIE, cookie)
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()[header::LOCATION].to_str()?;
    assert!(location.starts_with("https://client.example/callback?code="));
    assert!(location.contains("state=state_1"));
    let code = url::Url::parse(location)?
        .query_pairs()
        .find_map(|(name, value)| (name == "code").then(|| value.into_owned()))
        .ok_or("missing code")?;
    assert!(find_record(&adapter, "verification", "identifier", &code)
        .await?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn mcp_authorize_consent_accept_persists_consent() -> Result<(), Box<dyn std::error::Error>> {
    let (auth, adapter) = seeded_router_with_options(McpOptions {
        login_page: "/login".to_owned(),
        consent_page: Some("/consent".to_owned()),
        ..McpOptions::default()
    })
    .await?;
    seed_client(
        &adapter,
        "client_1",
        "secret_1",
        "https://client.example/callback",
        "web",
    )
    .await?;
    let cookie = signed_session_cookie("session_token_1")?;

    let response = auth
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/mcp/authorize?client_id=client_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid%20email&prompt=consent")
                .header(header::COOKIE, cookie.clone())
                .body(Vec::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response.headers()[header::LOCATION].to_str()?;
    assert!(location.starts_with("/consent?"));
    let code = url::Url::parse(&format!("http://localhost{location}"))?
        .query_pairs()
        .find_map(|(name, value)| (name == "consent_code").then(|| value.into_owned()))
        .ok_or("missing consent code")?;

    let consent = auth
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("http://localhost:3000/api/auth/oauth2/consent")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(serde_json::to_vec(&json!({
                    "accept": true,
                    "consent_code": code
                }))?)?,
        )
        .await?;
    assert_eq!(consent.status(), StatusCode::OK);
    assert!(json_body(&consent)?["redirectURI"]
        .as_str()
        .ok_or("missing redirectURI")?
        .starts_with("https://client.example/callback?code="));
    assert!(find_record(&adapter, "oauthConsent", "userId", "user_1")
        .await?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn mcp_authorize_rejects_invalid_client_redirect_scope_and_pkce(
) -> Result<(), Box<dyn std::error::Error>> {
    let (auth, adapter) = seeded_router().await?;
    seed_client(
        &adapter,
        "client_1",
        "secret_1",
        "https://client.example/callback",
        "web",
    )
    .await?;
    let cookie = signed_session_cookie("session_token_1")?;

    let invalid_scope = auth
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/mcp/authorize?client_id=client_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=admin")
                .header(header::COOKIE, cookie.clone())
                .body(Vec::new())?,
        )
        .await?;
    assert_eq!(invalid_scope.status(), StatusCode::FOUND);
    assert!(invalid_scope.headers()[header::LOCATION]
        .to_str()?
        .contains("invalid_scope"));

    let invalid_redirect = auth
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/mcp/authorize?client_id=client_1&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback&response_type=code")
                .header(header::COOKIE, cookie.clone())
                .body(Vec::new())?,
        )
        .await?;
    assert_eq!(invalid_redirect.status(), StatusCode::BAD_REQUEST);

    let invalid_pkce = auth
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/mcp/authorize?client_id=client_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&code_challenge=abc&code_challenge_method=MD5")
                .header(header::COOKIE, cookie)
                .body(Vec::new())?,
        )
        .await?;
    assert_eq!(invalid_pkce.status(), StatusCode::FOUND);
    assert!(invalid_pkce.headers()[header::LOCATION]
        .to_str()?
        .contains("invalid_request"));
    Ok(())
}

#[tokio::test]
async fn mcp_token_exchanges_authorization_code_and_refresh_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let (auth, adapter) = seeded_router().await?;
    seed_client(
        &adapter,
        "client_1",
        "secret_1",
        "https://client.example/callback",
        "web",
    )
    .await?;
    let code = seed_code(
        &adapter,
        "client_1",
        "user_1",
        "https://client.example/callback",
        "openid email offline_access",
        Some("challenge_1"),
        Some("plain"),
    )
    .await?;

    let token = auth
        .handle_async(form_request(
            Method::POST,
            "/api/auth/mcp/token",
            &format!("grant_type=authorization_code&client_id=client_1&client_secret=secret_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&code={code}&code_verifier=challenge_1"),
        )?)
        .await?;
    assert_eq!(token.status(), StatusCode::OK);
    let body = json_body(&token)?;
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    assert!(body["id_token"].as_str().is_some());

    let refresh_token = body["refresh_token"]
        .as_str()
        .ok_or("missing refresh token")?;
    let refreshed = auth
        .handle_async(form_request(
            Method::POST,
            "/api/auth/mcp/token",
            &format!("grant_type=refresh_token&client_id=client_1&client_secret=secret_1&refresh_token={refresh_token}"),
        )?)
        .await?;
    assert_eq!(refreshed.status(), StatusCode::OK);
    assert!(json_body(&refreshed)?["access_token"].as_str().is_some());
    Ok(())
}

#[tokio::test]
async fn mcp_token_rejects_invalid_code_secret_and_pkce() -> Result<(), Box<dyn std::error::Error>>
{
    let (auth, adapter) = seeded_router().await?;
    seed_client(
        &adapter,
        "client_1",
        "secret_1",
        "https://client.example/callback",
        "web",
    )
    .await?;
    let code = seed_code(
        &adapter,
        "client_1",
        "user_1",
        "https://client.example/callback",
        "openid",
        Some("expected"),
        Some("plain"),
    )
    .await?;

    let missing_code = auth
        .handle_async(form_request(
            Method::POST,
            "/api/auth/mcp/token",
            "grant_type=authorization_code&client_id=client_1&client_secret=secret_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
        )?)
        .await?;
    assert_eq!(missing_code.status(), StatusCode::BAD_REQUEST);

    let invalid_secret = auth
        .handle_async(form_request(
            Method::POST,
            "/api/auth/mcp/token",
            &format!("grant_type=authorization_code&client_id=client_1&client_secret=wrong&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&code={code}&code_verifier=expected"),
        )?)
        .await?;
    assert_eq!(invalid_secret.status(), StatusCode::UNAUTHORIZED);

    let consumed = auth
        .handle_async(form_request(
            Method::POST,
            "/api/auth/mcp/token",
            &format!("grant_type=authorization_code&client_id=client_1&client_secret=secret_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&code={code}&code_verifier=expected"),
        )?)
        .await?;
    assert_eq!(consumed.status(), StatusCode::UNAUTHORIZED);

    let code = seed_code(
        &adapter,
        "client_1",
        "user_1",
        "https://client.example/callback",
        "openid",
        Some("expected"),
        Some("plain"),
    )
    .await?;
    let invalid_pkce = auth
        .handle_async(form_request(
            Method::POST,
            "/api/auth/mcp/token",
            &format!("grant_type=authorization_code&client_id=client_1&client_secret=secret_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&code={code}&code_verifier=wrong"),
        )?)
        .await?;
    assert_eq!(invalid_pkce.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn mcp_get_session_returns_null_without_bearer_and_record_with_valid_bearer(
) -> Result<(), Box<dyn std::error::Error>> {
    let (auth, adapter) = seeded_router().await?;
    seed_access_token(
        &adapter,
        "access_1",
        "refresh_1",
        "client_1",
        "user_1",
        "openid",
    )
    .await?;

    let missing = auth
        .handle_async(request(Method::GET, "/api/auth/mcp/get-session", "")?)
        .await?;
    assert_eq!(missing.status(), StatusCode::OK);
    assert_eq!(json_body(&missing)?, Value::Null);
    assert_eq!(missing.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(
        missing.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
        "WWW-Authenticate"
    );

    let found = auth
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/mcp/get-session")
                .header(header::AUTHORIZATION, "Bearer access_1")
                .body(Vec::new())?,
        )
        .await?;
    assert_eq!(found.status(), StatusCode::OK);
    assert_eq!(json_body(&found)?["userId"], "user_1");
    Ok(())
}
