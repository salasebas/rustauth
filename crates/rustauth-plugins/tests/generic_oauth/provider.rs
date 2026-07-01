use super::common::*;

#[test]
fn provider_authorization_url_uses_rustauth_oauth2_callback_and_pkce() -> Result<(), OAuthError> {
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
        Some("calendar openid email".to_owned())
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
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
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
fn provider_token_url_params_cannot_override_protected_token_request_values(
) -> Result<(), OAuthError> {
    let mut config = example_config();
    // Security-critical keys must be ignored even through the override map...
    config.token_url_params.insert(
        "redirect_uri".to_owned(),
        "https://override.example.com/callback".to_owned(),
    );
    config
        .token_url_params
        .insert("grant_type".to_owned(), "custom_grant".to_owned());
    // ...while non-sensitive extension keys still apply.
    config
        .token_url_params
        .insert("audience".to_owned(), "api".to_owned());
    let provider = provider(config);
    let request = provider.authorization_code_request(SocialAuthorizationCodeRequest {
        code: "code-1".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
        device_id: None,
    })?;

    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/oauth2/callback/example")
    );
    assert_eq!(request.form_value("audience"), Some("api"));
    Ok(())
}

#[test]
fn provider_authorization_code_request_requires_code_verifier_when_pkce_is_enabled() {
    let provider = provider(example_config());

    let error = provider
        .authorization_code_request(SocialAuthorizationCodeRequest {
            code: "code-1".to_owned(),
            code_verifier: None,
            redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
            device_id: None,
        })
        .err()
        .map(|error| error.to_string());

    assert_eq!(
        error.as_deref(),
        Some("missing OAuth provider option `code_verifier`")
    );
}

#[test]
fn provider_authorization_code_request_allows_missing_code_verifier_when_pkce_is_disabled(
) -> Result<(), OAuthError> {
    let mut config = example_config();
    config.pkce = false;
    let provider = provider(config);

    let request = provider.authorization_code_request(SocialAuthorizationCodeRequest {
        code: "code-1".to_owned(),
        code_verifier: None,
        redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
        device_id: None,
    })?;

    assert_eq!(request.form_value("code_verifier"), None);
    Ok(())
}

#[test]
fn provider_create_authorization_url_requires_code_verifier_when_pkce_is_enabled() {
    let provider = provider(example_config());

    let error = provider
        .create_authorization_url(SocialAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
            code_verifier: None,
            scopes: Vec::new(),
            login_hint: None,
        })
        .err()
        .map(|error| error.to_string());

    assert_eq!(
        error.as_deref(),
        Some("missing OAuth provider option `code_verifier`")
    );
}

#[tokio::test]
async fn provider_uses_custom_get_token_and_maps_profile() -> Result<(), OAuthError> {
    let userinfo_request = Arc::new(Mutex::new(String::new()));
    let user_info_url = capture_get_server(
        Arc::clone(&userinfo_request),
        r#"{"sub":123,"email":"ada@example.com","name":"Ada"}"#,
    );
    let mut config = loopback_http_config(example_config());
    config.user_info_url = Some(user_info_url);
    config.get_token = Some(Arc::new(|request: GenericOAuthTokenRequest| {
        Box::pin(async move {
            assert_eq!(request.code, "code-1");
            assert_eq!(
                request.redirect_uri,
                "https://app.example.com/oauth2/callback/example"
            );
            Ok(OAuth2Tokens {
                access_token: Some("access-1".to_owned()),
                ..OAuth2Tokens::default()
            })
        })
    }));
    config.map_profile_to_user = Some(Arc::new(|mut profile: OAuth2UserInfo| {
        Box::pin(async move {
            profile.id = format!("mapped-{}", profile.id);
            profile.name = Some("Ada Lovelace".to_owned());
            profile.email_verified = true;
            Ok(profile)
        })
    }));
    let provider = provider(config);
    let tokens = provider
        .validate_authorization_code(SocialAuthorizationCodeRequest {
            code: "code-1".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
            device_id: None,
        })
        .await?;
    let Some(user) = provider.get_user_info(tokens, None).await? else {
        return Err(OAuthError::InvalidResponse("missing user info".to_owned()));
    };

    assert_eq!(user.id, "mapped-123");
    assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
    assert!(user.email_verified);
    let userinfo_contains_authorization = userinfo_request
        .lock()
        .map(|request| request.contains("authorization: Bearer access-1"))
        .unwrap_or(false);
    assert!(userinfo_contains_authorization);
    Ok(())
}

#[tokio::test]
async fn provider_ignores_unverified_id_token_claims_without_userinfo() -> Result<(), OAuthError> {
    let mut config = example_config();
    config.user_info_url = None;
    let provider = provider(config);
    let user = provider
        .get_user_info(
            OAuth2Tokens {
                id_token: Some(jwt_claims(
                    r#"{"sub":"forged-sub","email":"forged@example.com","name":"Forged","email_verified":true}"#,
                )),
                ..OAuth2Tokens::default()
            },
            None,
        )
        .await?;

    assert_eq!(user, None);
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_maps_claims() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = "nonce-1";
    let user = verified_id_token_user_info(valid_id_token_claims(nonce), Some(nonce)).await?;
    let user = user.ok_or("missing verified user info")?;

    assert_eq!(user.id, "oidc-user-1");
    assert_eq!(user.name.as_deref(), Some("Ada OIDC"));
    assert_eq!(user.email.as_deref(), Some("ada@example.com"));
    assert!(user.email_verified);
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_unsigned_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = "nonce-1";
    let claims = valid_id_token_claims(nonce);
    let (_signed_token, jwk) = signed_rs256_id_token(claims.clone())?;
    let token = jwt_claims(&claims.to_string());
    let result = verified_id_token_user_info_with_jwk(token, jwk, Some(nonce)).await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_missing_id_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_token, jwk) = signed_rs256_id_token(valid_id_token_claims("nonce-1"))?;
    let result =
        verified_id_token_user_info_from_tokens(OAuth2Tokens::default(), jwk, Some("nonce-1"))
            .await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_expired_token() -> Result<(), Box<dyn std::error::Error>>
{
    let nonce = "nonce-1";
    let mut claims = valid_id_token_claims(nonce);
    claims["exp"] = Value::from(OffsetDateTime::now_utc().unix_timestamp() - 3600);
    let result = verified_id_token_user_info(claims, Some(nonce)).await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_wrong_jwks_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = "nonce-1";
    let signing_key = TestSigningKey::new_rs256("generic-oauth-wrong-key")?;
    let wrong_key = TestSigningKey::new_rs256("generic-oauth-wrong-key")?;
    let token = signing_key.sign_rs256(valid_id_token_claims(nonce))?;
    let result =
        verified_id_token_user_info_with_jwk(token, wrong_key.public_jwk()?, Some(nonce)).await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_unsupported_hmac_algorithm(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = "nonce-1";
    let (token, jwk) = signed_hs256_id_token(valid_id_token_claims(nonce))?;
    let result = verified_id_token_user_info_with_jwk(token, jwk, Some(nonce)).await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_wrong_issuer() -> Result<(), Box<dyn std::error::Error>>
{
    let nonce = "nonce-1";
    let mut claims = valid_id_token_claims(nonce);
    claims["iss"] = Value::String("https://wrong.example.com".to_owned());
    let result = verified_id_token_user_info(claims, Some(nonce)).await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_wrong_audience(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = "nonce-1";
    let mut claims = valid_id_token_claims(nonce);
    claims["aud"] = Value::String("other-client".to_owned());
    let result = verified_id_token_user_info(claims, Some(nonce)).await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_missing_or_mismatched_nonce(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = "nonce-1";
    let missing = verified_id_token_user_info(valid_id_token_claims(nonce), None).await;
    let mismatched =
        verified_id_token_user_info(valid_id_token_claims(nonce), Some("wrong-nonce")).await;

    assert!(missing.is_err());
    assert!(mismatched.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_missing_exp_or_sub(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = "nonce-1";
    let mut missing_exp = valid_id_token_claims(nonce);
    missing_exp
        .as_object_mut()
        .ok_or("claims should be an object")?
        .remove("exp");
    let mut missing_sub = valid_id_token_claims(nonce);
    missing_sub
        .as_object_mut()
        .ok_or("claims should be an object")?
        .remove("sub");

    assert!(verified_id_token_user_info(missing_exp, Some(nonce))
        .await
        .is_err());
    assert!(verified_id_token_user_info(missing_sub, Some(nonce))
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn provider_verified_id_token_rejects_multi_audience_without_matching_azp(
) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = "nonce-1";
    let mut claims = valid_id_token_claims(nonce);
    claims["aud"] = serde_json::json!(["client-1", "other-client"]);
    claims["azp"] = Value::String("other-client".to_owned());
    let result = verified_id_token_user_info(claims, Some(nonce)).await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn provider_uses_custom_refresh_verify_and_revoke_hooks() {
    let mut config = example_config();
    config.refresh_access_token = Some(Arc::new(|refresh_token| {
        Box::pin(async move {
            Ok(OAuth2Tokens {
                access_token: Some(format!("refreshed-{refresh_token}")),
                ..OAuth2Tokens::default()
            })
        })
    }));
    config.verify_id_token = Some(Arc::new(|request| {
        Box::pin(async move {
            Ok(request.token == "id-token-1" && request.nonce.as_deref() == Some("nonce-1"))
        })
    }));
    config.revoke_token = Some(Arc::new(|token| {
        Box::pin(async move {
            if token == "token-1" {
                Ok(())
            } else {
                Err(OAuthError::InvalidResponse(format!(
                    "unexpected revoked token `{token}`"
                )))
            }
        })
    }));

    let provider = provider(config);
    let refreshed = provider
        .refresh_access_token("refresh-1".to_owned())
        .await
        .expect("custom refresh hook should run");
    let verified = provider
        .verify_id_token(SocialIdTokenRequest {
            token: "id-token-1".to_owned(),
            nonce: Some("nonce-1".to_owned()),
            ..SocialIdTokenRequest::default()
        })
        .await
        .expect("custom verify hook should run");
    provider
        .revoke_token("token-1".to_owned())
        .await
        .expect("custom revoke hook should run");

    assert_eq!(
        refreshed.access_token.as_deref(),
        Some("refreshed-refresh-1")
    );
    assert!(verified);
}

fn valid_id_token_claims(nonce: &str) -> Value {
    serde_json::json!({
        "iss": "https://idp.example.com",
        "sub": "oidc-user-1",
        "aud": "client-1",
        "exp": OffsetDateTime::now_utc().unix_timestamp() + Duration::hours(1).whole_seconds(),
        "nonce": nonce,
        "email": "ada@example.com",
        "email_verified": true,
        "name": "Ada OIDC",
        "picture": "https://img.example.com/ada-oidc.png"
    })
}

async fn verified_id_token_user_info(
    claims: Value,
    expected_nonce: Option<&str>,
) -> Result<Option<OAuth2UserInfo>, Box<dyn std::error::Error>> {
    let (token, jwk) = signed_rs256_id_token(claims)?;
    Ok(verified_id_token_user_info_with_jwk(token, jwk, expected_nonce).await?)
}

async fn verified_id_token_user_info_with_jwk(
    token: String,
    jwk: Value,
    expected_nonce: Option<&str>,
) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    verified_id_token_user_info_from_tokens(
        OAuth2Tokens {
            id_token: Some(token),
            ..OAuth2Tokens::default()
        },
        jwk,
        expected_nonce,
    )
    .await
}

async fn verified_id_token_user_info_from_tokens(
    tokens: OAuth2Tokens,
    jwk: Value,
    expected_nonce: Option<&str>,
) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let jwks_url = jwks_server(jwk);
    let mut config = loopback_http_config(verified_id_token_config());
    if let GenericOAuthProfileSource::VerifiedIdToken(profile) = &mut config.profile_source {
        profile.jwks_url = Some(jwks_url);
    }
    let provider = provider(config);
    provider
        .get_user_info_with_context(tokens, GenericOAuthUserInfoContext { expected_nonce })
        .await
}

#[tokio::test]
async fn provider_default_http_client_blocks_private_discovery_url() {
    let plugin = generic_oauth(GenericOAuthOptions {
        config: vec![GenericOAuthConfig::discovery(
            "discovery",
            "client-1",
            Some("secret-1"),
            "http://127.0.0.1/.well-known/openid-configuration",
        )],
    });
    let context = create_auth_context_with_adapter(
        RustAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            plugins: vec![plugin],
            ..RustAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()) as Arc<dyn DbAdapter>,
    )
    .unwrap();
    let provider = context
        .social_provider("discovery")
        .expect("discovery provider should be registered");

    let error = provider
        .refresh_access_token("refresh-1".to_owned())
        .await
        .expect_err("default client should block private discovery URL");

    assert!(
        matches!(&error, OAuthError::InvalidResponse(message) if message.contains("private or internal IP address")),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn provider_default_http_client_blocks_private_token_url() {
    let mut config = example_config();
    config.token_url = Some("http://127.0.0.1/oauth/token".to_owned());
    let provider = provider(config);

    let error = provider
        .validate_authorization_code(SocialAuthorizationCodeRequest {
            code: "code-1".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
            device_id: None,
        })
        .await
        .expect_err("default client should block private token URL");

    assert!(
        matches!(error, OAuthError::BlockedRequestUrl),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn provider_default_http_client_blocks_private_userinfo_url() {
    let mut config = example_config();
    config.user_info_url = Some("http://127.0.0.1/oauth/userinfo".to_owned());
    let provider = provider(config);

    let error = provider
        .get_user_info(
            OAuth2Tokens {
                access_token: Some("access-1".to_owned()),
                ..OAuth2Tokens::default()
            },
            None,
        )
        .await
        .expect_err("default client should block private userinfo URL");

    assert!(
        matches!(error, OAuthError::BlockedRequestUrl),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn provider_rejects_id_token_sign_in_without_custom_verifier() {
    let provider = provider(example_config());
    let verified = provider
        .verify_id_token(SocialIdTokenRequest {
            token: jwt_claims(r#"{"sub":"generic-user-1"}"#),
            ..SocialIdTokenRequest::default()
        })
        .await
        .expect("default verification should not error");

    assert!(!verified);
}
