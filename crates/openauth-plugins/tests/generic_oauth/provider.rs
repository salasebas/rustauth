use super::common::*;

#[test]
fn provider_authorization_url_uses_openauth_oauth2_callback_and_pkce() -> Result<(), OAuthError> {
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
        code_verifier: None,
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

#[tokio::test]
async fn provider_uses_custom_get_token_and_maps_profile() {
    let mut config = example_config();
    config.get_token = Some(Arc::new(|request: GenericOAuthTokenRequest| {
        Box::pin(async move {
            assert_eq!(request.code, "code-1");
            assert_eq!(
                request.redirect_uri,
                "https://app.example.com/oauth2/callback/example"
            );
            Ok(OAuth2Tokens {
                access_token: Some("access-1".to_owned()),
                id_token: Some(jwt_with_claims(
                    r#"{"sub":123,"email":"ada@example.com","name":"Ada"}"#,
                )),
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
            code_verifier: None,
            redirect_uri: "https://app.example.com/oauth2/callback/example".to_owned(),
            device_id: None,
        })
        .await
        .unwrap();
    let user = provider.get_user_info(tokens, None).await.unwrap().unwrap();

    assert_eq!(user.id, "mapped-123");
    assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
    assert!(user.email_verified);
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

#[tokio::test]
async fn provider_rejects_id_token_sign_in_without_custom_verifier() {
    let provider = provider(example_config());
    let verified = provider
        .verify_id_token(SocialIdTokenRequest {
            token: jwt_with_claims(r#"{"sub":"generic-user-1"}"#),
            ..SocialIdTokenRequest::default()
        })
        .await
        .expect("default verification should not error");

    assert!(!verified);
}
