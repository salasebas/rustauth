use super::*;

async fn register_oidc_provider_with_id_token_profile_endpoints(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                    "providerId":"okta",
                    "issuer":"https://idp.example.com",
                    "domain":"example.com",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{base_url}/authorize",
                        "tokenEndpoint":"{base_url}/token",
                        "jwksEndpoint":"{base_url}/keys",
                        "skipDiscovery":true,
                        "pkce":true
                    }}
                }}"#
            ),
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

#[tokio::test]
async fn oidc_callback_uses_userinfo_when_id_token_is_present_without_jwks(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                    "providerId":"okta",
                    "issuer":"https://idp.example.com",
                    "domain":"example.com",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{}/authorize",
                        "tokenEndpoint":"{}/token",
                        "userInfoEndpoint":"{}/userinfo",
                        "discoveryEndpoint":"{}/.well-known/openid-configuration",
                        "skipDiscovery":true,
                        "pkce":true
                    }}
                }}"#,
                oidc.base_url, oidc.base_url, oidc.base_url, oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=valid-id-token-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    let accounts = adapter.records("account").await;
    assert!(accounts.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_uses_id_token_claims_when_userinfo_endpoint_is_absent(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                    "providerId":"okta",
                    "issuer":"https://idp.example.com",
                    "domain":"example.com",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{}/authorize",
                        "tokenEndpoint":"{}/token",
                        "jwksEndpoint":"{}/keys",
                        "skipDiscovery":true,
                        "pkce":true
                    }}
                }}"#,
                oidc.base_url, oidc.base_url, oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=valid-id-token-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    let users = adapter.records("user").await;
    assert!(users.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("sso-user@example.com".to_owned()))
    }));
    let accounts = adapter.records("account").await;
    assert!(accounts.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_userinfo_without_stable_subject(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                    "providerId":"okta",
                    "issuer":"https://idp.example.com",
                    "domain":"example.com",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{}/authorize",
                        "tokenEndpoint":"{}/token",
                        "userInfoEndpoint":"{}/missing-sub-userinfo",
                        "jwksEndpoint":"{}/keys",
                        "skipDiscovery":true,
                        "pkce":false
                    }}
                }}"#,
                oidc.base_url, oidc.base_url, oidc.base_url, oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=unable_to_get_user_info"
        ))
    );
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_redirects_new_user_to_new_user_callback_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_endpoints(&router, &cookie, &oidc.base_url).await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","newUserCallbackURL":"/welcome","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/welcome"))
    );

    Ok(())
}

#[tokio::test]
async fn oidc_callback_does_not_implicitly_link_on_idp_email_verified_only(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_endpoints(&router, &cookie, &oidc.base_url).await?;
    seed_existing_sso_user(&adapter).await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=oauth_sign_in_failed"
        ))
    );
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_does_not_mark_new_user_email_verified_from_idp_claim_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_endpoints(&router, &cookie, &oidc.base_url).await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    let users = adapter.records("user").await;
    let created = users
        .iter()
        .find(|record| {
            record.get("email") == Some(&DbValue::String("sso-user@example.com".to_owned()))
        })
        .ok_or("missing created SSO user")?;
    assert_eq!(
        created.get("email_verified"),
        Some(&DbValue::Boolean(false))
    );

    Ok(())
}

#[tokio::test]
async fn oidc_callback_implicitly_links_when_trust_email_verified_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions {
        trust_email_verified: true,
        ..SsoOptions::default()
    })?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_endpoints(&router, &cookie, &oidc.base_url).await?;
    seed_existing_sso_user(&adapter).await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
            && record.get("user_id") == Some(&DbValue::String("existing_sso_user".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_invalid_id_token_before_creating_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_id_token_profile_endpoints(&router, &cookie, &oidc.base_url)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=id-token-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=invalid_id_token"
        ))
    );
    assert_eq!(adapter.records("user").await.len(), 1);
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_id_token_without_expiration(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_id_token_profile_endpoints(&router, &cookie, &oidc.base_url)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=missing-exp-id-token-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=invalid_id_token"
        ))
    );
    assert_eq!(adapter.records("user").await.len(), 1);
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_id_token_without_subject() -> Result<(), Box<dyn std::error::Error>>
{
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_id_token_profile_endpoints(&router, &cookie, &oidc.base_url)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=missing-sub-id-token-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=invalid_id_token"
        ))
    );
    assert_eq!(adapter.records("user").await.len(), 1);
    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_accepts_valid_id_token_from_provider_jwks(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_id_token_profile_endpoints(&router, &cookie, &oidc.base_url)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=valid-id-token-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(callback.headers().get(header::SET_COOKIE).is_some());
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}
