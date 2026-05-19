use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn oidc_callback_uses_default_sso_provider_from_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(default_oidc_sso_options(&oidc.base_url))?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback?state={state}&code=auth-code"),
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
        record.get("provider_id") == Some(&DbValue::String("default-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_path_uses_default_sso_provider_by_provider_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(default_oidc_sso_options(&oidc.base_url))?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/default-okta?state={state}&code=auth-code"),
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
        record.get("provider_id") == Some(&DbValue::String("default-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_discovers_default_sso_oidc_endpoints_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        default_oidc_sso_options_requiring_discovery(&oidc.base_url),
        vec![oidc.base_url.clone()],
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/default-okta?state={state}&code=auth-code"),
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
        record.get("provider_id") == Some(&DbValue::String("default-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_redirects_stable_discovery_error_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let mut options = default_oidc_sso_options_requiring_discovery(&oidc.base_url);
    if let Some(config) = options
        .default_sso
        .first_mut()
        .and_then(|provider| provider.oidc_config.as_mut())
    {
        config.authorization_endpoint = Some(format!("{}/authorize", oidc.base_url));
        config.token_endpoint = None;
        config.jwks_endpoint = None;
        config.user_info_endpoint = None;
        config.discovery_endpoint = format!("{}/missing-openid-configuration", oidc.base_url);
    }
    let (_adapter, router) =
        router_with_options_and_trusted_origins(options, vec![oidc.base_url.clone()])?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/default-okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=discovery_not_found"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn oidc_callback_discovers_stored_oidc_provider_endpoints_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    seed_runtime_discovery_oidc_provider(&adapter, &oidc.base_url).await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"runtime-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/runtime-okta?state={state}&code=auth-code"),
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
        record.get("provider_id") == Some(&DbValue::String("runtime-okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_redirects_provider_error_to_state_error_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

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
            &format!("/sso/callback/okta?state={state}&error=access_denied"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=access_denied"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn oidc_callback_redirects_no_code_to_state_error_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

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
            &format!("/sso/callback/okta?state={state}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(http::header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=no_code"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn oidc_callback_exchanges_code_creates_session_and_redirects(
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
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(callback.headers().get(header::SET_COOKIE).is_some());

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
async fn oidc_callback_uses_client_secret_basic_token_auth(
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
                        "jwksEndpoint":"{}/keys",
                        "tokenEndpointAuthentication":"client_secret_basic",
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
    let token_request = oidc.token_requests().pop().ok_or("missing token request")?;
    let expected = base64::engine::general_purpose::STANDARD.encode("client_123456:super-secret");
    assert!(token_request.contains(&format!("authorization: Basic {expected}")));
    assert!(!token_request.contains("client_secret=super-secret"));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_uses_client_secret_post_token_auth() -> Result<(), Box<dyn std::error::Error>>
{
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
                        "jwksEndpoint":"{}/keys",
                        "tokenEndpointAuthentication":"client_secret_post",
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
    let token_request = oidc.token_requests().pop().ok_or("missing token request")?;
    assert!(!token_request.contains("authorization: Basic "));
    assert!(token_request.contains("client_id=client_123456"));
    assert!(token_request.contains("client_secret=super-secret"));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_uses_discovered_client_secret_basic_token_auth(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (_adapter, router) = router_with_options_and_trusted_origins(
        default_oidc_sso_options_requiring_discovery(&oidc.base_url),
        vec![oidc.base_url.clone()],
    )?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let state = authorization_state(sign_in)?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/default-okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    let token_request = oidc.token_requests().pop().ok_or("missing token request")?;
    let expected = base64::engine::general_purpose::STANDARD.encode("client_123456:super-secret");
    assert!(token_request.contains(&format!("authorization: Basic {expected}")));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_assigns_user_to_provider_organization(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    let cookie = seed_session(&adapter).await?;
    seed_org_member(&adapter, "member_register", "org_1", "user_1", "admin").await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                    "providerId":"okta",
                    "issuer":"https://idp.example.com",
                    "domain":"example.com",
                    "organizationId":"org_1",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{}/authorize",
                        "tokenEndpoint":"{}/token",
                        "userInfoEndpoint":"{}/userinfo",
                        "jwksEndpoint":"{}/keys",
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
            &format!("/sso/callback/okta?state={state}&code=auth-code"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    let members = adapter.records("member").await;
    assert!(members.iter().any(|record| {
        record.get("organization_id") == Some(&DbValue::String("org_1".to_owned()))
            && record.get("role") == Some(&DbValue::String("member".to_owned()))
            && record.get("user_id") != Some(&DbValue::String("user_1".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_calls_provision_user_for_new_user() -> Result<(), Box<dyn std::error::Error>>
{
    let oidc = MockOidcServer::start().await?;
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let callback_calls = std::sync::Arc::clone(&calls);
    let (adapter, router) =
        router_with_options(SsoOptions::default().provision_user(move |input| {
            let callback_calls = std::sync::Arc::clone(&callback_calls);
            async move {
                assert_eq!(input.profile.provider_type, "oidc");
                assert_eq!(input.profile.provider_id, "okta");
                assert_eq!(input.profile.email, "sso-user@example.com");
                callback_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }))?;
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
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    Ok(())
}

#[tokio::test]
async fn oidc_callback_skips_provision_user_for_existing_user_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let callback_calls = std::sync::Arc::clone(&calls);
    let (adapter, router) = router_with_options(
        SsoOptions {
            trust_email_verified: true,
            ..SsoOptions::default()
        }
        .provision_user(move |_| {
            let callback_calls = std::sync::Arc::clone(&callback_calls);
            async move {
                callback_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }),
    )?;
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
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    Ok(())
}

#[tokio::test]
async fn oidc_callback_calls_provision_user_for_existing_user_when_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let callback_calls = std::sync::Arc::clone(&calls);
    let (adapter, router) = router_with_options(
        SsoOptions {
            trust_email_verified: true,
            ..SsoOptions::default()
        }
        .provision_user(move |input| {
            let callback_calls = std::sync::Arc::clone(&callback_calls);
            async move {
                assert!(!input.is_register);
                callback_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .provision_user_on_every_login(true),
    )?;
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
    assert_eq!(calls.load(Ordering::SeqCst), 1);

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
async fn oidc_callback_accepts_valid_id_token_from_provider_jwks(
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

#[tokio::test]
async fn oidc_callback_applies_custom_userinfo_mapping() -> Result<(), Box<dyn std::error::Error>> {
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
                    "userInfoEndpoint":"{}/mapped-userinfo",
                    "jwksEndpoint":"{}/keys",
                    "skipDiscovery":true,
                    "pkce":false,
                    "mapping":{{
                        "id":"external_id",
                        "email":"mail",
                        "emailVerified":"verified",
                        "name":"display",
                        "image":"avatar"
                    }}
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
    let accounts = adapter.records("account").await;
    assert!(accounts.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("okta".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("mapped_subject".to_owned()))
    }));
    let users = adapter.records("user").await;
    assert!(users.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("mapped-user@example.com".to_owned()))
            && record.get("name") == Some(&DbValue::String("Mapped User".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_exposes_mapped_extra_fields_to_provision_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let raw_attributes = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_raw = std::sync::Arc::clone(&raw_attributes);
    let (adapter, router) =
        router_with_options(SsoOptions::default().provision_user(move |input| {
            let captured_raw = std::sync::Arc::clone(&captured_raw);
            async move {
                if let Ok(mut guard) = captured_raw.lock() {
                    *guard = input.profile.raw_attributes.clone();
                }
                Ok(())
            }
        }))?;
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
                    "userInfoEndpoint":"{}/mapped-userinfo",
                    "jwksEndpoint":"{}/keys",
                    "skipDiscovery":true,
                    "pkce":false,
                    "mapping":{{
                        "id":"external_id",
                        "email":"mail",
                        "emailVerified":"verified",
                        "name":"display",
                        "image":"avatar",
                        "extraFields":{{
                            "department":"department",
                            "employeeNumber":"employee_number"
                        }}
                    }}
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
    let raw = raw_attributes
        .lock()
        .map_err(|_| "raw attributes lock poisoned")?
        .clone()
        .ok_or("missing raw attributes")?;
    assert_eq!(raw["department"], json!("Engineering"));
    assert_eq!(raw["employeeNumber"], json!("E-123"));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_normalizes_mixed_case_email_to_single_user(
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
                    "userInfoEndpoint":"{}/mixed-case-userinfo",
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

    for assertion in ["first", "second"] {
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
        assert_eq!(callback.status(), StatusCode::FOUND, "{assertion}");
    }

    let users = adapter.records("user").await;
    let normalized_users = users
        .iter()
        .filter(|record| {
            record.get("email") == Some(&DbValue::String("sso-user@example.com".to_owned()))
        })
        .count();
    assert_eq!(normalized_users, 1);
    assert!(users.iter().all(|record| {
        record.get("email") != Some(&DbValue::String("SSO-User@Example.Com".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_new_user_when_implicit_sign_up_is_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions {
        disable_implicit_sign_up: true,
        ..SsoOptions::default()
    })?;
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
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=oauth_sign_in_failed"
        ))
    );

    Ok(())
}

#[tokio::test]
async fn oidc_callback_allows_explicit_request_sign_up_when_implicit_sign_up_is_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions {
        disable_implicit_sign_up: true,
        ..SsoOptions::default()
    })?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider_with_endpoints(&router, &cookie, &oidc.base_url).await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error","requestSignUp":true}"#,
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

    Ok(())
}
