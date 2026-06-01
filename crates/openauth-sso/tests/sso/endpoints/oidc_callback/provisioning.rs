use super::*;

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
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=valid-id-token-code.{nonce}"),
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
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=valid-id-token-code.{nonce}"),
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
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=valid-id-token-code.{nonce}"),
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
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/okta?state={state}&code=valid-id-token-code.{nonce}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    Ok(())
}
