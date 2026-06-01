use super::*;

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
    let token_request = oidc.token_requests().pop().ok_or("missing token request")?;
    assert!(!token_request.contains("authorization: Basic "));
    assert!(token_request.contains("client_id=client_123456"));
    assert!(token_request.contains("client_secret=super-secret"));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_defaults_missing_token_auth_to_client_secret_basic(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let mut options = default_oidc_sso_options(&oidc.base_url);
    if let Some(config) = options
        .default_sso
        .get_mut(0)
        .and_then(|provider| provider.oidc_config.as_mut())
    {
        config.token_endpoint_authentication = None;
    }
    let (_adapter, router) = router_with_options(options)?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/default-okta?state={state}&code=valid-id-token-code.{nonce}"),
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
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!(
                "/sso/callback/default-okta?state={state}&code=self-issued-id-token-code.{nonce}"
            ),
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
