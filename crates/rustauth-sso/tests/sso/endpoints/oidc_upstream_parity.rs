//! Parity tests aligned with upstream `packages/sso/src/oidc.test.ts` (Better Auth 1.6.9).

use super::*;

#[tokio::test]
#[cfg(feature = "oidc")]
async fn register_rejects_invalid_issuer() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"bad-issuer",
                "issuer":"not-a-valid-url",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_ISSUER");
    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn register_rejects_duplicate_provider_id() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta",
                "issuer":"https://other-idp.example.com",
                "domain":"other.example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "skipDiscovery":true,
                    "authorizationEndpoint":"https://other-idp.example.com/authorize",
                    "tokenEndpoint":"https://other-idp.example.com/token",
                    "jwksEndpoint":"https://other-idp.example.com/keys"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_body(response)?["code"], "PROVIDER_EXISTS");
    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn sign_in_sso_resolves_stored_provider_by_email_domain(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let cookie = seed_session(&adapter).await?;

    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                "providerId":"okta",
                "issuer":"{}",
                "domain":"example.com",
                "oidcConfig":{{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "pkce":true
                }}
            }}"#,
                oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"email":"user@example.com","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let url = url::Url::parse(
        json_body(sign_in)?["url"]
            .as_str()
            .ok_or("missing authorization URL")?,
    )?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some(format!("{}/authorize", oidc.base_url).as_str())
    );
    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn sign_in_sso_hydrates_missing_authorization_endpoint_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let cookie = seed_session(&adapter).await?;

    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                "providerId":"okta",
                "issuer":"{issuer}",
                "domain":"example.com",
                "oidcConfig":{{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "tokenEndpoint":"{issuer}/token",
                    "jwksEndpoint":"{issuer}/keys",
                    "discoveryEndpoint":"{issuer}/.well-known/openid-configuration",
                    "skipDiscovery":true,
                    "pkce":true
                }}
            }}"#,
                issuer = oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let url = url::Url::parse(
        json_body(sign_in)?["url"]
            .as_str()
            .ok_or("missing authorization URL")?,
    )?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some(format!("{}/authorize", oidc.base_url).as_str())
    );
    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn sign_in_sso_uses_shared_redirect_uri_in_authorization_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default().redirect_uri("/sso/callback"),
        vec![oidc.base_url.clone()],
    )?;
    let cookie = seed_session(&adapter).await?;

    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                "providerId":"shared-okta",
                "issuer":"{issuer}",
                "domain":"example.com",
                "oidcConfig":{{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "pkce":true
                }}
            }}"#,
                issuer = oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"shared-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    let url = url::Url::parse(
        json_body(sign_in)?["url"]
            .as_str()
            .ok_or("missing authorization URL")?,
    )?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://app.example.com/sso/callback")
    );
    Ok(())
}

#[tokio::test]
#[cfg(feature = "oidc")]
async fn oidc_callback_completes_flow_via_shared_callback_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default().redirect_uri("/sso/callback"),
        vec![oidc.base_url.clone()],
    )?;
    let cookie = seed_session(&adapter).await?;

    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                "providerId":"shared-okta",
                "issuer":"{issuer}",
                "domain":"example.com",
                "oidcConfig":{{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "pkce":true
                }}
            }}"#,
                issuer = oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"shared-okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;

    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback?state={state}&code=self-issued-id-token-code.{nonce}"),
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
