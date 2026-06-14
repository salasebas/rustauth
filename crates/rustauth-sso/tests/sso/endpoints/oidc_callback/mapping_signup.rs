use super::*;

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
        let (state, nonce) = authorization_state_and_nonce(sign_in)?;
        let callback = router
            .handle_async(json_request(
                Method::GET,
                &format!("/sso/callback/okta?state={state}&code=valid-id-token-code.{nonce}"),
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
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );

    Ok(())
}
