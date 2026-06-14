use super::*;

#[tokio::test]
async fn register_discovers_oidc_endpoints_when_skip_discovery_is_false(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let cookie = seed_session(&adapter).await?;

    let response = router
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

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(
        body["oidcConfig"]["authorizationEndpoint"],
        format!("{}/authorize", oidc.base_url)
    );
    assert_eq!(
        body["oidcConfig"]["tokenEndpoint"],
        format!("{}/token", oidc.base_url)
    );
    assert_eq!(
        body["oidcConfig"]["jwksEndpoint"],
        format!("{}/keys", oidc.base_url)
    );
    assert_eq!(
        body["oidcConfig"]["revocationEndpoint"],
        format!("{}/revoke", oidc.base_url)
    );
    assert_eq!(
        body["oidcConfig"]["endSessionEndpoint"],
        format!("{}/endsession", oidc.base_url)
    );
    assert_eq!(
        body["oidcConfig"]["introspectionEndpoint"],
        format!("{}/introspection", oidc.base_url)
    );
    assert!(
        body["oidcConfig"]["scopes"].is_null(),
        "discovered scopes_supported must not become configured request scopes"
    );

    let records = adapter.records("sso_provider").await;
    let Some(DbValue::String(config)) = records[0].get("oidc_config") else {
        return Err("missing stored OIDC config".into());
    };
    assert!(config.contains(&format!(
        r#""authorizationEndpoint":"{}/authorize""#,
        oidc.base_url
    )));
    assert!(config.contains(&format!(
        r#""revocationEndpoint":"{}/revoke""#,
        oidc.base_url
    )));
    assert!(config.contains(&format!(
        r#""endSessionEndpoint":"{}/endsession""#,
        oidc.base_url
    )));
    assert!(config.contains(&format!(
        r#""introspectionEndpoint":"{}/introspection""#,
        oidc.base_url
    )));
    assert!(config.contains(r#""tokenEndpointAuthentication":"client_secret_basic""#));
    assert!(
        !config.contains(r#""scopes":"#),
        "stored OIDC config should preserve only explicitly configured scopes"
    );

    Ok(())
}

#[tokio::test]
async fn register_allows_skip_discovery_partial_config_for_runtime_discovery(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let cookie = seed_session(&adapter).await?;

    let response = router
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

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert!(body["oidcConfig"]["authorizationEndpoint"].is_null());

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign_in.status(), StatusCode::OK);
    let sign_in_body = json_body(sign_in)?;
    assert!(sign_in_body["url"]
        .as_str()
        .is_some_and(|url| url.starts_with(&format!("{}/authorize?", oidc.base_url))));

    Ok(())
}

#[tokio::test]
async fn register_accepts_strict_manual_oidc_matrix_for_common_idps(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.oidc.strict_manual_endpoint_origins = true;
    let (adapter, router) = router_with_options_and_trusted_origins(
        options,
        vec![
            "https://dev-123456.okta.com".to_owned(),
            "https://login.microsoftonline.com".to_owned(),
            "https://graph.microsoft.com".to_owned(),
            "https://accounts.google.com".to_owned(),
            "https://oauth2.googleapis.com".to_owned(),
            "https://openidconnect.googleapis.com".to_owned(),
            "https://www.googleapis.com".to_owned(),
        ],
    )?;
    let cookie = seed_session(&adapter).await?;

    struct ManualOidcCase {
        provider_id: &'static str,
        issuer: &'static str,
        domain: &'static str,
        authorization_endpoint: &'static str,
        token_endpoint: &'static str,
        user_info_endpoint: &'static str,
        jwks_endpoint: &'static str,
    }

    let cases = [
        ManualOidcCase {
            provider_id: "okta-prod",
            issuer: "https://dev-123456.okta.com/oauth2/default",
            domain: "okta.example.com",
            authorization_endpoint: "https://dev-123456.okta.com/oauth2/default/v1/authorize",
            token_endpoint: "https://dev-123456.okta.com/oauth2/default/v1/token",
            user_info_endpoint: "https://dev-123456.okta.com/oauth2/default/v1/userinfo",
            jwks_endpoint: "https://dev-123456.okta.com/oauth2/default/v1/keys",
        },
        ManualOidcCase {
            provider_id: "azure-prod",
            issuer: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
            domain: "contoso.com",
            authorization_endpoint: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize",
            token_endpoint: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token",
            user_info_endpoint: "https://graph.microsoft.com/oidc/userinfo",
            jwks_endpoint: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys",
        },
        ManualOidcCase {
            provider_id: "google-prod",
            issuer: "https://accounts.google.com",
            domain: "google.example.com",
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
            token_endpoint: "https://oauth2.googleapis.com/token",
            user_info_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
            jwks_endpoint: "https://www.googleapis.com/oauth2/v3/certs",
        },
    ];

    for case in cases {
        let response = router
            .handle_async(json_request(
                Method::POST,
                "/sso/register",
                &format!(
                    r#"{{
                    "providerId":"{}",
                    "issuer":"{}",
                    "domain":"{}",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{}",
                        "tokenEndpoint":"{}",
                        "userInfoEndpoint":"{}",
                        "jwksEndpoint":"{}",
                        "skipDiscovery":true,
                        "pkce":true
                    }}
                }}"#,
                    case.provider_id,
                    case.issuer,
                    case.domain,
                    case.authorization_endpoint,
                    case.token_endpoint,
                    case.user_info_endpoint,
                    case.jwks_endpoint
                ),
                Some(&cookie),
            )?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response)?;
        assert_eq!(body["providerId"], case.provider_id);
        assert_eq!(
            body["oidcConfig"]["authorizationEndpoint"],
            case.authorization_endpoint
        );
        assert_eq!(body["oidcConfig"]["tokenEndpoint"], case.token_endpoint);
        assert_eq!(body["oidcConfig"]["jwksEndpoint"], case.jwks_endpoint);
    }

    Ok(())
}

#[tokio::test]
async fn register_rejects_untrusted_manual_oidc_endpoint_when_strict_policy_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.oidc.strict_manual_endpoint_origins = true;
    let (adapter, router) = router_with_options_and_trusted_origins(
        options,
        vec!["https://dev-123456.okta.com".to_owned()],
    )?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta-prod",
                "issuer":"https://dev-123456.okta.com/oauth2/default",
                "domain":"okta.example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://dev-123456.okta.com/oauth2/default/v1/authorize",
                    "tokenEndpoint":"https://evil.example.com/token",
                    "userInfoEndpoint":"https://dev-123456.okta.com/oauth2/default/v1/userinfo",
                    "jwksEndpoint":"https://dev-123456.okta.com/oauth2/default/v1/keys",
                    "skipDiscovery":true,
                    "pkce":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "discovery_untrusted_origin");

    Ok(())
}

#[tokio::test]
async fn register_returns_stable_oidc_discovery_error_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    let cookie = seed_session(&adapter).await?;

    let response = router
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
                    "discoveryEndpoint":"{issuer}/missing-openid-configuration",
                    "skipDiscovery":false,
                    "pkce":true
                }}
            }}"#,
                issuer = oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "discovery_not_found");

    Ok(())
}

#[tokio::test]
async fn register_rejects_untrusted_oidc_discovery_origin() -> Result<(), Box<dyn std::error::Error>>
{
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
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
                    "discoveryEndpoint":"{issuer}/.well-known/openid-configuration",
                    "skipDiscovery":false,
                    "pkce":true
                }}
            }}"#,
                issuer = oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "discovery_untrusted_origin");

    Ok(())
}
