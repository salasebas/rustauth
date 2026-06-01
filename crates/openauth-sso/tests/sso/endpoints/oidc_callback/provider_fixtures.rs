use super::*;
use openauth_core::context::create_auth_context;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_sqlx::SqliteAdapter;
use openauth_sso::sso;
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn oidc_callback_maps_google_userinfo_fixture_claims(
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
    register_provider_fixture(
        &router,
        &cookie,
        ProviderFixtureRegistration {
            provider_id: "google-workspace",
            issuer: "https://accounts.google.com",
            domain: "example.com",
            user_info_path: "/fixtures/google/userinfo",
            mapping: Some(r#","mapping":{"extraFields":{"hostedDomain":"hd","locale":"locale"}}"#),
        },
        &oidc.base_url,
    )
    .await?;

    run_provider_fixture_callback(&router, "google-workspace", "google-userinfo-id-token-code")
        .await?;

    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("google-workspace".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("google-sub-123".to_owned()))
    }));
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("google.user@example.com".to_owned()))
            && record.get("name") == Some(&DbValue::String("Google Workspace User".to_owned()))
            && record.get("email_verified") == Some(&DbValue::Boolean(false))
    }));
    let raw = raw_attributes
        .lock()
        .map_err(|_| "raw attributes lock poisoned")?
        .clone()
        .ok_or("missing raw attributes")?;
    assert_eq!(raw["hostedDomain"], json!("example.com"));
    assert_eq!(raw["locale"], json!("en-US"));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_maps_azure_userinfo_fixture_with_custom_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let raw_attributes = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_raw = std::sync::Arc::clone(&raw_attributes);
    let (adapter, router) = router_with_options(
        SsoOptions {
            trust_email_verified: true,
            ..SsoOptions::default()
        }
        .provision_user(move |input| {
            let captured_raw = std::sync::Arc::clone(&captured_raw);
            async move {
                if let Ok(mut guard) = captured_raw.lock() {
                    *guard = input.profile.raw_attributes.clone();
                }
                Ok(())
            }
        }),
    )?;
    let cookie = seed_session(&adapter).await?;
    register_provider_fixture(
        &router,
        &cookie,
        ProviderFixtureRegistration {
            provider_id: "azure-entra",
            issuer: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
            domain: "contoso.com",
            user_info_path: "/fixtures/azure/userinfo",
            mapping: Some(
                r#","mapping":{"id":"oid","email":"preferred_username","emailVerified":"email_verified","name":"name","extraFields":{"tenantId":"tid","userPrincipalName":"upn"}}"#,
            ),
        },
        &oidc.base_url,
    )
    .await?;

    run_provider_fixture_callback(&router, "azure-entra", "azure-userinfo-id-token-code").await?;

    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("azure-entra".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("azure-oid-456".to_owned()))
    }));
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("ada@contoso.com".to_owned()))
            && record.get("email_verified") == Some(&DbValue::Boolean(true))
    }));
    let raw = raw_attributes
        .lock()
        .map_err(|_| "raw attributes lock poisoned")?
        .clone()
        .ok_or("missing raw attributes")?;
    assert_eq!(raw["tenantId"], json!("tenant-123"));
    assert_eq!(raw["userPrincipalName"], json!("ada@contoso.com"));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_maps_okta_userinfo_fixture_groups() -> Result<(), Box<dyn std::error::Error>>
{
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
    register_provider_fixture(
        &router,
        &cookie,
        ProviderFixtureRegistration {
            provider_id: "okta-default",
            issuer: "https://dev-123456.okta.com/oauth2/default",
            domain: "example.com",
            user_info_path: "/fixtures/okta/userinfo",
            mapping: Some(
                r#","mapping":{"extraFields":{"groups":"groups","zoneInfo":"zoneinfo"}}"#,
            ),
        },
        &oidc.base_url,
    )
    .await?;

    run_provider_fixture_callback(&router, "okta-default", "okta-userinfo-id-token-code").await?;

    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("okta-default".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("okta-sub-789".to_owned()))
    }));
    let raw = raw_attributes
        .lock()
        .map_err(|_| "raw attributes lock poisoned")?
        .clone()
        .ok_or("missing raw attributes")?;
    assert_eq!(raw["groups"], json!(["Engineering", "Admins"]));
    assert_eq!(raw["zoneInfo"], json!("America/Monterrey"));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_maps_azure_id_token_fixture_when_userinfo_is_absent(
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
                    "providerId":"azure-id-token",
                    "issuer":"https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                    "domain":"contoso.com",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{base}/authorize",
                        "tokenEndpoint":"{base}/token",
                        "jwksEndpoint":"{base}/keys",
                        "skipDiscovery":true,
                        "pkce":false,
                        "mapping":{{
                            "id":"oid",
                            "email":"preferred_username",
                            "emailVerified":"email_verified",
                            "name":"name",
                            "extraFields":{{"tenantId":"tid"}}
                        }}
                    }}
                }}"#,
                base = oidc.base_url
            ),
            Some(&cookie),
        )?)
        .await?;

    run_provider_fixture_callback(&router, "azure-id-token", "azure-id-token-code").await?;

    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("azure-id-token".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("azure-token-oid-456".to_owned()))
    }));
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("token.user@contoso.com".to_owned()))
    }));
    let raw = raw_attributes
        .lock()
        .map_err(|_| "raw attributes lock poisoned")?
        .clone()
        .ok_or("missing raw attributes")?;
    assert_eq!(raw["tenantId"], json!("tenant-123"));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_google_unverified_email_fixture_for_implicit_link(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions {
        trust_email_verified: true,
        ..SsoOptions::default()
    })?;
    let cookie = seed_session(&adapter).await?;
    register_provider_fixture(
        &router,
        &cookie,
        ProviderFixtureRegistration {
            provider_id: "google-unverified",
            issuer: "https://accounts.google.com",
            domain: "example.com",
            user_info_path: "/fixtures/google/unverified-userinfo",
            mapping: None,
        },
        &oidc.base_url,
    )
    .await?;
    seed_existing_sso_user(&adapter).await?;

    run_provider_fixture_callback_error(
        &router,
        "google-unverified",
        "google-unverified-userinfo-id-token-code",
        "oauth_sign_in_failed",
    )
    .await?;

    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_azure_fixture_missing_mapped_email(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_provider_fixture(
        &router,
        &cookie,
        ProviderFixtureRegistration {
            provider_id: "azure-missing-email",
            issuer: "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
            domain: "contoso.com",
            user_info_path: "/fixtures/azure/missing-preferred-username-userinfo",
            mapping: Some(r#","mapping":{"id":"oid","email":"preferred_username","name":"name"}"#),
        },
        &oidc.base_url,
    )
    .await?;

    run_provider_fixture_callback_error(
        &router,
        "azure-missing-email",
        "azure-userinfo-id-token-code",
        "unable_to_get_user_info",
    )
    .await?;

    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_okta_fixture_missing_subject(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_provider_fixture(
        &router,
        &cookie,
        ProviderFixtureRegistration {
            provider_id: "okta-missing-sub",
            issuer: "https://dev-123456.okta.com/oauth2/default",
            domain: "example.com",
            user_info_path: "/fixtures/okta/missing-sub-userinfo",
            mapping: None,
        },
        &oidc.base_url,
    )
    .await?;

    run_provider_fixture_callback_error(
        &router,
        "okta-missing-sub",
        "okta-userinfo-id-token-code",
        "unable_to_get_user_info",
    )
    .await?;

    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_azure_id_token_fixture_with_wrong_tenant_issuer(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_azure_id_token_provider(&router, &cookie, &oidc.base_url, "azure-wrong-issuer")
        .await?;

    run_provider_fixture_callback_error(
        &router,
        "azure-wrong-issuer",
        "azure-wrong-issuer-id-token-code",
        "invalid_id_token",
    )
    .await?;

    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_multi_audience_id_token_without_azp(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_id_token_only_provider(&router, &cookie, &oidc.base_url, "multi-aud-missing-azp")
        .await?;

    run_provider_fixture_callback_error(
        &router,
        "multi-aud-missing-azp",
        "multi-audience-missing-azp-code",
        "invalid_id_token",
    )
    .await?;

    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_rejects_multi_audience_id_token_with_wrong_azp(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_id_token_only_provider(&router, &cookie, &oidc.base_url, "multi-aud-wrong-azp")
        .await?;

    run_provider_fixture_callback_error(
        &router,
        "multi-aud-wrong-azp",
        "multi-audience-wrong-azp-code",
        "invalid_id_token",
    )
    .await?;

    assert!(adapter.records("account").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn oidc_callback_accepts_multi_audience_id_token_with_matching_azp(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_id_token_only_provider(&router, &cookie, &oidc.base_url, "multi-aud-valid-azp")
        .await?;

    run_provider_fixture_callback(
        &router,
        "multi-aud-valid-azp",
        "multi-audience-valid-azp-code",
    )
    .await?;

    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("multi-aud-valid-azp".to_owned()))
            && record.get("account_id") == Some(&DbValue::String("subject_123".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn oidc_callback_provider_fixture_flow_persists_with_sqlite_adapter(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (pool, adapter, router) = sqlite_router_with_options(SsoOptions::default()).await?;
    let cookie = seed_session_for_adapter(adapter.as_ref()).await?;
    register_provider_fixture(
        &router,
        &cookie,
        ProviderFixtureRegistration {
            provider_id: "google-sqlite",
            issuer: "https://accounts.google.com",
            domain: "example.com",
            user_info_path: "/fixtures/google/userinfo",
            mapping: None,
        },
        &oidc.base_url,
    )
    .await?;

    run_provider_fixture_callback(&router, "google-sqlite", "google-userinfo-id-token-code")
        .await?;

    let user_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ? AND email_verified = ?")
            .bind("google.user@example.com")
            .bind(false)
            .fetch_one(&pool)
            .await?;
    let account_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM accounts WHERE provider_id = ? AND account_id = ?",
    )
    .bind("google-sqlite")
    .bind("google-sub-123")
    .fetch_one(&pool)
    .await?;
    assert_eq!(user_count, 1);
    assert_eq!(account_count, 1);

    Ok(())
}

struct ProviderFixtureRegistration<'a> {
    provider_id: &'a str,
    issuer: &'a str,
    domain: &'a str,
    user_info_path: &'a str,
    mapping: Option<&'a str>,
}

async fn register_provider_fixture(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
    fixture: ProviderFixtureRegistration<'_>,
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mapping = fixture.mapping.unwrap_or_default();
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                    "providerId":"{provider_id}",
                    "issuer":"{issuer}",
                    "domain":"{domain}",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{base_url}/authorize",
                        "tokenEndpoint":"{base_url}/token",
                        "userInfoEndpoint":"{base_url}{user_info_path}",
                        "jwksEndpoint":"{base_url}/keys",
                        "skipDiscovery":true,
                        "pkce":false
                        {mapping}
                    }}
                }}"#,
                provider_id = fixture.provider_id,
                issuer = fixture.issuer,
                domain = fixture.domain,
                user_info_path = fixture.user_info_path,
            ),
            Some(cookie),
        )?)
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(response.body())
    );
    Ok(())
}

async fn run_provider_fixture_callback(
    router: &openauth_core::api::AuthRouter,
    provider_id: &str,
    code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            &format!(
                r#"{{"providerId":"{provider_id}","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}}"#
            ),
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/{provider_id}?state={state}&code={code}.{nonce}"),
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

async fn run_provider_fixture_callback_error(
    router: &openauth_core::api::AuthRouter,
    provider_id: &str,
    code: &str,
    expected_error: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            &format!(
                r#"{{"providerId":"{provider_id}","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}}"#
            ),
            None,
        )?)
        .await?;
    let (state, nonce) = authorization_state_and_nonce(sign_in)?;
    let callback = router
        .handle_async(json_request(
            Method::GET,
            &format!("/sso/callback/{provider_id}?state={state}&code={code}.{nonce}"),
            "",
            None,
        )?)
        .await?;
    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(
        callback.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_str(&format!(
            "/login-error?error={expected_error}"
        ))?)
    );
    Ok(())
}

async fn register_id_token_only_provider(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
    base_url: &str,
    provider_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                    "providerId":"{provider_id}",
                    "issuer":"https://idp.example.com",
                    "domain":"example.com",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{base_url}/authorize",
                        "tokenEndpoint":"{base_url}/token",
                        "jwksEndpoint":"{base_url}/keys",
                        "skipDiscovery":true,
                        "pkce":false
                    }}
                }}"#
            ),
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

async fn register_azure_id_token_provider(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
    base_url: &str,
    provider_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                    "providerId":"{provider_id}",
                    "issuer":"https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                    "domain":"contoso.com",
                    "oidcConfig":{{
                        "clientId":"client_123456",
                        "clientSecret":"super-secret",
                        "authorizationEndpoint":"{base_url}/authorize",
                        "tokenEndpoint":"{base_url}/token",
                        "jwksEndpoint":"{base_url}/keys",
                        "skipDiscovery":true,
                        "pkce":false,
                        "mapping":{{
                            "id":"oid",
                            "email":"preferred_username",
                            "emailVerified":"email_verified",
                            "name":"name",
                            "extraFields":{{"tenantId":"tid"}}
                        }}
                    }}
                }}"#
            ),
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

async fn sqlite_router_with_options(
    options: SsoOptions,
) -> Result<
    (
        sqlx::SqlitePool,
        std::sync::Arc<SqliteAdapter>,
        openauth_core::api::AuthRouter,
    ),
    Box<dyn std::error::Error>,
> {
    let schema_context = create_auth_context(OpenAuthOptions {
        base_url: Some("https://app.example.com".to_owned()),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![sso(options.clone())],
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let adapter = std::sync::Arc::new(SqliteAdapter::with_schema(
        pool.clone(),
        schema_context.db_schema.clone(),
    ));
    adapter
        .create_schema(&schema_context.db_schema, None)
        .await?;
    let router = router_with_adapter_and_options(adapter.clone(), options)?;
    Ok((pool, adapter, router))
}
