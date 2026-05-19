use super::*;

#[tokio::test]
async fn sign_in_sso_with_oidc_provider_returns_authorization_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true,
                    "pkce":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","loginHint":"user@example.com"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["redirect"], true);
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/oauth2/v1/authorize")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("client_id").map(|value| value.as_ref()),
        Some("client_123456")
    );
    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://app.example.com/sso/callback/okta")
    );
    assert_eq!(
        query.get("scope").map(|value| value.as_ref()),
        Some("openid email profile offline_access")
    );
    assert_eq!(
        query.get("login_hint").map(|value| value.as_ref()),
        Some("user@example.com")
    );
    assert!(query.contains_key("state"));
    assert_eq!(
        query
            .get("code_challenge_method")
            .map(|value| value.as_ref()),
        Some("S256")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_accepts_form_urlencoded_body() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/sign-in/sso",
            "providerId=okta&callbackURL=%2Fdashboard&loginHint=user%40example.com",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/oauth2/v1/authorize")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_request_scopes_override_provider_scopes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true,
                    "pkce":false,
                    "scopes":["openid","email","groups"]
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","scopes":["openid","profile"]}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("scope").map(|value| value.as_ref()),
        Some("openid profile")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_uses_provider_for_organization_slug() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    seed_organization(&adapter, "org_1", "acme").await?;
    let oidc_config = OidcConfig {
        issuer: "https://idp.example.com".to_owned(),
        pkce: true,
        client_id: "client_123456".to_owned(),
        client_secret: "super-secret".into(),
        discovery_endpoint: "https://idp.example.com/.well-known/openid-configuration".to_owned(),
        authorization_endpoint: Some("https://idp.example.com/oauth2/v1/authorize".to_owned()),
        token_endpoint: Some("https://idp.example.com/oauth2/v1/token".to_owned()),
        user_info_endpoint: Some("https://idp.example.com/oauth2/v1/userinfo".to_owned()),
        jwks_endpoint: Some("https://idp.example.com/oauth2/v1/keys".to_owned()),
        token_endpoint_authentication: Some(TokenEndpointAuthentication::ClientSecretBasic),
        scopes: None,
        mapping: None,
        override_user_info: false,
    };
    SsoProviderStore::new(adapter.as_ref())
        .create(CreateSsoProviderInput {
            provider_id: "acme-okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "acme.example.com".to_owned(),
            user_id: "other_user".to_owned(),
            organization_id: Some("org_1".to_owned()),
            oidc_config: Some(serde_json::to_string(&oidc_config)?),
            saml_config: None,
            domain_verified: None,
        })
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"organizationSlug":"acme","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/oauth2/v1/authorize")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("client_id").map(|value| value.as_ref()),
        Some("client_123456")
    );
    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://app.example.com/sso/callback/acme-okta")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_uses_default_sso_oidc_by_provider_id() -> Result<(), Box<dyn std::error::Error>>
{
    let oidc = MockOidcServer::start().await?;
    let (_adapter, router) = router_with_options(default_oidc_sso_options(&oidc.base_url))?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some(format!("{}/authorize", oidc.base_url).as_str())
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_discovers_default_sso_oidc_endpoints_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (_adapter, router) = router_with_options_and_trusted_origins(
        default_oidc_sso_options_requiring_discovery(&oidc.base_url),
        vec![oidc.base_url.clone()],
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some(format!("{}/authorize", oidc.base_url).as_str())
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_returns_stable_discovery_error_code() -> Result<(), Box<dyn std::error::Error>>
{
    let oidc = MockOidcServer::start().await?;
    let mut options = default_oidc_sso_options_requiring_discovery(&oidc.base_url);
    if let Some(config) = options
        .default_sso
        .first_mut()
        .and_then(|provider| provider.oidc_config.as_mut())
    {
        config.discovery_endpoint = format!("{}/missing-openid-configuration", oidc.base_url);
    }
    let (_adapter, router) =
        router_with_options_and_trusted_origins(options, vec![oidc.base_url.clone()])?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "discovery_not_found");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_discovers_stored_oidc_provider_endpoints_at_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (adapter, router) = router_with_options_and_trusted_origins(
        SsoOptions::default(),
        vec![oidc.base_url.clone()],
    )?;
    seed_runtime_discovery_oidc_provider(&adapter, &oidc.base_url).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"runtime-okta","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some(format!("{}/authorize", oidc.base_url).as_str())
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_uses_default_sso_oidc_by_email_domain(
) -> Result<(), Box<dyn std::error::Error>> {
    let oidc = MockOidcServer::start().await?;
    let (_adapter, router) = router_with_options(default_oidc_sso_options(&oidc.base_url))?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"email":"ada@example.com","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query.get("client_id").map(|value| value.as_ref()),
        Some("client_123456")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_rejects_untrusted_absolute_callback_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"https://evil.example.com/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["code"], "INVALID_CALLBACK_URL");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_rejects_callback_url_loop_to_sso_callback(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/sso/callback/okta"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["code"], "INVALID_CALLBACK_URL");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_rejects_protocol_relative_error_callback_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_oidc_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"okta","callbackURL":"/dashboard","errorCallbackURL":"//evil.example.com/login"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)?["code"], "INVALID_ERROR_CALLBACK_URL");

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_saml_provider_returns_authn_request_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["redirect"], true);
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/saml/sso")
    );
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    let relay_state = query.get("RelayState").ok_or("missing RelayState")?;
    let saml_request = query.get("SAMLRequest").ok_or("missing SAMLRequest")?;
    let xml = inflate_redirect_binding(saml_request)?;
    assert!(xml.contains("<samlp:AuthnRequest"));
    assert!(xml.contains(
        r#"AssertionConsumerServiceURL="https://app.example.com/sso/saml2/sp/acs/saml-okta""#
    ));
    assert!(xml.contains(r#"Destination="https://idp.example.com/saml/sso""#));

    let verification_records = adapter.records("verification").await;
    assert!(verification_records.iter().any(|record| {
        record.get("identifier")
            == Some(&DbValue::String(format!(
                "saml-authn-request:{relay_state}"
            )))
    }));

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_saml_provider_stores_ten_minute_relay_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    let relay_state = query.get("RelayState").ok_or("missing RelayState")?;
    let verification_records = adapter.records("verification").await;
    let record = verification_records
        .iter()
        .find(|record| {
            record.get("identifier")
                == Some(&DbValue::String(format!(
                    "saml-authn-request:{relay_state}"
                )))
        })
        .ok_or("missing SAML AuthnRequest state record")?;
    let Some(DbValue::String(value)) = record.get("value") else {
        return Err("missing SAML AuthnRequest state payload".into());
    };
    let payload: serde_json::Value = serde_json::from_str(value)?;
    let created_at = payload["createdAt"].as_i64().ok_or("missing createdAt")?;
    let expires_at = payload["expiresAt"].as_i64().ok_or("missing expiresAt")?;

    assert_eq!(expires_at - created_at, 600);

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_saml_provider_prefers_explicit_acs_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/post-auth-callback",
                    "acsUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let query = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    let saml_request = query.get("SAMLRequest").ok_or("missing SAMLRequest")?;
    let xml = inflate_redirect_binding(saml_request)?;
    assert!(xml.contains(
        r#"AssertionConsumerServiceURL="https://app.example.com/sso/saml2/sp/acs/saml-okta""#
    ));
    assert!(!xml.contains("https://app.example.com/post-auth-callback"));

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_dual_provider_defaults_to_oidc() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_dual_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"hybrid","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/oauth2/v1/authorize")
    );

    Ok(())
}

#[tokio::test]
async fn sign_in_sso_with_dual_provider_can_select_saml() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_dual_provider(&router, &cookie).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"hybrid","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://idp.example.com/saml/sso")
    );

    Ok(())
}

#[cfg(not(feature = "saml-signed"))]
#[tokio::test]
async fn sign_in_sso_with_signed_saml_authn_request_fails_until_key_support_exists(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "SAML_AUTHN_REQUEST_SIGNING_NOT_SUPPORTED"
    );

    Ok(())
}

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn sign_in_sso_with_signed_saml_authn_request_adds_redirect_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let idp = signed_saml_idp()?;
    let register_body = json!({
        "providerId": "saml-okta",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "entryPoint": "https://idp.example.com/saml/sso",
            "cert": idp.cert,
            "privateKey": idp.key_pem,
            "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/saml-okta",
            "spMetadata": {"entityId": "https://app.example.com/saml/sp"},
            "wantAssertionsSigned": true,
            "authnRequestsSigned": true
        }
    })
    .to_string();
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_body,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert!(url.query_pairs().any(|(key, _)| key == "SigAlg"));
    assert!(url.query_pairs().any(|(key, _)| key == "Signature"));
    let verifier = samael::crypto::UrlVerifier::from_x509(&idp.cert_der)?;
    assert!(verifier.verify_signed_request_url(&url)?);

    Ok(())
}

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn sign_in_sso_with_signed_saml_authn_request_requires_private_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "SAML_AUTHN_REQUEST_PRIVATE_KEY_REQUIRED"
    );

    Ok(())
}

async fn register_dual_provider(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"hybrid",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                },
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/hybrid",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}
