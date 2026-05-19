use super::*;

#[tokio::test]
async fn register_persists_and_sanitizes_oidc_config() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
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
                    "scopes":["openid","email"]
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["oidcConfig"]["clientIdLastFour"], "****3456");
    assert!(body["oidcConfig"].get("clientSecret").is_none());
    assert_eq!(body["providerType"], "oidc");
    assert_eq!(body["type"], "oidc");
    assert_eq!(
        body["redirectURI"],
        "https://app.example.com/sso/callback/okta"
    );
    assert_eq!(
        body["oidcConfig"]["authorizationEndpoint"],
        "https://idp.example.com/oauth2/v1/authorize"
    );

    let records = adapter.records("ssoProvider").await;
    let Some(DbValue::String(config)) = records[0].get("oidcConfig") else {
        return Err("missing stored OIDC config".into());
    };
    assert!(config.contains(r#""clientSecret":"super-secret""#));
    assert!(config.contains(
        r#""discoveryEndpoint":"https://idp.example.com/.well-known/openid-configuration""#
    ));

    Ok(())
}

#[tokio::test]
async fn register_accepts_form_urlencoded_body() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(form_request(
            Method::POST,
            "/sso/register",
            "providerId=form-okta&issuer=https%3A%2F%2Fidp.example.com&domain=example.com",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response)?["providerId"], "form-okta");

    Ok(())
}

#[tokio::test]
async fn register_returns_shared_oidc_redirect_uri_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().redirect_uri("/sso/callback"))?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"shared-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["type"], "oidc");
    assert_eq!(body["redirectURI"], "https://app.example.com/sso/callback");

    Ok(())
}

#[tokio::test]
async fn register_allows_provider_with_oidc_and_saml_configs(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

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
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["providerType"], "saml");
    assert_eq!(body["type"], "saml");
    assert!(body["oidcConfig"].is_object());
    assert!(body["samlConfig"].is_object());
    assert_eq!(
        body["redirectURI"],
        "https://app.example.com/sso/callback/hybrid"
    );

    let records = adapter.records("ssoProvider").await;
    assert!(matches!(
        records[0].get("oidcConfig"),
        Some(DbValue::String(_))
    ));
    assert!(matches!(
        records[0].get("samlConfig"),
        Some(DbValue::String(_))
    ));

    Ok(())
}

#[tokio::test]
async fn register_uses_dynamic_provider_limit_callback() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default().providers_limit_callback(
        |user: User| async move {
            Ok(if user.email == "user@example.com" {
                1
            } else {
                2
            })
        },
    ))?;
    let cookie = seed_session(&adapter).await?;

    let first = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta-one",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta-two",
                "issuer":"https://idp2.example.com",
                "domain":"example.org",
                "oidcConfig":{
                    "clientId":"client_654321",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp2.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp2.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp2.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(second)?["code"], "SSO_PROVIDERS_LIMIT_REACHED");
    assert_eq!(adapter.records("ssoProvider").await.len(), 1);

    Ok(())
}

#[tokio::test]
async fn register_dynamic_provider_limit_zero_disables_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(
        SsoOptions::default().providers_limit_callback(|_user: User| async move { Ok(0) }),
    )?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com"
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(response)?["code"],
        "SSO_PROVIDER_REGISTRATION_DISABLED"
    );
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_saml_config_accepts_idp_metadata_single_sign_on_service(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let body = json!({
        "providerId": "metadata-saml",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "cert": "CERTIFICATE",
            "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/metadata-saml",
            "spMetadata": {},
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "idpMetadata": {
                "singleSignOnService": [{
                    "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "Location": "https://idp.example.com/saml/from-service"
                }]
            }
        }
    });

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &serde_json::to_string(&body)?,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["providerType"], "saml");
    assert_eq!(body["type"], "saml");
    assert!(body.get("redirectURI").is_none());
    let records = adapter.records("ssoProvider").await;
    let Some(DbValue::String(config)) = records[0].get("samlConfig") else {
        return Err("missing stored SAML config".into());
    };
    assert!(config.contains(r#""entryPoint":"https://idp.example.com/saml/from-service""#));
    assert!(config.contains(r#""singleSignOnService""#));

    Ok(())
}

#[tokio::test]
async fn register_saml_config_extracts_entry_point_from_idp_metadata_xml(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let metadata = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><md:IDPSSODescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/from-metadata"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/post"/></md:IDPSSODescriptor></md:EntityDescriptor>"#;
    let body = json!({
        "providerId": "metadata-saml",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "cert": "CERTIFICATE",
            "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/metadata-saml",
            "spMetadata": {},
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "idpMetadata": {
                "metadata": metadata
            }
        }
    });

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &serde_json::to_string(&body)?,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let records = adapter.records("ssoProvider").await;
    let Some(DbValue::String(config)) = records[0].get("samlConfig") else {
        return Err("missing stored SAML config".into());
    };
    assert!(config.contains(r#""entryPoint":"https://idp.example.com/saml/from-metadata""#));
    assert!(config.contains(r#""metadata":"#));

    Ok(())
}

#[tokio::test]
async fn register_saml_config_rejects_oversized_idp_metadata_xml(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.max_metadata_size = 16;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    let body = json!({
        "providerId": "metadata-saml",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "cert": "CERTIFICATE",
            "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/metadata-saml",
            "spMetadata": {},
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "idpMetadata": {
                "metadata": "<EntityDescriptor><IDPSSODescriptor /></EntityDescriptor>"
            }
        }
    });

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &serde_json::to_string(&body)?,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_METADATA_TOO_LARGE");
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_public_suffix_domain() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_DOMAIN");
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_empty_comma_separated_domain_segment(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com, ,corp.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_DOMAIN");
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_invalid_oidc_endpoint_url_when_discovery_is_skipped(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
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
                    "authorizationEndpoint":"/relative/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_OIDC_CONFIG");
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_saml_config_with_invalid_entry_point(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"broken-saml",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"not-a-url",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/broken-saml",
                    "spMetadata":{},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response)?;
    assert_eq!(body["code"], "INVALID_SAML_CONFIG");
    assert!(body["message"]
        .as_str()
        .is_some_and(|message| message.contains("entryPoint")));
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_saml_config_with_non_http_entry_point(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"broken-saml",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"javascript:alert(1)",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/broken-saml",
                    "spMetadata":{},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "INVALID_SAML_CONFIG");
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_saml_config_with_unknown_signature_algorithm(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"broken-saml",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/broken-saml",
                    "spMetadata":{},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false,
                    "signatureAlgorithm":"rsa-sha257"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_UNKNOWN_ALGORITHM");
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

#[tokio::test]
async fn register_rejects_deprecated_saml_algorithm_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.algorithms.on_deprecated = DeprecatedAlgorithmBehavior::Reject;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"broken-saml",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/broken-saml",
                    "spMetadata":{},
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false,
                    "signatureAlgorithm":"rsa-sha1"
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response)?["code"],
        "SAML_DEPRECATED_CONFIG_ALGORITHM"
    );
    assert!(adapter.records("ssoProvider").await.is_empty());

    Ok(())
}

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

    let records = adapter.records("ssoProvider").await;
    let Some(DbValue::String(config)) = records[0].get("oidcConfig") else {
        return Err("missing stored OIDC config".into());
    };
    assert!(config.contains(&format!(
        r#""authorizationEndpoint":"{}/authorize""#,
        oidc.base_url
    )));
    assert!(config.contains(r#""tokenEndpointAuthentication":"client_secret_basic""#));

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

#[tokio::test]
async fn register_persists_provider_for_session_user() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) =
        router_with_options(SsoOptions::default().domain_verification_enabled(true))?;
    let cookie = seed_session(&adapter).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{"providerId":"okta","issuer":"https://idp.example.com","domain":"example.com"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["providerId"], "okta");
    assert_eq!(body["domainVerified"], false);

    let records = adapter.records("ssoProvider").await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("providerId"),
        Some(&openauth_core::db::DbValue::String("okta".to_owned()))
    );
    assert_eq!(
        records[0].get("userId"),
        Some(&openauth_core::db::DbValue::String("user_1".to_owned()))
    );

    Ok(())
}
