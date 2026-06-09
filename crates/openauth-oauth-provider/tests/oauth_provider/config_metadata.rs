use super::common::*;

#[test]
fn oauth_provider_uses_upstream_default_scopes_grants_and_expirations(
) -> Result<(), OAuthProviderConfigError> {
    let options = OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        ..OAuthProviderOptions::default()
    };
    let plugin = oauth_provider(options.clone())?;
    let resolved = resolve_oauth_provider_options(options)?;

    assert_eq!(plugin.id, "oauth-provider");
    assert_eq!(
        resolved.scopes,
        ["openid", "profile", "email", "offline_access"]
    );
    assert_eq!(
        resolved.claims,
        [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "sid",
            "scope",
            "azp",
            "email",
            "email_verified",
            "name",
            "picture",
            "family_name",
            "given_name"
        ]
    );
    assert_eq!(resolved.code_expires_in, 600);
    assert_eq!(resolved.access_token_expires_in, 3600);
    assert_eq!(resolved.refresh_token_expires_in, 2_592_000);
    assert_eq!(
        resolved.grant_types,
        [
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken
        ]
    );
    assert_eq!(resolved.store_client_secret, SecretStorage::Hashed);
    Ok(())
}

#[test]
fn oauth_provider_contributes_default_rate_limit_rules() -> Result<(), OAuthProviderConfigError> {
    let plugin = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        ..OAuthProviderOptions::default()
    })?;
    let rules = &plugin.rate_limit;

    assert_eq!(rules.len(), 6);
    assert!(rules
        .iter()
        .any(|rule| { rule.path == "/oauth2/token" && rule.rule == RateLimitRule::new(60, 20) }));
    assert!(rules.iter().any(|rule| {
        rule.path == "/oauth2/authorize" && rule.rule == RateLimitRule::new(60, 30)
    }));
    assert!(rules.iter().any(|rule| {
        rule.path == "/oauth2/introspect" && rule.rule == RateLimitRule::new(60, 100)
    }));
    assert!(rules
        .iter()
        .any(|rule| { rule.path == "/oauth2/revoke" && rule.rule == RateLimitRule::new(60, 30) }));
    assert!(rules
        .iter()
        .any(|rule| { rule.path == "/oauth2/register" && rule.rule == RateLimitRule::new(60, 5) }));
    assert!(rules.iter().any(|rule| {
        rule.path == "/oauth2/userinfo" && rule.rule == RateLimitRule::new(60, 60)
    }));
    Ok(())
}

#[test]
fn oauth_provider_rate_limit_options_override_and_disable_endpoint_rules(
) -> Result<(), OAuthProviderConfigError> {
    let plugin = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        rate_limits: OAuthProviderRateLimits {
            token: OAuthProviderRateLimit::Custom(RateLimitRule::new(10, 3)),
            introspect: OAuthProviderRateLimit::Custom(RateLimitRule::new(30, 7)),
            revoke: OAuthProviderRateLimit::Disabled,
            userinfo: OAuthProviderRateLimit::Disabled,
            ..OAuthProviderRateLimits::default()
        },
        ..OAuthProviderOptions::default()
    })?;
    let rules = &plugin.rate_limit;

    assert_eq!(rules.len(), 4);
    assert!(rules
        .iter()
        .any(|rule| { rule.path == "/oauth2/token" && rule.rule == RateLimitRule::new(10, 3) }));
    assert!(rules.iter().any(|rule| {
        rule.path == "/oauth2/introspect" && rule.rule == RateLimitRule::new(30, 7)
    }));
    assert!(!rules.iter().any(|rule| rule.path == "/oauth2/revoke"));
    assert!(!rules.iter().any(|rule| rule.path == "/oauth2/userinfo"));
    Ok(())
}

#[test]
fn oauth_provider_contributes_plural_snake_case_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context =
        create_auth_context_with_adapter(options_with_provider(default_provider()?), adapter())?;
    let clients = context
        .db_schema
        .table("oauth_client")
        .ok_or_else(|| OpenAuthError::InvalidConfig("missing oauth client schema".to_owned()))?;
    let refresh_tokens = context
        .db_schema
        .table("oauth_refresh_token")
        .ok_or_else(|| OpenAuthError::InvalidConfig("missing refresh token schema".to_owned()))?;
    let access_tokens = context
        .db_schema
        .table("oauth_access_token")
        .ok_or_else(|| OpenAuthError::InvalidConfig("missing access token schema".to_owned()))?;
    let consents = context
        .db_schema
        .table("oauth_consent")
        .ok_or_else(|| OpenAuthError::InvalidConfig("missing consent schema".to_owned()))?;

    assert_eq!(clients.name, "oauth_clients");
    assert_eq!(refresh_tokens.name, "oauth_refresh_tokens");
    assert_eq!(access_tokens.name, "oauth_access_tokens");
    assert_eq!(consents.name, "oauth_consents");
    assert_eq!(
        clients.field("client_id").map(|field| field.name.as_str()),
        Some("client_id")
    );
    assert_eq!(
        clients
            .field("token_endpoint_auth_method")
            .map(|field| field.name.as_str()),
        Some("token_endpoint_auth_method")
    );
    assert_eq!(
        clients
            .field("redirect_uris")
            .map(|field| field.name.as_str()),
        Some("redirect_uris")
    );
    Ok(())
}

#[test]
fn oauth_provider_mcp_protected_resource_metadata_rejects_invalid_resource_urls(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        grant_types: vec![GrantType::ClientCredentials],
        ..OAuthProviderOptions::default()
    };
    let plugin = oauth_provider(options.clone())?;
    let resolved = resolve_oauth_provider_options(options)?;
    let context = create_auth_context_with_adapter(options_with_provider(plugin), adapter())?;

    let metadata =
        mcp_protected_resource_metadata(&context, &resolved, "https://api.example.com/mcp")?;
    assert_eq!(metadata["resource"], "https://api.example.com/mcp");
    assert_eq!(metadata["authorization_servers"], json!([BASE_URL]));
    assert_eq!(
        metadata["scopes_supported"],
        json!(["openid", "profile", "email", "offline_access"])
    );
    assert_eq!(
        metadata["grant_types_supported"],
        json!(["client_credentials"])
    );

    let result = mcp_protected_resource_metadata(&context, &resolved, "not a url");
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn metadata_endpoint_returns_oidc_server_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let router = router(default_provider()?, adapter())?;
    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/openid-configuration",
            "",
            None,
        )?)
        .await?;
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static(
            "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"
        ))
    );
    let body = json_body(response)?;

    assert_eq!(body["issuer"], BASE_URL);
    assert_eq!(
        body["authorization_endpoint"],
        format!("{BASE_URL}/oauth2/authorize")
    );
    assert_eq!(body["token_endpoint"], format!("{BASE_URL}/oauth2/token"));
    assert_eq!(
        body["userinfo_endpoint"],
        format!("{BASE_URL}/oauth2/userinfo")
    );
    assert_eq!(
        body["scopes_supported"],
        json!(["openid", "profile", "email", "offline_access"])
    );
    Ok(())
}

#[tokio::test]
async fn metadata_endpoint_advertises_custom_claims_supported(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(
        oauth_provider(OAuthProviderOptions {
            advertised_claims_supported: vec![
                "sub".to_owned(),
                "https://example.com/organization".to_owned(),
            ],
            ..default_options()
        })?,
        adapter(),
    )?;
    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/openid-configuration",
            "",
            None,
        )?)
        .await?;
    let body = json_body(response)?;

    assert_eq!(
        body["claims_supported"],
        json!(["sub", "https://example.com/organization"])
    );
    Ok(())
}

#[tokio::test]
async fn oauth_authorization_server_returns_oidc_metadata_when_openid_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router(default_provider()?, adapter())?;
    let oauth = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/oauth-authorization-server",
            "",
            None,
        )?)
        .await?;
    let openid = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/openid-configuration",
            "",
            None,
        )?)
        .await?;
    assert_eq!(json_body(oauth)?, json_body(openid)?);
    Ok(())
}

#[test]
fn oauth_provider_jwt_plugin_options_fill_advertised_metadata_defaults(
) -> Result<(), OAuthProviderConfigError> {
    use openauth_plugins::jwt::{JwkAlgorithm, JwtJwksOptions, JwtOptions};

    let options = OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        ..OAuthProviderOptions::default()
    };
    let jwt_options = JwtOptions {
        jwks: JwtJwksOptions {
            remote_url: Some("https://issuer.example/.well-known/jwks.json".into()),
            key_pair_algorithm: Some(JwkAlgorithm::Es256),
            jwks_path: "/custom-jwks".into(),
            ..JwtJwksOptions::default()
        },
        ..JwtOptions::default()
    };
    let _plugin = oauth_provider_with_jwt(options.clone(), jwt_options.clone())?;
    let resolved =
        openauth_oauth_provider::resolve_oauth_provider_options_with_jwt(options, jwt_options)?;

    assert_eq!(
        resolved.advertised_jwks_uri.as_deref(),
        Some("https://issuer.example/.well-known/jwks.json")
    );
    assert_eq!(resolved.advertised_id_token_signing_algorithms, ["ES256"]);
    assert_eq!(resolved.jwks_path, "/custom-jwks");
    Ok(())
}

#[test]
fn oauth_provider_rejects_client_registration_scopes_not_in_server_scopes() {
    let result = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        client_registration_allowed_scopes: vec!["admin".into()],
        ..OAuthProviderOptions::default()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::UnknownClientRegistrationScope(
            "admin".into()
        ))
    );
}

#[test]
fn oauth_provider_rejects_refresh_token_without_authorization_code_grant() {
    let result = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        grant_types: vec![GrantType::RefreshToken],
        ..OAuthProviderOptions::default()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::RefreshTokenRequiresAuthorizationCode)
    );
}

#[test]
fn oauth_provider_rejects_short_pairwise_secret() {
    let result = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        pairwise_secret: Some("too-short".into()),
        ..OAuthProviderOptions::default()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::PairwiseSecretTooShort)
    );
}

#[test]
fn oauth_provider_rejects_hashed_client_secrets_without_jwt_plugin() {
    let result = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        disable_jwt_plugin: true,
        store_client_secret: SecretStorage::Hashed,
        ..OAuthProviderOptions::default()
    });

    assert_eq!(
        result.map(|_| ()),
        Err(OAuthProviderConfigError::HashedClientSecretsRequireJwtPlugin)
    );
}
