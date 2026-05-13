use openauth_oauth_provider::{
    oauth_provider, GrantType, OAuthProviderConfigError, OAuthProviderOptions, SecretStorage,
};

#[test]
fn oauth_provider_uses_upstream_default_scopes_grants_and_expirations(
) -> Result<(), OAuthProviderConfigError> {
    let plugin = oauth_provider(OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        ..OAuthProviderOptions::default()
    })?;

    assert_eq!(plugin.id, "oauth-provider");
    assert_eq!(
        plugin.options.scopes,
        ["openid", "profile", "email", "offline_access"]
    );
    assert_eq!(
        plugin.options.claims,
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
    assert_eq!(plugin.options.code_expires_in, 600);
    assert_eq!(plugin.options.access_token_expires_in, 3600);
    assert_eq!(plugin.options.refresh_token_expires_in, 2_592_000);
    assert_eq!(
        plugin.options.grant_types,
        [
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken
        ]
    );
    assert_eq!(plugin.options.store_client_secret, SecretStorage::Hashed);
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
