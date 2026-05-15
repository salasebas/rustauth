use openauth_core::context::{
    create_auth_context, create_auth_context_with_environment, AuthEnvironment,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    OpenAuthOptions, PasswordOptions, RateLimitOptions, RateLimitStorageOption, SessionOptions,
};
use openauth_core::plugin::{AuthPlugin, PluginInitOutput};
use openauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialOAuthProvider, SocialProviderFuture,
};
use std::sync::Arc;
use url::Url;

#[test]
fn create_auth_context_resolves_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert_eq!(ctx.base_path, "/api/auth");
    assert_eq!(ctx.session_config.expires_in, 60 * 60 * 24 * 7);
    assert_eq!(ctx.password.config.min_password_length, 8);
    Ok(())
}

#[test]
fn create_auth_context_applies_session_and_password_options(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        session: SessionOptions {
            expires_in: Some(120),
            update_age: Some(30),
            fresh_age: Some(10),
            ..SessionOptions::default()
        },
        password: PasswordOptions {
            min_password_length: 12,
            max_password_length: 256,
            ..PasswordOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;

    assert_eq!(ctx.session_config.expires_in, 120);
    assert_eq!(ctx.session_config.update_age, 30);
    assert_eq!(ctx.password.config.max_password_length, 256);
    Ok(())
}

#[test]
fn create_auth_context_rejects_missing_secret_in_production() {
    let result = create_auth_context(OpenAuthOptions {
        production: true,
        ..OpenAuthOptions::default()
    });

    assert!(result.is_err());
}

#[test]
fn create_auth_context_uses_better_auth_secret_from_environment(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        OpenAuthOptions::default(),
        AuthEnvironment {
            better_auth_secret: Some("env-secret-at-least-32-chars-long!!".to_owned()),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(ctx.secret, "env-secret-at-least-32-chars-long!!");
    Ok(())
}

#[test]
fn create_auth_context_prefers_options_secret_over_environment(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        OpenAuthOptions {
            secret: Some("option-secret-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        AuthEnvironment {
            better_auth_secret: Some("env-secret-at-least-32-chars-long!!".to_owned()),
            auth_secret: Some("auth-secret-at-least-32-chars-long!!".to_owned()),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(ctx.secret, "option-secret-at-least-32-chars-long!!");
    Ok(())
}

#[test]
fn create_auth_context_builds_secret_config_from_environment_secrets(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        OpenAuthOptions::default(),
        AuthEnvironment {
            better_auth_secrets: Some(
                "2:secret-b-at-least-32-chars-long!!,1:secret-a-at-least-32-chars-long!!"
                    .to_owned(),
            ),
            better_auth_secret: Some("legacy-secret-at-least-32-chars!!".to_owned()),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(ctx.secret, "secret-b-at-least-32-chars-long!!");
    assert!(matches!(
        ctx.secret_config,
        openauth_core::context::SecretMaterial::Rotating(_)
    ));
    Ok(())
}

#[test]
fn create_auth_context_rejects_external_rate_limit_storage_without_storage_contract() {
    let result = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            storage: RateLimitStorageOption::Database,
            ..RateLimitOptions::default()
        },
        ..OpenAuthOptions::default()
    });

    assert!(matches!(
        result,
        Err(openauth_core::error::OpenAuthError::InvalidConfig(message))
            if message.contains("custom_storage")
    ));
}

#[test]
fn create_auth_context_resolves_unique_social_provider_registry(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        social_providers: vec![Arc::new(TestProvider::new("github"))],
        ..OpenAuthOptions::default()
    })?;

    assert!(ctx.social_provider("github").is_some());
    Ok(())
}

#[test]
fn create_auth_context_rejects_duplicate_social_provider_ids() {
    let result = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        social_providers: vec![
            Arc::new(TestProvider::new("github")),
            Arc::new(TestProvider::new("github")),
        ],
        ..OpenAuthOptions::default()
    });

    assert!(matches!(
        result,
        Err(OpenAuthError::InvalidConfig(message)) if message.contains("duplicate social provider")
    ));
}

#[test]
fn create_auth_context_accepts_plugin_social_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("plugin-provider"));
    let plugin = AuthPlugin::new("social-plugin").with_social_provider(provider);

    let ctx = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![plugin],
        ..OpenAuthOptions::default()
    })?;

    assert!(ctx.social_provider("plugin-provider").is_some());
    Ok(())
}

#[test]
fn create_auth_context_accepts_plugin_init_social_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("social-plugin").with_init(|_context| {
        let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("init-provider"));
        Ok(PluginInitOutput::new().social_provider(provider))
    });

    let ctx = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![plugin],
        ..OpenAuthOptions::default()
    })?;

    assert!(ctx.social_provider("init-provider").is_some());
    Ok(())
}

#[test]
fn plugin_init_sees_social_providers_registered_by_previous_plugin(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("first-provider"));
    let first = AuthPlugin::new("first").with_social_provider(provider);
    let second = AuthPlugin::new("second").with_init(|context| {
        assert!(context.social_provider("first-provider").is_some());
        Ok(PluginInitOutput::new())
    });

    create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![first, second],
        ..OpenAuthOptions::default()
    })?;

    Ok(())
}

#[test]
fn create_auth_context_rejects_duplicate_social_provider_from_plugin() {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("github"));
    let plugin = AuthPlugin::new("social-plugin").with_social_provider(provider);

    let result = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        social_providers: vec![Arc::new(TestProvider::new("github"))],
        plugins: vec![plugin],
        ..OpenAuthOptions::default()
    });

    assert!(matches!(
        result,
        Err(OpenAuthError::InvalidConfig(message)) if message.contains("duplicate social provider")
    ));
}

#[test]
fn create_auth_context_rejects_duplicate_social_provider_from_plugin_init() {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("github"));
    let plugin = AuthPlugin::new("social-plugin")
        .with_social_provider(provider)
        .with_init(|_context| {
            let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("github"));
            Ok(PluginInitOutput::new().social_provider(provider))
        });

    let result = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![plugin],
        ..OpenAuthOptions::default()
    });

    assert!(matches!(
        result,
        Err(OpenAuthError::InvalidConfig(message)) if message.contains("duplicate social provider")
    ));
}

#[test]
fn create_auth_context_rejects_empty_social_provider_id_from_plugin() {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new(""));
    let plugin = AuthPlugin::new("social-plugin").with_social_provider(provider);

    let result = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![plugin],
        ..OpenAuthOptions::default()
    });

    assert!(matches!(
        result,
        Err(OpenAuthError::InvalidConfig(message))
            if message.contains("social provider id cannot be empty")
    ));
}

#[derive(Debug)]
struct TestProvider {
    id: String,
    options: ProviderOptions,
}

impl TestProvider {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            options: ProviderOptions {
                client_id: Some("client-id".into()),
                ..ProviderOptions::default()
            },
        }
    }
}

impl SocialOAuthProvider for TestProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        "Test Provider"
    }

    fn provider_options(&self) -> ProviderOptions {
        self.options.clone()
    }

    fn create_authorization_url(
        &self,
        input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        Url::parse(&format!(
            "https://provider.example.com/oauth?client_id=client-id&state={}&redirect_uri={}",
            input.state, input.redirect_uri
        ))
        .map_err(OAuthError::InvalidUrl)
    }

    fn validate_authorization_code(
        &self,
        _input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async { Ok(OAuth2Tokens::default()) })
    }

    fn get_user_info(
        &self,
        _tokens: OAuth2Tokens,
        _provider_user: Option<serde_json::Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async { Ok(None) })
    }
}
