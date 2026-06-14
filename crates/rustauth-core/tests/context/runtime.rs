use time::Duration;

use rustauth_core::context::{
    create_auth_context, create_auth_context_with_environment, AuthEnvironment,
};
#[cfg(feature = "oauth")]
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{
    AccountLinkingOptions, AccountOptions, PasswordOptions, RateLimitOptions,
    RateLimitStorageOption, RustAuthOptions, SessionOptions,
};
#[cfg(feature = "oauth")]
use rustauth_core::plugin::{AuthPlugin, PluginInitOutput};
#[cfg(feature = "oauth")]
use rustauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialOAuthProvider, SocialProviderFuture,
};
#[cfg(feature = "oauth")]
use std::sync::Arc;
#[cfg(feature = "oauth")]
use url::Url;

#[test]
fn create_auth_context_resolves_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    }))?;

    assert_eq!(ctx.base_path, "/api/auth");
    assert_eq!(ctx.session_config.expires_in, Duration::days(7));
    assert_eq!(ctx.password.config.min_password_length, 8);
    Ok(())
}

#[test]
fn create_auth_context_applies_session_and_password_options(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        session: SessionOptions {
            expires_in: Some(Duration::seconds(120)),
            update_age: Some(Duration::seconds(30)),
            fresh_age: Some(Duration::seconds(10)),
            ..SessionOptions::default()
        },
        password: PasswordOptions {
            min_password_length: 12,
            max_password_length: 256,
            ..PasswordOptions::default()
        },
        ..RustAuthOptions::default()
    }))?;

    assert_eq!(ctx.session_config.expires_in, Duration::seconds(120));
    assert_eq!(ctx.session_config.update_age, Duration::seconds(30));
    assert_eq!(ctx.password.config.max_password_length, 256);
    Ok(())
}

#[test]
fn create_auth_context_preserves_fresh_age_zero() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        session: SessionOptions {
            fresh_age: Some(Duration::ZERO),
            ..SessionOptions::default()
        },
        ..RustAuthOptions::default()
    }))?;

    assert_eq!(ctx.session_config.fresh_age, Duration::ZERO);
    Ok(())
}

#[test]
fn create_auth_context_rejects_missing_secret_in_production() {
    let result = create_auth_context(crate::common::with_test_defaults(
        RustAuthOptions::default().production(true),
    ));

    assert!(result.is_err());
}

#[test]
fn create_auth_context_uses_rustauth_secret_from_environment(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        RustAuthOptions::default(),
        AuthEnvironment {
            rustauth_secret: Some("env-secret-at-least-32-chars-long!!".to_owned()),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(ctx.secret, "env-secret-at-least-32-chars-long!!");
    Ok(())
}

#[test]
fn create_auth_context_merges_trusted_origins_from_environment(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        RustAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
            trusted_origins: rustauth_core::options::TrustedOriginOptions::Static(vec![
                "https://static.example.com".to_owned(),
            ]),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..RustAuthOptions::default()
        },
        AuthEnvironment {
            rustauth_trusted_origins: Some(
                "https://env.example.com, ,https://static.example.com".to_owned(),
            ),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(
        ctx.trusted_origins,
        vec![
            "https://app.example.com",
            "https://static.example.com",
            "https://env.example.com",
        ]
    );
    Ok(())
}

#[test]
fn create_auth_context_uses_default_and_custom_app_name() -> Result<(), Box<dyn std::error::Error>>
{
    let default_ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    }))?;
    let custom_ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        app_name: Some("Example Auth".to_owned()),
        ..RustAuthOptions::default()
    }))?;

    assert_eq!(default_ctx.app_name, "RustAuth");
    assert_eq!(custom_ctx.app_name, "Example Auth");
    Ok(())
}

#[test]
fn create_auth_context_resolves_trusted_providers_per_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        account: AccountOptions {
            account_linking: AccountLinkingOptions::default()
                .trusted_provider("static")
                .trusted_providers_for_request_provider(
                    |request: Option<&rustauth_core::api::ApiRequest>| {
                        let tenant = request
                            .and_then(|request| request.headers().get("x-tenant"))
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("default");
                        Ok(vec![format!("{tenant}-provider")])
                    },
                ),
            ..AccountOptions::default()
        },
        ..RustAuthOptions::default()
    }))?;
    let request = http::Request::builder()
        .uri("https://app.example.com/api/auth")
        .header("x-tenant", "acme")
        .body(Vec::new())?;

    let providers = ctx.trusted_providers_for_request(Some(&request))?;

    assert_eq!(providers, vec!["static", "acme-provider"]);
    Ok(())
}

#[test]
fn create_auth_context_prefers_options_secret_over_environment(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context_with_environment(
        RustAuthOptions {
            secret: Some("option-secret-at-least-32-chars-long!!".to_owned()),
            ..RustAuthOptions::default()
        },
        AuthEnvironment {
            rustauth_secret: Some("env-secret-at-least-32-chars-long!!".to_owned()),
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
        RustAuthOptions::default(),
        AuthEnvironment {
            rustauth_secrets: Some(
                "2:secret-b-at-least-32-chars-long!!,1:secret-a-at-least-32-chars-long!!"
                    .to_owned(),
            ),
            rustauth_secret: Some("legacy-secret-at-least-32-chars!!".to_owned()),
            ..AuthEnvironment::default()
        },
    )?;

    assert_eq!(ctx.secret, "secret-b-at-least-32-chars-long!!");
    assert!(matches!(
        ctx.secret_config,
        rustauth_core::context::SecretMaterial::Rotating(_)
    ));
    Ok(())
}

#[test]
fn create_auth_context_rejects_external_rate_limit_storage_without_storage_contract() {
    let result = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            storage: RateLimitStorageOption::Database,
            ..RateLimitOptions::default()
        },
        ..RustAuthOptions::default()
    }));

    assert!(matches!(
        result,
        Err(rustauth_core::error::RustAuthError::InvalidConfig(message))
            if message.contains("custom_store") && message.contains("custom_storage")
    ));
}

#[test]
#[cfg(feature = "oauth")]
fn create_auth_context_resolves_unique_social_provider_registry(
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        social_providers: vec![Arc::new(TestProvider::new("github"))],
        ..RustAuthOptions::default()
    }))?;

    assert!(ctx.social_provider("github").is_some());
    Ok(())
}

#[test]
#[cfg(feature = "oauth")]
fn create_auth_context_rejects_duplicate_social_provider_ids() {
    let result = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        social_providers: vec![
            Arc::new(TestProvider::new("github")),
            Arc::new(TestProvider::new("github")),
        ],
        ..RustAuthOptions::default()
    }));

    assert!(matches!(
        result,
        Err(RustAuthError::InvalidConfig(message)) if message.contains("duplicate social provider")
    ));
}

#[test]
#[cfg(feature = "oauth")]
fn create_auth_context_accepts_plugin_social_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("plugin-provider"));
    let plugin = AuthPlugin::new("social-plugin").with_social_provider(provider);

    let ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![plugin],
        ..RustAuthOptions::default()
    }))?;

    assert!(ctx.social_provider("plugin-provider").is_some());
    Ok(())
}

#[test]
#[cfg(feature = "oauth")]
fn create_auth_context_accepts_plugin_init_social_provider(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("social-plugin").with_init(|_context| {
        let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("init-provider"));
        Ok(PluginInitOutput::new().social_provider(provider))
    });

    let ctx = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![plugin],
        ..RustAuthOptions::default()
    }))?;

    assert!(ctx.social_provider("init-provider").is_some());
    Ok(())
}

#[test]
#[cfg(feature = "oauth")]
fn plugin_init_sees_social_providers_registered_by_previous_plugin(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("first-provider"));
    let first = AuthPlugin::new("first").with_social_provider(provider);
    let second = AuthPlugin::new("second").with_init(|context| {
        assert!(context.social_provider("first-provider").is_some());
        Ok(PluginInitOutput::new())
    });

    create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![first, second],
        ..RustAuthOptions::default()
    }))?;

    Ok(())
}

#[test]
#[cfg(feature = "oauth")]
fn create_auth_context_rejects_duplicate_social_provider_from_plugin() {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("github"));
    let plugin = AuthPlugin::new("social-plugin").with_social_provider(provider);

    let result = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        social_providers: vec![Arc::new(TestProvider::new("github"))],
        plugins: vec![plugin],
        ..RustAuthOptions::default()
    }));

    assert!(matches!(
        result,
        Err(RustAuthError::InvalidConfig(message)) if message.contains("duplicate social provider")
    ));
}

#[test]
#[cfg(feature = "oauth")]
fn create_auth_context_rejects_duplicate_social_provider_from_plugin_init() {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("github"));
    let plugin = AuthPlugin::new("social-plugin")
        .with_social_provider(provider)
        .with_init(|_context| {
            let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new("github"));
            Ok(PluginInitOutput::new().social_provider(provider))
        });

    let result = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![plugin],
        ..RustAuthOptions::default()
    }));

    assert!(matches!(
        result,
        Err(RustAuthError::InvalidConfig(message)) if message.contains("duplicate social provider")
    ));
}

#[test]
#[cfg(feature = "oauth")]
fn create_auth_context_rejects_empty_social_provider_id_from_plugin() {
    let provider: Arc<dyn SocialOAuthProvider> = Arc::new(TestProvider::new(""));
    let plugin = AuthPlugin::new("social-plugin").with_social_provider(provider);

    let result = create_auth_context(crate::common::with_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        plugins: vec![plugin],
        ..RustAuthOptions::default()
    }));

    assert!(matches!(
        result,
        Err(RustAuthError::InvalidConfig(message))
            if message.contains("social provider id cannot be empty")
    ));
}

#[derive(Debug)]
#[cfg(feature = "oauth")]
struct TestProvider {
    id: String,
    options: ProviderOptions,
}

#[cfg(feature = "oauth")]
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

#[cfg(feature = "oauth")]
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
