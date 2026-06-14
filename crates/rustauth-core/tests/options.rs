use rustauth_core::context::{AuthEnvironment, SecretMaterial};
use rustauth_core::crypto::{SecretConfig, SecretEntry};
use rustauth_core::env::{allows_development_defaults, is_production, is_production_posture};
use rustauth_core::options::{
    DeploymentMode, EmailPasswordOptions, ExperimentalOptions, IpAddressOptions, RustAuthOptions,
};
use rustauth_core::plugin::AuthPlugin;
use std::sync::{Mutex, MutexGuard, OnceLock};

struct EnvRestore(Vec<(&'static str, Option<String>)>);

impl EnvRestore {
    fn unset(keys: &[&'static str]) -> Self {
        let saved = keys
            .iter()
            .map(|key| (*key, std::env::var(key).ok()))
            .collect::<Vec<_>>();
        for key in keys {
            std::env::remove_var(key);
        }
        Self(saved)
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_env() -> MutexGuard<'static, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn rustauth_options_debug_redacts_secret_material() {
    let options = RustAuthOptions {
        secret: Some("legacy-secret-should-not-appear".to_owned()),
        secrets: vec![SecretEntry {
            version: 1,
            value: "rotating-secret-should-not-appear".to_owned(),
        }],
        ..RustAuthOptions::default()
    };

    let output = format!("{options:?}");

    assert!(output.contains("<redacted>"));
    assert!(!output.contains("legacy-secret-should-not-appear"));
    assert!(!output.contains("rotating-secret-should-not-appear"));
}

#[test]
fn secret_rotation_debug_redacts_secret_material() {
    let entry = SecretEntry {
        version: 1,
        value: "entry-secret-should-not-appear".to_owned(),
    };
    let config = SecretConfig::new([(1, "config-secret-should-not-appear")])
        .with_legacy_secret("legacy-rotation-secret-should-not-appear");
    let material = SecretMaterial::Rotating(config.clone());

    let entry_output = format!("{entry:?}");
    let config_output = format!("{config:?}");
    let material_output = format!("{material:?}");

    assert!(!entry_output.contains("entry-secret-should-not-appear"));
    assert!(!config_output.contains("config-secret-should-not-appear"));
    assert!(!config_output.contains("legacy-rotation-secret-should-not-appear"));
    assert!(!material_output.contains("config-secret-should-not-appear"));
    assert!(!material_output.contains("legacy-rotation-secret-should-not-appear"));
}

#[test]
fn auth_environment_debug_redacts_secret_material() {
    let environment = AuthEnvironment {
        rustauth_secret: Some("rustauth-secret-should-not-appear".to_owned()),
        rustauth_secrets: Some("1:rotating-env-secret-should-not-appear".to_owned()),
        rustauth_trusted_origins: Some("https://trusted.example.com".to_owned()),
    };

    let output = format!("{environment:?}");

    assert!(!output.contains("rustauth-secret-should-not-appear"));
    assert!(!output.contains("rotating-env-secret-should-not-appear"));
}

#[test]
fn auth_environment_from_process_is_empty_when_secret_env_is_unset() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&[
        "RUSTAUTH_SECRET",
        "RUSTAUTH_SECRETS",
        "RUSTAUTH_TRUSTED_ORIGINS",
    ]);

    assert_eq!(AuthEnvironment::from_process(), AuthEnvironment::default());
}

#[test]
fn auth_environment_from_process_reads_mocked_secret_env() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&[
        "RUSTAUTH_SECRET",
        "RUSTAUTH_SECRETS",
        "RUSTAUTH_TRUSTED_ORIGINS",
    ]);
    std::env::set_var("RUSTAUTH_SECRET", "rustauth-secret");
    std::env::set_var("RUSTAUTH_SECRETS", "2:next,1:prev");
    std::env::set_var("RUSTAUTH_TRUSTED_ORIGINS", "https://trusted.example.com");

    assert_eq!(
        AuthEnvironment::from_process(),
        AuthEnvironment {
            rustauth_secret: Some("rustauth-secret".to_owned()),
            rustauth_secrets: Some("2:next,1:prev".to_owned()),
            rustauth_trusted_origins: Some("https://trusted.example.com".to_owned()),
        }
    );
}

#[test]
fn is_production_is_false_when_rust_env_is_unset() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV"]);

    assert!(!is_production());
}

#[test]
fn is_production_only_accepts_exact_production_rust_env() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    std::env::set_var("RUST_ENV", "development");
    assert!(!is_production());

    std::env::set_var("RUST_ENV", "production");
    assert!(is_production());
}

#[test]
fn ambiguous_deployment_fails_closed_without_explicit_development() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    let options = RustAuthOptions::default();
    assert!(is_production_posture(&options));
    assert!(!allows_development_defaults(&options));
}

#[test]
fn explicit_development_option_allows_development_defaults() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    let options = RustAuthOptions::default().development(true);
    assert!(!is_production_posture(&options));
    assert!(allows_development_defaults(&options));
}

#[test]
fn production_option_overrides_development_flag() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    let options = RustAuthOptions::default()
        .development(true)
        .production(true);
    assert!(is_production_posture(&options));
    assert!(!allows_development_defaults(&options));
}

#[test]
fn email_password_is_disabled_by_default_until_explicitly_opted_in() {
    assert!(!EmailPasswordOptions::default().enabled);
    assert!(!RustAuthOptions::default().email_password.enabled);
}

#[test]
fn rustauth_options_plugins_appends_without_replacing() {
    let options = RustAuthOptions::new()
        .plugin(AuthPlugin::new("first"))
        .plugins(vec![AuthPlugin::new("second"), AuthPlugin::new("third")]);

    let ids: Vec<_> = options
        .plugins
        .iter()
        .map(|plugin| plugin.id.as_str())
        .collect();
    assert_eq!(ids, ["first", "second", "third"]);
}

#[test]
fn rustauth_options_set_plugins_replaces_list() {
    let options = RustAuthOptions::new()
        .plugin(AuthPlugin::new("first"))
        .set_plugins(vec![AuthPlugin::new("only")]);

    let ids: Vec<_> = options
        .plugins
        .iter()
        .map(|plugin| plugin.id.as_str())
        .collect();
    assert_eq!(ids, ["only"]);
}

#[test]
fn deployment_mode_auto_honors_rust_env_matrix() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    let auto = RustAuthOptions::default();
    assert_eq!(auto.mode, DeploymentMode::Auto);
    assert!(is_production_posture(&auto));
    assert!(!allows_development_defaults(&auto));

    std::env::set_var("RUST_ENV", "development");
    assert!(allows_development_defaults(&RustAuthOptions::default()));

    let explicit = RustAuthOptions::default().deployment_mode(DeploymentMode::Development);
    assert!(allows_development_defaults(&explicit));

    std::env::set_var("RUST_ENV", "production");
    assert!(!allows_development_defaults(&explicit));
    assert!(!allows_development_defaults(&RustAuthOptions::default()));
    assert!(!allows_development_defaults(
        &RustAuthOptions::default().deployment_mode(DeploymentMode::Production)
    ));
}

#[test]
fn collection_aliases_match_primary_methods() {
    let options = RustAuthOptions::new()
        .push_plugin(AuthPlugin::new("first"))
        .extend_plugins(vec![AuthPlugin::new("second")])
        .push_disabled_path("/one")
        .set_disabled_paths(["/two", "/three"]);

    let ids: Vec<_> = options
        .plugins
        .iter()
        .map(|plugin| plugin.id.as_str())
        .collect();
    assert_eq!(ids, ["first", "second"]);
    assert_eq!(
        options.disabled_paths,
        ["/two".to_owned(), "/three".to_owned()]
    );

    let ip = IpAddressOptions::new()
        .header("X-Forwarded-For")
        .headers(["X-Real-Ip"]);
    assert_eq!(ip.headers, ["X-Real-Ip".to_owned()]);
}

#[cfg(feature = "oauth")]
#[test]
fn social_providers_batch_appends_in_order() {
    use rustauth_oauth::oauth2::{
        OAuth2Tokens, OAuth2UserInfo, ProviderOptions, SocialAuthorizationCodeRequest,
        SocialAuthorizationUrlRequest, SocialOAuthProvider, SocialProviderFuture,
    };
    use url::Url;

    struct StubProvider(&'static str);

    impl SocialOAuthProvider for StubProvider {
        fn id(&self) -> &str {
            self.0
        }

        fn name(&self) -> &str {
            self.0
        }

        fn provider_options(&self) -> ProviderOptions {
            ProviderOptions::default()
        }

        fn create_authorization_url(
            &self,
            _input: SocialAuthorizationUrlRequest,
        ) -> Result<Url, rustauth_oauth::oauth2::OAuthError> {
            Url::parse("https://example.com/oauth")
                .map_err(rustauth_oauth::oauth2::OAuthError::InvalidUrl)
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

    let options = RustAuthOptions::new()
        .social_provider(StubProvider("github"))
        .social_providers([StubProvider("google"), StubProvider("apple")]);

    let ids: Vec<_> = options
        .social_providers
        .iter()
        .map(|provider| provider.id())
        .collect();
    assert_eq!(ids, ["github", "google", "apple"]);

    let options = RustAuthOptions::new()
        .try_social_providers::<_, _, std::convert::Infallible>([
            Ok(StubProvider("one")),
            Ok(StubProvider("two")),
        ])
        .expect("providers should construct");
    let ids: Vec<_> = options
        .social_providers
        .iter()
        .map(|provider| provider.id())
        .collect();
    assert_eq!(ids, ["one", "two"]);
}

#[test]
fn experimental_joins_default_to_enabled_and_can_be_disabled() {
    assert!(RustAuthOptions::default().experimental.joins);

    let options = RustAuthOptions {
        experimental: ExperimentalOptions { joins: false },
        ..RustAuthOptions::default()
    };

    assert!(!options.experimental.joins);
    assert!(format!("{options:?}").contains("experimental"));
}
