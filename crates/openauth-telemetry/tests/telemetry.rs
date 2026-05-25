//! Integration tests aligned with Better Auth `packages/telemetry/src/telemetry.test.ts`.

#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openauth_core::db::{DbFieldType, DbValue};
use openauth_core::error::OpenAuthError;
#[cfg(feature = "oauth")]
use openauth_core::oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
use openauth_core::options::{
    AccountLinkingOptions, AccountOptions, AdvancedOptions, ChangeEmailOptions, CookieCacheOptions,
    CookieCacheStrategy, CookieConfig, EmailPasswordOptions, EmailVerificationOptions,
    OpenAuthOptions, PasswordOptions, SessionAdditionalField, SessionOptions, TelemetryOptions,
    UserAdditionalField, UserOptions,
};
use openauth_core::options::{
    EmailVerificationCallbackPayload, PasswordResetEmail, PasswordResetPayload, VerificationEmail,
};
use openauth_telemetry::{
    create_telemetry, types::CustomTrackFn, DetectionInfo, RuntimeInfo, TelemetryContext,
    TelemetryEvent, TelemetryHttpError, TelemetryHttpTransport, TelemetryTestHooks,
};
use serde_json::{json, Value};
use std::sync::OnceLock;
use tokio::sync::oneshot;
use tokio::sync::Mutex as AsyncMutex;

fn telemetry_env_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

fn assert_json_superset(actual: &Value, expected: &Value, ctx: &str) {
    match (actual, expected) {
        (Value::Object(am), Value::Object(em)) => {
            for (k, ev) in em {
                let Some(av) = am.get(k) else {
                    panic!("{ctx}: missing key {k}");
                };
                assert_json_superset(av, ev, &format!("{ctx}.{k}"));
            }
        }
        (Value::Array(a), Value::Array(e)) if a.len() >= e.len() => {
            for (i, pair) in e.iter().enumerate() {
                assert_json_superset(&a[i], pair, &format!("{ctx}[{i}]"));
            }
        }
        _ if actual == expected => {}
        _ => panic!("{ctx}: mismatch\nactual={actual:#}\nexpected={expected:#}"),
    }
}

struct EnvRestore(Vec<(&'static str, Option<String>)>);

impl EnvRestore {
    fn unset(keys: &[&'static str]) -> Self {
        let saved = keys
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect::<Vec<_>>();
        for k in keys {
            std::env::remove_var(k);
        }
        Self(saved)
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, old) in self.0.iter() {
            match old {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

struct CountingTransport {
    posts: Arc<AtomicUsize>,
}

impl TelemetryHttpTransport for CountingTransport {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), TelemetryHttpError>> + Send + 'a>> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(()) })
    }
}

struct CapturingTransport {
    posts: Arc<AtomicUsize>,
    urls: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<Value>>>,
}

impl TelemetryHttpTransport for CapturingTransport {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), TelemetryHttpError>> + Send + 'a>> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        self.urls.lock().expect("lock").push(url.to_owned());
        self.bodies.lock().expect("lock").push(body.clone());
        Box::pin(async move { Ok(()) })
    }
}

fn upstream_style_hooks() -> TelemetryTestHooks {
    TelemetryTestHooks {
        anonymous_id: Some("anon-123".into()),
        runtime: Some(RuntimeInfo {
            name: "node".into(),
            version: Some("test".into()),
        }),
        database: Some(Some(DetectionInfo {
            name: "postgresql".into(),
            version: Some("1.0.0".into()),
        })),
        framework: Some(Some(DetectionInfo {
            name: "next".into(),
            version: Some("15.0.0".into()),
        })),
        environment: Some("test".into()),
        system_info: Some(json!({
            "systemPlatform": "darwin",
            "systemRelease": "24.6.0",
            "systemArchitecture": "arm64",
            "cpuCount": 8,
            "cpuModel": "Apple M3",
            "cpuSpeed": 3200,
            "memory": 17179869184_i64,
            "isDocker": false,
            "isTTY": true,
            "isWSL": false,
            "isCI": false,
        })),
        package_manager: Some(Some(DetectionInfo {
            name: "cargo".into(),
            version: Some("1.85.0".into()),
        })),
    }
}

fn send_verification_email_noop(
    _email: VerificationEmail,
    _request: Option<&http::Request<Vec<u8>>>,
) -> Result<(), OpenAuthError> {
    Ok(())
}

fn before_email_verification_noop(
    _payload: EmailVerificationCallbackPayload,
    _request: Option<&http::Request<Vec<u8>>>,
) -> Result<(), OpenAuthError> {
    Ok(())
}

fn after_email_verification_noop(
    _payload: EmailVerificationCallbackPayload,
    _request: Option<&http::Request<Vec<u8>>>,
) -> Result<(), OpenAuthError> {
    Ok(())
}

fn send_reset_password_noop(
    _payload: PasswordResetEmail,
    _request: Option<&http::Request<Vec<u8>>>,
) -> Result<(), OpenAuthError> {
    Ok(())
}

fn on_password_reset_noop(
    _payload: PasswordResetPayload,
    _request: Option<&http::Request<Vec<u8>>>,
) -> Result<(), OpenAuthError> {
    Ok(())
}

#[test]
fn auth_config_snapshot_reports_modeled_options_with_upstream_keys() {
    let options = OpenAuthOptions {
        secret: Some("super-secret".into()),
        base_url: Some("https://app.example.com/auth".into()),
        email_verification: EmailVerificationOptions::new()
            .send_verification_email(send_verification_email_noop)
            .before_email_verification(before_email_verification_noop)
            .after_email_verification(after_email_verification_noop)
            .send_on_sign_up(true)
            .send_on_sign_in(true)
            .auto_sign_in_after_verification(true)
            .expires_in(900),
        email_password: EmailPasswordOptions::new()
            .enabled(false)
            .disable_sign_up(true)
            .require_email_verification(true)
            .auto_sign_in(false),
        password: PasswordOptions::new()
            .min_password_length(12)
            .max_password_length(256)
            .send_reset_password(send_reset_password_noop)
            .reset_password_token_expires_in(600)
            .on_password_reset(on_password_reset_noop)
            .revoke_sessions_on_password_reset(true),
        user: UserOptions::new()
            .change_email(ChangeEmailOptions::new().enabled(true))
            .additional_field(
                "tier",
                UserAdditionalField::new(DbFieldType::String)
                    .optional()
                    .default_value(DbValue::String("free".into()))
                    .db_name("account_tier"),
            ),
        session: SessionOptions::new()
            .disable_session_refresh(true)
            .store_session_in_database(true)
            .preserve_session_in_database(true)
            .cookie_cache(
                CookieCacheOptions::new()
                    .enabled(true)
                    .max_age(300)
                    .strategy(CookieCacheStrategy::Jwt),
            )
            .additional_field(
                "tenant",
                SessionAdditionalField::new(DbFieldType::String).hidden(),
            ),
        account: AccountOptions::new()
            .encrypt_oauth_tokens(true)
            .update_account_on_sign_in(false)
            .account_linking(
                AccountLinkingOptions::new()
                    .enabled(false)
                    .trusted_provider("github")
                    .allow_unlinking_all(true)
                    .update_user_info_on_link(true),
            ),
        secondary_storage: Some(Arc::new(TestSecondaryStorage)),
        ..Default::default()
    };

    let config = openauth_telemetry::get_telemetry_auth_config(
        &options,
        &TelemetryContext {
            database: Some("postgresql".into()),
            adapter: Some("sqlx".into()),
            ..Default::default()
        },
    );

    assert_json_superset(
        &config,
        &json!({
            "database": "postgresql",
            "adapter": "sqlx",
            "emailVerification": {
                "sendVerificationEmail": true,
                "sendOnSignUp": true,
                "sendOnSignIn": true,
                "autoSignInAfterVerification": true,
                "expiresIn": 900,
                "beforeEmailVerification": true,
                "afterEmailVerification": true
            },
            "emailAndPassword": {
                "enabled": false,
                "disableSignUp": true,
                "requireEmailVerification": true,
                "maxPasswordLength": 256,
                "minPasswordLength": 12,
                "sendResetPassword": true,
                "resetPasswordTokenExpiresIn": 600,
                "onPasswordReset": true,
                "autoSignIn": false,
                "revokeSessionsOnPasswordReset": true
            },
            "user": {
                "additionalFields": {
                    "tier": {
                        "type": "String",
                        "required": false,
                        "input": true,
                        "returned": true,
                        "defaultValue": true,
                        "dbName": true
                    }
                },
                "changeEmail": {
                    "enabled": true,
                    "sendChangeEmailConfirmation": false
                }
            },
            "session": {
                "additionalFields": {
                    "tenant": {
                        "type": "String",
                        "required": true,
                        "input": true,
                        "returned": false,
                        "defaultValue": false,
                        "dbName": false
                    }
                },
                "cookieCache": {
                    "enabled": true,
                    "maxAge": 300,
                    "strategy": "jwt"
                },
                "disableSessionRefresh": true,
                "preserveSessionInDatabase": true,
                "storeSessionInDatabase": true
            },
            "account": {
                "encryptOAuthTokens": true,
                "updateAccountOnSignIn": false,
                "accountLinking": {
                    "enabled": false,
                    "trustedProviders": ["github"],
                    "updateUserInfoOnLink": true,
                    "allowUnlinkingAll": true
                }
            },
            "secondaryStorage": true
        }),
        "config",
    );
    assert!(config["emailVerification"]["onEmailVerification"].is_null());
    assert!(config["user"]["changeEmail"]["sendChangeEmailVerification"].is_null());
    assert!(config["advanced"]["database"]["useNumberId"].is_null());

    let serialized = serde_json::to_string(&config).expect("serialize config");
    assert!(!serialized.contains("super-secret"));
    assert!(!serialized.contains("https://app.example.com"));
    assert!(!serialized.contains("account_tier"));
    assert!(!serialized.contains("free"));
}

#[derive(Debug)]
struct TestSecondaryStorage;

impl openauth_core::options::SecondaryStorage for TestSecondaryStorage {
    fn get<'a>(
        &'a self,
        _key: &'a str,
    ) -> openauth_core::options::SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move { Ok(None) })
    }

    fn set<'a>(
        &'a self,
        _key: &'a str,
        _value: String,
        _ttl_seconds: Option<u64>,
    ) -> openauth_core::options::SecondaryStorageFuture<'a, ()> {
        Box::pin(async move { Ok(()) })
    }

    fn delete<'a>(
        &'a self,
        _key: &'a str,
    ) -> openauth_core::options::SecondaryStorageFuture<'a, ()> {
        Box::pin(async move { Ok(()) })
    }
}

#[cfg(feature = "oauth")]
struct TestSocialProvider {
    options: ProviderOptions,
}

#[cfg(feature = "oauth")]
impl SocialOAuthProvider for TestSocialProvider {
    fn id(&self) -> &str {
        "github"
    }

    fn name(&self) -> &str {
        "GitHub"
    }

    fn provider_options(&self) -> ProviderOptions {
        self.options.clone()
    }

    fn create_authorization_url(
        &self,
        _input: SocialAuthorizationUrlRequest,
    ) -> Result<url::Url, OAuthError> {
        url::Url::parse("https://example.com/oauth").map_err(OAuthError::InvalidUrl)
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
        _provider_user: Option<Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async { Ok(None) })
    }

    fn verify_id_token(&self, _input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async { Ok(true) })
    }
}

#[cfg(feature = "oauth")]
#[test]
fn auth_config_snapshot_reports_social_provider_options_without_credentials() {
    let options = OpenAuthOptions::new().social_provider(TestSocialProvider {
        options: ProviderOptions {
            client_id: Some(openauth_core::oauth::oauth2::ClientId::from(
                "github-client",
            )),
            client_secret: Some("github-secret".into()),
            scope: vec!["read:user".into(), "user:email".into()],
            disable_default_scope: true,
            disable_id_token_sign_in: true,
            disable_implicit_sign_up: true,
            disable_sign_up: true,
            prompt: Some("select_account".into()),
            override_user_info_on_sign_in: true,
            ..Default::default()
        },
    });

    let config =
        openauth_telemetry::get_telemetry_auth_config(&options, &TelemetryContext::default());

    assert_json_superset(
        &config["socialProviders"][0],
        &json!({
            "id": "github",
            "disableDefaultScope": true,
            "disableIdTokenSignIn": true,
            "disableImplicitSignUp": true,
            "disableSignUp": true,
            "overrideUserInfoOnSignIn": true,
            "prompt": "select_account",
            "scope": ["read:user", "user:email"]
        }),
        "socialProviders[0]",
    );

    let serialized = serde_json::to_string(&config).expect("serialize config");
    assert!(!serialized.contains("github-client"));
    assert!(!serialized.contains("github-secret"));
}

#[tokio::test]
async fn publishes_init_when_enabled() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let captured = Arc::new(Mutex::new(None::<Value>));
    let cap = captured.clone();
    let custom: CustomTrackFn = Arc::new(move |ev: TelemetryEvent| {
        let cap = cap.clone();
        Box::pin(async move {
            let j = serde_json::to_value(&ev).expect("serialize event");
            *cap.lock().expect("lock") = Some(j);
        })
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost.com".into()),
        advanced: AdvancedOptions {
            cookie_prefix: Some("test".into()),
            cross_subdomain_cookies: Some(CookieConfig {
                enabled: true,
                domain: Some(".test.com".into()),
            }),
            ..Default::default()
        },
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let ctx = TelemetryContext {
        custom_track: Some(custom),
        skip_test_check: true,
        test_hooks: Some(upstream_style_hooks()),
        ..Default::default()
    };

    let expected_config =
        openauth_telemetry::get_telemetry_auth_config(&options, &TelemetryContext::default());

    create_telemetry(&options, ctx).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let event = captured
        .lock()
        .expect("lock")
        .take()
        .expect("custom track must capture init");

    assert_eq!(event["type"], "init");
    assert_eq!(event["anonymousId"], "anon-123");

    let payload = &event["payload"];
    assert_json_superset(payload, &json!({ "environment": "test" }), "payload");
    assert_json_superset(
        payload,
        &json!({
            "runtime": { "name": "node", "version": "test" },
            "database": { "name": "postgresql", "version": "1.0.0" },
            "framework": { "name": "next", "version": "15.0.0" },
            "packageManager": { "name": "cargo", "version": "1.85.0" },
        }),
        "payload",
    );
    assert_json_superset(&payload["config"], &expected_config, "payload.config");
}

#[tokio::test]
async fn does_not_publish_when_disabled_via_env() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var("OPENAUTH_TELEMETRY", "false");

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn does_not_publish_when_disabled_via_option() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        telemetry: TelemetryOptions {
            enabled: Some(false),
            debug: false,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn telemetry_env_true_enables_init_publish() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var("OPENAUTH_TELEMETRY", "true");

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    create_telemetry(
        &OpenAuthOptions::default(),
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn telemetry_env_one_enables_init_publish() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var("OPENAUTH_TELEMETRY", "1");

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    create_telemetry(
        &OpenAuthOptions::default(),
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn telemetry_env_zero_does_not_enable_init_publish() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var("OPENAUTH_TELEMETRY", "0");

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    create_telemetry(
        &OpenAuthOptions::default(),
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_environment_suppresses_telemetry_without_skip_test_check() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&[
        "OPENAUTH_TELEMETRY",
        "OPENAUTH_TELEMETRY_ENDPOINT",
        "RUST_ENV",
        "TEST",
    ]);
    std::env::set_var("RUST_ENV", "test");

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    let options = OpenAuthOptions {
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: false,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn panicking_custom_track_does_not_abort_create_telemetry() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let custom: CustomTrackFn = Arc::new(|_ev| {
        Box::pin(async move {
            panic!("test panic");
        })
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let _publisher = create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;
}

#[tokio::test]
async fn slow_init_custom_track_does_not_block_create_telemetry() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let (started_tx, started_rx) = oneshot::channel();
    let started_tx = Arc::new(Mutex::new(Some(started_tx)));
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        let started_tx = started_tx.clone();
        Box::pin(async move {
            if let Some(tx) = started_tx.lock().expect("lock").take() {
                let _ = tx.send(());
            }
            std::future::pending::<()>().await;
        })
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let result = tokio::time::timeout(
        Duration::from_millis(50),
        create_telemetry(
            &options,
            TelemetryContext {
                custom_track: Some(custom),
                skip_test_check: true,
                ..Default::default()
            },
        ),
    )
    .await;

    assert!(
        result.is_ok(),
        "create_telemetry should not wait for init delivery"
    );
    tokio::time::timeout(Duration::from_millis(50), started_rx)
        .await
        .expect("init track should start")
        .expect("init track should signal start");
}

#[tokio::test]
async fn init_with_missing_manifest_env_still_tracks() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&[
        "OPENAUTH_TELEMETRY",
        "OPENAUTH_TELEMETRY_ENDPOINT",
        "CARGO_MANIFEST_DIR",
    ]);

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    let options = OpenAuthOptions {
        base_url: Some("https://example.com".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(calls.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn noop_skips_http_transport_when_no_endpoint_and_no_custom_sink() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let posts = Arc::new(AtomicUsize::new(0));
    let transport: Arc<dyn TelemetryHttpTransport> = Arc::new(CountingTransport {
        posts: posts.clone(),
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let publisher = create_telemetry(
        &options,
        TelemetryContext {
            skip_test_check: true,
            http_transport: Some(transport),
            ..Default::default()
        },
    )
    .await;

    publisher
        .publish(TelemetryEvent {
            event_type: "test-event".into(),
            anonymous_id: None,
            payload: json!({ "test": "data" }),
        })
        .await;

    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn endpoint_env_posts_init_to_configured_collector() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var(
        "OPENAUTH_TELEMETRY_ENDPOINT",
        "https://collector.example.com/track",
    );

    let posts = Arc::new(AtomicUsize::new(0));
    let urls = Arc::new(Mutex::new(Vec::new()));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let transport: Arc<dyn TelemetryHttpTransport> = Arc::new(CapturingTransport {
        posts: posts.clone(),
        urls: urls.clone(),
        bodies,
    });

    let options = OpenAuthOptions {
        base_url: Some("https://app.example.com".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            skip_test_check: true,
            http_transport: Some(transport),
            test_hooks: Some(upstream_style_hooks()),
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        urls.lock().expect("lock").clone(),
        vec!["https://collector.example.com/track".to_owned()]
    );
}

#[tokio::test]
async fn custom_track_wins_over_configured_endpoint() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var(
        "OPENAUTH_TELEMETRY_ENDPOINT",
        "https://collector.example.com/track",
    );

    let posts = Arc::new(AtomicUsize::new(0));
    let urls = Arc::new(Mutex::new(Vec::new()));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let transport: Arc<dyn TelemetryHttpTransport> = Arc::new(CapturingTransport {
        posts: posts.clone(),
        urls,
        bodies,
    });

    let custom_calls = Arc::new(AtomicUsize::new(0));
    let c = custom_calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    let options = OpenAuthOptions {
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            http_transport: Some(transport),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(custom_calls.load(Ordering::SeqCst), 1);
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn debug_mode_skips_http_posting() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var(
        "OPENAUTH_TELEMETRY_ENDPOINT",
        "https://collector.example.com/track",
    );

    let posts = Arc::new(AtomicUsize::new(0));
    let urls = Arc::new(Mutex::new(Vec::new()));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let transport: Arc<dyn TelemetryHttpTransport> = Arc::new(CapturingTransport {
        posts: posts.clone(),
        urls,
        bodies,
    });

    let options = OpenAuthOptions {
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: true,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            http_transport: Some(transport),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn debug_env_skips_http_posting() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&[
        "OPENAUTH_TELEMETRY",
        "OPENAUTH_TELEMETRY_DEBUG",
        "OPENAUTH_TELEMETRY_ENDPOINT",
    ]);
    std::env::set_var(
        "OPENAUTH_TELEMETRY_ENDPOINT",
        "https://collector.example.com/track",
    );
    std::env::set_var("OPENAUTH_TELEMETRY_DEBUG", "true");

    let posts = Arc::new(AtomicUsize::new(0));
    let urls = Arc::new(Mutex::new(Vec::new()));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let transport: Arc<dyn TelemetryHttpTransport> = Arc::new(CapturingTransport {
        posts: posts.clone(),
        urls,
        bodies,
    });

    let options = OpenAuthOptions {
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            http_transport: Some(transport),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn publish_reuses_resolved_anonymous_id_and_overrides_caller_id() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let captured = Arc::new(Mutex::new(Vec::<TelemetryEvent>::new()));
    let cap = captured.clone();
    let custom: CustomTrackFn = Arc::new(move |ev| {
        let cap = cap.clone();
        Box::pin(async move {
            cap.lock().expect("lock").push(ev);
        })
    });

    let options = OpenAuthOptions {
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let publisher = create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            test_hooks: Some(TelemetryTestHooks {
                anonymous_id: Some("resolved-id".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    publisher
        .publish(TelemetryEvent {
            event_type: "cli_generate".into(),
            anonymous_id: Some("caller-id".into()),
            payload: json!({ "outcome": "generated" }),
        })
        .await;

    let events = captured.lock().expect("lock");
    let event = events
        .iter()
        .find(|event| event.event_type == "cli_generate")
        .expect("published cli event");
    assert_eq!(event.anonymous_id.as_deref(), Some("resolved-id"));
    assert_eq!(event.payload, json!({ "outcome": "generated" }));
}

#[tokio::test]
async fn empty_endpoint_env_is_treated_as_missing_endpoint() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var("OPENAUTH_TELEMETRY_ENDPOINT", "");

    let posts = Arc::new(AtomicUsize::new(0));
    let transport: Arc<dyn TelemetryHttpTransport> = Arc::new(CountingTransport {
        posts: posts.clone(),
    });

    let options = OpenAuthOptions {
        base_url: Some("https://app.example.com".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let publisher = create_telemetry(
        &options,
        TelemetryContext {
            skip_test_check: true,
            http_transport: Some(transport),
            ..Default::default()
        },
    )
    .await;

    publisher
        .publish(TelemetryEvent {
            event_type: "test-event".into(),
            anonymous_id: None,
            payload: json!({ "test": "data" }),
        })
        .await;

    assert_eq!(posts.load(Ordering::SeqCst), 0);
}
