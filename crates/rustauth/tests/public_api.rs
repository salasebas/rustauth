use http::{header, Method, Request, StatusCode};
use rustauth::api::{
    core_auth_async_endpoints, create_auth_endpoint, ApiErrorResponse, ApiRequest, ApiResponse,
    AsyncAuthEndpoint, AuthEndpoint, AuthEndpointOptions, BodyField, BodySchema, EndpointKind,
    JsonSchemaType, OpenApiOperation,
};
#[cfg(feature = "telemetry")]
use rustauth::context::ContextTelemetryEvent;
use rustauth::db::DbAdapter;
use rustauth::db::{HookedAdapter, MemoryAdapter};
use rustauth::error::RustAuthError;
#[cfg(feature = "oauth")]
use rustauth::oauth::oauth2::SocialOAuthProvider;
#[cfg(feature = "telemetry")]
use rustauth::options::TelemetryOptions;
use rustauth::options::{
    AdvancedOptions, ChangeEmailOptions, CookieCacheOptions, CookieCacheStrategy,
    DeleteUserOptions, EmailVerificationOptions, HybridRateLimitOptions, RateLimitConsumeInput,
    RateLimitDecision, RateLimitFuture, RateLimitOptions, RateLimitRule, RateLimitStorageOption,
    RateLimitStore, RustAuthOptions, SessionAdditionalField, SessionOptions, TrustedOriginOptions,
    UserOptions, VerificationEmail,
};
use rustauth::plugin::{
    AuthPlugin, PluginAfterHookAction, PluginBeforeHookAction, PluginDatabaseAfterInput,
    PluginDatabaseBeforeAction, PluginDatabaseBeforeInput, PluginDatabaseHook,
    PluginDatabaseHookContext, PluginDatabaseOperation, PluginEndpoint, PluginEndpointHooks,
    PluginErrorCode, PluginHookMatcher, PluginMigration, PluginRateLimitRule, PluginRequestAction,
    PluginSchemaContribution,
};
use rustauth::prelude::*;
#[cfg(feature = "telemetry")]
use rustauth::telemetry::{CustomTrackFn, TelemetryContext};
use rustauth::user::UpdateUserInput;
use rustauth_core::auth::session::{SessionAuth, SignOutResult};
use serde_json::Value;
use std::collections::BTreeMap;
#[cfg(feature = "telemetry")]
use std::future::Future;
#[cfg(feature = "telemetry")]
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};
use time::Duration;

static SQL_TEST_ID: AtomicU64 = AtomicU64::new(0);
const DEFAULT_POSTGRES_URL: &str = "postgres://user:password@localhost:5432/rustauth";
const DEFAULT_MYSQL_URL: &str = "mysql://user:password@localhost:3306/rustauth";

fn postgres_url_from_env(value: Option<String>) -> String {
    value.unwrap_or_else(|| DEFAULT_POSTGRES_URL.to_owned())
}

fn mysql_url_from_env(value: Option<String>) -> String {
    value.unwrap_or_else(|| DEFAULT_MYSQL_URL.to_owned())
}

#[test]
fn prelude_exports_app_dev_surface() {
    fn _uses_prelude(
        _auth: RustAuth,
        _builder: RustAuthBuilder,
        _error: RustAuthError,
        _options: RustAuthOptions,
        _adapter: MemoryAdapter,
        _plugin: AuthPlugin,
    ) {
    }
    let _ = _uses_prelude;
}

#[test]
fn sql_test_urls_default_to_docker_compose_services_when_env_is_unset() {
    assert_eq!(postgres_url_from_env(None), DEFAULT_POSTGRES_URL);
    assert_eq!(mysql_url_from_env(None), DEFAULT_MYSQL_URL);
}

#[test]
fn sql_test_urls_allow_env_overrides() {
    assert_eq!(
        postgres_url_from_env(Some("postgres://custom.example.test/db".to_owned())),
        "postgres://custom.example.test/db"
    );
    assert_eq!(
        mysql_url_from_env(Some("mysql://custom.example.test/db".to_owned())),
        "mysql://custom.example.test/db"
    );
}

#[tokio::test]
async fn rustauth_builder_exposes_primary_initializer() -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .rate_limit(RateLimitOptions::memory().enabled(false))
        .build()
        .await?;

    let response = auth.handler(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .body(Vec::new())?,
    )?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn async_init_without_telemetry_feature() -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .rate_limit(RateLimitOptions::memory().enabled(false))
        .build()
        .await?;

    let response = auth.handler(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/ok")
            .body(Vec::new())?,
    )?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[cfg(feature = "telemetry")]
#[tokio::test]
async fn rustauth_async_builder_wires_context_telemetry_publisher(
) -> Result<(), Box<dyn std::error::Error>> {
    let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let custom_track: CustomTrackFn = {
        let captured = Arc::clone(&captured);
        Arc::new(move |event| {
            let captured = Arc::clone(&captured);
            Box::pin(async move {
                captured.lock().await.push(event);
            }) as Pin<Box<dyn Future<Output = ()> + Send>>
        })
    };

    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .telemetry(TelemetryOptions::new().enabled(true))
        .rate_limit(RateLimitOptions::memory().enabled(false))
        .telemetry_context(TelemetryContext {
            skip_test_check: true,
            custom_track: Some(custom_track),
            ..TelemetryContext::default()
        })
        .build()
        .await?;

    auth.context()
        .publish_telemetry(ContextTelemetryEvent {
            event_type: "custom_event".to_owned(),
            anonymous_id: Some("caller-provided-id".to_owned()),
            payload: serde_json::json!({ "server": true }),
        })
        .await;

    let events = captured.lock().await;
    let init = events
        .iter()
        .find(|event| event.event_type == "init")
        .ok_or("missing init telemetry event")?;
    let custom = events
        .iter()
        .find(|event| event.event_type == "custom_event")
        .ok_or("missing custom telemetry event")?;

    let init_id = init
        .anonymous_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or("missing init anonymous_id")?;
    let custom_id = custom
        .anonymous_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or("missing custom anonymous_id")?;
    assert_eq!(init_id, custom_id);
    assert_eq!(custom.payload["server"], true);
    Ok(())
}

#[cfg(feature = "i18n")]
#[test]
fn i18n_feature_reexports_i18n_crate() {
    let dictionary = rustauth::i18n::translation_dictionary([("CODE", "Message")]);
    assert_eq!(dictionary.get("CODE").map(String::as_str), Some("Message"));
}

#[tokio::test]
async fn rustauth_builder_accepts_adapter_and_extra_endpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let extra = AuthEndpoint {
        path: "/builder-custom".to_owned(),
        method: Method::GET,
        handler: |_context, _request| rustauth::api::response(StatusCode::OK, b"BUILDER".to_vec()),
    };
    let auth = RustAuthBuilder::new()
        .secret("secret-a-at-least-32-chars-long!!")
        .adapter(MemoryAdapter::new())
        .endpoint(extra)
        .build()
        .await?;

    let response = auth.handler(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/builder-custom")
            .body(Vec::new())?,
    )?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"BUILDER");
    Ok(())
}

#[test]
#[allow(deprecated)]
fn option_builders_cover_common_nested_configuration() {
    let options = RustAuthOptions::new()
        .secret("secret-a-at-least-32-chars-long!!")
        .base_url("https://auth.example.com")
        .base_path("/auth")
        .production(true)
        .session(
            SessionOptions::new()
                .expires_in(Duration::seconds(3600))
                .update_age(Duration::seconds(60))
                .fresh_age(Duration::seconds(30))
                .cookie_cache(
                    CookieCacheOptions::new()
                        .enabled(true)
                        .max_age(Duration::seconds(300))
                        .strategy(CookieCacheStrategy::Jwe)
                        .refresh_cache(false)
                        .version("v1"),
                ),
        )
        .user(
            UserOptions::new()
                .change_email(ChangeEmailOptions::new().enabled(true))
                .delete_user(DeleteUserOptions::new().enabled(true)),
        )
        .rate_limit(
            RateLimitOptions::memory()
                .enabled(true)
                .window(Duration::seconds(60))
                .max(10)
                .storage(RateLimitStorageOption::Memory),
        );

    assert_eq!(
        options.base_url.as_deref(),
        Some("https://auth.example.com")
    );
    assert_eq!(options.base_path.as_deref(), Some("/auth"));
    assert!(options.explicit_production());
    assert_eq!(options.session.expires_in, Some(Duration::seconds(3600)));
    assert!(options.session.cookie_cache.enabled);
    assert!(options.user.change_email.enabled);
    assert_eq!(options.rate_limit.window, Duration::seconds(60));
}

#[cfg(feature = "passkey")]
#[test]
fn passkey_feature_reexports_passkey_crate() {
    let plugin = rustauth::passkey::passkey(rustauth::passkey::PasskeyOptions::default());

    assert_eq!(plugin.id, "passkey");
}

#[cfg(feature = "sso")]
#[test]
fn sso_feature_reexports_sso_crate() {
    let plugin = rustauth::sso::sso(rustauth::sso::SsoOptions::default());

    assert_eq!(plugin.id, "sso");
    assert_eq!(rustauth::sso::UPSTREAM_PLUGIN_ID, "sso");
    assert_eq!(plugin.version.as_deref(), Some(rustauth::sso::VERSION));
}

#[cfg(feature = "oauth-provider")]
#[test]
fn oauth_provider_feature_reexports_oauth_provider_crate() {
    assert_eq!(rustauth::oauth_provider::VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn option_builder_aliases_match_new_constructors() {
    let options = RustAuthOptions::new().rate_limit(
        RateLimitOptions::builder()
            .custom_rule("/login", RateLimitRule::new(time::Duration::seconds(10), 2))
            .hybrid(HybridRateLimitOptions::builder().set_enabled(true)),
    );

    assert_eq!(options.rate_limit.custom_rules[0].path, "/login");
    assert_eq!(
        options.rate_limit.custom_rules[0].rule,
        Some(RateLimitRule {
            window: time::Duration::seconds(10),
            max: 2
        })
    );
    assert!(options.rate_limit.hybrid.enabled);
}

#[test]
fn rate_limit_builders_cover_distributed_and_hybrid_configuration() {
    let database = RateLimitOptions::database(TestRateLimitStore)
        .enabled(true)
        .window(Duration::seconds(30))
        .max(5)
        .hybrid(HybridRateLimitOptions::enabled().local_multiplier(3));
    let secondary = RateLimitOptions::secondary_storage(TestRateLimitStore)
        .enabled(true)
        .window(Duration::seconds(60))
        .max(20);
    let memory = RateLimitOptions::memory()
        .enabled(true)
        .memory_cleanup_interval(Some(std::time::Duration::from_secs(30)));

    assert_eq!(database.storage, RateLimitStorageOption::Database);
    assert!(database.custom_store.is_some());
    assert!(database.hybrid.enabled);
    assert_eq!(database.hybrid.local_multiplier, 3);
    assert_eq!(secondary.storage, RateLimitStorageOption::SecondaryStorage);
    assert!(secondary.custom_store.is_some());
    assert_eq!(
        memory.memory_cleanup_interval,
        Some(std::time::Duration::from_secs(30))
    );
}

#[tokio::test]
async fn rustauth_builder_uses_sqlx_rate_limit_store_with_handler_async(
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let schema = rustauth::db::auth_schema(rustauth::db::AuthSchemaOptions {
        rate_limit_storage: rustauth::db::RateLimitStorage::Database,
        ..rustauth::db::AuthSchemaOptions::default()
    });
    let adapter = rustauth_sqlx::SqliteAdapter::with_schema(pool, schema.clone());
    adapter.create_schema(&schema, None).await?;
    let stores = rustauth_sqlx::SqliteStores {
        adapter: adapter.clone(),
        rate_limit: rustauth_sqlx::SqliteRateLimitStore::from(&adapter),
    };
    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .adapter(stores.adapter)
        .rate_limit(
            RateLimitOptions::database(stores.rate_limit)
                .enabled(true)
                .window(Duration::seconds(60))
                .max(1),
        )
        .build()
        .await?;

    let first = auth
        .handler_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .body(Vec::new())?,
        )
        .await?;
    let second = auth
        .handler_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[tokio::test]
async fn rustauth_builder_initializes_memory_rate_limit_backend(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .rate_limit(
            RateLimitOptions::memory()
                .enabled(true)
                .window(Duration::seconds(60))
                .max(1),
        )
        .build()
        .await?;

    let first = auth
        .handler_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .body(Vec::new())?,
        )
        .await?;
    let second = auth
        .handler_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[tokio::test]
async fn rustauth_builder_initializes_secondary_rate_limit_backend(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .secret("secret-a-at-least-32-chars-long!!")
        .rate_limit(
            RateLimitOptions::secondary_storage(TestRateLimitStore)
                .enabled(true)
                .window(Duration::seconds(60))
                .max(1),
        )
        .build()
        .await?;

    let response = auth
        .handler_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/ok")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn rustauth_crate_reexports_adapter_schema_contracts() -> Result<(), Box<dyn std::error::Error>> {
    let schema = rustauth::db::auth_schema(rustauth::db::AuthSchemaOptions::default());
    let user_table = schema.table("user").ok_or("user table should exist")?;

    assert_eq!(user_table.name, "users");
    assert!(user_table.field("email").is_some());
    Ok(())
}

#[test]
fn rustauth_crate_reexports_error_code_trait() {
    use rustauth::api::ApiErrorCode;
    use rustauth::error_codes::ErrorCode;
    use rustauth::plugin::PluginErrorCode;
    use rustauth_core::auth::email_password::AuthFlowErrorCode;

    fn assert_error_code(code: impl ErrorCode) {
        assert!(!code.as_str().is_empty());
        assert!(!code.message().is_empty());
    }

    assert_error_code(ApiErrorCode::NotFound);
    assert_error_code(AuthFlowErrorCode::InvalidEmail);
    assert_error_code(PluginErrorCode::new("PLUGIN_ERROR", "Plugin error"));
}

#[test]
fn rustauth_crate_reexports_core_primitives() {
    let token = rustauth::crypto::random::generate_random_string(16);

    assert_eq!(token.len(), 16);
}

#[cfg(feature = "oauth")]
#[test]
fn rustauth_crate_reexports_oauth_and_social_provider_packages() {
    let provider = rustauth::oauth::oauth2::OAuthProviderMetadata::new("example", "Example");

    assert_eq!(provider.id(), "example");
    assert!(rustauth::social_providers::PROVIDER_IDS.contains(&"github"));
}

#[cfg(feature = "sqlx")]
#[test]
fn rustauth_crate_reexports_sqlx_adapter_package_behind_feature() {
    let _kind = rustauth::db::MigrationStatementKind::CreateTable;
}

#[cfg(feature = "sqlx-sqlite")]
#[test]
fn rustauth_crate_reexports_sqlx_sqlite_adapter_behind_feature() {
    let type_name = std::any::type_name::<rustauth::sqlx::SqliteAdapter>();

    assert!(type_name.contains("SqliteAdapter"));
}

#[cfg(feature = "tokio-postgres")]
#[test]
fn rustauth_crate_reexports_tokio_postgres_adapter_package_behind_feature() {
    let _constructor = rustauth::tokio_postgres::TokioPostgresAdapter::connect;
}

#[cfg(feature = "deadpool-postgres")]
#[test]
fn rustauth_crate_reexports_deadpool_postgres_adapter_package_behind_feature() {
    let _constructor = rustauth::deadpool_postgres::DeadpoolPostgresAdapter::builder;
}

#[cfg(feature = "plugins")]
#[test]
fn rustauth_crate_reexports_plugins_package_behind_feature() {
    assert!(rustauth::plugins::PLUGIN_IDS.contains(&"generic-oauth"));
}

#[cfg(feature = "plugins")]
#[test]
fn public_api_rustauth_plugins_reexport_exposes_siwe_constructor(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = rustauth::plugins::siwe::siwe(rustauth::plugins::siwe::SiweOptions::new(
        "example.com",
        || async { Ok("nonce".to_owned()) },
        |_args: rustauth::plugins::siwe::SiweVerifyMessageArgs| async { Ok(true) },
    ))?;

    assert_eq!(plugin.id, "siwe");
    assert_eq!(plugin.endpoints.len(), 2);
    Ok(())
}

#[cfg(feature = "oauth")]
#[test]
fn rustauth_crate_accepts_social_oauth_runtime_providers() -> Result<(), Box<dyn std::error::Error>>
{
    let provider: Arc<dyn SocialOAuthProvider> =
        Arc::new(rustauth::social_providers::providers::github(
            rustauth::social_providers::SocialProviderConfig::new("client-id", "client-secret"),
        )?);
    let options = RustAuthOptions {
        social_providers: vec![provider],
        ..RustAuthOptions::default()
    };

    assert_eq!(options.social_providers[0].id(), "github");
    Ok(())
}

#[test]
fn auth_oauth_public_reexports_include_core_types() {
    let user_info = rustauth::auth::oauth::OAuthUserInfo {
        id: "id".to_owned(),
        name: "name".to_owned(),
        email: "user@example.com".to_owned(),
        image: None,
        email_verified: true,
        raw_attributes: None,
    };

    assert_eq!(user_info.email, "user@example.com");
}

#[cfg(feature = "oauth")]
#[test]
fn oauth_public_reexports_include_oauth_crate_helpers() {
    use rustauth::api::PathParams;

    let _authentication = rustauth::oauth::oauth2::ClientAuthentication::Basic;
    let _path_params = PathParams::new(BTreeMap::new());
}

#[cfg(feature = "oauth")]
#[test]
fn rustauth_crate_reexports_oauth_plugin_contract_types() -> Result<(), Box<dyn std::error::Error>>
{
    use rustauth::plugin::PluginInitOutput;

    let provider: Arc<dyn SocialOAuthProvider> =
        Arc::new(rustauth::social_providers::providers::github(
            rustauth::social_providers::SocialProviderConfig::new("client-id", "client-secret"),
        )?);
    let _plugin = AuthPlugin::new("test-plugin").with_social_provider(provider.clone());
    let _plugin_init = PluginInitOutput::new().social_provider(provider);
    Ok(())
}

#[tokio::test]
async fn rustauth_instance_exposes_async_handler() -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..RustAuthOptions::default()
        })
        .build()
        .await?;
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok")
        .body(Vec::new())?;

    let response = auth.handler_async(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"OK");
    Ok(())
}

#[test]
fn rustauth_crate_reexports_core_contract_types() -> Result<(), Box<dyn std::error::Error>> {
    fn _uses_api_request(_request: ApiRequest) {}
    fn _uses_api_response(_response: ApiResponse) {}
    fn _uses_error(_error: RustAuthError) {}

    let _endpoint_type: Option<AuthEndpoint> = None;
    let _async_endpoint_type: Option<AsyncAuthEndpoint> = None;
    let _api_error = ApiErrorResponse {
        code: "TEST".to_owned(),
        message: "test".to_owned(),
        original_message: None,
    };
    let _plugin_endpoint_type: Option<PluginEndpoint> = None;
    let _plugin_error = PluginErrorCode::new("PLUGIN_ERROR", "Plugin error");
    let _plugin_rate_rule = PluginRateLimitRule::new(
        "/plugin/*",
        RateLimitRule {
            window: time::Duration::seconds(10),
            max: 1,
        },
    );
    let _plugin_schema_type: Option<PluginSchemaContribution> = None;
    let _plugin_hooks = PluginEndpointHooks::default();
    let _plugin_matcher = PluginHookMatcher::path("/plugin/*");
    let _hooked_adapter_type: Option<HookedAdapter> = None;
    let memory_adapter = MemoryAdapter::new();
    let _plugin_db_operation = PluginDatabaseOperation::Create;
    let hook_logger = rustauth_core::env::logger::create_logger(
        rustauth_core::env::logger::LoggerOptions::default(),
    );
    let _plugin_db_context = PluginDatabaseHookContext {
        plugin_id: "test-plugin".to_owned(),
        hook_name: "audit".to_owned(),
        operation: PluginDatabaseOperation::Create,
        model: "user".to_owned(),
        adapter: &memory_adapter,
        request_path: None,
        logger: &hook_logger,
    };
    let _plugin_db_before_input: Option<PluginDatabaseBeforeInput> = None;
    let _plugin_db_after_input: Option<PluginDatabaseAfterInput> = None;
    let _plugin_db_before_action =
        PluginDatabaseBeforeAction::Cancel(RustAuthError::Api("blocked".to_owned()));
    let _plugin_db_hook = PluginDatabaseHook::before_create("audit", |_context, query| {
        Ok(PluginDatabaseBeforeAction::Continue(
            PluginDatabaseBeforeInput::Create(query),
        ))
    });
    let _plugin_migration = PluginMigration::new("create_plugin_tables");
    let _before_action_type: Option<PluginBeforeHookAction> = None;
    let _after_action_type: Option<PluginAfterHookAction> = None;
    let _action_type: Option<PluginRequestAction> = None;
    let _trusted_origins = TrustedOriginOptions::default();
    let _rate_limit = RateLimitOptions::default();
    let _rate_limit_input = RateLimitConsumeInput {
        key: "127.0.0.1|/test".to_owned(),
        rule: RateLimitRule {
            window: time::Duration::seconds(10),
            max: 1,
        },
        now_ms: 1_700_000_000_000,
    };
    let _rate_limit_decision = RateLimitDecision {
        permitted: true,
        retry_after: 0,
        limit: 1,
        remaining: 0,
        reset_after: 10,
    };
    let _rate_limit_store: Option<Arc<dyn RateLimitStore>> = None;
    let _user_options = UserOptions {
        change_email: ChangeEmailOptions {
            enabled: true,
            update_email_without_verification: true,
            ..Default::default()
        },
        delete_user: DeleteUserOptions::builder().enabled(true),
        ..UserOptions::default()
    };
    let _email_verification = EmailVerificationOptions::default();
    let _verification_email_type: Option<VerificationEmail> = None;
    let _cookie_strategy = CookieCacheStrategy::Jwe;
    let _memory_storage = rustauth::rate_limit::GovernorMemoryRateLimitStore::new();
    let _session_auth_type: Option<SessionAuth<'_>> = None;
    let _update_user = UpdateUserInput::new().name("Ada").image(None);
    let _route_builder = core_auth_async_endpoints;
    let _endpoint_options = AuthEndpointOptions::new()
        .operation_id("testOperation")
        .body_schema(BodySchema::object([BodyField::new(
            "email",
            JsonSchemaType::String,
        )]))
        .openapi(OpenApiOperation::new("testOperation"));
    let _built_endpoint = create_auth_endpoint(
        "/test",
        Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| async move { rustauth::api::response(StatusCode::OK, Vec::new()) },
    );
    let _sign_out = SignOutResult {
        success: true,
        cookies: Vec::new(),
    };
    Ok(())
}

#[tokio::test]
async fn rustauth_initializer_accepts_extra_endpoints_and_exposes_registry(
) -> Result<(), Box<dyn std::error::Error>> {
    let extra = AuthEndpoint {
        path: "/custom".to_owned(),
        method: Method::GET,
        handler: |_context, _request| rustauth::api::response(StatusCode::OK, b"CUSTOM".to_vec()),
    };
    let async_extra = AsyncAuthEndpoint::new("/async-custom", Method::GET, |_context, _request| {
        Box::pin(async move { rustauth::api::response(StatusCode::OK, b"ASYNC CUSTOM".to_vec()) })
    });
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..RustAuthOptions::default()
        })
        .endpoint(extra)
        .async_endpoint(async_extra)
        .build()
        .await?;

    let registry = auth.endpoint_registry();
    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/ok" && endpoint.kind == EndpointKind::Sync));
    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/custom" && endpoint.kind == EndpointKind::Sync));
    assert!(registry
        .iter()
        .any(|endpoint| endpoint.path == "/async-custom" && endpoint.kind == EndpointKind::Async));

    let sync_response = auth.handler(
        Request::builder()
            .method(Method::GET)
            .uri("http://localhost:3000/api/auth/custom")
            .body(Vec::new())?,
    )?;
    assert_eq!(sync_response.body(), b"CUSTOM");

    let async_response = auth
        .handler_async(
            Request::builder()
                .method(Method::GET)
                .uri("http://localhost:3000/api/auth/async-custom")
                .body(Vec::new())?,
        )
        .await?;
    assert_eq!(async_response.body(), b"ASYNC CUSTOM");
    let openapi = auth.openapi_schema();
    assert_eq!(openapi["openapi"], "3.1.1");
    Ok(())
}

#[tokio::test]
async fn rustauth_initializer_rejects_endpoint_conflicts() -> Result<(), Box<dyn std::error::Error>>
{
    let conflicting = AuthEndpoint {
        path: "/ok".to_owned(),
        method: Method::GET,
        handler: |_context, _request| rustauth::api::response(StatusCode::OK, Vec::new()),
    };

    let result = RustAuth::builder()
        .options(RustAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..RustAuthOptions::default()
        })
        .endpoint(conflicting)
        .build()
        .await;

    assert!(
        matches!(result, Err(RustAuthError::Api(message)) if message.contains("endpoint conflict"))
    );
    Ok(())
}

#[tokio::test]
async fn rustauth_with_adapter_supports_email_password_session_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .options(test_options())
        .adapter(MemoryAdapter::new())
        .build()
        .await?;

    let sign_up = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_up);
    assert!(cookie.contains("rustauth.session_token="));

    let session = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(session.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(session.body())?;
    assert_eq!(body["user"]["email"], "ada@example.com");

    let sign_out = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-out",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(sign_out.status(), StatusCode::OK);
    assert!(set_cookie_values(&sign_out)
        .iter()
        .any(|value| value.starts_with("rustauth.session_token=;")));

    let after = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(after.body())?;
    assert!(body.is_null());
    Ok(())
}

#[tokio::test]
async fn rustauth_with_adapter_runs_database_hooks_for_core_endpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = AuthPlugin::new("profile-hook").with_database_hook(
        PluginDatabaseHook::before_create("rewrite-user-name", |_context, mut query| {
            if query.model == "user" {
                query.data.insert(
                    "name".to_owned(),
                    rustauth::db::DbValue::String("Hooked".to_owned()),
                );
            }
            Ok(PluginDatabaseBeforeAction::Continue(
                PluginDatabaseBeforeInput::Create(query),
            ))
        }),
    );
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            plugins: vec![plugin],
            ..test_options()
        })
        .adapter(MemoryAdapter::new())
        .build()
        .await?;

    let sign_up = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada-hooked@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign_up.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(sign_up.body())?;
    assert_eq!(body["user"]["name"], "Hooked");
    Ok(())
}

#[tokio::test]
async fn rustauth_create_schema_uses_plugin_augmented_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let captured_schema = Arc::new(StdMutex::new(None));
    let adapter = SchemaCapturingAdapter {
        captured_schema: Arc::clone(&captured_schema),
    };
    let plugin = AuthPlugin::new("profile-schema").with_schema(PluginSchemaContribution::field(
        "user",
        "tenant_id",
        rustauth::db::DbField::new("tenant_id", rustauth::db::DbFieldType::String).optional(),
    ));
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            plugins: vec![plugin],
            ..test_options()
        })
        .adapter(adapter)
        .build()
        .await?;

    auth.create_schema(None).await?;

    let schema = captured_schema
        .lock()
        .map_err(|_| RustAuthError::Adapter("schema lock poisoned".to_owned()))?
        .clone()
        .ok_or("schema was not passed to adapter")?;
    let user_table = schema.table("user").ok_or("user table missing")?;
    assert!(user_table.field("tenant_id").is_some());
    Ok(())
}

#[tokio::test]
async fn rustauth_create_schema_includes_database_rate_limit_table(
) -> Result<(), Box<dyn std::error::Error>> {
    let captured_schema = Arc::new(StdMutex::new(None));
    let adapter = SchemaCapturingAdapter {
        captured_schema: Arc::clone(&captured_schema),
    };
    let auth = RustAuth::builder()
        .options(test_options())
        .adapter(adapter)
        .rate_limit(
            RateLimitOptions::database(TestRateLimitStore)
                .enabled(true)
                .window(Duration::seconds(60))
                .max(1),
        )
        .build()
        .await?;

    auth.create_schema(None).await?;

    let schema = captured_schema
        .lock()
        .map_err(|_| RustAuthError::Adapter("schema lock poisoned".to_owned()))?
        .clone()
        .ok_or("schema was not passed to adapter")?;
    let table = schema
        .table("rate_limit")
        .ok_or("rate_limit table missing")?;
    assert_eq!(table.name, "rate_limits");
    assert!(table.field("key").is_some());
    assert!(table.field("count").is_some());
    assert!(table.field("last_request").is_some());
    Ok(())
}

#[tokio::test]
async fn adapter_run_migrations_uses_plugin_augmented_schema_from_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let captured_schema = Arc::new(StdMutex::new(None));
    let adapter: Arc<dyn DbAdapter> = Arc::new(SchemaCapturingAdapter {
        captured_schema: Arc::clone(&captured_schema),
    });
    let plugin = AuthPlugin::new("migration-schema").with_schema(PluginSchemaContribution::field(
        "user",
        "workspace_id",
        rustauth::db::DbField::new("workspace_id", rustauth::db::DbFieldType::String).optional(),
    ));
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            plugins: vec![plugin],
            ..test_options()
        })
        .adapter_arc(Arc::clone(&adapter))
        .build()
        .await?;

    assert!(captured_schema
        .lock()
        .map_err(|_| RustAuthError::Adapter("schema lock poisoned".to_owned()))?
        .is_none());

    let schema = auth.context().db_schema.clone();
    adapter.run_migrations(&schema).await?;

    let schema = captured_schema
        .lock()
        .map_err(|_| RustAuthError::Adapter("schema lock poisoned".to_owned()))?
        .clone()
        .ok_or("migration schema was not passed to adapter")?;
    let user_table = schema.table("user").ok_or("user table missing")?;
    assert!(user_table.field("workspace_id").is_some());
    Ok(())
}

#[tokio::test]
async fn rustauth_run_migrations_applies_sqlite_plugin_schema_and_http_flows(
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let base_schema = rustauth::db::auth_schema(rustauth::db::AuthSchemaOptions::default());
    let adapter: Arc<dyn DbAdapter> = Arc::new(rustauth_sqlx::SqliteAdapter::with_schema(
        pool.clone(),
        base_schema.clone(),
    ));
    adapter.run_migrations(&base_schema).await?;
    let plugin =
        AuthPlugin::new("sqlite-tenant-schema").with_schema(PluginSchemaContribution::field(
            "user",
            "tenant_id",
            rustauth::db::DbField::new("tenant_id", rustauth::db::DbFieldType::String)
                .optional()
                .indexed(),
        ));
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            plugins: vec![plugin],
            ..test_options()
        })
        .adapter_arc(Arc::clone(&adapter))
        .build()
        .await?;

    adapter.run_migrations(&auth.context().db_schema).await?;
    let sign_up = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"sqlite-plugin@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let cookie = cookie_header(&sign_up);
    let session = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;

    let tenant_column_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'tenant_id'",
    )
    .fetch_one(&pool)
    .await?;
    let tenant_index_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_users_tenant_id'",
    )
    .fetch_one(&pool)
    .await?;

    assert_eq!(sign_up.status(), StatusCode::OK);
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(tenant_column_count, 1);
    assert_eq!(tenant_index_count, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires `docker compose up -d postgres`"]
async fn rustauth_run_migrations_applies_postgres_plugin_schema_and_http_flows(
) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = postgres_url_from_env(std::env::var("RUSTAUTH_TEST_POSTGRES_URL").ok());
    let schema_name = unique_sql_prefix();
    let base_schema = rustauth::db::auth_schema(rustauth::db::AuthSchemaOptions::default());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    sqlx::query(&format!("CREATE SCHEMA {schema_name}"))
        .execute(&pool)
        .await?;
    sqlx::query(&format!("SET search_path TO {schema_name}"))
        .execute(&pool)
        .await?;
    let adapter: Arc<dyn DbAdapter> = Arc::new(rustauth_sqlx::PostgresAdapter::with_schema(
        pool.clone(),
        base_schema.clone(),
    ));
    adapter.run_migrations(&base_schema).await?;
    let plugin =
        AuthPlugin::new("postgres-tenant-schema").with_schema(PluginSchemaContribution::field(
            "user",
            "tenant_id",
            rustauth::db::DbField::new("tenant_id", rustauth::db::DbFieldType::String)
                .optional()
                .indexed(),
        ));
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            plugins: vec![plugin],
            ..test_options()
        })
        .adapter_arc(Arc::clone(&adapter))
        .build()
        .await?;

    adapter.run_migrations(&auth.context().db_schema).await?;
    let sign_up = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"postgres-plugin@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let cookie = cookie_header(&sign_up);
    let session = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;

    let users_table = "users";
    let tenant_column_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = 'tenant_id'",
    )
    .bind(users_table)
    .fetch_one(&pool)
    .await?;
    let tenant_index_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND tablename = $1 AND indexname = $2",
    )
    .bind(users_table)
    .bind("idx_users_tenant_id")
    .fetch_one(&pool)
    .await?;

    assert_eq!(sign_up.status(), StatusCode::OK);
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(tenant_column_count, 1);
    assert_eq!(tenant_index_count, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires `docker compose up -d mysql`"]
async fn rustauth_run_migrations_applies_mysql_plugin_schema_and_http_flows(
) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = mysql_url_from_env(std::env::var("RUSTAUTH_TEST_MYSQL_URL").ok());
    let base_schema = rustauth::db::auth_schema(rustauth::db::AuthSchemaOptions::default());
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let adapter: Arc<dyn DbAdapter> = Arc::new(rustauth_sqlx::MySqlAdapter::with_schema(
        pool.clone(),
        base_schema.clone(),
    ));
    adapter.run_migrations(&base_schema).await?;
    let plugin =
        AuthPlugin::new("mysql-tenant-schema").with_schema(PluginSchemaContribution::field(
            "user",
            "tenant_id",
            rustauth::db::DbField::new("tenant_id", rustauth::db::DbFieldType::String)
                .optional()
                .indexed(),
        ));
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            plugins: vec![plugin],
            ..test_options()
        })
        .adapter_arc(Arc::clone(&adapter))
        .build()
        .await?;

    adapter.run_migrations(&auth.context().db_schema).await?;
    let email = format!("mysql-plugin-{}@example.com", unique_sql_prefix());
    let sign_up = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            &format!(r#"{{"name":"Ada","email":"{email}","password":"secret123"}}"#),
            None,
        )?)
        .await?;
    let cookie = cookie_header(&sign_up);
    let session = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;

    let tenant_column_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'tenant_id'",
    )
    .fetch_one(&pool)
    .await?;
    let tenant_index_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'users' AND index_name = 'idx_users_tenant_id'",
    )
    .fetch_one(&pool)
    .await?;

    assert_eq!(sign_up.status(), StatusCode::OK);
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(tenant_column_count, 1);
    assert_eq!(tenant_index_count, 1);
    Ok(())
}

#[tokio::test]
async fn rustauth_create_schema_without_adapter_returns_invalid_config(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder().options(test_options()).build().await?;

    let result = auth.create_schema(None).await;

    assert!(
        matches!(result, Err(RustAuthError::InvalidConfig(message)) if message.contains("requires an adapter-backed instance"))
    );
    Ok(())
}

#[tokio::test]
async fn rustauth_with_adapter_supports_sign_in_and_session_revocation(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .options(test_options())
        .adapter(MemoryAdapter::new())
        .build()
        .await?;
    let _ = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    let sign_in = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_in);

    let sessions = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/list-sessions",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(sessions.body())?;
    let token = body
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item.get("token"))
        .and_then(Value::as_str)
        .ok_or("missing listed session token")?;

    let revoke = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/revoke-session",
            &format!(r#"{{"token":"{token}"}}"#),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(revoke.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(revoke.body())?;
    assert_eq!(body["status"], true);
    Ok(())
}

#[tokio::test]
async fn rustauth_with_adapter_supports_update_session_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .options(RustAuthOptions {
            session: SessionOptions {
                additional_fields: BTreeMap::from([(
                    "theme".to_owned(),
                    SessionAdditionalField::new(rustauth::db::DbFieldType::String),
                )]),
                ..SessionOptions::default()
            },
            ..test_options()
        })
        .adapter(MemoryAdapter::new())
        .build()
        .await?;
    let sign_up = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header(&sign_up);

    let updated = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{"theme":"dark"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(updated.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(updated.body())?;
    assert_eq!(body["session"]["theme"], "dark");

    let session = auth
        .handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(session.body())?;
    assert_eq!(body["session"]["theme"], "dark");
    Ok(())
}

#[tokio::test]
async fn rustauth_with_adapter_supports_bulk_and_other_session_revocation(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = RustAuth::builder()
        .options(test_options())
        .adapter(MemoryAdapter::new())
        .build()
        .await?;
    let first = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let first_cookie = cookie_header(&first);
    let second = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    let second_cookie = cookie_header(&second);

    let revoke_other = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/revoke-other-sessions",
            "",
            Some(&second_cookie),
        )?)
        .await?;
    assert_eq!(revoke_other.status(), StatusCode::OK);
    let first_after: Value = serde_json::from_slice(
        auth.handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&first_cookie),
        )?)
        .await?
        .body(),
    )?;
    assert!(first_after.is_null());

    let revoke_all = auth
        .handler_async(json_request(
            Method::POST,
            "/api/auth/revoke-sessions",
            "",
            Some(&second_cookie),
        )?)
        .await?;
    assert_eq!(revoke_all.status(), StatusCode::OK);
    let second_after: Value = serde_json::from_slice(
        auth.handler_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&second_cookie),
        )?)
        .await?
        .body(),
    )?;
    assert!(second_after.is_null());
    Ok(())
}

#[tokio::test]
async fn rustauth_with_adapter_rejects_core_endpoint_conflicts(
) -> Result<(), Box<dyn std::error::Error>> {
    let conflicting = AuthEndpoint {
        path: "/ok".to_owned(),
        method: Method::GET,
        handler: |_context, _request| rustauth::api::response(StatusCode::OK, Vec::new()),
    };

    let result = RustAuth::builder()
        .options(test_options())
        .adapter(MemoryAdapter::new())
        .endpoint(conflicting)
        .build()
        .await;

    assert!(
        matches!(result, Err(RustAuthError::Api(message)) if message.contains("endpoint conflict"))
    );
    Ok(())
}

fn test_options() -> RustAuthOptions {
    rustauth_core::test_utils::with_integration_test_defaults(RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..RustAuthOptions::default()
    })
}

fn unique_sql_prefix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_default();
    let process = std::process::id() & 0xffff;
    let sequence = SQL_TEST_ID.fetch_add(1, Ordering::Relaxed) & 0xfff;
    format!(
        "oa_public_{process:x}_{:08x}_{sequence:x}",
        nanos & 0xffff_ffff
    )
}

fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

fn cookie_header(response: &http::Response<Vec<u8>>) -> String {
    set_cookie_values(response)
        .into_iter()
        .filter_map(|value| value.split_once(';').map(|(cookie, _)| cookie.to_owned()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

struct SchemaCapturingAdapter {
    captured_schema: Arc<StdMutex<Option<rustauth::db::DbSchema>>>,
}

struct TestRateLimitStore;

impl RateLimitStore for TestRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            Ok(RateLimitDecision {
                permitted: true,
                retry_after: 0,
                limit: input.rule.max,
                remaining: input.rule.max.saturating_sub(1),
                reset_after: input.rule.window.whole_seconds() as u64,
            })
        })
    }
}

impl rustauth::db::DbAdapter for SchemaCapturingAdapter {
    fn id(&self) -> &str {
        "schema-capture"
    }

    fn capabilities(&self) -> rustauth::db::AdapterCapabilities {
        rustauth::db::AdapterCapabilities::new(self.id())
    }

    fn create<'a>(
        &'a self,
        _query: rustauth::db::Create,
    ) -> rustauth::db::AdapterFuture<'a, rustauth::db::DbRecord> {
        Box::pin(async { Ok(rustauth::db::DbRecord::new()) })
    }

    fn find_one<'a>(
        &'a self,
        _query: rustauth::db::FindOne,
    ) -> rustauth::db::AdapterFuture<'a, Option<rustauth::db::DbRecord>> {
        Box::pin(async { Ok(None) })
    }

    fn find_many<'a>(
        &'a self,
        _query: rustauth::db::FindMany,
    ) -> rustauth::db::AdapterFuture<'a, Vec<rustauth::db::DbRecord>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn count<'a>(&'a self, _query: rustauth::db::Count) -> rustauth::db::AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn update<'a>(
        &'a self,
        _query: rustauth::db::Update,
    ) -> rustauth::db::AdapterFuture<'a, Option<rustauth::db::DbRecord>> {
        Box::pin(async { Ok(None) })
    }

    fn update_many<'a>(
        &'a self,
        _query: rustauth::db::UpdateMany,
    ) -> rustauth::db::AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn delete<'a>(&'a self, _query: rustauth::db::Delete) -> rustauth::db::AdapterFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn delete_many<'a>(
        &'a self,
        _query: rustauth::db::DeleteMany,
    ) -> rustauth::db::AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn transaction<'a>(
        &'a self,
        callback: rustauth::db::TransactionCallback<'a>,
    ) -> rustauth::db::AdapterFuture<'a, ()> {
        callback(Box::new(self))
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a rustauth::db::DbSchema,
        _file: Option<&'a str>,
    ) -> rustauth::db::AdapterFuture<'a, Option<rustauth::db::SchemaCreation>> {
        Box::pin(async move {
            self.captured_schema
                .lock()
                .map_err(|_| RustAuthError::Adapter("schema lock poisoned".to_owned()))?
                .replace(schema.clone());
            Ok(None)
        })
    }

    fn run_migrations<'a>(
        &'a self,
        schema: &'a rustauth::db::DbSchema,
    ) -> rustauth::db::AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.captured_schema
                .lock()
                .map_err(|_| RustAuthError::Adapter("schema lock poisoned".to_owned()))?
                .replace(schema.clone());
            Ok(())
        })
    }
}
