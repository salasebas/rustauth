use std::collections::HashMap;
use std::env;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use openauth::db::{
    auth_schema, AuthSchemaOptions, Count, DbAdapter, DbRecord, DbSchema, DbValue, DeleteMany,
    FindMany, RateLimitStorage,
};
use openauth::plugin::AuthPlugin;
use openauth::rate_limit::GovernorMemoryRateLimitStore;
use openauth::{
    AdvancedOptions, EmailPasswordOptions, EndpointInfo, HybridRateLimitOptions, OpenAuth,
    OpenAuthError, OpenAuthOptions, RateLimitOptions, RateLimitRule, RateLimitStore,
};
use openauth_axum::OpenAuthAxumExt;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_deadpool_postgres::{DeadpoolPostgresAdapter, DeadpoolPostgresStores};
use openauth_fred::FredOpenAuthStores;
use openauth_redis::RedisOpenAuthStores;
use openauth_sqlx::{
    MySqlAdapter, MySqlStores, PostgresAdapter, PostgresStores, SqliteAdapter, SqliteStores,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

mod seed;

const AUTH_BASE_PATH: &str = "/api/axum/auth";
const PROFILE_AUTH_PATH_PREFIX: &str = "/api/example/auth/";
const DEFAULT_SECRET: &str = "openauth-example-dev-secret-at-least-32-chars";
const RATE_LIMIT_WINDOW_HEADER: &str = "x-openauth-example-rate-window";
const RATE_LIMIT_MAX_HEADER: &str = "x-openauth-example-rate-max";
const RATE_LIMIT_ENABLED_HEADER: &str = "x-openauth-example-rate-enabled";
const PREFERENCES_KEY: &str = "openauth:full-app:preferences";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DbBackend {
    Memory,
    Sqlite,
    PostgresSqlx,
    PostgresDeadpool,
    MysqlSqlx,
}

impl DbBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Sqlite => "sqlite",
            Self::PostgresSqlx => "postgres-sqlx",
            Self::PostgresDeadpool => "postgres-deadpool",
            Self::MysqlSqlx => "mysql-sqlx",
        }
    }

    fn default_database_url(self) -> String {
        match self {
            Self::Memory => String::new(),
            Self::Sqlite => "sqlite://examples/full-app/data/openauth.sqlite".to_owned(),
            Self::PostgresSqlx | Self::PostgresDeadpool => {
                "postgres://user:password@127.0.0.1:5432/openauth".to_owned()
            }
            Self::MysqlSqlx => "mysql://user:password@127.0.0.1:3306/openauth".to_owned(),
        }
    }

    fn per_backend_database_url_env(self) -> Option<&'static str> {
        match self {
            Self::Memory => None,
            Self::Sqlite => Some("OPENAUTH_EXAMPLE_SQLITE_DATABASE_URL"),
            Self::PostgresSqlx | Self::PostgresDeadpool => {
                Some("OPENAUTH_EXAMPLE_POSTGRES_DATABASE_URL")
            }
            Self::MysqlSqlx => Some("OPENAUTH_EXAMPLE_MYSQL_DATABASE_URL"),
        }
    }

    /// Backends that point at the same physical database. Dropping the schema
    /// through one of them must invalidate cached state for all of them.
    fn shared_database_backends(self) -> &'static [DbBackend] {
        match self {
            Self::PostgresSqlx | Self::PostgresDeadpool => {
                &[Self::PostgresSqlx, Self::PostgresDeadpool]
            }
            Self::Memory => &[Self::Memory],
            Self::Sqlite => &[Self::Sqlite],
            Self::MysqlSqlx => &[Self::MysqlSqlx],
        }
    }
}

impl FromStr for DbBackend {
    type Err = ExampleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "memory" => Ok(Self::Memory),
            "sqlite" => Ok(Self::Sqlite),
            "postgres" | "postgresql" | "postgres-sqlx" => Ok(Self::PostgresSqlx),
            "postgres-deadpool" | "deadpool-postgres" => Ok(Self::PostgresDeadpool),
            "mysql" | "mysql-sqlx" => Ok(Self::MysqlSqlx),
            other => Err(ExampleError::InvalidConfig(format!(
                "unsupported OPENAUTH_EXAMPLE_DB `{other}`; use memory, sqlite, postgres-sqlx, postgres-deadpool, or mysql-sqlx"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitBackend {
    Memory,
    Database,
    Redis,
    Valkey,
    HybridRedis,
    HybridValkey,
    FredRedis,
    FredValkey,
}

impl RateLimitBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Database => "database",
            Self::Redis => "redis",
            Self::Valkey => "valkey",
            Self::HybridRedis => "hybrid-redis",
            Self::HybridValkey => "hybrid-valkey",
            Self::FredRedis => "fred-redis",
            Self::FredValkey => "fred-valkey",
        }
    }
}

impl FromStr for RateLimitBackend {
    type Err = ExampleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "memory" => Ok(Self::Memory),
            "database" | "sql" => Ok(Self::Database),
            "redis" => Ok(Self::Redis),
            "valkey" => Ok(Self::Valkey),
            "hybrid-redis" => Ok(Self::HybridRedis),
            "hybrid-valkey" => Ok(Self::HybridValkey),
            "fred-redis" => Ok(Self::FredRedis),
            "fred-valkey" => Ok(Self::FredValkey),
            other => Err(ExampleError::InvalidConfig(format!(
                "unsupported OPENAUTH_EXAMPLE_RATE_LIMIT `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExampleConfig {
    pub host: String,
    pub port: u16,
    pub base_url: String,
    pub secret: String,
    pub db: DbBackend,
    pub rate_limit: RateLimitBackend,
    pub rate_limit_enabled: bool,
    pub rate_limit_window: u64,
    pub rate_limit_max: u64,
    pub database_url: String,
    /// Explicit URLs keyed by SQL backend. Populated from `DATABASE_URL` (startup
    /// backend) and optional `OPENAUTH_EXAMPLE_*_DATABASE_URL` overrides.
    database_urls: HashMap<DbBackend, String>,
    /// When false, alternate backend selection fails unless that backend has an
    /// entry in [`Self::database_urls`].
    allow_default_database_urls: bool,
    pub redis_url: String,
    pub valkey_url: String,
    /// Enables the example's privileged control plane (database viewer, schema
    /// reset, dynamic profile rate-limit header overrides). Secure by default:
    /// only on for loopback binds unless `OPENAUTH_EXAMPLE_DEV_CONTROLS` is set.
    pub dev_controls: bool,
}

impl ExampleConfig {
    pub fn from_env() -> Result<Self, ExampleError> {
        let host = env_or("OPENAUTH_EXAMPLE_HOST", "127.0.0.1");
        let port = env_or("OPENAUTH_EXAMPLE_PORT", "3000")
            .parse::<u16>()
            .map_err(|error| {
                ExampleError::InvalidConfig(format!("OPENAUTH_EXAMPLE_PORT is invalid: {error}"))
            })?;
        let default_base_url = format!("http://{host}:{port}{AUTH_BASE_PATH}");
        let base_url = env::var("OPENAUTH_EXAMPLE_BASE_URL").unwrap_or(default_base_url);
        validate_example_base_url(&base_url)?;
        let secret = env::var("OPENAUTH_SECRET").unwrap_or_else(|_| DEFAULT_SECRET.to_owned());
        let db = env_or("OPENAUTH_EXAMPLE_DB", "sqlite").parse::<DbBackend>()?;
        let rate_limit =
            env_or("OPENAUTH_EXAMPLE_RATE_LIMIT", "memory").parse::<RateLimitBackend>()?;
        let rate_limit_enabled = env_or("OPENAUTH_EXAMPLE_RATE_LIMIT_ENABLED", "true")
            .parse::<bool>()
            .map_err(|error| {
                ExampleError::InvalidConfig(format!(
                    "OPENAUTH_EXAMPLE_RATE_LIMIT_ENABLED is invalid: {error}"
                ))
            })?;
        let rate_limit_window = env_or("OPENAUTH_EXAMPLE_RATE_LIMIT_WINDOW", "60")
            .parse::<u64>()
            .map_err(|error| {
                ExampleError::InvalidConfig(format!(
                    "OPENAUTH_EXAMPLE_RATE_LIMIT_WINDOW is invalid: {error}"
                ))
            })?;
        let rate_limit_max = env_or("OPENAUTH_EXAMPLE_RATE_LIMIT_MAX", "120")
            .parse::<u64>()
            .map_err(|error| {
                ExampleError::InvalidConfig(format!(
                    "OPENAUTH_EXAMPLE_RATE_LIMIT_MAX is invalid: {error}"
                ))
            })?;
        let (database_url, database_urls, allow_default_database_urls) = load_database_urls(db)?;
        let redis_url = env_or("REDIS_URL", "redis://127.0.0.1:6379");
        let valkey_url = env_or("VALKEY_URL", "valkey://127.0.0.1:6380");
        let dev_controls = match env::var("OPENAUTH_EXAMPLE_DEV_CONTROLS") {
            Ok(value) => value.parse::<bool>().map_err(|error| {
                ExampleError::InvalidConfig(format!(
                    "OPENAUTH_EXAMPLE_DEV_CONTROLS is invalid: {error}"
                ))
            })?,
            Err(_) => is_loopback_host(&host),
        };

        Ok(Self {
            host,
            port,
            base_url,
            secret,
            db,
            rate_limit,
            rate_limit_enabled,
            rate_limit_window,
            rate_limit_max,
            database_url,
            database_urls,
            allow_default_database_urls,
            redis_url,
            valkey_url,
            dev_controls,
        })
    }

    pub fn database_url_for(&self, db: DbBackend) -> Result<String, ExampleError> {
        match db {
            DbBackend::Memory => Ok(String::new()),
            db => {
                if let Some(url) = self.database_urls.get(&db) {
                    return Ok(url.clone());
                }
                if self.allow_default_database_urls {
                    Ok(db.default_database_url())
                } else {
                    Err(ExampleError::InvalidConfig(format!(
                        "no database URL configured for backend `{}`; set DATABASE_URL when it is the startup backend (`OPENAUTH_EXAMPLE_DB`) or `{}`",
                        db.as_str(),
                        db.per_backend_database_url_env()
                            .unwrap_or("OPENAUTH_EXAMPLE_DATABASE_URL"),
                    )))
                }
            }
        }
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ExampleError> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|error| {
                ExampleError::InvalidConfig(format!("listen address is invalid: {error}"))
            })
    }
}

#[derive(Debug)]
pub enum ExampleError {
    InvalidConfig(String),
    Io(std::io::Error),
    OpenAuth(OpenAuthError),
    Axum(openauth_axum::OpenAuthAxumError),
    Redis(redis::RedisError),
    Sqlx(sqlx::Error),
}

impl fmt::Display for ExampleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::OpenAuth(error) => write!(formatter, "{error}"),
            Self::Axum(error) => write!(formatter, "{error}"),
            Self::Redis(error) => write!(formatter, "{error}"),
            Self::Sqlx(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ExampleError {}

impl From<std::io::Error> for ExampleError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<OpenAuthError> for ExampleError {
    fn from(error: OpenAuthError) -> Self {
        Self::OpenAuth(error)
    }
}

impl From<openauth_axum::OpenAuthAxumError> for ExampleError {
    fn from(error: openauth_axum::OpenAuthAxumError) -> Self {
        Self::Axum(error)
    }
}

impl From<redis::RedisError> for ExampleError {
    fn from(error: redis::RedisError) -> Self {
        Self::Redis(error)
    }
}

impl From<sqlx::Error> for ExampleError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sqlx(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProfileKey {
    db: DbBackend,
    rate_limit: RateLimitBackend,
    rate_limit_enabled: bool,
    rate_limit_window: u64,
    rate_limit_max: u64,
}

#[derive(Default)]
struct ProfileCache {
    entries: tokio::sync::Mutex<HashMap<ProfileKey, Arc<OpenAuth>>>,
    build_count: AtomicU64,
}

impl ProfileCache {
    async fn get_or_insert<F, Fut>(
        &self,
        key: ProfileKey,
        build: F,
    ) -> Result<Arc<OpenAuth>, ExampleError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<OpenAuth, ExampleError>>,
    {
        let mut entries = self.entries.lock().await;
        if let Some(auth) = entries.get(&key) {
            return Ok(Arc::clone(auth));
        }

        let auth = Arc::new(build().await?);
        self.build_count.fetch_add(1, Ordering::SeqCst);
        entries.insert(key, Arc::clone(&auth));
        Ok(auth)
    }

    async fn invalidate_db(&self, db: DbBackend) {
        self.entries.lock().await.retain(|key, _| key.db != db);
    }

    #[cfg(test)]
    fn build_count(&self) -> u64 {
        self.build_count.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct ViewerAdapterCache {
    entries: tokio::sync::Mutex<HashMap<DbBackend, Arc<dyn DbAdapter>>>,
    migrated: tokio::sync::Mutex<HashMap<DbBackend, ()>>,
    connect_count: AtomicU64,
}

impl ViewerAdapterCache {
    async fn get_or_connect(
        &self,
        db: DbBackend,
        database_url: &str,
        schema: &DbSchema,
    ) -> Result<Arc<dyn DbAdapter>, ExampleError> {
        let mut entries = self.entries.lock().await;
        if let Some(adapter) = entries.get(&db) {
            return Ok(Arc::clone(adapter));
        }

        let adapter = self.connect(db, database_url, schema).await?;
        self.connect_count.fetch_add(1, Ordering::SeqCst);
        entries.insert(db, Arc::clone(&adapter));
        Ok(adapter)
    }

    /// Connects and ensures migrations ran once for this cached adapter.
    async fn get_or_connect_migrated(
        &self,
        db: DbBackend,
        database_url: &str,
        schema: &DbSchema,
    ) -> Result<Arc<dyn DbAdapter>, ExampleError> {
        let adapter = self.get_or_connect(db, database_url, schema).await?;
        let mut migrated = self.migrated.lock().await;
        if migrated.contains_key(&db) {
            return Ok(adapter);
        }
        adapter.run_migrations(schema).await?;
        migrated.insert(db, ());
        Ok(adapter)
    }

    async fn connect(
        &self,
        db: DbBackend,
        database_url: &str,
        _schema: &DbSchema,
    ) -> Result<Arc<dyn DbAdapter>, ExampleError> {
        if db == DbBackend::Memory {
            return Err(ExampleError::InvalidConfig(
                "memory adapters are not cached in the viewer adapter cache".to_owned(),
            ));
        }
        connect_sql_adapter(db, database_url).await
    }

    async fn invalidate_db(&self, db: DbBackend) {
        self.entries.lock().await.remove(&db);
        self.migrated.lock().await.remove(&db);
    }

    #[cfg(test)]
    fn connect_count(&self) -> u64 {
        self.connect_count.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
struct AppState {
    config: ExampleConfig,
    runtime: RuntimeInfo,
    endpoints: Vec<EndpointView>,
    openapi: serde_json::Value,
    services: Vec<ServiceStatus>,
    memory_adapter: openauth::MemoryAdapter,
    memory_rate_limit_store: Arc<GovernorMemoryRateLimitStore>,
    profile_cache: Arc<ProfileCache>,
    viewer_adapter_cache: Arc<ViewerAdapterCache>,
    /// In-process preferences when Redis is unreachable (demo fallback).
    preferences_store: Arc<Mutex<Option<ExamplePreferences>>>,
    dev_controls: bool,
}

#[derive(Clone, Serialize)]
struct RuntimeInfo {
    openauth_version: String,
    framework: String,
    auth_base_path: String,
    db_backend: String,
    rate_limit_backend: String,
    rate_limit_enabled: bool,
    rate_limit_window: u64,
    rate_limit_max: u64,
    base_url: String,
    database_url: String,
    redis_url: String,
    valkey_url: String,
}

#[derive(Clone, Serialize)]
struct EndpointView {
    method: String,
    path: String,
    kind: String,
    operation_id: String,
    media_types: Vec<String>,
}

#[derive(Clone, Serialize)]
struct ServiceStatus {
    id: String,
    label: String,
    host: String,
    port: u16,
    available: bool,
}

#[derive(Debug, Clone, Serialize)]
struct TableColumnView {
    name: String,
    physical_name: String,
    kind: String,
    hidden: bool,
    required: bool,
}

#[derive(Debug, Clone, Serialize)]
struct TableSummaryView {
    id: String,
    name: String,
    columns: Vec<TableColumnView>,
}

#[derive(Debug, Clone, Serialize)]
struct TableRowsView {
    db: String,
    table: String,
    page: usize,
    page_size: usize,
    total: u64,
    columns: Vec<TableColumnView>,
    rows: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct TableQuery {
    db: Option<String>,
    table: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
    q: Option<String>,
    columns: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DbQuery {
    db: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReferenceQuery {
    theme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExamplePreferences {
    db: String,
    rate_limit: String,
}

impl ExamplePreferences {
    fn from_config(config: &ExampleConfig) -> Self {
        Self {
            db: config.db.as_str().to_owned(),
            rate_limit: config.rate_limit.as_str().to_owned(),
        }
    }

    fn validate(&self) -> Result<(), ExampleError> {
        self.db.parse::<DbBackend>()?;
        self.rate_limit.parse::<RateLimitBackend>()?;
        Ok(())
    }
}

pub fn app() -> Router {
    static_app(demo_runtime(), true)
}

/// Hardened variant of [`app`] with the privileged control plane disabled,
/// mirroring a non-loopback deployment (`dev_controls = false`). Used by tests
/// and as a reference for the secure-by-default behavior.
pub fn app_hardened() -> Router {
    static_app(demo_runtime(), false)
}

/// Injects a loopback client IP for integration tests that invoke the router
/// through `tower::ServiceExt::oneshot` without Axum `ConnectInfo`.
#[doc(hidden)]
pub fn smoke_request<B>(mut request: axum::http::Request<B>) -> axum::http::Request<B> {
    use std::net::{IpAddr, Ipv4Addr};
    request
        .extensions_mut()
        .insert(openauth::RequestClientIp(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    request
}

fn demo_runtime() -> RuntimeInfo {
    RuntimeInfo {
        openauth_version: openauth::VERSION.to_owned(),
        framework: "axum".to_owned(),
        auth_base_path: AUTH_BASE_PATH.to_owned(),
        db_backend: "test".to_owned(),
        rate_limit_backend: "test".to_owned(),
        rate_limit_enabled: true,
        rate_limit_window: 60,
        rate_limit_max: 120,
        base_url: format!("http://127.0.0.1:3000{AUTH_BASE_PATH}"),
        database_url: String::new(),
        redis_url: "redis://127.0.0.1:6379".to_owned(),
        valkey_url: "valkey://127.0.0.1:6380".to_owned(),
    }
}

pub async fn app_from_env() -> Result<Router, ExampleError> {
    build_app(ExampleConfig::from_env()?).await
}

pub async fn build_app(config: ExampleConfig) -> Result<Router, ExampleError> {
    ensure_sqlite_parent(&config)?;
    let memory_rate_limit_store = Arc::new(GovernorMemoryRateLimitStore::new());

    match config.db {
        DbBackend::Memory => {
            let auth = build_auth(
                config.clone(),
                AUTH_BASE_PATH.to_owned(),
                openauth::MemoryAdapter::new(),
                None,
                memory_rate_limit_store.clone(),
            )
            .await?;
            Ok(router_with_auth(auth, &config, memory_rate_limit_store).await?)
        }
        DbBackend::Sqlite => {
            let stores =
                SqliteStores::connect_with_schema(&config.database_url, example_auth_schema()?)
                    .await?;
            let rate_limit = match config.rate_limit {
                RateLimitBackend::Database => {
                    Some(RateLimitOptions::database(stores.rate_limit.clone()))
                }
                _ => None,
            };
            let auth = build_auth(
                config.clone(),
                AUTH_BASE_PATH.to_owned(),
                stores.adapter,
                rate_limit,
                memory_rate_limit_store.clone(),
            )
            .await?;
            auth.run_migrations().await?;
            Ok(router_with_auth(auth, &config, memory_rate_limit_store).await?)
        }
        DbBackend::PostgresSqlx => {
            let stores =
                PostgresStores::connect_with_schema(&config.database_url, example_auth_schema()?)
                    .await?;
            let rate_limit = match config.rate_limit {
                RateLimitBackend::Database => {
                    Some(RateLimitOptions::database(stores.rate_limit.clone()))
                }
                _ => None,
            };
            let auth = build_auth(
                config.clone(),
                AUTH_BASE_PATH.to_owned(),
                stores.adapter,
                rate_limit,
                memory_rate_limit_store.clone(),
            )
            .await?;
            auth.run_migrations().await?;
            Ok(router_with_auth(auth, &config, memory_rate_limit_store).await?)
        }
        DbBackend::PostgresDeadpool => {
            let stores = DeadpoolPostgresStores::connect_with_schema_checked(
                &config.database_url,
                example_auth_schema()?,
            )
            .await?;
            let rate_limit = match config.rate_limit {
                RateLimitBackend::Database => {
                    Some(RateLimitOptions::database(stores.rate_limit.clone()))
                }
                _ => None,
            };
            let auth = build_auth(
                config.clone(),
                AUTH_BASE_PATH.to_owned(),
                stores.adapter,
                rate_limit,
                memory_rate_limit_store.clone(),
            )
            .await?;
            auth.run_migrations().await?;
            Ok(router_with_auth(auth, &config, memory_rate_limit_store).await?)
        }
        DbBackend::MysqlSqlx => {
            let stores =
                MySqlStores::connect_with_schema(&config.database_url, example_auth_schema()?)
                    .await?;
            let rate_limit = match config.rate_limit {
                RateLimitBackend::Database => {
                    Some(RateLimitOptions::database(stores.rate_limit.clone()))
                }
                _ => None,
            };
            let auth = build_auth(
                config.clone(),
                AUTH_BASE_PATH.to_owned(),
                stores.adapter,
                rate_limit,
                memory_rate_limit_store.clone(),
            )
            .await?;
            auth.run_migrations().await?;
            Ok(router_with_auth(auth, &config, memory_rate_limit_store).await?)
        }
    }
}

fn example_plugins(
    adapter: Arc<dyn openauth::db::DbAdapter>,
) -> Result<Vec<AuthPlugin>, ExampleError> {
    use openauth::oauth_provider::{oauth_provider, McpOptions, OAuthProviderOptions};
    use openauth::passkey::{passkey, PasskeyOptions};
    use openauth::plugins::{
        admin::{admin, AdminOptions},
        anonymous::{anonymous, AnonymousOptions},
        api_key::api_key,
        bearer::bearer,
        custom_session::custom_session,
        device_authorization::device_authorization,
        email_otp::{email_otp, EmailOtpOptions},
        haveibeenpwned::{have_i_been_pwned_with_options, HaveIBeenPwnedOptions},
        jwt::jwt,
        last_login_method::{last_login_method, LastLoginMethodOptions},
        magic_link::{magic_link, MagicLinkOptions},
        multi_session::multi_session,
        oauth_proxy::oauth_proxy_default,
        one_tap::{one_tap, OneTapOptions},
        one_time_token::one_time_token,
        open_api::{open_api, OpenApiOptions},
        organization::organization,
        phone_number::{phone_number, PhoneNumberOptions},
        siwe::{siwe, SiweOptions},
        two_factor::{two_factor, TwoFactorOptions},
        username::username,
    };
    use openauth::scim::{scim, ScimOptions};
    use openauth::sso::{sso, SsoOptions};
    use openauth::stripe::{
        stripe, OrganizationStripeOptions, StripeClient, StripeOptions, SubscriptionOptions,
    };
    use std::future;

    Ok(vec![
        admin(AdminOptions::default()),
        anonymous(AnonymousOptions::default()),
        api_key(),
        bearer(),
        // CAPTCHA is omitted: its `UNKNOWN_ERROR` code conflicts with `passkey`.
        custom_session(|input| Box::pin(future::ready(Ok(input.session)))),
        device_authorization(),
        email_otp(adapter.clone(), EmailOtpOptions::default()),
        // `generic-oauth` is omitted: its `SESSION_REQUIRED` code conflicts with `passkey`.
        have_i_been_pwned_with_options(HaveIBeenPwnedOptions {
            enabled: false,
            ..HaveIBeenPwnedOptions::default()
        }),
        jwt().map_err(ExampleError::from)?,
        last_login_method(LastLoginMethodOptions::default()),
        magic_link(MagicLinkOptions::new(|_email| {
            Box::pin(future::ready(Ok(())))
        })),
        oauth_provider(OAuthProviderOptions {
            login_page: "/".to_owned(),
            consent_page: "/".to_owned(),
            disable_jwt_plugin: true,
            allow_dynamic_client_registration: true,
            mcp: Some(McpOptions::default()),
            ..OAuthProviderOptions::default()
        })
        .map_err(|error| ExampleError::InvalidConfig(error.to_string()))?,
        multi_session(),
        oauth_proxy_default(),
        one_tap(OneTapOptions::default()),
        one_time_token(),
        open_api(OpenApiOptions::default()),
        organization(),
        phone_number(adapter.clone(), PhoneNumberOptions::default()),
        siwe(SiweOptions::new(
            "localhost",
            || async { Ok("openauth-example-nonce".to_owned()) },
            |_args| async { Ok(true) },
        ))
        .map_err(ExampleError::from)?,
        two_factor(TwoFactorOptions::default()),
        username(),
        passkey(PasskeyOptions::default()),
        sso(SsoOptions::default()),
        scim(ScimOptions::default()),
        stripe(
            StripeOptions::new(StripeClient::new("sk_test"), "whsec_openauth_example_dev")
                .subscription(SubscriptionOptions {
                    enabled: true,
                    plans: Arc::new(Vec::new()),
                    get_plans: None,
                    require_email_verification: false,
                    authorize_reference: None,
                    on_subscription_complete: None,
                    on_subscription_created: None,
                    on_subscription_update: None,
                    on_subscription_cancel: None,
                    on_subscription_deleted: None,
                    get_checkout_session_params: None,
                })
                .organization(OrganizationStripeOptions::enabled()),
        ),
    ])
}

fn example_db_schema(
    adapter: Arc<dyn openauth::db::DbAdapter>,
) -> Result<openauth::db::DbSchema, ExampleError> {
    Ok(
        create_auth_context_with_adapter(example_open_auth_options(adapter.clone())?, adapter)?
            .db_schema,
    )
}

/// Plugin-augmented schema used by the example's SQL adapters and viewer.
fn example_auth_schema() -> Result<openauth::db::DbSchema, ExampleError> {
    example_db_schema(Arc::new(openauth::MemoryAdapter::new()))
}

async fn open_sqlite_adapter(database_url: &str) -> Result<SqliteAdapter, ExampleError> {
    Ok(SqliteAdapter::connect_with_schema(database_url, example_auth_schema()?).await?)
}

async fn open_postgres_sqlx_adapter(database_url: &str) -> Result<PostgresAdapter, ExampleError> {
    Ok(PostgresAdapter::connect_with_schema(database_url, example_auth_schema()?).await?)
}

async fn open_postgres_deadpool_adapter(
    database_url: &str,
) -> Result<DeadpoolPostgresAdapter, ExampleError> {
    Ok(DeadpoolPostgresAdapter::builder()
        .database_url(database_url)
        .schema(example_auth_schema()?)
        .checked(true)
        .connect()
        .await?)
}

async fn open_mysql_sqlx_adapter(database_url: &str) -> Result<MySqlAdapter, ExampleError> {
    Ok(MySqlAdapter::connect_with_schema(database_url, example_auth_schema()?).await?)
}

async fn connect_sql_adapter(
    db: DbBackend,
    database_url: &str,
) -> Result<Arc<dyn openauth::db::DbAdapter>, ExampleError> {
    let adapter: Arc<dyn openauth::db::DbAdapter> = match db {
        DbBackend::Sqlite => Arc::new(open_sqlite_adapter(database_url).await?),
        DbBackend::PostgresSqlx => Arc::new(open_postgres_sqlx_adapter(database_url).await?),
        DbBackend::PostgresDeadpool => {
            Arc::new(open_postgres_deadpool_adapter(database_url).await?)
        }
        DbBackend::MysqlSqlx => Arc::new(open_mysql_sqlx_adapter(database_url).await?),
        DbBackend::Memory => {
            return Err(ExampleError::InvalidConfig(
                "memory adapters are not opened through connect_sql_adapter".to_owned(),
            ));
        }
    };
    Ok(adapter)
}

fn example_open_auth_options(
    adapter: Arc<dyn openauth::db::DbAdapter>,
) -> Result<OpenAuthOptions, ExampleError> {
    let mut options = OpenAuthOptions::new()
        .secret(DEFAULT_SECRET.to_owned())
        .email_password(EmailPasswordOptions::new().enabled(true))
        .plugins(example_plugins(adapter)?);
    #[cfg(debug_assertions)]
    {
        options = openauth_core::test_utils::apply_fast_password_defaults(options);
    }
    Ok(options)
}

async fn build_auth<A>(
    config: ExampleConfig,
    auth_base_path: String,
    adapter: A,
    database_rate_limit: Option<RateLimitOptions>,
    memory_rate_limit_store: Arc<GovernorMemoryRateLimitStore>,
) -> Result<OpenAuth, ExampleError>
where
    A: openauth::db::DbAdapter + 'static,
{
    let adapter = Arc::new(adapter);
    let rate_limit = match config.rate_limit {
        RateLimitBackend::Memory => rate_limit_defaults(&config, RateLimitOptions::memory())
            .custom_store_arc(memory_rate_limit_store as Arc<dyn RateLimitStore>),
        RateLimitBackend::Database => rate_limit_defaults(
            &config,
            database_rate_limit.ok_or_else(|| {
                ExampleError::InvalidConfig(
                    "database rate limiting requires a SQL OPENAUTH_EXAMPLE_DB backend".to_owned(),
                )
            })?,
        ),
        RateLimitBackend::Redis => shared_redis_rate_limit(&config, &config.redis_url).await?,
        RateLimitBackend::Valkey => shared_redis_rate_limit(&config, &config.valkey_url).await?,
        RateLimitBackend::HybridRedis => shared_redis_rate_limit(&config, &config.redis_url)
            .await?
            .hybrid(HybridRateLimitOptions::enabled()),
        RateLimitBackend::HybridValkey => shared_redis_rate_limit(&config, &config.valkey_url)
            .await?
            .hybrid(HybridRateLimitOptions::enabled()),
        RateLimitBackend::FredRedis | RateLimitBackend::FredValkey => {
            // Applied below through FredOpenAuthStores so the example demonstrates
            // the shared Fred secondary-storage + rate-limit wiring.
            RateLimitOptions::memory()
        }
    };

    let options = example_open_auth_options(adapter.clone())?
        .base_url(auth_base_url_for_path(&config.base_url, &auth_base_path)?)
        .base_path(auth_base_path)
        .secret(config.secret.clone())
        .rate_limit(rate_limit)
        .advanced(AdvancedOptions::builder().cookie_prefix(cookie_prefix(config.db)));
    let options = match config.rate_limit {
        RateLimitBackend::FredRedis => {
            apply_fred_stores(&config, &config.redis_url, options).await?
        }
        RateLimitBackend::FredValkey => {
            apply_fred_stores(&config, &config.valkey_url, options).await?
        }
        _ => options,
    };

    OpenAuth::builder()
        .options(options)
        .adapter_arc(adapter)
        .build()
        .map_err(ExampleError::from)
}

fn rate_limit_defaults(config: &ExampleConfig, options: RateLimitOptions) -> RateLimitOptions {
    let rule = RateLimitRule::new(config.rate_limit_window, config.rate_limit_max);
    options
        .enabled(config.rate_limit_enabled)
        .window(config.rate_limit_window)
        .max(config.rate_limit_max)
        .missing_ip_policy(openauth::options::MissingIpPolicy::SharedBucket)
        .custom_rule("/sign-in/*", rule.clone())
        .custom_rule("/sign-up/*", rule)
}

async fn shared_redis_rate_limit(
    config: &ExampleConfig,
    url: &str,
) -> Result<RateLimitOptions, ExampleError> {
    Ok(rate_limit_defaults(
        config,
        RateLimitOptions::secondary_storage(RedisOpenAuthStores::connect(url).await?.rate_limit),
    ))
}

async fn apply_fred_stores(
    config: &ExampleConfig,
    url: &str,
    options: OpenAuthOptions,
) -> Result<OpenAuthOptions, ExampleError> {
    let stores = FredOpenAuthStores::connect(url).await?;
    Ok(stores
        .apply_to_options(options)
        .rate_limit(rate_limit_defaults(
            config,
            RateLimitOptions::secondary_storage(stores.rate_limit.clone()),
        )))
}

fn cookie_prefix(db: DbBackend) -> String {
    format!("open-auth-{}", db.as_str())
}

async fn router_with_auth(
    auth: OpenAuth,
    config: &ExampleConfig,
    memory_rate_limit_store: Arc<GovernorMemoryRateLimitStore>,
) -> Result<Router, ExampleError> {
    let runtime = RuntimeInfo {
        openauth_version: openauth::VERSION.to_owned(),
        framework: "axum".to_owned(),
        auth_base_path: AUTH_BASE_PATH.to_owned(),
        db_backend: config.db.as_str().to_owned(),
        rate_limit_backend: config.rate_limit.as_str().to_owned(),
        rate_limit_enabled: config.rate_limit_enabled,
        rate_limit_window: config.rate_limit_window,
        rate_limit_max: config.rate_limit_max,
        base_url: config.base_url.clone(),
        database_url: display_database_url(config),
        redis_url: config.redis_url.clone(),
        valkey_url: config.valkey_url.clone(),
    };
    let endpoints = endpoint_views(auth.endpoint_registry());
    let openapi = auth.openapi_schema();
    let services = detect_services().await;
    let openauth_routes = auth.into_routes();

    Ok(static_app_with_data(
        config.clone(),
        runtime,
        endpoints,
        openapi,
        services,
        memory_rate_limit_store,
    )
    .nest(AUTH_BASE_PATH, openauth_routes))
}

fn static_app(runtime: RuntimeInfo, dev_controls: bool) -> Router {
    static_app_with_data(
        ExampleConfig {
            host: "127.0.0.1".to_owned(),
            port: 3000,
            base_url: format!("http://127.0.0.1:3000{AUTH_BASE_PATH}"),
            secret: DEFAULT_SECRET.to_owned(),
            db: DbBackend::Sqlite,
            rate_limit: RateLimitBackend::Memory,
            rate_limit_enabled: true,
            rate_limit_window: 60,
            rate_limit_max: 120,
            database_url: DbBackend::Sqlite.default_database_url(),
            database_urls: HashMap::new(),
            allow_default_database_urls: true,
            redis_url: "redis://127.0.0.1:6379".to_owned(),
            valkey_url: "valkey://127.0.0.1:6380".to_owned(),
            dev_controls,
        },
        runtime,
        Vec::new(),
        serde_json::json!({}),
        default_services(),
        Arc::new(GovernorMemoryRateLimitStore::new()),
    )
}

fn static_app_with_data(
    config: ExampleConfig,
    runtime: RuntimeInfo,
    endpoints: Vec<EndpointView>,
    openapi: serde_json::Value,
    services: Vec<ServiceStatus>,
    memory_rate_limit_store: Arc<GovernorMemoryRateLimitStore>,
) -> Router {
    let dev_controls = config.dev_controls;
    let state = AppState {
        config,
        runtime,
        endpoints,
        openapi,
        services,
        memory_adapter: openauth::MemoryAdapter::new(),
        memory_rate_limit_store,
        profile_cache: Arc::new(ProfileCache::default()),
        viewer_adapter_cache: Arc::new(ViewerAdapterCache::default()),
        preferences_store: Arc::new(Mutex::new(None)),
        dev_controls,
    };

    Router::new()
        .route("/", get(home))
        .route("/styles.css", get(styles))
        .route("/app.js", get(script))
        .route("/api/example/runtime", get(runtime_json))
        .route("/api/example/endpoints", get(endpoints_json))
        .route("/api/example/openapi.json", get(openapi_json))
        .route("/api/example/reference", get(openapi_reference_page))
        .route("/api/example/services", get(services_json))
        .route(
            "/api/example/preferences",
            get(preferences_json).post(save_preferences),
        )
        .route("/api/example/tables", get(tables_json))
        .route("/api/example/table", get(table_rows_json))
        .route("/api/example/database/drop", post(drop_database))
        .route("/api/example/database/seed", post(seed_database))
        .route("/api/example/auth/{db}/{rate}", any(dynamic_auth_handler))
        .route(
            "/api/example/auth/{db}/{rate}/{*path}",
            any(dynamic_auth_handler),
        )
        .with_state(state)
}

async fn home(State(state): State<AppState>) -> Html<String> {
    Html(render_home(&state))
}

async fn styles() -> Response {
    static_response("text/css; charset=utf-8", STYLES)
}

async fn script() -> Response {
    static_response("text/javascript; charset=utf-8", SCRIPT)
}

async fn runtime_json(State(state): State<AppState>) -> Json<RuntimeInfo> {
    Json(state.runtime)
}

async fn endpoints_json(State(state): State<AppState>) -> Json<Vec<EndpointView>> {
    Json(state.endpoints)
}

async fn openapi_json(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.openapi)
}

const SCALAR_API_REFERENCE_VERSION: &str = "1.59.0";

async fn openapi_reference_page(Query(query): Query<ReferenceQuery>) -> Html<String> {
    Html(openapi_scalar_page_html(
        query.theme.as_deref().unwrap_or("system"),
    ))
}

fn openapi_scalar_page_html(theme_pref: &str) -> String {
    let theme_pref = escape_js_string(match theme_pref {
        "light" | "dark" => theme_pref,
        _ => "system",
    });
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenAuth API Reference</title>
  <style>
    html, body {{
      margin: 0;
      min-height: 100dvh;
    }}
    body.docs-page {{
      display: flex;
      flex-direction: column;
    }}
    .docs-topbar {{
      flex: none;
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 14px;
      border-bottom: 1px solid color-mix(in oklch, CanvasText 12%, transparent);
      background: Canvas;
      color: CanvasText;
    }}
    .docs-back {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 8px;
      border: 1px solid color-mix(in oklch, CanvasText 14%, transparent);
      color: inherit;
      font: 500 13px/1.2 system-ui, sans-serif;
      text-decoration: none;
    }}
    .docs-back:hover {{
      background: color-mix(in oklch, CanvasText 6%, transparent);
    }}
    .docs-back svg {{
      width: 16px;
      height: 16px;
      flex: none;
    }}
    .docs-topbar-label {{
      font: 600 13px/1.2 system-ui, sans-serif;
      color: color-mix(in oklch, CanvasText 72%, transparent);
    }}
    #scalar-api-reference {{
      flex: 1;
      min-height: 0;
      width: 100%;
    }}
  </style>
</head>
<body class="docs-page">
  <header class="docs-topbar">
    <a class="docs-back" href='/#openapi' title="Back to OpenAuth example">
      <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path d="M9.5 3.5 5 8l4.5 4.5" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>Back to app</span>
    </a>
    <span class="docs-topbar-label">API reference</span>
  </header>
  <div id="scalar-api-reference"></div>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@{scalar_version}"></script>
  <script>
    function resolveScalarTheme(pref) {{
      if (pref === "light") return "default";
      if (pref === "dark") return "kepler";
      return window.matchMedia("(prefers-color-scheme: dark)").matches ? "kepler" : "default";
    }}
    Scalar.createApiReference(document.getElementById("scalar-api-reference"), {{
      url: "/api/example/openapi.json",
      theme: resolveScalarTheme("{theme_pref}"),
      metaData: {{
        title: "OpenAuth API",
        description: "Interactive OpenAPI reference for this example instance"
      }},
      layout: "modern",
      showSidebar: true
    }});
  </script>
</body>
</html>"#,
        theme_pref = theme_pref,
        scalar_version = SCALAR_API_REFERENCE_VERSION,
    )
}

fn escape_js_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

async fn services_json(State(state): State<AppState>) -> Json<Vec<ServiceStatus>> {
    Json(state.services)
}

async fn preferences_json(State(state): State<AppState>) -> Response {
    if let Some(rejection) = control_plane_guard(&state) {
        return rejection;
    }
    Json(load_preferences(&state.config, &state.preferences_store).await).into_response()
}

async fn save_preferences(
    State(state): State<AppState>,
    Json(preferences): Json<ExamplePreferences>,
) -> Response {
    if let Some(rejection) = control_plane_guard(&state) {
        return rejection;
    }
    if let Err(error) = preferences.validate() {
        return json_error(StatusCode::BAD_REQUEST, &error.to_string());
    }
    match persist_preferences(&state.config, &state.preferences_store, &preferences).await {
        Ok(()) => Json(preferences).into_response(),
        Err(error) => json_error(StatusCode::BAD_REQUEST, &error.to_string()),
    }
}

async fn tables_json(State(state): State<AppState>, Query(query): Query<DbQuery>) -> Response {
    if let Some(rejection) = control_plane_guard(&state) {
        return rejection;
    }
    let db = parse_db_query(query.db.as_deref());
    let Ok(db) = db else {
        return json_error(StatusCode::BAD_REQUEST, "invalid db");
    };
    match db {
        DbBackend::Memory => Json(table_summaries(db)).into_response(),
        DbBackend::Sqlite
        | DbBackend::PostgresSqlx
        | DbBackend::PostgresDeadpool
        | DbBackend::MysqlSqlx => Json(table_summaries(db)).into_response(),
    }
}

async fn table_rows_json(
    State(state): State<AppState>,
    Query(query): Query<TableQuery>,
) -> Response {
    if let Some(rejection) = control_plane_guard(&state) {
        return rejection;
    }
    let db = match parse_db_query(query.db.as_deref()) {
        Ok(db) => db,
        Err(error) => return json_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    match table_rows_for_db(&state, db, query).await {
        Ok(view) => Json(view).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, &error.to_string()),
    }
}

async fn drop_database(State(state): State<AppState>, Query(query): Query<DbQuery>) -> Response {
    if let Some(rejection) = control_plane_guard(&state) {
        return rejection;
    }
    let db = match parse_db_query(query.db.as_deref()) {
        Ok(db) => db,
        Err(error) => return json_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    match drop_database_for_db(&state, db).await {
        Ok(outcome) => Json(outcome).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, &error.to_string()),
    }
}

async fn seed_database(State(state): State<AppState>, Query(query): Query<DbQuery>) -> Response {
    if let Some(rejection) = control_plane_guard(&state) {
        return rejection;
    }
    let db = match parse_db_query(query.db.as_deref()) {
        Ok(db) => db,
        Err(error) => return json_error(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    match seed_database_for_db(&state, db).await {
        Ok(outcome) => Json(outcome).into_response(),
        Err(error) => json_error(StatusCode::BAD_GATEWAY, &error.to_string()),
    }
}

fn parse_db_query(value: Option<&str>) -> Result<DbBackend, ExampleError> {
    value.unwrap_or("sqlite").parse::<DbBackend>()
}

async fn dynamic_auth_handler(
    State(state): State<AppState>,
    Path(params): Path<HashMap<String, String>>,
    request: Request<Body>,
) -> Response {
    let Some(db) = params
        .get("db")
        .and_then(|value| value.parse::<DbBackend>().ok())
    else {
        return json_error(StatusCode::BAD_REQUEST, "invalid db profile");
    };
    let Some(rate_limit) = params
        .get("rate")
        .and_then(|value| value.parse::<RateLimitBackend>().ok())
    else {
        return json_error(StatusCode::BAD_REQUEST, "invalid rate-limit profile");
    };
    let mut config = state.config.clone();
    if state.dev_controls {
        apply_rate_limit_headers(&mut config, request.headers());
    }
    let auth_base_path = profile_base_path(db, rate_limit);
    let profile_key = ProfileKey {
        db,
        rate_limit,
        rate_limit_enabled: config.rate_limit_enabled,
        rate_limit_window: config.rate_limit_window,
        rate_limit_max: config.rate_limit_max,
    };
    let config_for_build = config.clone();
    let memory_adapter = state.memory_adapter.clone();
    let memory_rate_limit_store = state.memory_rate_limit_store.clone();
    match state
        .profile_cache
        .get_or_insert(profile_key, || async {
            build_profile_auth(
                config_for_build,
                db,
                rate_limit,
                auth_base_path,
                memory_adapter,
                memory_rate_limit_store,
            )
            .await
        })
        .await
    {
        Ok(auth) => openauth_axum::handle(auth.as_ref(), request).await,
        Err(error) => json_error(StatusCode::BAD_GATEWAY, &error.to_string()),
    }
}

fn apply_rate_limit_headers(config: &mut ExampleConfig, headers: &HeaderMap) {
    if let Some(enabled) = header_bool(headers, RATE_LIMIT_ENABLED_HEADER) {
        config.rate_limit_enabled = enabled;
    }
    if let Some(window) = header_u64(headers, RATE_LIMIT_WINDOW_HEADER) {
        config.rate_limit_window = window.clamp(1, 3600);
    }
    if let Some(max) = header_u64(headers, RATE_LIMIT_MAX_HEADER) {
        config.rate_limit_max = max.clamp(1, 10_000);
    }
}

fn header_u64(headers: &HeaderMap, name: &'static str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse::<u64>().ok()
}

fn header_bool(headers: &HeaderMap, name: &'static str) -> Option<bool> {
    headers.get(name)?.to_str().ok()?.parse::<bool>().ok()
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"error":"{}"}}"#, escape_json(message)),
    )
        .into_response()
}

/// Rejects privileged control-plane requests unless dev controls are enabled.
/// Secure by default: only loopback binds (or an explicit
/// `OPENAUTH_EXAMPLE_DEV_CONTROLS=true`) expose the database viewer, schema
/// reset, and preferences endpoints.
fn control_plane_guard(state: &AppState) -> Option<Response> {
    if state.dev_controls {
        return None;
    }
    Some(json_error(
        StatusCode::FORBIDDEN,
        "example control endpoints are disabled; set OPENAUTH_EXAMPLE_DEV_CONTROLS=true for local development",
    ))
}

async fn build_profile_auth(
    mut config: ExampleConfig,
    db: DbBackend,
    rate_limit: RateLimitBackend,
    auth_base_path: String,
    memory_adapter: openauth::MemoryAdapter,
    memory_rate_limit_store: Arc<GovernorMemoryRateLimitStore>,
) -> Result<OpenAuth, ExampleError> {
    config.db = db;
    config.rate_limit = rate_limit;
    config.database_url = config.database_url_for(db)?;
    ensure_sqlite_parent(&config)?;

    match db {
        DbBackend::Memory => {
            build_auth(
                config,
                auth_base_path,
                memory_adapter,
                None,
                memory_rate_limit_store,
            )
            .await
        }
        DbBackend::Sqlite => {
            let stores =
                SqliteStores::connect_with_schema(&config.database_url, example_auth_schema()?)
                    .await?;
            let database_rate_limit = RateLimitOptions::database(stores.rate_limit.clone());
            // Schema work is intentionally not done on the request path; the
            // configured backend is migrated at startup and the gated reset
            // action handles explicit (re)initialization.
            build_auth(
                config,
                auth_base_path,
                stores.adapter,
                Some(database_rate_limit),
                memory_rate_limit_store,
            )
            .await
        }
        DbBackend::PostgresSqlx => {
            let stores =
                PostgresStores::connect_with_schema(&config.database_url, example_auth_schema()?)
                    .await?;
            let database_rate_limit = RateLimitOptions::database(stores.rate_limit.clone());
            build_auth(
                config,
                auth_base_path,
                stores.adapter,
                Some(database_rate_limit),
                memory_rate_limit_store,
            )
            .await
        }
        DbBackend::PostgresDeadpool => {
            let stores = DeadpoolPostgresStores::connect_with_schema_checked(
                &config.database_url,
                example_auth_schema()?,
            )
            .await?;
            let database_rate_limit = RateLimitOptions::database(stores.rate_limit.clone());
            build_auth(
                config,
                auth_base_path,
                stores.adapter,
                Some(database_rate_limit),
                memory_rate_limit_store,
            )
            .await
        }
        DbBackend::MysqlSqlx => {
            let stores =
                MySqlStores::connect_with_schema(&config.database_url, example_auth_schema()?)
                    .await?;
            let database_rate_limit = RateLimitOptions::database(stores.rate_limit.clone());
            build_auth(
                config,
                auth_base_path,
                stores.adapter,
                Some(database_rate_limit),
                memory_rate_limit_store,
            )
            .await
        }
    }
}

fn static_response(content_type: &'static str, body: &'static str) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn endpoint_views(endpoints: Vec<EndpointInfo>) -> Vec<EndpointView> {
    endpoints
        .into_iter()
        .map(|endpoint| EndpointView {
            method: endpoint.method.to_string(),
            path: format!("{AUTH_BASE_PATH}{}", endpoint.path),
            kind: format!("{:?}", endpoint.kind).to_lowercase(),
            operation_id: endpoint.operation_id.unwrap_or_default(),
            media_types: endpoint.allowed_media_types,
        })
        .collect()
}

fn profile_base_path(db: DbBackend, rate_limit: RateLimitBackend) -> String {
    format!("/api/example/auth/{}/{}", db.as_str(), rate_limit.as_str())
}

async fn table_rows_for_db(
    state: &AppState,
    db: DbBackend,
    query: TableQuery,
) -> Result<TableRowsView, ExampleError> {
    let mut config = state.config.clone();
    config.db = db;
    config.database_url = config.database_url_for(db)?;
    ensure_sqlite_parent(&config)?;

    match db {
        DbBackend::Memory => read_table(&state.memory_adapter, db, query).await,
        DbBackend::Sqlite
        | DbBackend::PostgresSqlx
        | DbBackend::PostgresDeadpool
        | DbBackend::MysqlSqlx => {
            let schema = viewer_schema();
            let adapter = state
                .viewer_adapter_cache
                .get_or_connect(db, &config.database_url, &schema)
                .await?;
            read_table(adapter.as_ref(), db, query).await
        }
    }
}

async fn seed_database_for_db(
    state: &AppState,
    db: DbBackend,
) -> Result<serde_json::Value, ExampleError> {
    let schema = viewer_schema();
    let password_hash = seed::seed_password_hash()?;
    let summary = match db {
        DbBackend::Memory => {
            seed::seed_database(&state.memory_adapter, &schema, &password_hash).await?
        }
        DbBackend::Sqlite
        | DbBackend::PostgresSqlx
        | DbBackend::PostgresDeadpool
        | DbBackend::MysqlSqlx => {
            let mut config = state.config.clone();
            config.db = db;
            config.database_url = config.database_url_for(db)?;
            ensure_sqlite_parent(&config)?;
            let adapter = state
                .viewer_adapter_cache
                .get_or_connect_migrated(db, &config.database_url, &schema)
                .await?;
            seed::seed_database(adapter.as_ref(), &schema, &password_hash).await?
        }
    };
    state.profile_cache.invalidate_db(db).await;
    Ok(serde_json::json!({
        "db": db,
        "seeded": true,
        "tables_seeded": summary.tables_seeded,
        "rows_inserted": summary.rows_inserted,
        "tables": summary.tables,
        "demo_user": {
            "email": "seed@example.com",
            "password": "password123456",
            "id": "seed_user_demo",
        },
    }))
}

async fn drop_database_for_db(
    state: &AppState,
    db: DbBackend,
) -> Result<serde_json::Value, ExampleError> {
    let mut config = state.config.clone();
    config.db = db;
    config.database_url = config.database_url_for(db)?;
    ensure_sqlite_parent(&config)?;

    match db {
        DbBackend::Memory => {
            let deleted = drop_adapter_records(&state.memory_adapter).await?;
            invalidate_db_caches(state, db).await;
            Ok(serde_json::json!({ "db": db, "deleted": deleted, "reset_schema": true }))
        }
        DbBackend::Sqlite => {
            reset_sqlite_schema(&config).await?;
            invalidate_db_caches(state, db).await;
            Ok(serde_json::json!({ "db": db, "deleted": null, "reset_schema": true }))
        }
        DbBackend::PostgresSqlx | DbBackend::PostgresDeadpool => {
            reset_postgres_schema(&config).await?;
            invalidate_db_caches(state, db).await;
            Ok(serde_json::json!({ "db": db, "deleted": null, "reset_schema": true }))
        }
        DbBackend::MysqlSqlx => {
            reset_mysql_schema(&config).await?;
            invalidate_db_caches(state, db).await;
            Ok(serde_json::json!({ "db": db, "deleted": null, "reset_schema": true }))
        }
    }
}

async fn invalidate_db_caches(state: &AppState, db: DbBackend) {
    for shared in db.shared_database_backends() {
        state.profile_cache.invalidate_db(*shared).await;
        state.viewer_adapter_cache.invalidate_db(*shared).await;
    }
}

const SQL_RESET_DROP_BATCH: usize = 100;

fn quote_mysql_ident(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

fn quote_pg_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

async fn drop_mysql_tables(pool: &sqlx::MySqlPool, tables: &[String]) -> Result<(), ExampleError> {
    if tables.is_empty() {
        return Ok(());
    }
    let mut conn = pool.acquire().await?;
    sqlx::query("SET FOREIGN_KEY_CHECKS = 0")
        .execute(&mut *conn)
        .await?;
    for chunk in tables.chunks(SQL_RESET_DROP_BATCH) {
        let list = chunk
            .iter()
            .map(|table| quote_mysql_ident(table))
            .collect::<Vec<_>>()
            .join(", ");
        sqlx::query(&format!("DROP TABLE IF EXISTS {list}"))
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("SET FOREIGN_KEY_CHECKS = 1")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn drop_postgres_tables(pool: &sqlx::PgPool, tables: &[String]) -> Result<(), ExampleError> {
    if tables.is_empty() {
        return Ok(());
    }
    for chunk in tables.chunks(SQL_RESET_DROP_BATCH) {
        let list = chunk
            .iter()
            .map(|table| quote_pg_ident(table))
            .collect::<Vec<_>>()
            .join(", ");
        sqlx::query(&format!("DROP TABLE IF EXISTS {list} CASCADE"))
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn reset_sqlite_schema(config: &ExampleConfig) -> Result<(), ExampleError> {
    let pool = sqlx::SqlitePool::connect(&config.database_url).await?;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&pool)
        .await?;
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&pool)
    .await?;
    for table in tables {
        sqlx::query(&format!("DROP TABLE IF EXISTS \"{table}\""))
            .execute(&pool)
            .await?;
    }
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await?;
    let adapter = open_sqlite_adapter(&config.database_url).await?;
    rebuild_auth_schema(config.clone(), config.db, adapter, None).await
}

async fn reset_postgres_schema(config: &ExampleConfig) -> Result<(), ExampleError> {
    let pool = sqlx::PgPool::connect(&config.database_url).await?;
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()",
    )
    .fetch_all(&pool)
    .await?;
    drop_postgres_tables(&pool, &tables).await?;
    let adapter = open_postgres_sqlx_adapter(&config.database_url).await?;
    rebuild_auth_schema(config.clone(), config.db, adapter, None).await
}

async fn reset_mysql_schema(config: &ExampleConfig) -> Result<(), ExampleError> {
    let pool = sqlx::MySqlPool::connect(&config.database_url).await?;
    // Recent MySQL builds expose table-name columns as VARBINARY; cast to CHAR so
    // sqlx can decode them as Rust strings.
    let tables = sqlx::query_scalar::<_, String>(
        "SELECT CAST(table_name AS CHAR) FROM information_schema.tables \
         WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'",
    )
    .fetch_all(&pool)
    .await?;
    drop_mysql_tables(&pool, &tables).await?;
    let adapter = open_mysql_sqlx_adapter(&config.database_url).await?;
    rebuild_auth_schema(config.clone(), config.db, adapter, None).await
}

async fn rebuild_auth_schema<A>(
    config: ExampleConfig,
    db: DbBackend,
    adapter: A,
    database_rate_limit: Option<RateLimitOptions>,
) -> Result<(), ExampleError>
where
    A: DbAdapter + 'static,
{
    let mut config = config;
    config.db = db;
    let auth = build_auth(
        config,
        profile_base_path(db, RateLimitBackend::Memory),
        adapter,
        database_rate_limit,
        Arc::new(GovernorMemoryRateLimitStore::new()),
    )
    .await?;
    auth.run_migrations().await?;
    Ok(())
}

fn local_preferences(
    config: &ExampleConfig,
    store: &Arc<Mutex<Option<ExamplePreferences>>>,
) -> ExamplePreferences {
    store
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .unwrap_or_else(|| ExamplePreferences::from_config(config))
}

async fn load_preferences(
    config: &ExampleConfig,
    store: &Arc<Mutex<Option<ExamplePreferences>>>,
) -> ExamplePreferences {
    match redis_get(config, PREFERENCES_KEY).await {
        Ok(Some(value)) => {
            let preferences = serde_json::from_str::<ExamplePreferences>(&value)
                .unwrap_or_else(|_| ExamplePreferences::from_config(config));
            if preferences.validate().is_ok() {
                preferences
            } else {
                ExamplePreferences::from_config(config)
            }
        }
        Ok(None) => local_preferences(config, store),
        Err(_) => local_preferences(config, store),
    }
}

async fn persist_preferences(
    config: &ExampleConfig,
    store: &Arc<Mutex<Option<ExamplePreferences>>>,
    preferences: &ExamplePreferences,
) -> Result<(), ExampleError> {
    let value = serde_json::to_string(preferences).map_err(|error| {
        ExampleError::InvalidConfig(format!("preferences could not be encoded: {error}"))
    })?;
    match redis_set(config, PREFERENCES_KEY, &value).await {
        Ok(()) => Ok(()),
        Err(_) => {
            *store
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(preferences.clone());
            Ok(())
        }
    }
}

async fn redis_get(config: &ExampleConfig, key: &str) -> Result<Option<String>, ExampleError> {
    let client = redis::Client::open(config.redis_url.as_str())?;
    let mut connection = client.get_multiplexed_async_connection().await?;
    Ok(redis::cmd("GET")
        .arg(key)
        .query_async(&mut connection)
        .await?)
}

async fn redis_set(config: &ExampleConfig, key: &str, value: &str) -> Result<(), ExampleError> {
    let client = redis::Client::open(config.redis_url.as_str())?;
    let mut connection = client.get_multiplexed_async_connection().await?;
    redis::cmd("SET")
        .arg(key)
        .arg(value)
        .query_async::<()>(&mut connection)
        .await?;
    Ok(())
}

async fn read_table(
    adapter: &dyn DbAdapter,
    db: DbBackend,
    query: TableQuery,
) -> Result<TableRowsView, ExampleError> {
    let schema = viewer_schema();
    let table = query.table.unwrap_or_else(|| "user".to_owned());
    let Some(table_meta) = schema.table(&table) else {
        return Err(ExampleError::InvalidConfig(format!(
            "unknown table `{table}`"
        )));
    };
    let page_size = query.page_size.unwrap_or(50).clamp(1, 100);
    let page = query.page.unwrap_or(0);
    let selected = selected_columns(query.columns.as_deref(), table_meta);
    let total = adapter
        .count(Count::new(table.clone()))
        .await
        .unwrap_or_default();
    let rows = match adapter
        .find_many(
            FindMany::new(table.clone())
                .limit(page_size)
                .offset(page.saturating_mul(page_size)),
        )
        .await
    {
        Ok(rows) => rows,
        Err(OpenAuthError::TableNotFound { .. }) => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let rows = rows
        .into_iter()
        .filter(|record| record_matches(record, query.q.as_deref()))
        .map(|record| record_to_json(record, &selected))
        .collect();

    Ok(TableRowsView {
        db: db.as_str().to_owned(),
        table,
        page,
        page_size,
        total,
        columns: table_columns(table_meta),
        rows,
    })
}

async fn drop_adapter_records<A>(adapter: &A) -> Result<u64, ExampleError>
where
    A: DbAdapter,
{
    let schema = example_db_schema(Arc::new(openauth::MemoryAdapter::new()))?;
    let mut deleted = 0;
    for (logical_name, _) in schema.tables() {
        match adapter.delete_many(DeleteMany::new(logical_name)).await {
            Ok(count) => deleted += count,
            Err(OpenAuthError::TableNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(deleted)
}

fn viewer_schema() -> openauth::db::DbSchema {
    example_auth_schema().unwrap_or_else(|_| {
        auth_schema(AuthSchemaOptions {
            rate_limit_storage: RateLimitStorage::Database,
            ..AuthSchemaOptions::default()
        })
    })
}

fn table_summaries(_db: DbBackend) -> Vec<TableSummaryView> {
    let schema = viewer_schema();
    schema
        .tables()
        .map(|(id, table)| TableSummaryView {
            id: id.to_owned(),
            name: table.name.clone(),
            columns: table_columns(table),
        })
        .collect()
}

fn table_columns(table: &openauth::db::DbTable) -> Vec<TableColumnView> {
    table
        .fields
        .iter()
        .map(|(name, field)| TableColumnView {
            name: name.clone(),
            physical_name: field.name.clone(),
            kind: format!("{:?}", field.field_type).to_lowercase(),
            hidden: !field.returned,
            required: field.required,
        })
        .collect()
}

fn selected_columns(columns: Option<&str>, table: &openauth::db::DbTable) -> Vec<String> {
    let columns = columns
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|column| !column.is_empty())
        .filter(|column| table.fields.contains_key(*column))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if columns.is_empty() {
        table.fields.keys().cloned().collect()
    } else {
        columns
    }
}

fn record_matches(record: &DbRecord, query: Option<&str>) -> bool {
    let Some(query) = query.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    let query = query.to_ascii_lowercase();
    record.values().any(|value| {
        db_value_to_json(value)
            .to_string()
            .to_ascii_lowercase()
            .contains(&query)
    })
}

fn record_to_json(record: DbRecord, columns: &[String]) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for column in columns {
        if let Some(value) = record.get(column) {
            object.insert(column.clone(), db_value_to_json(value));
        }
    }
    serde_json::Value::Object(object)
}

fn db_value_to_json(value: &DbValue) -> serde_json::Value {
    match value {
        DbValue::String(value) => serde_json::Value::String(value.clone()),
        DbValue::Number(value) => serde_json::Value::Number((*value).into()),
        DbValue::Boolean(value) => serde_json::Value::Bool(*value),
        DbValue::Timestamp(value) => serde_json::Value::String(
            value
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| value.to_string()),
        ),
        DbValue::Json(value) => value.clone(),
        DbValue::StringArray(values) => serde_json::json!(values),
        DbValue::NumberArray(values) => serde_json::json!(values),
        DbValue::Record(record) => {
            record_to_json(record.clone(), &record.keys().cloned().collect::<Vec<_>>())
        }
        DbValue::RecordArray(records) => serde_json::Value::Array(
            records
                .iter()
                .map(|record| {
                    record_to_json(record.clone(), &record.keys().cloned().collect::<Vec<_>>())
                })
                .collect(),
        ),
        DbValue::Null => serde_json::Value::Null,
    }
}

fn validate_example_base_url(base_url: &str) -> Result<(), ExampleError> {
    let url = parse_example_base_url(base_url)?;
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(ExampleError::InvalidConfig(
            "OPENAUTH_EXAMPLE_BASE_URL must be an absolute URL with a host".to_owned(),
        ));
    }
    Ok(())
}

fn parse_example_base_url(base_url: &str) -> Result<url::Url, ExampleError> {
    url::Url::parse(base_url).map_err(|error| {
        ExampleError::InvalidConfig(format!("OPENAUTH_EXAMPLE_BASE_URL is invalid: {error}"))
    })
}

fn format_url_origin(url: &url::Url) -> String {
    let mut origin = format!("{}://", url.scheme());
    if let Some(host) = url.host_str() {
        origin.push_str(host);
    }
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    origin
}

fn trim_url_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_owned()
    }
}

fn configured_path_prefix(path: &str) -> String {
    let path = trim_url_path(path);
    if path.is_empty() {
        return String::new();
    }

    if let Some(idx) = path.find(PROFILE_AUTH_PATH_PREFIX) {
        if idx > 0 {
            return trim_url_path(&path[..idx]);
        }
        return String::new();
    }

    if path.ends_with(AUTH_BASE_PATH) {
        return trim_url_path(path.strip_suffix(AUTH_BASE_PATH).unwrap_or(path.as_str()));
    }

    path
}

fn auth_base_url_for_path(
    configured_base_url: &str,
    auth_base_path: &str,
) -> Result<String, ExampleError> {
    let parsed = parse_example_base_url(configured_base_url)?;
    let origin = format_url_origin(&parsed);
    let prefix = configured_path_prefix(parsed.path());
    Ok(format!("{origin}{prefix}{auth_base_path}"))
}

async fn detect_services() -> Vec<ServiceStatus> {
    let mut services = default_services();
    for service in &mut services {
        service.available = tcp_available(&service.host, service.port).await;
    }
    services
}

fn default_services() -> Vec<ServiceStatus> {
    vec![
        service("sqlite", "SQLite file", "localhost", 0, true),
        service("postgres", "Postgres", "127.0.0.1", 5432, false),
        service("mysql", "MySQL", "127.0.0.1", 3306, false),
        service("redis", "Redis", "127.0.0.1", 6379, false),
        service("valkey", "Valkey", "127.0.0.1", 6380, false),
    ]
}

fn service(id: &str, label: &str, host: &str, port: u16, available: bool) -> ServiceStatus {
    ServiceStatus {
        id: id.to_owned(),
        label: label.to_owned(),
        host: host.to_owned(),
        port,
        available,
    }
}

async fn tcp_available(host: &str, port: u16) -> bool {
    if port == 0 {
        return true;
    }
    let address = format!("{host}:{port}");
    tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(address))
        .await
        .is_ok_and(|result| result.is_ok())
}

fn render_home(state: &AppState) -> String {
    let endpoint_rows = state
        .endpoints
        .iter()
        .map(|endpoint| {
            format!(
                r#"<tr data-endpoint-row data-method="{method}" data-path="{path}" data-operation="{operation}"><td><span class="method method-{method_class}">{method}</span></td><td><code>{path}</code></td><td>{kind}</td><td>{operation}</td></tr>"#,
                method = escape_html(&endpoint.method),
                method_class = escape_html(&endpoint.method.to_ascii_lowercase()),
                path = escape_html(&endpoint.path),
                kind = escape_html(&endpoint.kind),
                operation = escape_html(&endpoint.operation_id)
            )
        })
        .collect::<String>();
    let openapi_json = escape_html(
        &serde_json::to_string_pretty(&state.openapi).unwrap_or_else(|_| "{}".to_owned()),
    );
    let services = state
        .services
        .iter()
        .map(|service| {
            let status = if service.available { "online" } else { "offline" };
            let endpoint = if service.port == 0 {
                "local file".to_owned()
            } else {
                format!("{}:{}", service.host, service.port)
            };
            format!(
                r#"<div class="service service-{status}"><span>{label}</span><strong>{status}</strong><small>{endpoint}</small></div>"#,
                status = status,
                label = escape_html(&service.label),
                endpoint = escape_html(&endpoint)
            )
        })
        .collect::<String>();
    let db_options = service_options(
        &state.services,
        &state.runtime.db_backend,
        &[
            "memory",
            "sqlite",
            "postgres-sqlx",
            "postgres-deadpool",
            "mysql-sqlx",
        ],
    );
    let rate_limit_options = service_options(
        &state.services,
        &state.runtime.rate_limit_backend,
        &[
            "memory",
            "database",
            "redis",
            "valkey",
            "hybrid-redis",
            "hybrid-valkey",
            "fred-redis",
            "fred-valkey",
        ],
    );
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenAuth full app example</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body data-auth-root="/api/example/auth" data-rate-limit-enabled="{rate_limit_enabled}" data-rate-limit-window="{rate_limit_window}" data-rate-limit-max="{rate_limit_max}">
  <header class="shell-header">
    <div class="brand">
      <span class="logo">OA</span>
      <div>
        <p class="eyebrow">OpenAuth example</p>
        <h1>Full app</h1>
      </div>
    </div>
    <div class="status-pill">Axum / <span data-current-db>{db}</span> / <span data-current-rate>{rate_limit}</span></div>
  </header>

  <main class="layout">
    <aside class="sidebar">
      <div class="profile-controls">
        <label>Adapter
          <select id="profile-db">{db_options}</select>
        </label>
        <label>Rate limit
          <select id="profile-rate-limit">{rate_limit_options}</select>
        </label>
      </div>
      <section id="sidebar-user" class="sidebar-user" hidden>
        <div class="avatar" id="sidebar-avatar">OA</div>
        <div class="sidebar-user-copy">
          <strong id="sidebar-name"></strong>
          <span id="sidebar-email"></span>
          <small id="sidebar-username"></small>
        </div>
        <button class="danger sidebar-signout" data-action="sign-out">Sign out</button>
      </section>
      <nav class="tabs" aria-label="Example sections">
      <button class="tab active" data-tab="overview">Overview</button>
      <button class="tab" data-tab="auth">Email/password</button>
      <button class="tab" data-tab="sessions">Sessions</button>
      <button class="tab" data-tab="storage">Storage</button>
      <button class="tab" data-tab="rate-limit">Rate limiting</button>
      <button class="tab" data-tab="database">Database</button>
      <button class="tab" data-tab="openapi">OpenAPI</button>
      <button class="tab" data-tab="settings">Settings</button>
      </nav>
    </aside>

    <div class="content">
    <section id="overview" class="panel active">
      <div class="panel-heading">
        <div>
          <p class="eyebrow">Runtime</p>
          <h2>Axum auth lab</h2>
        </div>
        <span class="count-pill">{endpoint_count} endpoints</span>
      </div>
      <div class="grid metrics">
        <div><span>OpenAuth</span><strong>{version}</strong></div>
        <div><span>Framework</span><strong>{framework}</strong></div>
        <div><span>Adapter</span><strong data-current-db>{db}</strong></div>
        <div><span>Rate limit</span><strong data-current-rate>{rate_limit}</strong></div>
      </div>
      <dl class="details">
        <dt>Auth base path</dt><dd><code>{auth_base_path}</code></dd>
        <dt>Base URL</dt><dd><code>{base_url}</code></dd>
      </dl>
      <div class="service-grid">{services}</div>
    </section>

    <section id="auth" class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Credentials</p><h2>Email/password</h2></div>
      </div>
      <div class="columns">
        <form class="box" data-auth-form="signup">
          <h2>Sign up</h2>
          <label>Name <input name="name" autocomplete="name" value="Example User"></label>
          <label>Email <input name="email" type="email" autocomplete="email" value="user@example.com"></label>
          <label>Password <input name="password" type="password" autocomplete="new-password" value="password123456"></label>
          <button type="submit" data-loading-text="Creating..."><span class="button-label">Create user</span><span class="spinner" aria-hidden="true"></span></button>
        </form>
        <form class="box" data-auth-form="signin">
          <h2>Sign in</h2>
          <label>Email <input name="email" type="email" autocomplete="email" value="user@example.com"></label>
          <label>Password <input name="password" type="password" autocomplete="current-password" value="password123456"></label>
          <button type="submit" data-loading-text="Signing in..."><span class="button-label">Sign in</span><span class="spinner" aria-hidden="true"></span></button>
        </form>
      </div>
      <pre id="auth-output" class="output">No request yet.</pre>
    </section>

    <section id="sessions" class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Current browser</p><h2>Sessions</h2></div>
      </div>
      <div class="actions">
        <button data-action="get-session" data-loading-text="Loading..."><span class="button-label">Get session</span><span class="spinner" aria-hidden="true"></span></button>
        <button data-action="list-sessions" data-loading-text="Loading..."><span class="button-label">List sessions</span><span class="spinner" aria-hidden="true"></span></button>
      </div>
      <pre id="session-output" class="output">No request yet.</pre>
    </section>

    <section id="storage" class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Persistence</p><h2>Storage adapters</h2></div>
      </div>
      <label class="select-label">Active adapter
        <select data-profile-db-mirror>{db_options}</select>
      </label>
      <div class="grid metrics">
        <div><span>Selected DB</span><strong data-current-db>{db}</strong></div>
        <div><span>DATABASE_URL</span><strong>{database_url}</strong></div>
      </div>
      <p class="note">Use <code>OPENAUTH_EXAMPLE_DB</code> with <code>memory</code>, <code>sqlite</code>, <code>postgres-sqlx</code>, <code>postgres-deadpool</code>, or <code>mysql-sqlx</code>.</p>
    </section>

    <section id="rate-limit" class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Protection</p><h2>Rate limiting</h2></div>
      </div>
      <label class="select-label">Active backend
        <select data-profile-rate-mirror>{rate_limit_options}</select>
      </label>
      <div class="grid metrics">
        <div><span>Selected backend</span><strong data-current-rate>{rate_limit}</strong></div>
        <div><span>Window</span><strong><span id="rate-window-display">{rate_limit_window}</span>s</strong></div>
        <div><span>Max requests</span><strong id="rate-max-display">{rate_limit_max}</strong></div>
        <div><span>Redis URL</span><strong>{redis_url}</strong></div>
        <div><span>Valkey URL</span><strong>{valkey_url}</strong></div>
      </div>
      <p class="note">Use <code>memory</code>, <code>database</code>, <code>redis</code>, <code>valkey</code>, <code>hybrid-redis</code>, <code>hybrid-valkey</code>, <code>fred-redis</code>, or <code>fred-valkey</code>.</p>
      <div class="columns">
        <form class="box" id="rate-settings-form">
          <h2>Rate limit settings</h2>
          <label class="check-label"><input id="rate-enabled" type="checkbox"> Enabled</label>
          <label>Window seconds <input id="rate-window" type="number" min="1" max="3600" step="1"></label>
          <label>Max requests <input id="rate-max" type="number" min="1" max="10000" step="1"></label>
          <button type="submit" data-loading-text="Saving..."><span class="button-label">Apply settings</span><span class="spinner" aria-hidden="true"></span></button>
        </form>
        <div class="box">
          <h2>Active profile</h2>
          <dl class="details compact-details">
            <dt>Adapter</dt><dd><code data-current-db>{db}</code></dd>
            <dt>Rate backend</dt><dd><code data-current-rate>{rate_limit}</code></dd>
            <dt>Cookie prefix</dt><dd><code id="settings-cookie-prefix">open-auth-{db}</code></dd>
          </dl>
          <p class="note">Settings are saved in this browser and sent as headers by the example UI. They also override sign-in/sign-up special rules.</p>
        </div>
      </div>
      <pre id="settings-output" class="output">No rate-limit request yet.</pre>
    </section>

    <section id="database" class="panel panel-flush">
      <div class="studio">
        <aside class="studio-sidebar">
          <div class="studio-heading">
            <p class="eyebrow">Database studio</p>
            <h2>Tables</h2>
          </div>
          <label>Database
            <select id="studio-db">{db_options}</select>
          </label>
          <div class="studio-actions">
            <input id="studio-search" placeholder="Search rows">
            <button id="studio-refresh" data-loading-text="Refreshing..."><span class="button-label">Refresh</span><span class="spinner" aria-hidden="true"></span></button>
          </div>
          <nav id="studio-tables" class="studio-tables"></nav>
          <button id="drop-database" class="danger" data-loading-text="Resetting..."><span class="button-label">Reset database schema</span><span class="spinner" aria-hidden="true"></span></button>
          <button id="seed-database" data-loading-text="Seeding..."><span class="button-label">Seed database</span><span class="spinner" aria-hidden="true"></span></button>
        </aside>
        <section class="studio-main">
          <div class="studio-toolbar">
            <div>
              <strong id="studio-table-title">user</strong>
              <span id="studio-meta">0 rows</span>
            </div>
            <div class="toolbar-actions">
              <button id="columns-button" class="ghost">Columns</button>
              <label>Rows
                <select id="studio-page-size">
                  <option value="25">25</option>
                  <option value="50" selected>50</option>
                  <option value="100">100</option>
                </select>
              </label>
              <button id="studio-prev" class="ghost">Prev</button>
              <span id="studio-page">0</span>
              <button id="studio-next" class="ghost">Next</button>
            </div>
          </div>
          <div id="columns-popover" class="columns-popover" hidden></div>
          <div class="studio-table-wrap">
            <table class="studio-table">
              <thead id="studio-head"></thead>
              <tbody id="studio-body"></tbody>
            </table>
          </div>
        </section>
      </div>
    </section>

    <section id="openapi" class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Contract</p><h2>OpenAPI explorer</h2></div>
        <input class="search" id="endpoint-search" placeholder="Filter endpoints">
      </div>
      <div class="actions">
        <a class="button ghost" href="/api/example/openapi.json" download="openauth-openapi.json">Download spec</a>
        <a class="button ghost" href="/api/example/endpoints" target="_blank" rel="noreferrer">Registry JSON</a>
        <a class="button" id="openapi-docs-link" href="/api/example/reference" target="_blank" rel="noreferrer">Open API docs</a>
      </div>
      <div class="table-frame">
      <table class="endpoint-table">
        <thead><tr><th>Method</th><th>Path</th><th>Kind</th><th>Operation</th></tr></thead>
        <tbody>{endpoint_rows}</tbody>
      </table>
      </div>
      <details class="json-details">
        <summary>Raw OpenAPI JSON</summary>
        <pre class="output json-output">{openapi_json}</pre>
      </details>
    </section>

    <section id="settings" class="panel">
      <div class="panel-heading">
        <div><p class="eyebrow">Preferences</p><h2>Settings</h2></div>
      </div>
      <div class="columns">
        <div class="box">
          <h2>Appearance</h2>
          <label>Theme
            <select id="theme-select">
              <option value="system">System</option>
              <option value="dark">Dark mode</option>
              <option value="light">Light mode</option>
            </select>
          </label>
          <p class="note">Saved locally. System follows your OS preference.</p>
        </div>
        <div class="box">
          <h2>Saved profile</h2>
          <dl class="details compact-details">
            <dt>Adapter</dt><dd><code data-current-db>{db}</code></dd>
            <dt>Rate backend</dt><dd><code data-current-rate>{rate_limit}</code></dd>
            <dt>Stored in</dt><dd><code>Redis</code></dd>
          </dl>
        </div>
      </div>
    </section>
    </div>
  </main>
  <dialog id="signout-dialog">
    <form method="dialog" class="dialog-card">
      <h2>Sign out?</h2>
      <p>This will clear the current OpenAuth session cookie for this browser.</p>
      <menu>
        <button value="cancel" class="button ghost">Cancel</button>
        <button value="confirm" class="danger" data-loading-text="Signing out..."><span class="button-label">Sign out</span><span class="spinner" aria-hidden="true"></span></button>
      </menu>
    </form>
  </dialog>
  <dialog id="drop-dialog">
    <form method="dialog" class="dialog-card">
      <h2>Reset database schema?</h2>
      <p id="drop-dialog-copy">This will reset OpenAuth tables for the selected adapter and run migrations again.</p>
      <menu>
        <button value="cancel" class="button ghost">Cancel</button>
        <button value="confirm" class="danger" data-loading-text="Dropping..."><span class="button-label">Drop data</span><span class="spinner" aria-hidden="true"></span></button>
      </menu>
    </form>
  </dialog>
  <script src="/app.js"></script>
</body>
</html>"#,
        version = escape_html(&state.runtime.openauth_version),
        framework = escape_html(&state.runtime.framework),
        db = escape_html(&state.runtime.db_backend),
        rate_limit = escape_html(&state.runtime.rate_limit_backend),
        rate_limit_enabled = state.runtime.rate_limit_enabled,
        rate_limit_window = state.runtime.rate_limit_window,
        rate_limit_max = state.runtime.rate_limit_max,
        endpoint_count = state.endpoints.len(),
        auth_base_path = escape_html(&state.runtime.auth_base_path),
        base_url = escape_html(&state.runtime.base_url),
        database_url = escape_html(&state.runtime.database_url),
        redis_url = escape_html(&state.runtime.redis_url),
        valkey_url = escape_html(&state.runtime.valkey_url),
        services = services,
        db_options = db_options,
        rate_limit_options = rate_limit_options,
        endpoint_rows = endpoint_rows,
        openapi_json = openapi_json,
    )
}

fn service_options(services: &[ServiceStatus], active: &str, values: &[&str]) -> String {
    values
        .iter()
        .map(|value| {
            let available = match *value {
                "memory" | "database" => true,
                "postgres-sqlx" | "postgres-deadpool" => services
                    .iter()
                    .find(|service| service.id == "postgres")
                    .is_some_and(|service| service.available),
                "mysql-sqlx" => services
                    .iter()
                    .find(|service| service.id == "mysql")
                    .is_some_and(|service| service.available),
                "hybrid-redis" | "fred-redis" => services
                    .iter()
                    .find(|service| service.id == "redis")
                    .is_some_and(|service| service.available),
                "hybrid-valkey" | "fred-valkey" => services
                    .iter()
                    .find(|service| service.id == "valkey")
                    .is_some_and(|service| service.available),
                other => services
                    .iter()
                    .find(|service| service.id == other)
                    .is_some_and(|service| service.available),
            };
            let selected = if *value == active { " selected" } else { "" };
            let disabled = if available { "" } else { " disabled" };
            let suffix = if available { "" } else { " (offline)" };
            format!(
                r#"<option value="{value}"{selected}{disabled}>{value}{suffix}</option>"#,
                value = escape_html(value),
                selected = selected,
                disabled = disabled,
                suffix = suffix
            )
        })
        .collect()
}

fn ensure_sqlite_parent(config: &ExampleConfig) -> Result<(), ExampleError> {
    if config.db != DbBackend::Sqlite {
        return Ok(());
    }
    let Some(path) = config.database_url.strip_prefix("sqlite://") else {
        return Ok(());
    };
    if path == ":memory:" {
        return Ok(());
    }
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        std::fs::File::create(path)?;
    }
    Ok(())
}

fn display_database_url(config: &ExampleConfig) -> String {
    match config.db {
        DbBackend::Memory => "not used".to_owned(),
        DbBackend::Sqlite => config.database_url.clone(),
        DbBackend::PostgresSqlx | DbBackend::PostgresDeadpool | DbBackend::MysqlSqlx => {
            redact_password(&config.database_url)
        }
    }
}

fn redact_password(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let Some((credentials, host)) = rest.split_once('@') else {
        return url.to_owned();
    };
    let Some((user, _password)) = credentials.split_once(':') else {
        return url.to_owned();
    };
    format!("{scheme}://{user}:<redacted>@{host}")
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn load_database_urls(
    startup_db: DbBackend,
) -> Result<(String, HashMap<DbBackend, String>, bool), ExampleError> {
    let explicit_primary = env::var("DATABASE_URL").ok();
    let mut database_urls = HashMap::new();
    let mut any_explicit = false;

    for db in [
        DbBackend::Sqlite,
        DbBackend::PostgresSqlx,
        DbBackend::PostgresDeadpool,
        DbBackend::MysqlSqlx,
    ] {
        if let Some(env_name) = db.per_backend_database_url_env() {
            if let Ok(url) = env::var(env_name) {
                database_urls.insert(db, url);
                any_explicit = true;
            }
        }
    }

    let database_url = match explicit_primary {
        Some(url) => {
            database_urls.insert(startup_db, url.clone());
            any_explicit = true;
            url
        }
        None => database_urls
            .get(&startup_db)
            .cloned()
            .unwrap_or_else(|| startup_db.default_database_url()),
    };

    Ok((database_url, database_urls, !any_explicit))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

const STYLES: &str = r#"
:root {
  color-scheme: dark;
  --bg: oklch(0.15 0.006 255);
  --bg-2: oklch(0.18 0.006 255);
  --panel: oklch(0.19 0.006 255);
  --panel-2: oklch(0.215 0.006 255);
  --text: oklch(0.93 0.006 255);
  --muted: oklch(0.66 0.006 255);
  --soft: oklch(0.255 0.006 255);
  --border: oklch(0.31 0.006 255);
  --border-strong: oklch(0.42 0.008 255);
  --accent: oklch(0.74 0.13 158);
  --accent-contrast: oklch(0.16 0.015 158);
  --success: oklch(0.72 0.14 155);
  --danger: oklch(0.67 0.16 28);
  --warning: oklch(0.76 0.14 78);
  --code: oklch(0.235 0.007 255);
  --shadow: 0 20px 70px oklch(0.08 0.006 255 / 0.42);
  --mono: "SFMono-Regular", "JetBrains Mono", "Cascadia Code", Consolas, monospace;
  --sans: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --studio-bg: oklch(0.135 0.006 255);
  --studio-panel: oklch(0.17 0.006 255);
  --studio-line: oklch(0.31 0.006 255);
  --studio-text: oklch(0.91 0.006 255);
  --studio-muted: oklch(0.63 0.006 255);
  --studio-hover: oklch(0.2 0.006 255);
  --studio-active: oklch(0.245 0.006 255);
}

@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
    color-scheme: light;
    --bg: oklch(0.965 0.004 255);
    --bg-2: oklch(0.935 0.004 255);
    --panel: oklch(0.99 0.003 255);
    --panel-2: oklch(0.965 0.004 255);
    --text: oklch(0.19 0.006 255);
    --muted: oklch(0.48 0.006 255);
    --soft: oklch(0.94 0.004 255);
    --border: oklch(0.87 0.005 255);
    --border-strong: oklch(0.76 0.006 255);
    --accent: oklch(0.56 0.12 158);
    --accent-contrast: oklch(0.985 0.004 158);
    --code: oklch(0.94 0.004 255);
    --shadow: 0 18px 55px oklch(0.68 0.01 255 / 0.16);
    --studio-bg: oklch(0.982 0.004 255);
    --studio-panel: oklch(0.955 0.004 255);
    --studio-line: oklch(0.84 0.005 255);
    --studio-text: oklch(0.22 0.006 255);
    --studio-muted: oklch(0.52 0.006 255);
    --studio-hover: oklch(0.94 0.004 255);
    --studio-active: oklch(0.9 0.006 255);
  }
}

:root[data-theme="light"] {
  color-scheme: light;
  --bg: oklch(0.965 0.004 255);
  --bg-2: oklch(0.935 0.004 255);
  --panel: oklch(0.99 0.003 255);
  --panel-2: oklch(0.965 0.004 255);
  --text: oklch(0.19 0.006 255);
  --muted: oklch(0.48 0.006 255);
  --soft: oklch(0.94 0.004 255);
  --border: oklch(0.87 0.005 255);
  --border-strong: oklch(0.76 0.006 255);
  --accent: oklch(0.56 0.12 158);
  --accent-contrast: oklch(0.985 0.004 158);
  --code: oklch(0.94 0.004 255);
  --shadow: 0 18px 55px oklch(0.68 0.01 255 / 0.16);
  --studio-bg: oklch(0.982 0.004 255);
  --studio-panel: oklch(0.955 0.004 255);
  --studio-line: oklch(0.84 0.005 255);
  --studio-text: oklch(0.22 0.006 255);
  --studio-muted: oklch(0.52 0.006 255);
  --studio-hover: oklch(0.94 0.004 255);
  --studio-active: oklch(0.9 0.006 255);
}

:root[data-theme="dark"] {
  color-scheme: dark;
}

* { box-sizing: border-box; }
html {
  background: var(--bg);
}
body {
  margin: 0;
  background:
    radial-gradient(circle at 12% -10%, oklch(0.44 0.08 158 / 0.18), transparent 34rem),
    linear-gradient(135deg, var(--bg), var(--bg-2) 55%, var(--bg)),
    var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background-image:
    linear-gradient(var(--border) 1px, transparent 1px),
    linear-gradient(90deg, var(--border) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: linear-gradient(to bottom, oklch(0 0 0 / 0.36), transparent 54%);
  opacity: 0.18;
}
.shell-header {
  position: sticky;
  top: 0;
  z-index: 5;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 24px;
  padding: 14px clamp(16px, 3vw, 34px);
  border-bottom: 1px solid var(--border);
  background: color-mix(in oklch, var(--bg) 84%, transparent);
  backdrop-filter: blur(16px);
}
.brand { display: flex; align-items: center; gap: 12px; }
.logo {
  display: grid;
  place-items: center;
  width: 32px;
  height: 32px;
  border: 1px solid var(--border-strong);
  border-radius: 7px;
  background: var(--panel-2);
  color: var(--accent);
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
}
.eyebrow {
  margin: 0 0 4px;
  color: var(--muted);
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0;
  text-transform: uppercase;
}
h1, h2 { margin: 0; letter-spacing: 0; }
h1 { font-size: 22px; }
h2 { font-size: 20px; }
.status-pill, .count-pill {
  padding: 7px 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel-2);
  color: var(--muted);
  font-family: var(--mono);
  font-size: 13px;
  white-space: nowrap;
}
.layout {
  display: grid;
  grid-template-columns: 244px minmax(0, 1fr);
  gap: 18px;
  width: min(1480px, calc(100vw - 28px));
  margin: 18px auto 42px;
}
.sidebar {
  position: sticky;
  top: 76px;
  align-self: start;
  border: 1px solid var(--border);
  border-radius: 9px;
  background: color-mix(in oklch, var(--panel) 96%, transparent);
  box-shadow: var(--shadow);
  overflow: hidden;
}
.profile-controls {
  display: grid;
  gap: 12px;
  padding: 14px;
  border-bottom: 1px solid var(--border);
}
.profile-controls label {
  margin: 0;
  font-size: 12px;
}
.sidebar-user {
  display: grid;
  grid-template-columns: 38px minmax(0, 1fr);
  gap: 10px;
  align-items: center;
  padding: 14px;
  border-bottom: 1px solid var(--border);
}
.sidebar-user[hidden] { display: none; }
.avatar {
  width: 38px;
  height: 38px;
  border-radius: 999px;
  display: grid;
  place-items: center;
  overflow: hidden;
  background: var(--soft);
  color: var(--accent);
  border: 1px solid var(--border);
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
}
.avatar img { width: 100%; height: 100%; object-fit: cover; }
.sidebar-user-copy { min-width: 0; display: grid; gap: 2px; }
.sidebar-user-copy strong,
.sidebar-user-copy span,
.sidebar-user-copy small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.sidebar-user-copy span,
.sidebar-user-copy small { color: var(--muted); }
.sidebar-signout {
  grid-column: 1 / -1;
  width: 100%;
}
.tabs { display: grid; padding: 8px; gap: 3px; }
.tab, button, .button {
  min-height: 38px;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: var(--text);
  padding: 8px 11px;
  font: inherit;
  cursor: pointer;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  transition: transform 180ms cubic-bezier(0.16, 1, 0.3, 1), background 180ms cubic-bezier(0.16, 1, 0.3, 1), border-color 180ms cubic-bezier(0.16, 1, 0.3, 1);
}
.tab { justify-content: flex-start; color: var(--muted); font-size: 14px; }
.tab.active, .tab:hover { background: var(--soft); color: var(--text); }
.tab.active { box-shadow: inset 0 0 0 1px var(--border); }
button:active, .button:active { transform: translateY(1px); }
button[type="submit"], .button {
  background: var(--accent);
  border-color: var(--accent);
  color: var(--accent-contrast);
  font-weight: 650;
}
button:hover, .button:hover { border-color: var(--border-strong); }
button:disabled { cursor: not-allowed; opacity: 0.62; }
.button.ghost, button.ghost { background: var(--panel-2); color: var(--text); border-color: var(--border); }
.danger {
  background: color-mix(in oklch, var(--danger) 12%, var(--panel));
  color: var(--danger);
  border-color: color-mix(in oklch, var(--danger) 38%, var(--border));
}
.content { min-width: 0; }
.panel {
  display: none;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 9px;
  padding: 22px;
  box-shadow: var(--shadow);
}
.panel.active { display: block; }
.panel-flush { padding: 0; overflow: hidden; }
.panel-heading {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
}
.grid { display: grid; gap: 12px; }
.metrics { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
.metrics div, .box, .service {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  background: var(--panel-2);
}
.metrics span, .service span { display: block; color: var(--muted); font-size: 13px; margin-bottom: 8px; }
.metrics strong, .service strong { word-break: break-word; }
.details { display: grid; grid-template-columns: max-content 1fr; gap: 10px 16px; margin: 18px 0; }
dt { color: var(--muted); }
dd { margin: 0; min-width: 0; }
code {
  background: var(--code);
  border: 1px solid var(--border);
  border-radius: 5px;
  padding: 2px 5px;
  font-family: var(--mono);
  font-size: 0.92em;
}
.columns { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
label, .select-label { display: grid; gap: 7px; color: var(--muted); font-size: 14px; margin-bottom: 12px; }
.check-label {
  display: flex;
  align-items: center;
  gap: 9px;
}
.check-label input { width: auto; min-height: auto; }
input, select {
  width: 100%;
  border: 1px solid var(--border);
  border-radius: 7px;
  min-height: 40px;
  padding: 8px 10px;
  color: var(--text);
  background: var(--bg);
  font: inherit;
}
.search { max-width: 320px; }
.actions { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; }
.output {
  min-height: 170px;
  overflow: auto;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: oklch(0.13 0.006 255);
  color: oklch(0.92 0.006 255);
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.55;
}
.json-output { max-height: 460px; }
.note { color: var(--muted); line-height: 1.6; }
.service-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 12px;
  margin-top: 18px;
}
.endpoint-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 12px;
  margin-top: 18px;
}
.service { display: grid; gap: 4px; }
.service small { color: var(--muted); }
.service-online strong { color: var(--success); }
.service-offline strong { color: var(--muted); }
td code {
  display: inline-block;
  max-width: 100%;
  overflow-wrap: anywhere;
  white-space: normal;
}
.method {
  display: inline-flex;
  min-width: 64px;
  justify-content: center;
  border-radius: 6px;
  padding: 4px 8px;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 700;
  background: var(--soft);
}
.method-post { color: oklch(0.78 0.13 78); background: oklch(0.28 0.04 78); }
.method-get { color: oklch(0.78 0.13 155); background: oklch(0.27 0.04 155); }
.method-delete { color: oklch(0.76 0.13 28); background: oklch(0.28 0.04 28); }
.method-put, .method-patch { color: oklch(0.78 0.1 236); background: oklch(0.28 0.04 236); }
.table-frame {
  margin-top: 18px;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: auto;
}
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { padding: 12px 12px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: 0; }
.endpoint-table code { font-family: var(--mono); }
.json-details { margin-top: 18px; }
.json-details summary { cursor: pointer; color: var(--muted); margin-bottom: 12px; }
.spinner {
  display: none;
  width: 14px;
  height: 14px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
.is-loading .spinner { display: inline-block; }
@keyframes spin { to { transform: rotate(360deg); } }
dialog {
  border: 0;
  border-radius: 10px;
  padding: 0;
  background: var(--panel);
  color: var(--text);
  box-shadow: 0 24px 80px oklch(0.08 0.006 255 / 0.55);
}
dialog::backdrop { background: oklch(0.08 0.006 255 / 0.62); backdrop-filter: blur(3px); }
.dialog-card { width: min(420px, calc(100vw - 32px)); padding: 22px; }
.dialog-card p { color: var(--muted); line-height: 1.6; }
.dialog-card menu { display: flex; justify-content: flex-end; gap: 10px; padding: 0; margin: 18px 0 0; }
.compact-details { margin: 10px 0 0; }
.studio {
  display: grid;
  grid-template-columns: 292px minmax(0, 1fr);
  height: min(800px, calc(100dvh - 136px));
  min-height: 560px;
  overflow: hidden;
  background: var(--studio-bg);
  color: var(--studio-text);
}
.studio-sidebar {
  display: grid;
  grid-template-rows: auto auto auto minmax(0, 1fr) auto auto;
  gap: 12px;
  min-height: 0;
  overflow: hidden;
  padding: 18px;
  border-right: 1px solid var(--studio-line);
}
.studio-heading h2 { font-size: 26px; }
.studio label { color: var(--studio-muted); }
.studio input,
.studio select {
  background: var(--studio-bg);
  color: var(--studio-text);
  border-color: var(--studio-line);
}
.studio-actions { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; }
.studio-tables {
  display: grid;
  align-content: start;
  gap: 4px;
  min-height: 0;
  overflow-x: hidden;
  overflow-y: auto;
  overscroll-behavior: contain;
}
.studio-table-button {
  justify-content: flex-start;
  width: 100%;
  color: var(--studio-muted);
  border-color: transparent;
}
.studio-table-button.active,
.studio-table-button:hover {
  background: var(--studio-active);
  color: var(--studio-text);
}
.studio-main {
  min-width: 0;
  min-height: 0;
  height: 100%;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  position: relative;
}
.studio-toolbar {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
  min-height: 64px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--studio-line);
  background: var(--studio-panel);
}
.studio-toolbar strong { display: block; font-size: 16px; }
.studio-toolbar span { color: var(--studio-muted); font-size: 13px; }
.toolbar-actions { display: flex; align-items: center; gap: 8px; }
.toolbar-actions label { margin: 0; display: flex; align-items: center; gap: 8px; }
.toolbar-actions select { width: 84px; }
.columns-popover {
  position: absolute;
  right: 180px;
  top: 58px;
  z-index: 2;
  display: grid;
  gap: 8px;
  min-width: 220px;
  max-height: 320px;
  overflow: auto;
  padding: 12px;
  border: 1px solid var(--studio-line);
  border-radius: 8px;
  background: var(--studio-panel);
  box-shadow: 0 20px 60px oklch(0.08 0.006 255 / 0.5);
}
.columns-popover[hidden] { display: none; }
.studio-table-wrap {
  flex: 1;
  min-width: 0;
  min-height: 0;
  overflow: auto;
  overscroll-behavior: contain;
}
.studio-table {
  margin: 0;
  min-width: 900px;
  color: var(--studio-text);
  font-family: var(--mono);
  font-size: 13px;
}
.studio-table th,
.studio-table td {
  border-color: var(--studio-line);
  white-space: nowrap;
  max-width: 340px;
  overflow: hidden;
  text-overflow: ellipsis;
}
.studio-table th {
  position: sticky;
  top: 0;
  z-index: 1;
  background: var(--studio-panel);
  color: var(--studio-muted);
}
.studio-table tr:hover td { background: var(--studio-hover); }
@media (max-width: 820px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar { position: static; }
  .tabs { display: flex; flex-wrap: wrap; }
  .details { grid-template-columns: 1fr; }
  .shell-header { align-items: flex-start; flex-direction: column; }
  .panel-heading { align-items: flex-start; flex-direction: column; }
  .studio { grid-template-columns: 1fr; height: auto; }
  .studio-sidebar { border-right: 0; border-bottom: 1px solid var(--studio-line); }
  .studio-main { min-height: 520px; }
  .toolbar-actions { flex-wrap: wrap; justify-content: flex-start; }
}
"#;

const SCRIPT: &str = r#"
let authBase = "/api/axum/auth";
const authRoot = document.body.dataset.authRoot || "/api/example/auth";
const dbSelect = document.getElementById("profile-db");
const rateSelect = document.getElementById("profile-rate-limit");
const dbMirrors = document.querySelectorAll("[data-profile-db-mirror]");
const rateMirrors = document.querySelectorAll("[data-profile-rate-mirror]");
const signoutDialog = document.getElementById("signout-dialog");
const signoutConfirm = signoutDialog?.querySelector("[value='confirm']");
const sidebarUser = document.getElementById("sidebar-user");
const sidebarAvatar = document.getElementById("sidebar-avatar");
const sidebarName = document.getElementById("sidebar-name");
const sidebarEmail = document.getElementById("sidebar-email");
const sidebarUsername = document.getElementById("sidebar-username");
const rateEnabled = document.getElementById("rate-enabled");
const rateWindow = document.getElementById("rate-window");
const rateMax = document.getElementById("rate-max");
const rateWindowDisplay = document.getElementById("rate-window-display");
const rateMaxDisplay = document.getElementById("rate-max-display");
const settingsCookiePrefix = document.getElementById("settings-cookie-prefix");
const themeSelect = document.getElementById("theme-select");
const dropDialog = document.getElementById("drop-dialog");
const dropConfirm = dropDialog?.querySelector("[value='confirm']");
const dropDialogCopy = document.getElementById("drop-dialog-copy");
const studioDb = document.getElementById("studio-db");
const studioTables = document.getElementById("studio-tables");
const studioSearch = document.getElementById("studio-search");
const studioHead = document.getElementById("studio-head");
const studioBody = document.getElementById("studio-body");
const studioMeta = document.getElementById("studio-meta");
const studioTitle = document.getElementById("studio-table-title");
const studioPage = document.getElementById("studio-page");
const studioPageSize = document.getElementById("studio-page-size");
const columnsPopover = document.getElementById("columns-popover");
let currentStudioTable = "user";
let currentStudioColumns = [];
let visibleStudioColumns = new Set();
let currentStudioPage = 0;

function savedTheme() {
  return localStorage.getItem("openauth-example-theme") || "system";
}

function openApiDocsUrl(theme = savedTheme()) {
  const selected = ["system", "dark", "light"].includes(theme) ? theme : "system";
  return `/api/example/reference?theme=${encodeURIComponent(selected)}`;
}

function updateOpenApiDocsLink() {
  const link = document.getElementById("openapi-docs-link");
  if (link) link.href = openApiDocsUrl();
}

function applyTheme(theme) {
  const selected = ["system", "dark", "light"].includes(theme) ? theme : "system";
  if (selected === "system") {
    document.documentElement.removeAttribute("data-theme");
  } else {
    document.documentElement.dataset.theme = selected;
  }
  if (themeSelect) themeSelect.value = selected;
  localStorage.setItem("openauth-example-theme", selected);
  updateOpenApiDocsLink();
}

applyTheme(savedTheme());
themeSelect?.addEventListener("change", () => applyTheme(themeSelect.value));

function savedRateLimitSettings() {
  try {
    return JSON.parse(localStorage.getItem("openauth-example-rate-limit") || "null");
  } catch (_error) {
    return null;
  }
}

const savedRateSettings = savedRateLimitSettings();
const rateSettings = savedRateSettings || {
  enabled: document.body.dataset.rateLimitEnabled !== "false",
  window: Number(document.body.dataset.rateLimitWindow || 60),
  max: Number(document.body.dataset.rateLimitMax || 120),
};
let profileHydrated = false;

function profilePath() {
  return `${authRoot}/${dbSelect?.value || "sqlite"}/${rateSelect?.value || "memory"}`;
}

function rateHeaders() {
  return {
    "x-openauth-example-rate-enabled": String(rateSettings.enabled),
    "x-openauth-example-rate-window": String(rateSettings.window),
    "x-openauth-example-rate-max": String(rateSettings.max),
  };
}

async function loadPreferences() {
  if (!dbSelect || !rateSelect) return;
  try {
    const preferences = await exampleJson("/api/example/preferences");
    if (preferences?.db) dbSelect.value = preferences.db;
    if (preferences?.rateLimit) rateSelect.value = preferences.rateLimit;
  } catch (error) {
    console.warn("Could not load Redis-backed preferences", error);
  } finally {
    profileHydrated = true;
  }
}

async function savePreferences() {
  if (!profileHydrated || !dbSelect || !rateSelect) return;
  try {
    await exampleJson("/api/example/preferences", {
      method: "POST",
      body: JSON.stringify({ db: dbSelect.value, rateLimit: rateSelect.value }),
    });
  } catch (error) {
    console.warn("Could not persist Redis-backed preferences", error);
  }
}

function updateProfile(options = {}) {
  authBase = profilePath();
  dbMirrors.forEach((select) => { select.value = dbSelect.value; });
  rateMirrors.forEach((select) => { select.value = rateSelect.value; });
  if (studioDb && studioDb.value !== dbSelect.value) studioDb.value = dbSelect.value;
  const databaseOption = rateSelect?.querySelector("option[value='database']");
  if (databaseOption) {
    databaseOption.disabled = dbSelect?.value === "memory";
    if (databaseOption.disabled && rateSelect.value === "database") {
      rateSelect.value = "memory";
      authBase = profilePath();
    }
  }
  document.querySelectorAll("[data-current-db]").forEach((item) => { item.textContent = dbSelect?.value || "sqlite"; });
  document.querySelectorAll("[data-current-rate]").forEach((item) => { item.textContent = rateSelect?.value || "memory"; });
  if (settingsCookiePrefix) settingsCookiePrefix.textContent = `open-auth-${dbSelect?.value || "sqlite"}`;
  hideSidebarUser();
  void refreshSession();
  void loadStudioTables();
  if (options.persist) void savePreferences();
}

dbSelect?.addEventListener("change", () => updateProfile({ persist: true }));
rateSelect?.addEventListener("change", () => updateProfile({ persist: true }));
dbMirrors.forEach((select) => select.addEventListener("change", () => {
  dbSelect.value = select.value;
  updateProfile({ persist: true });
}));
rateMirrors.forEach((select) => select.addEventListener("change", () => {
  rateSelect.value = select.value;
  updateProfile({ persist: true });
}));
void loadPreferences().then(() => updateProfile());

function hydrateSettingsForm() {
  if (rateEnabled) rateEnabled.checked = rateSettings.enabled;
  if (rateWindow) rateWindow.value = String(rateSettings.window);
  if (rateMax) rateMax.value = String(rateSettings.max);
  if (rateWindowDisplay) rateWindowDisplay.textContent = String(rateSettings.window);
  if (rateMaxDisplay) rateMaxDisplay.textContent = String(rateSettings.max);
}

hydrateSettingsForm();

const TAB_IDS = ["overview", "auth", "sessions", "storage", "rate-limit", "database", "openapi", "settings"];

function tabFromHash() {
  const hash = location.hash.replace(/^#\/?/, "");
  return TAB_IDS.includes(hash) ? hash : "overview";
}

function setActiveTab(tabId, options = {}) {
  document.querySelectorAll(".tab").forEach((item) => {
    item.classList.toggle("active", item.dataset.tab === tabId);
  });
  document.querySelectorAll(".panel").forEach((item) => {
    item.classList.toggle("active", item.id === tabId);
  });
  if (options.updateHash !== false) {
    const nextHash = `#${tabId}`;
    if (location.hash !== nextHash) {
      history.replaceState(null, "", `${location.pathname}${location.search}${nextHash}`);
    }
  }
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => setActiveTab(tab.dataset.tab));
});

window.addEventListener("hashchange", () => setActiveTab(tabFromHash(), { updateHash: false }));
setActiveTab(tabFromHash(), { updateHash: false });

const dropDatabaseButton = document.getElementById("drop-database");
const seedDatabaseButton = document.getElementById("seed-database");

function setLoading(button, loading) {
  if (!button) return;
  if (!button.dataset.defaultText) {
    button.dataset.defaultText = button.querySelector(".button-label")?.textContent || button.textContent;
  }
  const label = button.querySelector(".button-label");
  button.disabled = loading;
  button.classList.toggle("is-loading", loading);
  if (label) {
    label.textContent = loading ? (button.dataset.loadingText || "Loading...") : button.dataset.defaultText;
  }
}

function setStudioDatabaseBusy(loadingButton, busy) {
  for (const button of [dropDatabaseButton, seedDatabaseButton]) {
    if (!button) continue;
    if (busy && button !== loadingButton) {
      button.disabled = true;
      continue;
    }
    if (!busy) {
      button.disabled = false;
      setLoading(button, false);
      continue;
    }
    setLoading(button, true);
  }
}

async function withStudioDatabaseAction(loadingButton, target, task) {
  setStudioDatabaseBusy(loadingButton, true);
  try {
    show(target, await task());
  } catch (error) {
    show(target, { error: error.message });
  } finally {
    setStudioDatabaseBusy(loadingButton, false);
  }
}

function normalizeDates(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return value;
  for (const [key, nested] of Object.entries(value)) {
    if ((key.endsWith("_at") || key.endsWith("At")) && Array.isArray(nested)) {
      value[key] = "OffsetDateTime array from older response";
    } else {
      normalizeDates(nested);
    }
  }
  return value;
}

function show(target, value) {
  document.getElementById(target).textContent = JSON.stringify(normalizeDates(value), null, 2);
}

function initials(user) {
  const source = user?.name || user?.email || "OpenAuth";
  return source
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "OA";
}

function hideSidebarUser() {
  if (sidebarUser) sidebarUser.hidden = true;
}

function showSidebarUser(user) {
  if (!user || !sidebarUser) {
    hideSidebarUser();
    return;
  }
  sidebarUser.hidden = false;
  sidebarName.textContent = user.name || "Unnamed user";
  sidebarEmail.textContent = user.email || "";
  sidebarUsername.textContent = user.display_username || user.username || "";
  sidebarAvatar.textContent = "";
  if (user.image) {
    const image = document.createElement("img");
    image.src = user.image;
    image.alt = "";
    sidebarAvatar.appendChild(image);
  } else {
    sidebarAvatar.textContent = initials(user);
  }
}

function syncSessionFromResponse(result) {
  const user = result?.body?.user || result?.body?.session?.user;
  if (user) {
    showSidebarUser(user);
  } else if (result?.status >= 400 || result?.body === null || result?.body?.session === null) {
    hideSidebarUser();
  }
  return result;
}

async function refreshSession() {
  try {
    syncSessionFromResponse(await requestJson("/get-session"));
  } catch (_error) {
    hideSidebarUser();
  }
}

async function requestJson(path, options = {}) {
  const response = await fetch(`${authBase}${path}`, {
    credentials: "include",
    headers: { "content-type": "application/json", ...rateHeaders(), ...(options.headers || {}) },
    ...options,
  });
  const text = await response.text();
  let body = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (_error) {}
  return { status: response.status, headers: Object.fromEntries(response.headers.entries()), body };
}

async function exampleJson(path, options = {}) {
  const response = await fetch(path, {
    credentials: "include",
    headers: { "content-type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const text = await response.text();
  let body = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (_error) {}
  if (!response.ok) throw new Error(body?.error || response.statusText);
  return body;
}

async function withLoading(button, target, task) {
  setLoading(button, true);
  try {
    show(target, await task());
  } catch (error) {
    show(target, { error: error.message });
  } finally {
    setLoading(button, false);
  }
}

document.querySelectorAll("[data-auth-form]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button[type='submit']");
    await withLoading(button, "auth-output", async () => {
      const data = Object.fromEntries(new FormData(form).entries());
      data.rememberMe = true;
      const path = form.dataset.authForm === "signup" ? "/sign-up/email" : "/sign-in/email";
      return syncSessionFromResponse(await requestJson(path, { method: "POST", body: JSON.stringify(data) }));
    });
  });
});

document.querySelector("[data-action='get-session']").addEventListener("click", async (event) => {
  await withLoading(event.currentTarget, "session-output", async () => syncSessionFromResponse(await requestJson("/get-session")));
});

document.querySelector("[data-action='list-sessions']").addEventListener("click", async (event) => {
  await withLoading(event.currentTarget, "session-output", () => requestJson("/list-sessions"));
});

document.getElementById("rate-settings-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button[type='submit']");
  await withLoading(button, "settings-output", async () => {
    rateSettings.enabled = Boolean(rateEnabled?.checked);
    rateSettings.window = Math.max(1, Math.min(3600, Number(rateWindow?.value || 60)));
    rateSettings.max = Math.max(1, Math.min(10000, Number(rateMax?.value || 120)));
    localStorage.setItem("openauth-example-rate-limit", JSON.stringify(rateSettings));
    hydrateSettingsForm();
    const result = await requestJson("/ok");
    return { applied: rateSettings, probe: result };
  });
});

document.querySelectorAll("[data-action='sign-out']").forEach((button) => button.addEventListener("click", () => {
  signoutDialog?.showModal();
}));

signoutDialog?.addEventListener("close", async () => {
  if (signoutDialog.returnValue !== "confirm") return;
  await withLoading(signoutConfirm, "session-output", async () => {
    const result = await requestJson("/sign-out", { method: "POST" });
    hideSidebarUser();
    return result;
  });
});

document.getElementById("endpoint-search")?.addEventListener("input", (event) => {
  const needle = event.target.value.trim().toLowerCase();
  document.querySelectorAll("[data-endpoint-row]").forEach((item) => {
    const haystack = `${item.dataset.method} ${item.dataset.path} ${item.dataset.operation}`.toLowerCase();
    item.hidden = needle !== "" && !haystack.includes(needle);
  });
});

updateOpenApiDocsLink();

async function loadStudioTables() {
  if (!studioTables || !studioDb) return;
  const db = studioDb.value || dbSelect?.value || "sqlite";
  try {
    const tables = await exampleJson(`/api/example/tables?db=${encodeURIComponent(db)}`);
    studioTables.innerHTML = "";
    for (const table of tables) {
      const button = document.createElement("button");
      button.className = "studio-table-button";
      button.textContent = table.id;
      button.dataset.table = table.id;
      button.addEventListener("click", () => {
        currentStudioTable = table.id;
        currentStudioPage = 0;
        visibleStudioColumns = new Set(table.columns.map((column) => column.name));
        void loadStudioRows();
      });
      studioTables.appendChild(button);
    }
    if (!tables.some((table) => table.id === currentStudioTable)) {
      currentStudioTable = tables[0]?.id || "user";
    }
    const active = tables.find((table) => table.id === currentStudioTable) || tables[0];
    if (active) visibleStudioColumns = new Set(active.columns.map((column) => column.name));
    await loadStudioRows();
  } catch (error) {
    studioTables.innerHTML = `<span class="note">${escapeHtml(error.message)}</span>`;
  }
}

async function loadStudioRows() {
  if (!studioDb || !studioHead || !studioBody) return;
  const params = new URLSearchParams({
    db: studioDb.value || "sqlite",
    table: currentStudioTable,
    page: String(currentStudioPage),
    page_size: studioPageSize?.value || "50",
    q: studioSearch?.value || "",
    columns: [...visibleStudioColumns].join(","),
  });
  const data = await exampleJson(`/api/example/table?${params}`);
  currentStudioColumns = data.columns;
  if (visibleStudioColumns.size === 0) {
    visibleStudioColumns = new Set(data.columns.map((column) => column.name));
  }
  renderStudio(data);
}

function renderStudio(data) {
  document.querySelectorAll(".studio-table-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.table === data.table);
  });
  if (studioTitle) studioTitle.textContent = data.table;
  if (studioMeta) studioMeta.textContent = `${data.total} rows`;
  if (studioPage) studioPage.textContent = String(data.page);
  const visibleColumns = data.columns.filter((column) => visibleStudioColumns.has(column.name));
  studioHead.innerHTML = `<tr>${visibleColumns.map((column) => `<th>${escapeHtml(column.name)} <small>${escapeHtml(column.kind)}</small></th>`).join("")}</tr>`;
  studioBody.innerHTML = data.rows.length
    ? data.rows.map((row) => `<tr>${visibleColumns.map((column) => `<td title="${escapeHtml(formatCell(row[column.name]))}">${escapeHtml(formatCell(row[column.name]))}</td>`).join("")}</tr>`).join("")
    : `<tr><td colspan="${Math.max(1, visibleColumns.length)}">No rows.</td></tr>`;
  renderColumnsPopover();
}

function renderColumnsPopover() {
  if (!columnsPopover) return;
  columnsPopover.innerHTML = currentStudioColumns.map((column) => `
    <label class="check-label">
      <input type="checkbox" value="${escapeHtml(column.name)}" ${visibleStudioColumns.has(column.name) ? "checked" : ""}>
      ${escapeHtml(column.name)} <small>${escapeHtml(column.kind)}</small>
    </label>
  `).join("");
  columnsPopover.querySelectorAll("input[type='checkbox']").forEach((input) => {
    input.addEventListener("change", () => {
      if (input.checked) visibleStudioColumns.add(input.value);
      else visibleStudioColumns.delete(input.value);
      void loadStudioRows();
    });
  });
}

function formatCell(value) {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

studioDb?.addEventListener("change", () => {
  if (dbSelect) dbSelect.value = studioDb.value;
  currentStudioPage = 0;
  updateProfile({ persist: true });
});
studioSearch?.addEventListener("input", () => {
  currentStudioPage = 0;
  void loadStudioRows();
});
studioPageSize?.addEventListener("change", () => {
  currentStudioPage = 0;
  void loadStudioRows();
});
document.getElementById("studio-refresh")?.addEventListener("click", async (event) => {
  await withLoading(event.currentTarget, "settings-output", async () => {
    await loadStudioTables();
    return { refreshed: true };
  });
});
document.getElementById("studio-prev")?.addEventListener("click", () => {
  currentStudioPage = Math.max(0, currentStudioPage - 1);
  void loadStudioRows();
});
document.getElementById("studio-next")?.addEventListener("click", () => {
  currentStudioPage += 1;
  void loadStudioRows();
});
document.getElementById("columns-button")?.addEventListener("click", () => {
  if (columnsPopover) columnsPopover.hidden = !columnsPopover.hidden;
});
document.getElementById("drop-database")?.addEventListener("click", async (event) => {
  if (dropDialogCopy) dropDialogCopy.textContent = `This will reset OpenAuth tables for ${studioDb?.value || "sqlite"} and run migrations again.`;
  dropDialog?.showModal();
});

dropDialog?.addEventListener("close", async () => {
  if (dropDialog.returnValue !== "confirm") return;
  await withStudioDatabaseAction(dropDatabaseButton, "settings-output", async () => {
    const result = await exampleJson(`/api/example/database/drop?db=${encodeURIComponent(studioDb?.value || "sqlite")}`, { method: "POST" });
    hideSidebarUser();
    await loadStudioTables();
    return result;
  });
});

document.getElementById("seed-database")?.addEventListener("click", async (event) => {
  await withStudioDatabaseAction(event.currentTarget, "settings-output", async () => {
    const result = await exampleJson(`/api/example/database/seed?db=${encodeURIComponent(studioDb?.value || "sqlite")}`, { method: "POST" });
    await loadStudioTables();
    await loadStudioRows();
    return result;
  });
});

void loadStudioTables();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configured_base_url_prefix_is_preserved_for_static_routes() -> Result<(), ExampleError>
    {
        let config = ExampleConfig {
            host: "127.0.0.1".to_owned(),
            port: 3000,
            base_url: "https://example.com/demo/api/axum/auth".to_owned(),
            secret: DEFAULT_SECRET.to_owned(),
            db: DbBackend::Memory,
            rate_limit: RateLimitBackend::Memory,
            rate_limit_enabled: true,
            rate_limit_window: 60,
            rate_limit_max: 120,
            database_url: String::new(),
            database_urls: HashMap::new(),
            allow_default_database_urls: true,
            redis_url: "redis://127.0.0.1:6379".to_owned(),
            valkey_url: "valkey://127.0.0.1:6380".to_owned(),
            dev_controls: true,
        };

        let auth = build_auth(
            config,
            AUTH_BASE_PATH.to_owned(),
            openauth::MemoryAdapter::new(),
            None,
            Arc::new(GovernorMemoryRateLimitStore::new()),
        )
        .await?;

        assert_eq!(
            auth.context().base_url,
            "https://example.com/demo/api/axum/auth"
        );
        Ok(())
    }

    #[tokio::test]
    async fn configured_base_url_prefix_is_preserved_for_dynamic_profiles(
    ) -> Result<(), ExampleError> {
        let config = ExampleConfig {
            host: "127.0.0.1".to_owned(),
            port: 3000,
            base_url: "https://example.com/demo/api/axum/auth".to_owned(),
            secret: DEFAULT_SECRET.to_owned(),
            db: DbBackend::Memory,
            rate_limit: RateLimitBackend::Memory,
            rate_limit_enabled: true,
            rate_limit_window: 60,
            rate_limit_max: 120,
            database_url: String::new(),
            database_urls: HashMap::new(),
            allow_default_database_urls: true,
            redis_url: "redis://127.0.0.1:6379".to_owned(),
            valkey_url: "valkey://127.0.0.1:6380".to_owned(),
            dev_controls: true,
        };
        let profile_path = profile_base_path(DbBackend::Memory, RateLimitBackend::Memory);

        let auth = build_profile_auth(
            config,
            DbBackend::Memory,
            RateLimitBackend::Memory,
            profile_path.clone(),
            openauth::MemoryAdapter::new(),
            Arc::new(GovernorMemoryRateLimitStore::new()),
        )
        .await?;

        assert_eq!(
            auth.context().base_url,
            format!("https://example.com/demo{profile_path}")
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires redis; fred + full plugin stack needs a pre-migrated adapter"]
    async fn fred_profiles_wire_secondary_storage_with_rate_limit() -> Result<(), ExampleError> {
        let config = ExampleConfig {
            host: "127.0.0.1".to_owned(),
            port: 3000,
            base_url: format!("http://127.0.0.1:3000{AUTH_BASE_PATH}"),
            secret: DEFAULT_SECRET.to_owned(),
            db: DbBackend::Memory,
            rate_limit: RateLimitBackend::FredRedis,
            rate_limit_enabled: true,
            rate_limit_window: 60,
            rate_limit_max: 120,
            database_url: String::new(),
            database_urls: HashMap::new(),
            allow_default_database_urls: true,
            redis_url: "redis://127.0.0.1:6379".to_owned(),
            valkey_url: "valkey://127.0.0.1:6380".to_owned(),
            dev_controls: true,
        };

        let auth = build_profile_auth(
            config,
            DbBackend::Memory,
            RateLimitBackend::FredRedis,
            profile_base_path(DbBackend::Memory, RateLimitBackend::FredRedis),
            openauth::MemoryAdapter::new(),
            Arc::new(GovernorMemoryRateLimitStore::new()),
        )
        .await?;

        assert!(
            auth.context().secondary_storage.is_some(),
            "fred profiles should demonstrate FredOpenAuthStores, not only FredRateLimitStore"
        );
        assert!(auth.context().rate_limit.custom_store.is_some());
        assert_eq!(
            auth.context().rate_limit.storage,
            openauth::RateLimitStorageOption::SecondaryStorage
        );
        Ok(())
    }

    #[test]
    fn invalid_example_base_url_is_rejected() {
        let missing_scheme = validate_example_base_url("127.0.0.1:3000/api/axum/auth");
        assert!(missing_scheme.is_err(), "missing scheme must be rejected");
        assert!(matches!(
            missing_scheme,
            Err(ExampleError::InvalidConfig(message))
                if message.contains("OPENAUTH_EXAMPLE_BASE_URL is invalid")
        ));

        let garbage = validate_example_base_url("not-a-valid-url");
        assert!(garbage.is_err(), "garbage input must be rejected");
        assert!(matches!(
            garbage,
            Err(ExampleError::InvalidConfig(message))
                if message.contains("OPENAUTH_EXAMPLE_BASE_URL is invalid")
        ));
    }

    #[test]
    fn auth_base_url_for_path_rejects_malformed_input_without_localhost_fallback() {
        assert!(matches!(
            auth_base_url_for_path("127.0.0.1:3000/api/axum/auth", AUTH_BASE_PATH),
            Err(ExampleError::InvalidConfig(message)) if !message.contains("127.0.0.1")
        ));
    }

    fn test_example_config(db: DbBackend, database_url: impl Into<String>) -> ExampleConfig {
        let database_url = database_url.into();
        let (database_urls, allow_default_database_urls) =
            explicit_database_state(db, &database_url);
        ExampleConfig {
            host: "127.0.0.1".to_owned(),
            port: 3000,
            base_url: format!("http://127.0.0.1:3000{AUTH_BASE_PATH}"),
            secret: DEFAULT_SECRET.to_owned(),
            db,
            rate_limit: RateLimitBackend::Memory,
            rate_limit_enabled: true,
            rate_limit_window: 60,
            rate_limit_max: 120,
            database_url,
            database_urls,
            allow_default_database_urls,
            redis_url: "redis://127.0.0.1:6379".to_owned(),
            valkey_url: "valkey://127.0.0.1:6380".to_owned(),
            dev_controls: true,
        }
    }

    fn explicit_database_state(
        db: DbBackend,
        database_url: &str,
    ) -> (HashMap<DbBackend, String>, bool) {
        let mut database_urls = HashMap::new();
        if db != DbBackend::Memory && !database_url.is_empty() {
            database_urls.insert(db, database_url.to_owned());
            (database_urls, false)
        } else {
            (database_urls, true)
        }
    }

    fn test_app_state(config: ExampleConfig) -> AppState {
        AppState {
            runtime: RuntimeInfo {
                openauth_version: openauth::VERSION.to_owned(),
                framework: "axum".to_owned(),
                auth_base_path: AUTH_BASE_PATH.to_owned(),
                db_backend: config.db.as_str().to_owned(),
                rate_limit_backend: config.rate_limit.as_str().to_owned(),
                rate_limit_enabled: config.rate_limit_enabled,
                rate_limit_window: config.rate_limit_window,
                rate_limit_max: config.rate_limit_max,
                base_url: config.base_url.clone(),
                database_url: display_database_url(&config),
                redis_url: config.redis_url.clone(),
                valkey_url: config.valkey_url.clone(),
            },
            dev_controls: config.dev_controls,
            endpoints: Vec::new(),
            openapi: serde_json::json!({}),
            services: Vec::new(),
            memory_adapter: openauth::MemoryAdapter::new(),
            memory_rate_limit_store: Arc::new(GovernorMemoryRateLimitStore::new()),
            profile_cache: Arc::new(ProfileCache::default()),
            viewer_adapter_cache: Arc::new(ViewerAdapterCache::default()),
            preferences_store: Arc::new(Mutex::new(None)),
            config,
        }
    }

    #[tokio::test]
    async fn preferences_fall_back_when_redis_is_unreachable() -> Result<(), ExampleError> {
        let mut config = test_example_config(DbBackend::Sqlite, String::new());
        config.redis_url = "redis://127.0.0.1:6399".to_owned();
        let store = Arc::new(Mutex::new(None));

        let preferences = load_preferences(&config, &store).await;
        assert_eq!(preferences.db, "sqlite");
        assert_eq!(preferences.rate_limit, "memory");

        let updated = ExamplePreferences {
            db: "memory".to_owned(),
            rate_limit: "redis".to_owned(),
        };
        persist_preferences(&config, &store, &updated).await?;
        let preferences = load_preferences(&config, &store).await;
        assert_eq!(preferences.db, "memory");
        assert_eq!(preferences.rate_limit, "redis");
        Ok(())
    }

    #[test]
    fn demo_defaults_allow_unconfigured_alternate_backends() -> Result<(), ExampleError> {
        let mut config = test_example_config(DbBackend::Sqlite, String::new());
        config.database_url = DbBackend::Sqlite.default_database_url();
        config.allow_default_database_urls = true;
        assert_eq!(
            config.database_url_for(DbBackend::PostgresSqlx)?,
            DbBackend::PostgresSqlx.default_database_url()
        );
        Ok(())
    }

    #[tokio::test]
    async fn dynamic_profiles_do_not_replace_configured_database_urls(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let sqlite_path = std::env::temp_dir().join(format!(
            "openauth-ope150-profile-{}-{nanos}.sqlite",
            std::process::id()
        ));
        let custom_sqlite = format!("sqlite://{}", sqlite_path.display());
        let custom_postgres = "postgres://custom:pass@127.0.0.1:5432/custom_openauth".to_owned();
        ensure_sqlite_parent(&test_example_config(
            DbBackend::Sqlite,
            custom_sqlite.clone(),
        ))?;

        let mut config = test_example_config(DbBackend::PostgresSqlx, custom_postgres.clone());
        config
            .database_urls
            .insert(DbBackend::Sqlite, custom_sqlite.clone());

        assert_eq!(
            config.database_url_for(DbBackend::PostgresSqlx)?,
            custom_postgres
        );
        assert_eq!(config.database_url_for(DbBackend::Sqlite)?, custom_sqlite);
        assert_ne!(
            config.database_url_for(DbBackend::Sqlite)?,
            DbBackend::Sqlite.default_database_url()
        );

        let auth = build_profile_auth(
            config.clone(),
            DbBackend::Sqlite,
            RateLimitBackend::Memory,
            profile_base_path(DbBackend::Sqlite, RateLimitBackend::Memory),
            openauth::MemoryAdapter::new(),
            Arc::new(GovernorMemoryRateLimitStore::new()),
        )
        .await?;
        drop(auth);

        assert!(matches!(
            config.database_url_for(DbBackend::MysqlSqlx),
            Err(ExampleError::InvalidConfig(_))
        ));

        let _ = std::fs::remove_file(sqlite_path);
        Ok(())
    }

    #[tokio::test]
    async fn viewer_routes_reuse_selected_backend_config_without_default_fallback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let sqlite_path = std::env::temp_dir().join(format!(
            "openauth-ope150-viewer-{}-{nanos}.sqlite",
            std::process::id()
        ));
        let custom_sqlite = format!("sqlite://{}", sqlite_path.display());
        ensure_sqlite_parent(&test_example_config(
            DbBackend::Sqlite,
            custom_sqlite.clone(),
        ))?;

        let custom_postgres = "postgres://custom:pass@127.0.0.1:5432/custom_openauth".to_owned();
        let mut config = test_example_config(DbBackend::PostgresSqlx, custom_postgres);
        config
            .database_urls
            .insert(DbBackend::Sqlite, custom_sqlite.clone());
        ensure_sqlite_parent(&config)?;

        let adapter = SqliteAdapter::connect(&custom_sqlite).await?;
        let auth = build_auth(
            config.clone(),
            profile_base_path(DbBackend::Sqlite, RateLimitBackend::Memory),
            adapter,
            None,
            Arc::new(GovernorMemoryRateLimitStore::new()),
        )
        .await?;
        auth.run_migrations().await?;
        drop(auth);

        let state = test_app_state(config);

        assert_ne!(
            state.config.database_url_for(DbBackend::Sqlite)?,
            DbBackend::Sqlite.default_database_url()
        );

        table_rows_for_db(
            &state,
            DbBackend::Sqlite,
            TableQuery {
                db: Some("sqlite".to_owned()),
                table: Some("user".to_owned()),
                page: None,
                page_size: None,
                columns: None,
                q: None,
            },
        )
        .await?;

        assert!(matches!(
            table_rows_for_db(
                &state,
                DbBackend::MysqlSqlx,
                TableQuery {
                    db: Some("mysql".to_owned()),
                    table: Some("user".to_owned()),
                    page: None,
                    page_size: None,
                    columns: None,
                    q: None,
                },
            )
            .await,
            Err(ExampleError::InvalidConfig(_))
        ));

        let _ = std::fs::remove_file(sqlite_path);
        Ok(())
    }

    #[tokio::test]
    async fn seed_populates_memory_tables() -> Result<(), ExampleError> {
        let adapter = openauth::MemoryAdapter::new();
        let schema = viewer_schema();
        let password_hash = seed::seed_password_hash()?;
        let summary = seed::seed_database(&adapter, &schema, &password_hash).await?;
        assert!(
            summary.tables_seeded >= 20,
            "expected broad plugin coverage, got {} tables",
            summary.tables_seeded
        );
        let users = adapter
            .count(openauth::db::Count::new("user"))
            .await
            .map_err(ExampleError::from)?;
        assert!(users >= 1);
        Ok(())
    }

    #[tokio::test]
    async fn seed_populates_sqlite_tables() -> Result<(), ExampleError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| ExampleError::InvalidConfig(error.to_string()))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "openauth-example-seed-{}-{nanos}.sqlite",
            std::process::id()
        ));
        let database_url = format!("sqlite://{}", path.display());
        ensure_sqlite_parent(&test_example_config(
            DbBackend::Sqlite,
            database_url.clone(),
        ))?;

        let schema = viewer_schema();
        let adapter = SqliteAdapter::connect_with_schema(&database_url, schema.clone()).await?;
        adapter.run_migrations(&schema).await?;
        let password_hash = seed::seed_password_hash()?;
        let summary = seed::seed_database(&adapter, &schema, &password_hash).await?;
        let table_lookup_errors = summary
            .tables
            .iter()
            .filter_map(|table| table.error.as_deref())
            .filter(|error| error.contains("schema table"))
            .collect::<Vec<_>>();
        assert!(
            table_lookup_errors.is_empty(),
            "adapter schema must match viewer schema during seed: {table_lookup_errors:?}"
        );
        assert!(
            summary.tables_seeded >= 15,
            "expected broad plugin coverage, got {} tables seeded ({:?})",
            summary.tables_seeded,
            summary
                .tables
                .iter()
                .filter(|table| table.error.is_some())
                .collect::<Vec<_>>()
        );
        let users = adapter
            .count(openauth::db::Count::new("user"))
            .await
            .map_err(ExampleError::from)?;
        assert!(users >= 1);

        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    async fn seed_external_database(db: DbBackend, database_url: &str) -> Result<(), ExampleError> {
        let schema = viewer_schema();
        let adapter = match db {
            DbBackend::PostgresSqlx => {
                Arc::new(PostgresAdapter::connect_with_schema(database_url, schema.clone()).await?)
                    as Arc<dyn DbAdapter>
            }
            DbBackend::MysqlSqlx => {
                Arc::new(MySqlAdapter::connect_with_schema(database_url, schema.clone()).await?)
                    as Arc<dyn DbAdapter>
            }
            other => {
                return Err(ExampleError::InvalidConfig(format!(
                    "unsupported external seed backend `{}`",
                    other.as_str()
                )));
            }
        };
        adapter.run_migrations(&schema).await?;
        let password_hash = seed::seed_password_hash()?;
        let summary = seed::seed_database(adapter.as_ref(), &schema, &password_hash).await?;
        let failures = summary
            .tables
            .iter()
            .filter_map(|table| {
                table
                    .error
                    .as_deref()
                    .map(|error| (table.table.clone(), error))
            })
            .collect::<Vec<_>>();
        assert!(
            failures.is_empty(),
            "seed failures for {}: {failures:?}",
            db.as_str()
        );
        assert!(
            summary.tables_seeded >= 15,
            "expected broad plugin coverage for {}, got {} tables seeded",
            db.as_str(),
            summary.tables_seeded
        );
        let users = adapter
            .count(Count::new("user"))
            .await
            .map_err(ExampleError::from)?;
        assert!(users >= 1, "expected seeded user row for {}", db.as_str());
        Ok(())
    }

    async fn external_database_available(db: DbBackend, database_url: &str) -> bool {
        match db {
            DbBackend::PostgresSqlx => sqlx::PgPool::connect(database_url).await.is_ok(),
            DbBackend::MysqlSqlx => sqlx::MySqlPool::connect(database_url).await.is_ok(),
            _ => false,
        }
    }

    #[tokio::test]
    async fn seed_populates_postgres_tables() -> Result<(), ExampleError> {
        let database_url = DbBackend::PostgresSqlx.default_database_url();
        if !external_database_available(DbBackend::PostgresSqlx, &database_url).await {
            eprintln!("skipping postgres seed test: database unavailable at {database_url}");
            return Ok(());
        }
        seed_external_database(DbBackend::PostgresSqlx, &database_url).await
    }

    async fn mysql_table_exists(pool: &sqlx::MySqlPool, table: &str) -> Result<bool, ExampleError> {
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' \
             AND table_name = ?",
        )
        .bind(table)
        .fetch_one(pool)
        .await?;
        Ok(exists > 0)
    }

    #[tokio::test]
    async fn mysql_seed_and_schema_reset_integration() -> Result<(), ExampleError> {
        let database_url = DbBackend::MysqlSqlx.default_database_url();
        if !external_database_available(DbBackend::MysqlSqlx, &database_url).await {
            eprintln!("skipping mysql integration test: database unavailable at {database_url}");
            return Ok(());
        }

        seed_external_database(DbBackend::MysqlSqlx, &database_url).await?;

        const LEGACY_TABLE: &str = "openauth_example_legacy_reset_probe";
        let pool = sqlx::MySqlPool::connect(&database_url).await?;
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS `{LEGACY_TABLE}` (id INT PRIMARY KEY)"
        ))
        .execute(&pool)
        .await?;
        assert!(
            mysql_table_exists(&pool, LEGACY_TABLE).await?,
            "expected legacy probe table before reset"
        );

        let mut config = test_example_config(DbBackend::MysqlSqlx, database_url.clone());
        config.db = DbBackend::MysqlSqlx;
        reset_mysql_schema(&config).await?;

        assert!(
            !mysql_table_exists(&pool, LEGACY_TABLE).await?,
            "reset should drop legacy tables that are not part of the current schema"
        );
        Ok(())
    }

    #[tokio::test]
    async fn schema_reset_rejects_unconfigured_alternate_backend() -> Result<(), ExampleError> {
        let config = test_example_config(
            DbBackend::PostgresSqlx,
            "postgres://custom:pass@127.0.0.1:5432/custom_openauth".to_owned(),
        );
        let state = test_app_state(config);

        assert!(matches!(
            drop_database_for_db(&state, DbBackend::MysqlSqlx).await,
            Err(ExampleError::InvalidConfig(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn dynamic_profile_cache_reuses_auth_instances() -> Result<(), ExampleError> {
        let cache = ProfileCache::default();
        let memory_rate_limit_store = Arc::new(GovernorMemoryRateLimitStore::new());
        let config = test_example_config(DbBackend::Memory, String::new());
        let key = ProfileKey {
            db: DbBackend::Memory,
            rate_limit: RateLimitBackend::Memory,
            rate_limit_enabled: config.rate_limit_enabled,
            rate_limit_window: config.rate_limit_window,
            rate_limit_max: config.rate_limit_max,
        };

        for _ in 0..5 {
            let config_for_build = config.clone();
            let memory_adapter = openauth::MemoryAdapter::new();
            let memory_rate_limit_store = memory_rate_limit_store.clone();
            cache
                .get_or_insert(key.clone(), || async {
                    build_profile_auth(
                        config_for_build,
                        DbBackend::Memory,
                        RateLimitBackend::Memory,
                        profile_base_path(DbBackend::Memory, RateLimitBackend::Memory),
                        memory_adapter,
                        memory_rate_limit_store,
                    )
                    .await
                })
                .await?;
        }

        assert_eq!(
            cache.build_count(),
            1,
            "repeated requests to the same profile must reuse one cached OpenAuth instance"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dynamic_profile_cache_invalidates_after_database_drop() -> Result<(), ExampleError> {
        let cache = ProfileCache::default();
        let memory_rate_limit_store = Arc::new(GovernorMemoryRateLimitStore::new());
        let config = test_example_config(DbBackend::Memory, String::new());
        let key = ProfileKey {
            db: DbBackend::Memory,
            rate_limit: RateLimitBackend::Memory,
            rate_limit_enabled: config.rate_limit_enabled,
            rate_limit_window: config.rate_limit_window,
            rate_limit_max: config.rate_limit_max,
        };

        let config_for_build = config.clone();
        let memory_adapter = openauth::MemoryAdapter::new();
        cache
            .get_or_insert(key.clone(), || async {
                build_profile_auth(
                    config_for_build,
                    DbBackend::Memory,
                    RateLimitBackend::Memory,
                    profile_base_path(DbBackend::Memory, RateLimitBackend::Memory),
                    memory_adapter,
                    memory_rate_limit_store.clone(),
                )
                .await
            })
            .await?;
        cache.invalidate_db(DbBackend::Memory).await;

        let config_for_build = config.clone();
        let memory_adapter = openauth::MemoryAdapter::new();
        cache
            .get_or_insert(key, || async {
                build_profile_auth(
                    config_for_build,
                    DbBackend::Memory,
                    RateLimitBackend::Memory,
                    profile_base_path(DbBackend::Memory, RateLimitBackend::Memory),
                    memory_adapter,
                    memory_rate_limit_store,
                )
                .await
            })
            .await?;

        assert_eq!(
            cache.build_count(),
            2,
            "dropping a database profile must invalidate cached auth instances"
        );
        Ok(())
    }

    #[tokio::test]
    async fn viewer_adapter_cache_reuses_sql_connections() -> Result<(), ExampleError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| ExampleError::InvalidConfig(error.to_string()))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "openauth-ope93-viewer-{}-{nanos}.sqlite",
            std::process::id()
        ));
        let database_url = format!("sqlite://{}", path.display());
        ensure_sqlite_parent(&test_example_config(
            DbBackend::Sqlite,
            database_url.clone(),
        ))?;
        let cache = ViewerAdapterCache::default();

        let schema = viewer_schema();
        for _ in 0..5 {
            cache
                .get_or_connect(DbBackend::Sqlite, &database_url, &schema)
                .await?;
        }

        assert_eq!(
            cache.connect_count(),
            1,
            "repeated table viewer reads must reuse one cached SQL adapter"
        );

        cache.invalidate_db(DbBackend::Sqlite).await;
        cache
            .get_or_connect(DbBackend::Sqlite, &database_url, &schema)
            .await?;
        assert_eq!(
            cache.connect_count(),
            2,
            "schema reset must invalidate cached viewer adapters"
        );

        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn build_profile_auth_does_not_migrate_on_request_path(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "openauth-ope60-{}-{nanos}.sqlite",
            std::process::id()
        ));
        let database_url = format!("sqlite://{}", path.display());
        let config = test_example_config(DbBackend::Sqlite, database_url.clone());
        let mut config = config;
        config.rate_limit = RateLimitBackend::Database;

        let auth = build_profile_auth(
            config,
            DbBackend::Sqlite,
            RateLimitBackend::Database,
            profile_base_path(DbBackend::Sqlite, RateLimitBackend::Database),
            openauth::MemoryAdapter::new(),
            Arc::new(GovernorMemoryRateLimitStore::new()),
        )
        .await?;
        drop(auth);

        // The dynamic request path must not create the auth schema, so a fresh
        // connection to the same database has no `user` table to count.
        let adapter = SqliteAdapter::connect(&database_url).await?;
        assert!(
            adapter.count(Count::new("user")).await.is_err(),
            "the request path must not run migrations"
        );

        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    /// Locks the README to the accepted configuration surface so the docs stay
    /// aligned with [`RateLimitBackend`] parsing and the tuning env vars.
    #[test]
    fn readme_documents_rate_limit_surface() {
        const README: &str = include_str!("../README.md");
        for backend in [
            "memory",
            "database",
            "redis",
            "valkey",
            "hybrid-redis",
            "hybrid-valkey",
            "fred-redis",
            "fred-valkey",
        ] {
            assert!(
                matches!(
                    backend.parse::<RateLimitBackend>(),
                    Ok(parsed) if parsed.as_str() == backend
                ),
                "`{backend}` must round-trip through RateLimitBackend"
            );
            assert!(
                README.contains(backend),
                "README must document rate-limit backend `{backend}`"
            );
        }
        for var in [
            "OPENAUTH_EXAMPLE_RATE_LIMIT_ENABLED",
            "OPENAUTH_EXAMPLE_RATE_LIMIT_WINDOW",
            "OPENAUTH_EXAMPLE_RATE_LIMIT_MAX",
        ] {
            assert!(README.contains(var), "README must document `{var}`");
        }
    }
}
