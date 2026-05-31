use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use openauth_core::options::SecondaryStorage;
use openauth_core::plugin::PluginRequest;
use serde::{Deserialize, Serialize};

pub type ApiKeyPermissions = BTreeMap<String, Vec<String>>;
pub type ApiKeyGeneratorFuture =
    Pin<Box<dyn Future<Output = Result<String, OpenAuthError>> + Send + 'static>>;
pub type ApiKeyGenerator = Arc<dyn Fn(ApiKeyGeneratorInput) -> ApiKeyGeneratorFuture + Send + Sync>;
pub type ApiKeyGetterFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, OpenAuthError>> + Send + 'a>>;
pub type ApiKeyGetter =
    Arc<dyn for<'a> Fn(&'a AuthContext, &'a PluginRequest) -> ApiKeyGetterFuture<'a> + Send + Sync>;
pub type ApiKeyValidatorFuture<'a> =
    Pin<Box<dyn Future<Output = Result<bool, OpenAuthError>> + Send + 'a>>;
pub type ApiKeyValidator =
    Arc<dyn for<'a> Fn(&'a AuthContext, &'a str) -> ApiKeyValidatorFuture<'a> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyGeneratorInput {
    pub length: usize,
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApiKeyStorageMode {
    Database,
    SecondaryStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApiKeyReference {
    User,
    Organization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyRateLimitOptions {
    pub enabled: bool,
    pub time_window: i64,
    pub max_requests: i64,
}

impl Default for ApiKeyRateLimitOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            time_window: 1000 * 60 * 60 * 24,
            max_requests: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyExpirationOptions {
    pub default_expires_in: Option<i64>,
    pub disable_custom_expires_time: bool,
    pub min_expires_in_days: i64,
    pub max_expires_in_days: i64,
}

impl Default for ApiKeyExpirationOptions {
    fn default() -> Self {
        Self {
            default_expires_in: None,
            disable_custom_expires_time: false,
            min_expires_in_days: 1,
            max_expires_in_days: 365,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartingCharactersConfig {
    pub should_store: bool,
    pub characters_length: usize,
}

impl Default for StartingCharactersConfig {
    fn default() -> Self {
        Self {
            should_store: true,
            characters_length: 6,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ApiKeyConfiguration {
    pub config_id: Option<String>,
    pub api_key_headers: Vec<String>,
    pub disable_key_hashing: bool,
    pub default_key_length: usize,
    pub default_prefix: Option<String>,
    pub maximum_prefix_length: usize,
    pub minimum_prefix_length: usize,
    pub require_name: bool,
    pub maximum_name_length: usize,
    pub minimum_name_length: usize,
    pub enable_metadata: bool,
    pub key_expiration: ApiKeyExpirationOptions,
    pub rate_limit: ApiKeyRateLimitOptions,
    pub enable_session_for_api_keys: bool,
    pub default_permissions: Option<ApiKeyPermissions>,
    #[serde(skip)]
    pub custom_key_generator: Option<ApiKeyGenerator>,
    #[serde(skip)]
    pub custom_api_key_getter: Option<ApiKeyGetter>,
    #[serde(skip)]
    pub custom_api_key_validator: Option<ApiKeyValidator>,
    pub storage: ApiKeyStorageMode,
    pub fallback_to_database: bool,
    /// When `true` (and [`Self::fallback_to_database`] is enabled), reads that
    /// hit the secondary-storage cache are reconciled against the database
    /// before being returned: a missing row is treated as revoked and a newer
    /// `updated_at` refreshes the cache. This trades a per-read database lookup
    /// for immediate revocation of out-of-band database edits and keys without
    /// a TTL. Defaults to `false` to preserve the cache-first behavior that
    /// matches upstream Better Auth.
    pub revalidate_secondary_against_database: bool,
    #[serde(skip)]
    pub custom_storage: Option<Arc<dyn SecondaryStorage>>,
    pub defer_updates: bool,
    pub reference: ApiKeyReference,
    pub starting_characters: StartingCharactersConfig,
}

impl Default for ApiKeyConfiguration {
    fn default() -> Self {
        Self {
            config_id: None,
            api_key_headers: vec!["x-api-key".to_owned()],
            disable_key_hashing: false,
            default_key_length: 64,
            default_prefix: None,
            maximum_prefix_length: 32,
            minimum_prefix_length: 1,
            require_name: false,
            maximum_name_length: 32,
            minimum_name_length: 1,
            enable_metadata: false,
            key_expiration: ApiKeyExpirationOptions::default(),
            rate_limit: ApiKeyRateLimitOptions::default(),
            enable_session_for_api_keys: false,
            default_permissions: None,
            custom_key_generator: None,
            custom_api_key_getter: None,
            custom_api_key_validator: None,
            storage: ApiKeyStorageMode::Database,
            fallback_to_database: false,
            revalidate_secondary_against_database: false,
            custom_storage: None,
            defer_updates: false,
            reference: ApiKeyReference::User,
            starting_characters: StartingCharactersConfig::default(),
        }
    }
}

impl fmt::Debug for ApiKeyConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeyConfiguration")
            .field("config_id", &self.config_id)
            .field("api_key_headers", &self.api_key_headers)
            .field("disable_key_hashing", &self.disable_key_hashing)
            .field("default_key_length", &self.default_key_length)
            .field("default_prefix", &self.default_prefix)
            .field("maximum_prefix_length", &self.maximum_prefix_length)
            .field("minimum_prefix_length", &self.minimum_prefix_length)
            .field("require_name", &self.require_name)
            .field("maximum_name_length", &self.maximum_name_length)
            .field("minimum_name_length", &self.minimum_name_length)
            .field("enable_metadata", &self.enable_metadata)
            .field("key_expiration", &self.key_expiration)
            .field("rate_limit", &self.rate_limit)
            .field(
                "enable_session_for_api_keys",
                &self.enable_session_for_api_keys,
            )
            .field("default_permissions", &self.default_permissions)
            .field(
                "custom_key_generator",
                &self
                    .custom_key_generator
                    .as_ref()
                    .map(|_| "<custom-key-generator>"),
            )
            .field(
                "custom_api_key_getter",
                &self
                    .custom_api_key_getter
                    .as_ref()
                    .map(|_| "<custom-api-key-getter>"),
            )
            .field(
                "custom_api_key_validator",
                &self
                    .custom_api_key_validator
                    .as_ref()
                    .map(|_| "<custom-api-key-validator>"),
            )
            .field("storage", &self.storage)
            .field("fallback_to_database", &self.fallback_to_database)
            .field(
                "revalidate_secondary_against_database",
                &self.revalidate_secondary_against_database,
            )
            .field(
                "custom_storage",
                &self.custom_storage.as_ref().map(|_| "<custom-storage>"),
            )
            .field("defer_updates", &self.defer_updates)
            .field("reference", &self.reference)
            .field("starting_characters", &self.starting_characters)
            .finish()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ApiKeyOptions {
    pub configuration: ApiKeyConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiKeyOptionsError {
    #[error("config_id is required for each API key configuration in the api-key plugin")]
    MissingConfigId,
    #[error("config_id must be unique for each API key configuration in the api-key plugin")]
    DuplicateConfigId,
}

impl From<ApiKeyOptionsError> for OpenAuthError {
    fn from(error: ApiKeyOptionsError) -> Self {
        Self::InvalidConfig(error.to_string())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedConfigurations {
    configurations: Vec<ApiKeyConfiguration>,
}

impl ResolvedConfigurations {
    pub fn single(configuration: ApiKeyConfiguration) -> Self {
        Self {
            configurations: vec![configuration],
        }
    }

    pub fn multiple(configurations: Vec<ApiKeyConfiguration>) -> Result<Self, ApiKeyOptionsError> {
        let mut seen = HashSet::new();
        for configuration in &configurations {
            let Some(config_id) = configuration.config_id.as_deref() else {
                return Err(ApiKeyOptionsError::MissingConfigId);
            };
            if !seen.insert(config_id.to_owned()) {
                return Err(ApiKeyOptionsError::DuplicateConfigId);
            }
        }
        Ok(Self { configurations })
    }

    pub fn all(&self) -> &[ApiKeyConfiguration] {
        &self.configurations
    }

    pub fn resolve(&self, config_id: Option<&str>) -> Result<ApiKeyConfiguration, OpenAuthError> {
        if let Some(config_id) = config_id {
            if let Some(configuration) = self
                .configurations
                .iter()
                .find(|configuration| configuration.config_id.as_deref() == Some(config_id))
            {
                return Ok(with_default_config_id(configuration.clone()));
            }
        }

        self.configurations
            .iter()
            .find(|configuration| {
                configuration.config_id.is_none()
                    || configuration.config_id.as_deref() == Some("default")
            })
            .cloned()
            .map(with_default_config_id)
            .ok_or_else(|| {
                OpenAuthError::Api(
                    crate::api_key::errors::message(
                        crate::api_key::errors::NO_DEFAULT_API_KEY_CONFIGURATION_FOUND,
                    )
                    .to_owned(),
                )
            })
    }
}

fn with_default_config_id(mut configuration: ApiKeyConfiguration) -> ApiKeyConfiguration {
    if configuration.config_id.is_none() {
        configuration.config_id = Some("default".to_owned());
    }
    configuration
}
