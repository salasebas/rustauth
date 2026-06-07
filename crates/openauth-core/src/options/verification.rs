use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::OpenAuthError;

use super::model_schema::ModelSchemaOptions;

pub type StoreIdentifierHashFuture =
    Pin<Box<dyn Future<Output = Result<String, OpenAuthError>> + Send>>;
pub type StoreIdentifierHashFn = Arc<dyn Fn(String) -> StoreIdentifierHashFuture + Send + Sync>;

/// How verification identifiers are persisted.
#[derive(Clone, Default)]
pub enum StoreIdentifierOption {
    #[default]
    Plain,
    Hashed,
    Custom(StoreIdentifierHashFn),
}

impl fmt::Debug for StoreIdentifierOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => formatter.write_str("Plain"),
            Self::Hashed => formatter.write_str("Hashed"),
            Self::Custom(_) => formatter.write_str("Custom(<hash>)"),
        }
    }
}

/// Verification storage configuration.
#[derive(Clone, Debug, Default)]
pub enum VerificationStoreIdentifierConfig {
    #[default]
    Plain,
    Single(StoreIdentifierOption),
    WithOverrides {
        default: StoreIdentifierOption,
        overrides: BTreeMap<String, StoreIdentifierOption>,
    },
}

impl VerificationStoreIdentifierConfig {
    pub fn hashed() -> Self {
        Self::Single(StoreIdentifierOption::Hashed)
    }

    pub fn resolve(&self, identifier: &str) -> StoreIdentifierOption {
        match self {
            Self::Plain => StoreIdentifierOption::Plain,
            Self::Single(option) => option.clone(),
            Self::WithOverrides { default, overrides } => {
                for (prefix, option) in overrides {
                    if identifier.starts_with(prefix) {
                        return option.clone();
                    }
                }
                default.clone()
            }
        }
    }
}

/// Verification token storage options.
#[derive(Clone, Debug, Default)]
pub struct VerificationOptions {
    pub schema: ModelSchemaOptions,
    pub store_identifier: VerificationStoreIdentifierConfig,
    pub disable_cleanup: bool,
}

impl VerificationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn schema(mut self, schema: ModelSchemaOptions) -> Self {
        self.schema = schema;
        self
    }

    #[must_use]
    pub fn store_identifier_hashed(mut self) -> Self {
        self.store_identifier = VerificationStoreIdentifierConfig::hashed();
        self
    }

    #[must_use]
    pub fn store_identifier(mut self, config: VerificationStoreIdentifierConfig) -> Self {
        self.store_identifier = config;
        self
    }

    #[must_use]
    pub fn disable_cleanup(mut self, disabled: bool) -> Self {
        self.disable_cleanup = disabled;
        self
    }
}
