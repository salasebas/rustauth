//! Bundled database adapter + SQL-backed rate-limit store for each Diesel backend.

use std::sync::Arc;

use rustauth_core::db::{auth_schema, AuthSchemaOptions, DbAdapter, DbSchema};
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{RateLimitOptions, RustAuthOptions};

macro_rules! diesel_stores {
    ($stores:ident, $builder:ident, $adapter:ty, $rate_limit:ty) => {
        /// Database adapter and matching SQL-backed rate-limit store sharing one pool.
        #[derive(Debug, Clone)]
        pub struct $stores {
            pub adapter: $adapter,
            pub rate_limit: $rate_limit,
        }

        /// Configures and connects a [`$stores`] bundle.
        #[derive(Debug, Clone)]
        pub struct $builder {
            schema: DbSchema,
        }

        impl Default for $builder {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $builder {
            pub fn new() -> Self {
                Self {
                    schema: auth_schema(AuthSchemaOptions::default()),
                }
            }

            #[must_use]
            pub fn schema(mut self, schema: DbSchema) -> Self {
                self.schema = schema;
                self
            }

            pub async fn connect(self, database_url: &str) -> Result<$stores, RustAuthError> {
                let adapter = <$adapter>::connect_with_schema(database_url, self.schema).await?;
                let rate_limit = <$rate_limit>::from(&adapter);
                Ok($stores {
                    adapter,
                    rate_limit,
                })
            }
        }

        impl $stores {
            pub fn builder() -> $builder {
                $builder::new()
            }

            pub async fn connect(database_url: &str) -> Result<Self, RustAuthError> {
                Self::builder().connect(database_url).await
            }

            pub async fn connect_with_schema(
                database_url: &str,
                schema: DbSchema,
            ) -> Result<Self, RustAuthError> {
                Self::builder().schema(schema).connect(database_url).await
            }

            /// Wires the SQL-backed rate-limit store into [`RustAuthOptions`].
            #[must_use]
            pub fn apply_to_options(&self, options: RustAuthOptions) -> RustAuthOptions {
                options.rate_limit(RateLimitOptions::database(self.rate_limit.clone()))
            }

            pub fn adapter(&self) -> Arc<dyn DbAdapter> {
                Arc::new(self.adapter.clone())
            }

            pub fn adapter_ref(&self) -> &$adapter {
                &self.adapter
            }
        }
    };
}

#[cfg(feature = "postgres")]
diesel_stores!(
    DieselPostgresStores,
    DieselPostgresStoresBuilder,
    crate::DieselPostgresAdapter,
    crate::DieselPostgresRateLimitStore
);

#[cfg(feature = "mysql")]
diesel_stores!(
    DieselMysqlStores,
    DieselMysqlStoresBuilder,
    crate::DieselMysqlAdapter,
    crate::DieselMysqlRateLimitStore
);
