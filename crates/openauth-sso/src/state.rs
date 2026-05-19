use std::sync::Arc;

use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::options::SecondaryStorage;
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoStateRecord {
    pub identifier: String,
    pub value: String,
    pub expires_at: OffsetDateTime,
}

pub struct SsoStateStore<'a> {
    adapter: &'a dyn DbAdapter,
    secondary_storage: Option<Arc<dyn SecondaryStorage>>,
}

impl<'a> SsoStateStore<'a> {
    pub fn new(context: &AuthContext, adapter: &'a dyn DbAdapter) -> Self {
        Self {
            adapter,
            secondary_storage: context.secondary_storage(),
        }
    }

    pub async fn create(
        &self,
        identifier: impl Into<String>,
        value: impl Into<String>,
        expires_at: OffsetDateTime,
    ) -> Result<(), OpenAuthError> {
        let identifier = identifier.into();
        let value = value.into();
        if let Some(storage) = &self.secondary_storage {
            let payload = serde_json::to_string(&SecondaryStateRecord {
                value,
                expires_at: expires_at.unix_timestamp(),
            })
            .map_err(|error| {
                OpenAuthError::Api(format!("failed to serialize SSO state: {error}"))
            })?;
            storage
                .set(&identifier, payload, ttl_seconds(expires_at))
                .await?;
            return Ok(());
        }

        DbVerificationStore::new(self.adapter)
            .create_verification(CreateVerificationInput::new(identifier, value, expires_at))
            .await?;
        Ok(())
    }

    pub async fn find(&self, identifier: &str) -> Result<Option<SsoStateRecord>, OpenAuthError> {
        if let Some(storage) = &self.secondary_storage {
            let Some(payload) = storage.get(identifier).await? else {
                return Ok(None);
            };
            let record =
                serde_json::from_str::<SecondaryStateRecord>(&payload).map_err(|error| {
                    OpenAuthError::Api(format!("failed to deserialize SSO state: {error}"))
                })?;
            let expires_at =
                OffsetDateTime::from_unix_timestamp(record.expires_at).map_err(|error| {
                    OpenAuthError::Api(format!("invalid SSO state expiration: {error}"))
                })?;
            if expires_at <= OffsetDateTime::now_utc() {
                storage.delete(identifier).await?;
                return Ok(None);
            }
            return Ok(Some(SsoStateRecord {
                identifier: identifier.to_owned(),
                value: record.value,
                expires_at,
            }));
        }

        DbVerificationStore::new(self.adapter)
            .find_verification(identifier)
            .await
            .map(|record| {
                record.map(|record| SsoStateRecord {
                    identifier: record.identifier,
                    value: record.value,
                    expires_at: record.expires_at,
                })
            })
    }

    pub async fn delete(&self, identifier: &str) -> Result<(), OpenAuthError> {
        if let Some(storage) = &self.secondary_storage {
            return storage.delete(identifier).await;
        }
        DbVerificationStore::new(self.adapter)
            .delete_verification(identifier)
            .await
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SecondaryStateRecord {
    value: String,
    expires_at: i64,
}

fn ttl_seconds(expires_at: OffsetDateTime) -> Option<u64> {
    let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
    Some(u64::try_from(seconds).unwrap_or(0))
}
