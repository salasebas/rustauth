#[cfg(feature = "saml")]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "saml")]
use std::sync::{Mutex, OnceLock, Weak};

use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::options::SecondaryStorage;
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
#[cfg(feature = "saml")]
use tokio::sync::Mutex as AsyncMutex;

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

    /// Record SSO state only when `identifier` is not already present.
    ///
    /// Returns `Ok(true)` when the record was created and `Ok(false)` when another
    /// request already claimed the identifier (for example concurrent SAML assertion
    /// replay handling).
    #[cfg(feature = "saml")]
    pub async fn try_create(
        &self,
        identifier: impl Into<String>,
        value: impl Into<String>,
        expires_at: OffsetDateTime,
    ) -> Result<bool, OpenAuthError> {
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
            return storage
                .set_if_not_exists(&identifier, payload, ttl_seconds(expires_at))
                .await;
        }

        let lock = database_state_lock(&identifier);
        let _guard = lock.lock().await;
        if DbVerificationStore::new(self.adapter)
            .find_verification(&identifier)
            .await?
            .is_some()
        {
            return Ok(false);
        }
        DbVerificationStore::new(self.adapter)
            .create_verification(CreateVerificationInput::new(identifier, value, expires_at))
            .await?;
        Ok(true)
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

    #[cfg_attr(
        not(feature = "saml"),
        expect(
            dead_code,
            reason = "SSO state deletion is used by SAML session cleanup"
        )
    )]
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

#[cfg(feature = "saml")]
fn database_state_lock(identifier: &str) -> Arc<AsyncMutex<()>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Weak<AsyncMutex<()>>>>> = OnceLock::new();
    let mut registry = REGISTRY
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(lock) = registry.get(identifier).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(AsyncMutex::new(()));
    registry.insert(identifier.to_owned(), Arc::downgrade(&lock));
    registry.retain(|_, weak| weak.strong_count() > 0);
    lock
}
