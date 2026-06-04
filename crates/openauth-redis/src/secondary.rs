use openauth_core::error::OpenAuthError;
use openauth_core::options::{SecondaryStorage, SecondaryStorageFuture};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

use crate::url::{secondary_storage_scan_pattern, validate_key_prefix};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisSecondaryStorageOptions {
    pub key_prefix: String,
    pub scan_count: u32,
}

impl Default for RedisSecondaryStorageOptions {
    fn default() -> Self {
        Self {
            key_prefix: "openauth:".to_owned(),
            scan_count: 100,
        }
    }
}

#[derive(Clone)]
pub struct RedisSecondaryStorage {
    manager: ConnectionManager,
    options: RedisSecondaryStorageOptions,
}

impl RedisSecondaryStorage {
    pub async fn connect(redis_url: &str) -> Result<Self, OpenAuthError> {
        Self::connect_with_options(redis_url, RedisSecondaryStorageOptions::default()).await
    }

    pub async fn connect_redis(redis_url: &str) -> Result<Self, OpenAuthError> {
        Self::connect(redis_url).await
    }

    pub async fn connect_valkey(redis_url: &str) -> Result<Self, OpenAuthError> {
        Self::connect(redis_url).await
    }

    pub async fn connect_with_options(
        redis_url: &str,
        options: RedisSecondaryStorageOptions,
    ) -> Result<Self, OpenAuthError> {
        let manager = crate::connect_manager(redis_url).await?;
        Ok(Self::new(manager, options))
    }

    pub fn new(manager: ConnectionManager, options: RedisSecondaryStorageOptions) -> Self {
        Self { manager, options }
    }

    pub async fn list_keys(&self) -> Result<Vec<String>, OpenAuthError> {
        validate_secondary_storage_options(&self.options)?;
        let secondary_prefix = self.secondary_prefix();
        let pattern = secondary_storage_scan_pattern(&secondary_prefix);
        let physical_keys = scan_keys(&self.manager, &pattern, self.options.scan_count).await?;
        let mut keys = Vec::new();
        for key in physical_keys {
            if let Some(unprefixed) = key.strip_prefix(secondary_prefix.as_str()) {
                keys.push(unprefixed.to_owned());
            }
        }
        Ok(keys)
    }

    pub async fn clear(&self) -> Result<(), OpenAuthError> {
        let keys = self
            .list_keys()
            .await?
            .into_iter()
            .map(|key| self.prefixed_key(&key))
            .collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Ok(());
        }
        let mut manager = self.manager.clone();
        let _: usize = manager
            .del(keys)
            .await
            .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
        Ok(())
    }

    fn secondary_prefix(&self) -> String {
        format!("{}secondary:", self.options.key_prefix)
    }

    fn prefixed_key(&self, key: &str) -> Result<String, OpenAuthError> {
        validate_key_prefix(&self.options.key_prefix)?;
        Ok(format!("{}secondary:{key}", self.options.key_prefix))
    }
}

impl SecondaryStorage for RedisSecondaryStorage {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move {
            let mut manager = self.manager.clone();
            manager
                .get(self.prefixed_key(key)?)
                .await
                .map_err(|error| OpenAuthError::Adapter(error.to_string()))
        })
    }

    fn set<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            let redis_key = self.prefixed_key(key)?;
            let mut manager = self.manager.clone();
            match ttl_seconds {
                Some(ttl_seconds) if ttl_seconds > 0 => {
                    let _: () = manager
                        .set_ex(redis_key, value, ttl_seconds)
                        .await
                        .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
                }
                _ => {
                    let _: () = manager
                        .set(redis_key, value)
                        .await
                        .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
                }
            }
            Ok(())
        })
    }

    fn set_if_not_exists<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            let redis_key = self.prefixed_key(key)?;
            let mut manager = self.manager.clone();
            let mut command = redis::cmd("SET");
            command.arg(redis_key).arg(value).arg("NX");
            if let Some(ttl_seconds) = ttl_seconds.filter(|ttl| *ttl > 0) {
                command.arg("EX").arg(ttl_seconds);
            }
            let created: Option<String> = command
                .query_async(&mut manager)
                .await
                .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
            Ok(created.is_some())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            let mut manager = self.manager.clone();
            let _: usize = manager
                .del(self.prefixed_key(key)?)
                .await
                .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
            Ok(())
        })
    }
}

fn validate_secondary_storage_options(
    options: &RedisSecondaryStorageOptions,
) -> Result<(), OpenAuthError> {
    validate_key_prefix(&options.key_prefix)?;
    if options.scan_count == 0 {
        return Err(OpenAuthError::InvalidConfig(
            "secondary storage scan count must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

async fn scan_keys(
    manager: &ConnectionManager,
    pattern: &str,
    count: u32,
) -> Result<Vec<String>, OpenAuthError> {
    let mut conn = manager.clone();
    let mut cursor = 0u64;
    let mut keys = Vec::new();
    loop {
        let (next_cursor, page): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(count)
            .query_async(&mut conn)
            .await
            .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
        keys.extend(page);
        if next_cursor == 0 {
            break;
        }
        cursor = next_cursor;
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openauth_core::error::OpenAuthError;

    #[test]
    fn list_keys_rejects_empty_prefix() {
        let options = RedisSecondaryStorageOptions {
            key_prefix: String::new(),
            scan_count: 100,
        };
        assert!(matches!(
            validate_secondary_storage_options(&options),
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage key prefix must not be empty"
        ));
    }

    #[test]
    fn list_keys_rejects_zero_scan_count() {
        let options = RedisSecondaryStorageOptions {
            key_prefix: "openauth:".to_owned(),
            scan_count: 0,
        };
        assert!(matches!(
            validate_secondary_storage_options(&options),
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage scan count must be greater than zero"
        ));
    }
}
