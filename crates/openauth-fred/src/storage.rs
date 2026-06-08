use fred::clients::Client;
use fred::interfaces::KeysInterface;
use fred::types::scripts::Script;
use fred::types::{Expiration, SetOptions};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{SecondaryStorage, SecondaryStorageFuture};

use crate::error::fred_error;
use crate::store::connect_client;
use crate::FredSecondaryStorageOptions;

#[derive(Clone)]
pub struct FredSecondaryStorage {
    client: Client,
    options: FredSecondaryStorageOptions,
}

impl FredSecondaryStorage {
    pub async fn connect(url: &str) -> Result<Self, OpenAuthError> {
        Self::connect_with_options(url, FredSecondaryStorageOptions::default()).await
    }

    pub async fn connect_redis(url: &str) -> Result<Self, OpenAuthError> {
        Self::connect(url).await
    }

    pub async fn connect_valkey(url: &str) -> Result<Self, OpenAuthError> {
        Self::connect(url).await
    }

    pub async fn connect_with_options(
        url: &str,
        options: FredSecondaryStorageOptions,
    ) -> Result<Self, OpenAuthError> {
        let client = connect_client(url).await?;
        Ok(Self::new(client, options))
    }

    pub fn new(client: Client, options: FredSecondaryStorageOptions) -> Self {
        Self { client, options }
    }

    pub async fn list_keys(&self) -> Result<Vec<String>, OpenAuthError> {
        validate_secondary_storage_options(&self.options)?;
        let secondary_prefix = self.secondary_prefix();
        let pattern = secondary_storage_scan_pattern(&secondary_prefix);
        let mut cursor = "0".to_owned();
        let mut keys = Vec::new();

        loop {
            let (next_cursor, page): (String, Vec<String>) = self
                .client
                .scan_page(cursor, pattern.clone(), Some(self.options.scan_count), None)
                .await
                .map_err(|error| fred_error("secondary scan", error))?;
            for key in page {
                if let Some(unprefixed) = key.strip_prefix(secondary_prefix.as_str()) {
                    keys.push(unprefixed.to_owned());
                }
            }
            if next_cursor == "0" {
                break;
            }
            cursor = next_cursor;
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
        self.client
            .del::<u64, _>(keys)
            .await
            .map_err(|error| fred_error("secondary clear", error))?;
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

impl SecondaryStorage for FredSecondaryStorage {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move {
            self.client
                .get::<Option<String>, _>(self.prefixed_key(key)?)
                .await
                .map_err(|error| fred_error("secondary get", error))
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
            if ttl_seconds == Some(0) {
                self.client
                    .del::<u64, _>(redis_key)
                    .await
                    .map_err(|error| fred_error("secondary set", error))?;
                return Ok(());
            }
            let expire = ttl_seconds
                .map(|ttl| {
                    i64::try_from(ttl).map(Expiration::EX).map_err(|_| {
                        OpenAuthError::InvalidConfig(
                            "secondary storage ttl must fit in i64".to_owned(),
                        )
                    })
                })
                .transpose()?;
            self.client
                .set::<(), _, _>(redis_key, value, expire, None, false)
                .await
                .map_err(|error| fred_error("secondary set", error))
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
            if ttl_seconds == Some(0) {
                return Ok(false);
            }
            let expire = ttl_seconds
                .map(|ttl| {
                    i64::try_from(ttl).map(Expiration::EX).map_err(|_| {
                        OpenAuthError::InvalidConfig(
                            "secondary storage ttl must fit in i64".to_owned(),
                        )
                    })
                })
                .transpose()?;
            let created = self
                .client
                .set::<Option<String>, _, _>(redis_key, value, expire, Some(SetOptions::NX), false)
                .await
                .map_err(|error| fred_error("secondary set_if_not_exists", error))?;
            Ok(created.is_some())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            self.client
                .del::<u64, _>(self.prefixed_key(key)?)
                .await
                .map_err(|error| fred_error("secondary delete", error))?;
            Ok(())
        })
    }

    fn take<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move {
            self.client
                .getdel::<Option<String>, _>(self.prefixed_key(key)?)
                .await
                .map_err(|error| fred_error("secondary take", error))
        })
    }

    fn compare_and_set<'a>(
        &'a self,
        key: &'a str,
        expected: Option<String>,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            if ttl_seconds == Some(0) {
                return self.delete_if_value(key, expected).await;
            }
            let redis_key = self.prefixed_key(key)?;
            let script = Script::from_lua(
                r#"
local current = redis.call("GET", KEYS[1])
local expected_is_nil = ARGV[1]
local expected = ARGV[2]
if expected_is_nil == "1" then
  if current ~= false then return 0 end
else
  if current ~= expected then return 0 end
end
if ARGV[4] == "" then
  redis.call("SET", KEYS[1], ARGV[3])
else
  redis.call("SET", KEYS[1], ARGV[3], "EX", tonumber(ARGV[4]))
end
return 1
"#,
            );
            let expected_is_nil = expected.is_none();
            let expected = expected.unwrap_or_default();
            let ttl = ttl_seconds.map(|ttl| ttl.to_string()).unwrap_or_default();
            let applied: i64 = script
                .evalsha_with_reload(
                    &self.client,
                    vec![redis_key],
                    vec![
                        if expected_is_nil { "1" } else { "0" }.to_owned(),
                        expected,
                        value,
                        ttl,
                    ],
                )
                .await
                .map_err(|error| fred_error("secondary compare_and_set", error))?;
            Ok(applied == 1)
        })
    }

    fn delete_if_value<'a>(
        &'a self,
        key: &'a str,
        expected: Option<String>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            let Some(expected) = expected else {
                return Ok(false);
            };
            let redis_key = self.prefixed_key(key)?;
            let script = Script::from_lua(
                r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
  redis.call("DEL", KEYS[1])
  return 1
end
return 0
"#,
            );
            let deleted: i64 = script
                .evalsha_with_reload(&self.client, vec![redis_key], vec![expected])
                .await
                .map_err(|error| fred_error("secondary delete_if_value", error))?;
            Ok(deleted == 1)
        })
    }
}

fn secondary_storage_scan_pattern(prefix: &str) -> String {
    let mut pattern = String::with_capacity(prefix.len() + 1);
    for character in prefix.chars() {
        match character {
            '*' | '?' | '[' | ']' | '\\' => {
                pattern.push('\\');
                pattern.push(character);
            }
            _ => pattern.push(character),
        }
    }
    pattern.push('*');
    pattern
}

fn validate_key_prefix(prefix: &str) -> Result<(), OpenAuthError> {
    if prefix.is_empty() {
        return Err(OpenAuthError::InvalidConfig(
            "secondary storage key prefix must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn validate_secondary_storage_options(
    options: &FredSecondaryStorageOptions,
) -> Result<(), OpenAuthError> {
    validate_key_prefix(&options.key_prefix)?;
    if options.scan_count == 0 {
        return Err(OpenAuthError::InvalidConfig(
            "secondary storage scan count must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_pattern_escapes_redis_glob_metacharacters() {
        assert_eq!(
            secondary_storage_scan_pattern(r"tenant:*?[]\:"),
            r"tenant:\*\?\[\]\\:*"
        );
    }

    #[test]
    fn scan_pattern_leaves_plain_prefixes_readable() {
        assert_eq!(
            secondary_storage_scan_pattern("openauth:test:"),
            "openauth:test:*"
        );
    }

    #[test]
    fn secondary_scan_pattern_is_disjoint_from_rate_limit_namespace() {
        let prefix = "openauth:";
        let secondary_pattern = secondary_storage_scan_pattern(&format!("{prefix}secondary:"));
        assert_eq!(secondary_pattern, "openauth:secondary:*");

        let rate_limit_key = format!("{prefix}rate-limit:10.0.0.1|/sign-in");
        assert!(
            !rate_limit_key.starts_with("openauth:secondary:"),
            "co-located rate-limit keys must not share the secondary clear() scan prefix (OPE-37)"
        );

        // Legacy Fred secondary storage scanned `{prefix}*` and could delete rate-limit keys.
        let legacy_clear_pattern = secondary_storage_scan_pattern(prefix);
        assert_eq!(legacy_clear_pattern, "openauth:*");
        assert!(rate_limit_key.starts_with(prefix));
    }

    #[test]
    fn secondary_storage_matches_redis_secondary_namespace_layout() {
        let storage = FredSecondaryStorage::new(
            Client::default(),
            FredSecondaryStorageOptions {
                key_prefix: "test:".to_owned(),
                scan_count: 100,
            },
        );

        // Must match openauth-redis `RedisSecondaryStorage::key`: `{prefix}secondary:{key}`.
        assert_eq!(
            storage.prefixed_key("session:token").ok(),
            Some("test:secondary:session:token".to_owned())
        );
        assert_eq!(storage.secondary_prefix(), "test:secondary:");
        assert_eq!(
            secondary_storage_scan_pattern(&storage.secondary_prefix()),
            "test:secondary:*"
        );
    }

    #[tokio::test]
    async fn list_keys_rejects_empty_prefix_before_calling_redis() {
        let storage = FredSecondaryStorage::new(
            Client::default(),
            FredSecondaryStorageOptions {
                key_prefix: String::new(),
                scan_count: 100,
            },
        );

        assert!(matches!(
            storage.list_keys().await,
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage key prefix must not be empty"
        ));
    }

    #[tokio::test]
    async fn list_keys_rejects_zero_scan_count_before_calling_redis() {
        let storage = FredSecondaryStorage::new(
            Client::default(),
            FredSecondaryStorageOptions {
                key_prefix: "openauth:test:".to_owned(),
                scan_count: 0,
            },
        );

        assert!(matches!(
            storage.list_keys().await,
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage scan count must be greater than zero"
        ));
    }

    #[tokio::test]
    async fn clear_rejects_empty_prefix_before_calling_redis() {
        let storage = FredSecondaryStorage::new(
            Client::default(),
            FredSecondaryStorageOptions {
                key_prefix: String::new(),
                scan_count: 100,
            },
        );

        assert!(matches!(
            storage.clear().await,
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage key prefix must not be empty"
        ));
    }

    #[tokio::test]
    async fn clear_rejects_zero_scan_count_before_calling_redis() {
        let storage = FredSecondaryStorage::new(
            Client::default(),
            FredSecondaryStorageOptions {
                key_prefix: "openauth:test:".to_owned(),
                scan_count: 0,
            },
        );

        assert!(matches!(
            storage.clear().await,
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage scan count must be greater than zero"
        ));
    }

    fn empty_prefix_storage() -> FredSecondaryStorage {
        FredSecondaryStorage::new(
            Client::default(),
            FredSecondaryStorageOptions {
                key_prefix: String::new(),
                scan_count: 100,
            },
        )
    }

    #[tokio::test]
    async fn get_rejects_empty_prefix_before_calling_redis() {
        assert!(matches!(
            empty_prefix_storage().get("session").await,
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage key prefix must not be empty"
        ));
    }

    #[tokio::test]
    async fn set_rejects_empty_prefix_before_calling_redis() {
        assert!(matches!(
            empty_prefix_storage().set("session", "value".to_owned(), None).await,
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage key prefix must not be empty"
        ));
    }

    #[tokio::test]
    async fn delete_rejects_empty_prefix_before_calling_redis() {
        assert!(matches!(
            empty_prefix_storage().delete("session").await,
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage key prefix must not be empty"
        ));
    }

    #[tokio::test]
    async fn take_rejects_empty_prefix_before_calling_redis() {
        assert!(matches!(
            empty_prefix_storage().take("session").await,
            Err(OpenAuthError::InvalidConfig(message))
                if message == "secondary storage key prefix must not be empty"
        ));
    }
}
