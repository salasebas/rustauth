use std::sync::atomic::{AtomicI64, Ordering};

use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use time::OffsetDateTime;

use super::options::ApiKeyConfiguration;
use super::storage::ApiKeyStore;

static LAST_CHECK_UNIX: AtomicI64 = AtomicI64::new(0);

pub async fn delete_all_expired_api_keys(
    context: &AuthContext,
    options: &ApiKeyConfiguration,
    bypass_last_check_time: bool,
) -> Result<u64, OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    if !bypass_last_check_time {
        let last = LAST_CHECK_UNIX.load(Ordering::Relaxed);
        if last != 0 && now.unix_timestamp().saturating_sub(last) < 10 {
            return Ok(0);
        }
    }
    LAST_CHECK_UNIX.store(now.unix_timestamp(), Ordering::Relaxed);
    ApiKeyStore::new(context, options).delete_expired(now).await
}
