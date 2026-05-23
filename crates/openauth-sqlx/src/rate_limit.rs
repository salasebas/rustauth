use openauth_core::error::OpenAuthError;

pub(crate) fn count_from_i64(count: i64) -> Result<u64, OpenAuthError> {
    u64::try_from(count).map_err(|_| {
        OpenAuthError::Adapter("negative rate limit count persisted in database".to_owned())
    })
}

pub(crate) fn count_to_i64(count: u64) -> Result<i64, OpenAuthError> {
    i64::try_from(count)
        .map_err(|_| OpenAuthError::Adapter("rate limit count exceeds SQL BIGINT range".to_owned()))
}
