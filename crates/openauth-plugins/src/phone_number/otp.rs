use time::{Duration, OffsetDateTime};

use openauth_core::crypto::random::generate_random_string;
use openauth_core::error::OpenAuthError;
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};

pub(crate) fn generate_otp(length: usize) -> String {
    generate_random_string(length)
        .bytes()
        .map(|byte| char::from(b'0' + (byte % 10)))
        .collect()
}

pub(crate) fn encode(code: &str, attempts: u32) -> String {
    format!("{code}:{attempts}")
}

pub(crate) fn decode(value: &str) -> (&str, u32) {
    let Some((code, attempts)) = value.split_once(':') else {
        return (value, 0);
    };
    (code, attempts.parse().unwrap_or(0))
}

pub(crate) async fn create(
    adapter: &dyn openauth_core::db::DbAdapter,
    identifier: impl Into<String>,
    code: &str,
    expires_in: u64,
) -> Result<(), OpenAuthError> {
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            identifier.into(),
            encode(code, 0),
            OffsetDateTime::now_utc() + Duration::seconds(expires_in as i64),
        ))
        .await?;
    Ok(())
}
