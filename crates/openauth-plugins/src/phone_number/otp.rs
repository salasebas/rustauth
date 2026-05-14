use time::{Duration, OffsetDateTime};

use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindMany, Sort, SortDirection, Where};
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

pub(crate) async fn find_raw(
    adapter: &dyn DbAdapter,
    identifier: &str,
) -> Result<Option<VerificationRecord>, OpenAuthError> {
    let Some(record) = adapter
        .find_many(
            FindMany::new("verification")
                .where_clause(Where::new(
                    "identifier",
                    DbValue::String(identifier.to_owned()),
                ))
                .sort_by(Sort::new("created_at", SortDirection::Desc))
                .limit(1),
        )
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    Ok(Some(verification_from_record(record)?))
}

pub(crate) struct VerificationRecord {
    pub value: String,
    pub expires_at: OffsetDateTime,
}

fn verification_from_record(record: DbRecord) -> Result<VerificationRecord, OpenAuthError> {
    let value = match record.get("value") {
        Some(DbValue::String(value)) => value.clone(),
        _ => {
            return Err(OpenAuthError::Adapter(
                "verification.value must be a string".to_owned(),
            ));
        }
    };
    let expires_at = match record.get("expires_at") {
        Some(DbValue::Timestamp(value)) => *value,
        _ => {
            return Err(OpenAuthError::Adapter(
                "verification.expires_at must be a timestamp".to_owned(),
            ));
        }
    };
    Ok(VerificationRecord { value, expires_at })
}
