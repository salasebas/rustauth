use time::OffsetDateTime;

use rustauth_core::context::AuthContext;
use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::db::{Create, DbAdapter, DbRecord, DbValue, FindOne, User, Where};
use rustauth_core::error::RustAuthError;

use super::types::WalletAddress;

const WALLET_MODEL: &str = "wallet_address";
const DEFAULT_ID_LENGTH: usize = 32;

pub(crate) async fn find_wallet(
    adapter: &dyn DbAdapter,
    address: &str,
    chain_id: i64,
) -> Result<Option<WalletAddress>, RustAuthError> {
    let record = adapter
        .find_one(
            FindOne::new(WALLET_MODEL)
                .where_clause(Where::new("address", DbValue::String(address.to_owned())))
                .where_clause(Where::new("chain_id", DbValue::Number(chain_id))),
        )
        .await?;
    record.map(wallet_from_record).transpose()
}

pub(crate) async fn find_wallet_by_address(
    adapter: &dyn DbAdapter,
    address: &str,
) -> Result<Option<WalletAddress>, RustAuthError> {
    let record = adapter
        .find_one(
            FindOne::new(WALLET_MODEL)
                .where_clause(Where::new("address", DbValue::String(address.to_owned()))),
        )
        .await?;
    record.map(wallet_from_record).transpose()
}

pub(crate) async fn create_wallet(
    adapter: &dyn DbAdapter,
    user_id: &str,
    address: &str,
    chain_id: i64,
    is_primary: bool,
) -> Result<(), RustAuthError> {
    adapter
        .create(
            Create::new(WALLET_MODEL)
                .data(
                    "id",
                    DbValue::String(generate_random_string(DEFAULT_ID_LENGTH)),
                )
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("address", DbValue::String(address.to_owned()))
                .data("chain_id", DbValue::Number(chain_id))
                .data("is_primary", DbValue::Boolean(is_primary))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(crate) async fn user_for_wallet(
    context: &AuthContext,
    wallet: &WalletAddress,
) -> Result<Option<User>, RustAuthError> {
    context.users()?.find_user_by_id(&wallet.user_id).await
}

fn wallet_from_record(record: DbRecord) -> Result<WalletAddress, RustAuthError> {
    Ok(WalletAddress {
        id: required_string(&record, "id")?.to_owned(),
        user_id: required_string(&record, "user_id")?.to_owned(),
        address: required_string(&record, "address")?.to_owned(),
        chain_id: required_number(&record, "chain_id")?,
        is_primary: required_bool(&record, "is_primary")?,
        created_at: required_timestamp(&record, "created_at")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(RustAuthError::Adapter(format!(
            "wallet address record field `{field}` must be string"
        ))),
        None => Err(RustAuthError::Adapter(format!(
            "wallet address record is missing `{field}`"
        ))),
    }
}

fn required_number(record: &DbRecord, field: &str) -> Result<i64, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Number(value)) => Ok(*value),
        Some(_) => Err(RustAuthError::Adapter(format!(
            "wallet address record field `{field}` must be number"
        ))),
        None => Err(RustAuthError::Adapter(format!(
            "wallet address record is missing `{field}`"
        ))),
    }
}

fn required_bool(record: &DbRecord, field: &str) -> Result<bool, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(RustAuthError::Adapter(format!(
            "wallet address record field `{field}` must be boolean"
        ))),
        None => Err(RustAuthError::Adapter(format!(
            "wallet address record is missing `{field}`"
        ))),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(RustAuthError::Adapter(format!(
            "wallet address record field `{field}` must be timestamp"
        ))),
        None => Err(RustAuthError::Adapter(format!(
            "wallet address record is missing `{field}`"
        ))),
    }
}
