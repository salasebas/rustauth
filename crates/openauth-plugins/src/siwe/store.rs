use time::OffsetDateTime;

use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, FindOne, User, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::user::DbUserStore;

use super::types::WalletAddress;

const WALLET_MODEL: &str = "walletAddress";
const DEFAULT_ID_LENGTH: usize = 32;

pub(crate) async fn find_wallet(
    adapter: &dyn DbAdapter,
    address: &str,
    chain_id: i64,
) -> Result<Option<WalletAddress>, OpenAuthError> {
    let record = adapter
        .find_one(
            FindOne::new(WALLET_MODEL)
                .where_clause(Where::new("address", DbValue::String(address.to_owned())))
                .where_clause(Where::new("chainId", DbValue::Number(chain_id))),
        )
        .await?;
    record.map(wallet_from_record).transpose()
}

pub(crate) async fn find_wallet_by_address(
    adapter: &dyn DbAdapter,
    address: &str,
) -> Result<Option<WalletAddress>, OpenAuthError> {
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
) -> Result<(), OpenAuthError> {
    adapter
        .create(
            Create::new(WALLET_MODEL)
                .data(
                    "id",
                    DbValue::String(generate_random_string(DEFAULT_ID_LENGTH)),
                )
                .data("userId", DbValue::String(user_id.to_owned()))
                .data("address", DbValue::String(address.to_owned()))
                .data("chainId", DbValue::Number(chain_id))
                .data("isPrimary", DbValue::Boolean(is_primary))
                .data("createdAt", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(crate) async fn user_for_wallet(
    adapter: &dyn DbAdapter,
    wallet: &WalletAddress,
) -> Result<Option<User>, OpenAuthError> {
    DbUserStore::new(adapter)
        .find_user_by_id(&wallet.user_id)
        .await
}

fn wallet_from_record(record: DbRecord) -> Result<WalletAddress, OpenAuthError> {
    Ok(WalletAddress {
        id: required_string(&record, "id")?.to_owned(),
        user_id: required_string(&record, "userId")?.to_owned(),
        address: required_string(&record, "address")?.to_owned(),
        chain_id: required_number(&record, "chainId")?,
        is_primary: required_bool(&record, "isPrimary")?,
        created_at: required_timestamp(&record, "createdAt")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "wallet address record field `{field}` must be string"
        ))),
        None => Err(OpenAuthError::Adapter(format!(
            "wallet address record is missing `{field}`"
        ))),
    }
}

fn required_number(record: &DbRecord, field: &str) -> Result<i64, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Number(value)) => Ok(*value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "wallet address record field `{field}` must be number"
        ))),
        None => Err(OpenAuthError::Adapter(format!(
            "wallet address record is missing `{field}`"
        ))),
    }
}

fn required_bool(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "wallet address record field `{field}` must be boolean"
        ))),
        None => Err(OpenAuthError::Adapter(format!(
            "wallet address record is missing `{field}`"
        ))),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "wallet address record field `{field}` must be timestamp"
        ))),
        None => Err(OpenAuthError::Adapter(format!(
            "wallet address record is missing `{field}`"
        ))),
    }
}
