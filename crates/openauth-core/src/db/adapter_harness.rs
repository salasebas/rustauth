//! Reusable adapter contract checks for adapter crates.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;

use super::{
    Count, Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, JoinOption,
    Sort, SortDirection, Update, UpdateMany, Where, WhereOperator,
};
use crate::error::OpenAuthError;

static CONTRACT_ID: AtomicU64 = AtomicU64::new(0);

/// Run the shared adapter contract against an already-initialized adapter.
///
/// The caller owns schema creation and database isolation. This harness uses
/// unique record ids so SQL-backed tests can run against shared Docker
/// databases without truncating global tables.
pub async fn run_adapter_contract(adapter: &dyn DbAdapter) -> Result<(), OpenAuthError> {
    let prefix = contract_prefix(adapter.id());

    contract_filters_sorts_limits_selects_and_counts(adapter, &prefix).await?;
    contract_updates_and_deletes(adapter, &prefix).await?;
    contract_transactions(adapter, &prefix).await?;

    if adapter.capabilities().supports_joins {
        contract_joins(adapter, &prefix).await?;
    }

    Ok(())
}

async fn contract_filters_sorts_limits_selects_and_counts(
    adapter: &dyn DbAdapter,
    prefix: &str,
) -> Result<(), OpenAuthError> {
    let base = OffsetDateTime::UNIX_EPOCH;
    for (name, email, created_at) in [
        ("ada", "ada@example.com", base + time::Duration::seconds(1)),
        (
            "grace",
            "grace@example.com",
            base + time::Duration::seconds(3),
        ),
        (
            "alan",
            "alan@example.net",
            base + time::Duration::seconds(2),
        ),
    ] {
        create_user(adapter, &format!("{prefix}_{name}"), email, created_at).await?;
    }

    let records = adapter
        .find_many(
            FindMany::new("user")
                .where_clause(
                    Where::new("email", DbValue::String("EXAMPLE.COM".to_owned()))
                        .operator(WhereOperator::EndsWith)
                        .insensitive(),
                )
                .sort_by(Sort::new("created_at", SortDirection::Desc))
                .limit(1)
                .select(["id", "email"]),
        )
        .await?;
    let count = adapter
        .count(
            Count::new("user").where_clause(
                Where::new("email", DbValue::String("example.com".to_owned()))
                    .operator(WhereOperator::EndsWith)
                    .insensitive(),
            ),
        )
        .await?;

    assert_eq!(count, 2);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("id"),
        Some(&DbValue::String(format!("{prefix}_grace")))
    );
    assert_eq!(records[0].len(), 2);
    Ok(())
}

async fn contract_updates_and_deletes(
    adapter: &dyn DbAdapter,
    prefix: &str,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    for user_id in [format!("{prefix}_owner"), format!("{prefix}_other")] {
        create_user(adapter, &user_id, &format!("{user_id}@example.test"), now).await?;
    }

    for (id, user_id) in [
        (format!("{prefix}_session_1"), format!("{prefix}_owner")),
        (format!("{prefix}_session_2"), format!("{prefix}_owner")),
        (format!("{prefix}_session_3"), format!("{prefix}_other")),
    ] {
        create_session(adapter, &id, &user_id, now).await?;
    }

    let updated = adapter
        .update(
            Update::new("session")
                .where_clause(Where::new(
                    "id",
                    DbValue::String(format!("{prefix}_session_1")),
                ))
                .data("user_agent", DbValue::String("contract-updated".to_owned())),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("adapter contract did not update row".to_owned()))?;
    let updated_many = adapter
        .update_many(
            UpdateMany::new("session")
                .where_clause(Where::new(
                    "user_id",
                    DbValue::String(format!("{prefix}_owner")),
                ))
                .data("ip_address", DbValue::String("127.0.0.1".to_owned())),
        )
        .await?;
    let deleted_many = adapter
        .delete_many(DeleteMany::new("session").where_clause(Where::new(
            "user_id",
            DbValue::String(format!("{prefix}_owner")),
        )))
        .await?;
    let remaining = adapter
        .find_many(FindMany::new("session").where_clause(Where::new(
            "id",
            DbValue::String(format!("{prefix}_session_3")),
        )))
        .await?;

    assert_eq!(
        updated.get("user_agent"),
        Some(&DbValue::String("contract-updated".to_owned()))
    );
    assert_eq!(updated_many, 2);
    assert_eq!(deleted_many, 2);
    assert_eq!(remaining.len(), 1);

    create_verification(adapter, &format!("{prefix}_verification"), now).await?;
    adapter
        .delete(Delete::new("verification").where_clause(Where::new(
            "identifier",
            DbValue::String(format!("{prefix}_verification")),
        )))
        .await?;
    let deleted = adapter
        .find_one(FindOne::new("verification").where_clause(Where::new(
            "identifier",
            DbValue::String(format!("{prefix}_verification")),
        )))
        .await?;
    assert!(deleted.is_none());

    Ok(())
}

async fn contract_transactions(adapter: &dyn DbAdapter, prefix: &str) -> Result<(), OpenAuthError> {
    let commit_id = format!("{prefix}_tx_commit");
    let commit_email = format!("{commit_id}@example.test");
    adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                create_user(&tx, &commit_id, &commit_email, OffsetDateTime::now_utc()).await?;
                Ok(())
            })
        }))
        .await?;
    let committed = adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            "id",
            DbValue::String(format!("{prefix}_tx_commit")),
        )))
        .await?;
    assert!(committed.is_some());

    if !adapter.capabilities().supports_transactions {
        return Ok(());
    }

    let rollback_id = format!("{prefix}_tx_rollback");
    let rollback_email = format!("{rollback_id}@example.test");
    let result = adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                create_user(
                    &tx,
                    &rollback_id,
                    &rollback_email,
                    OffsetDateTime::now_utc(),
                )
                .await?;
                Err(OpenAuthError::Adapter(
                    "adapter contract rollback sentinel".to_owned(),
                ))
            })
        }))
        .await;
    assert!(result.is_err());

    let rolled_back = adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            "id",
            DbValue::String(format!("{prefix}_tx_rollback")),
        )))
        .await?;
    assert!(rolled_back.is_none());

    Ok(())
}

async fn contract_joins(adapter: &dyn DbAdapter, prefix: &str) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    let user_id = format!("{prefix}_join_user");
    create_user(adapter, &user_id, "join@example.test", now).await?;
    create_account(adapter, &format!("{prefix}_join_account"), &user_id, now).await?;

    let user = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id)))
                .join("account", JoinOption::enabled()),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("adapter contract join missed user".to_owned()))?;

    assert!(matches!(
        user.get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
    ));
    Ok(())
}

async fn create_user(
    adapter: &dyn DbAdapter,
    id: &str,
    email: &str,
    created_at: OffsetDateTime,
) -> Result<DbRecord, OpenAuthError> {
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String(id.to_owned()))
                .data("email", DbValue::String(email.to_owned()))
                .data("email_verified", DbValue::Boolean(false))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(created_at))
                .data("updated_at", DbValue::Timestamp(created_at)),
        )
        .await
}

async fn create_session(
    adapter: &dyn DbAdapter,
    id: &str,
    user_id: &str,
    now: OffsetDateTime,
) -> Result<DbRecord, OpenAuthError> {
    adapter
        .create(
            Create::new("session")
                .data("id", DbValue::String(id.to_owned()))
                .data(
                    "expires_at",
                    DbValue::Timestamp(now + time::Duration::hours(1)),
                )
                .data("token", DbValue::String(id.to_owned()))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("ip_address", DbValue::Null)
                .data("user_agent", DbValue::Null)
                .data("user_id", DbValue::String(user_id.to_owned())),
        )
        .await
}

async fn create_account(
    adapter: &dyn DbAdapter,
    id: &str,
    user_id: &str,
    now: OffsetDateTime,
) -> Result<DbRecord, OpenAuthError> {
    adapter
        .create(
            Create::new("account")
                .data("id", DbValue::String(id.to_owned()))
                .data("account_id", DbValue::String(id.to_owned()))
                .data("provider_id", DbValue::String("credential".to_owned()))
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("access_token", DbValue::Null)
                .data("refresh_token", DbValue::Null)
                .data("id_token", DbValue::Null)
                .data("access_token_expires_at", DbValue::Null)
                .data("refresh_token_expires_at", DbValue::Null)
                .data("scope", DbValue::Null)
                .data("password", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await
}

async fn create_verification(
    adapter: &dyn DbAdapter,
    identifier: &str,
    now: OffsetDateTime,
) -> Result<DbRecord, OpenAuthError> {
    adapter
        .create(
            Create::new("verification")
                .data("id", DbValue::String(identifier.to_owned()))
                .data("identifier", DbValue::String(identifier.to_owned()))
                .data("value", DbValue::String("contract-value".to_owned()))
                .data(
                    "expires_at",
                    DbValue::Timestamp(now + time::Duration::minutes(10)),
                )
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await
}

fn contract_prefix(adapter_id: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let sequence = CONTRACT_ID.fetch_add(1, Ordering::Relaxed);
    let adapter_id = adapter_id
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    format!("oa_contract_{adapter_id}_{millis}_{sequence}")
}
