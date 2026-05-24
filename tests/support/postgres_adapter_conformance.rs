use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use openauth_core::db::{
    auth_schema, AuthSchemaOptions, Count, Create, DbAdapter, DbRecord, DbSchema, DbValue, Delete,
    DeleteMany, FindMany, FindOne, JoinAdapter, JoinOption, RateLimitStorage, Sort, SortDirection,
    TableOptions, Update, UpdateMany, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use time::OffsetDateTime;
use tokio_postgres::NoTls;

static TEST_ID: AtomicU64 = AtomicU64::new(0);

pub const DEFAULT_POSTGRES_URL: &str = "postgres://user:password@localhost:5432/openauth";

pub fn database_url() -> String {
    database_url_from_env(std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok())
}

pub fn database_url_from_env(value: Option<String>) -> String {
    value.unwrap_or_else(|| DEFAULT_POSTGRES_URL.to_owned())
}

pub async fn raw_client() -> Result<tokio_postgres::Client, OpenAuthError> {
    let (client, connection) = tokio_postgres::connect(&database_url(), NoTls)
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?;
    tokio::spawn(async move {
        let _connection_result = connection.await;
    });
    Ok(client)
}

pub fn test_schema(adapter_prefix: &str) -> DbSchema {
    let prefix = unique_prefix(adapter_prefix);
    auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users"),
        account: table_options(&prefix, "accounts"),
        session: table_options(&prefix, "sessions"),
        verification: table_options(&prefix, "verifications"),
        rate_limit: table_options(&prefix, "rate_limits"),
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    })
}

pub fn table_options(prefix: &str, table: &str) -> TableOptions {
    TableOptions::default().with_name(format!("{prefix}_{table}"))
}

pub fn unique_prefix(adapter_prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_default();
    let process = std::process::id() & 0xffff;
    let sequence = TEST_ID.fetch_add(1, Ordering::Relaxed) & 0xfff;
    format!(
        "{adapter_prefix}_{process:x}_{:08x}_{sequence:x}",
        nanos & 0xffff_ffff
    )
}

pub async fn assert_round_trips_json_arrays_and_create_select<A>(
    adapter: &A,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let now = OffsetDateTime::now_utc();
    let created = adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(false))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data(
                    "profile",
                    DbValue::Json(serde_json::json!({"role": "admin", "enabled": true})),
                )
                .data(
                    "tags",
                    DbValue::StringArray(vec!["auth".to_owned(), "postgres".to_owned()]),
                )
                .data("scores", DbValue::NumberArray(vec![10, 20]))
                .select(["id", "profile"]),
        )
        .await?;

    assert_eq!(
        created.keys().cloned().collect::<Vec<_>>(),
        vec!["id".to_owned(), "profile".to_owned()]
    );

    create_user_with_json_and_arrays(
        adapter,
        "user_json_array",
        "array@example.com",
        DbValue::Json(serde_json::json!(["admin", {"enabled": true}])),
        DbValue::StringArray(Vec::new()),
        DbValue::NumberArray(Vec::new()),
    )
    .await?;
    create_user_with_json_and_arrays(
        adapter,
        "user_json_null",
        "null-json@example.com",
        DbValue::Json(serde_json::Value::Null),
        DbValue::StringArray(vec!["nullable".to_owned()]),
        DbValue::NumberArray(vec![0]),
    )
    .await?;

    let found = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned()))),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing json array user".to_owned()))?;
    assert_eq!(
        found.get("profile"),
        Some(&DbValue::Json(
            serde_json::json!({"role": "admin", "enabled": true})
        ))
    );
    assert_eq!(
        found.get("tags"),
        Some(&DbValue::StringArray(vec![
            "auth".to_owned(),
            "postgres".to_owned()
        ]))
    );
    assert_eq!(
        found.get("scores"),
        Some(&DbValue::NumberArray(vec![10, 20]))
    );

    let found_array = find_required(adapter, "user", "id", "user_json_array").await?;
    assert_eq!(
        found_array.get("profile"),
        Some(&DbValue::Json(
            serde_json::json!(["admin", {"enabled": true}])
        ))
    );

    let found_null = find_required(adapter, "user", "id", "user_json_null").await?;
    assert_eq!(
        found_null.get("profile"),
        Some(&DbValue::Json(serde_json::Value::Null))
    );
    Ok(())
}

pub async fn assert_returns_database_generated_uuid_ids<A>(
    adapter: &A,
    email: String,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let created = adapter
        .create(
            Create::new("user")
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String(email))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .select(["id", "email"]),
        )
        .await?;

    let Some(DbValue::String(id)) = created.get("id") else {
        return Err(OpenAuthError::Adapter(
            "missing generated UUID id".to_owned(),
        ));
    };
    uuid::Uuid::parse_str(id)
        .map_err(|error| OpenAuthError::Adapter(format!("invalid generated UUID: {error}")))?;
    Ok(())
}

pub async fn assert_supports_forced_uuid_ids<A>(
    adapter: &A,
    forced_id: &str,
    email: String,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let created = adapter
        .create(
            Create::new("user")
                .force_allow_id()
                .data("id", DbValue::String(forced_id.to_owned()))
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String(email))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .select(["id"]),
        )
        .await?;

    assert_eq!(
        created.get("id"),
        Some(&DbValue::String(forced_id.to_owned()))
    );
    Ok(())
}

pub async fn assert_returns_database_generated_serial_ids<A>(
    adapter: &A,
    email: String,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let created = adapter
        .create(
            Create::new("user")
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String(email))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .select(["id"]),
        )
        .await?;

    assert!(matches!(created.get("id"), Some(DbValue::Number(id)) if *id > 0));
    Ok(())
}

pub async fn assert_filters_sorts_limits_counts_and_mutates<A>(
    adapter: &A,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let base = OffsetDateTime::UNIX_EPOCH;
    for (id, email, created_at) in [
        (
            "user_1",
            "ada@example.com",
            base + time::Duration::seconds(1),
        ),
        (
            "user_2",
            "grace@example.com",
            base + time::Duration::seconds(3),
        ),
        (
            "user_3",
            "alan@example.net",
            base + time::Duration::seconds(2),
        ),
    ] {
        seed_user(adapter, id, email, created_at).await?;
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
                .offset(0),
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
    assert_eq!(
        records[0].get("id"),
        Some(&DbValue::String("user_2".to_owned()))
    );

    seed_session(adapter, "session_1", "user_1").await?;
    seed_session(adapter, "session_2", "user_1").await?;
    seed_session(adapter, "session_3", "user_2").await?;
    let updated = adapter
        .update(
            Update::new("session")
                .where_clause(Where::new("id", DbValue::String("session_1".to_owned())))
                .data("user_agent", DbValue::String("updated".to_owned())),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing updated session".to_owned()))?;
    let deleted = adapter
        .delete_many(
            DeleteMany::new("session")
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned()))),
        )
        .await?;

    assert_eq!(
        updated.get("user_agent"),
        Some(&DbValue::String("updated".to_owned()))
    );
    assert_eq!(deleted, 2);
    assert_eq!(adapter.find_many(FindMany::new("session")).await?.len(), 1);
    Ok(())
}

pub async fn assert_empty_mutations_delete_one_and_case_insensitive_arrays<A>(
    adapter: &A,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    seed_user(
        adapter,
        "user_1",
        "Ada@Example.COM",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_user(
        adapter,
        "user_2",
        "grace@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_user(
        adapter,
        "user_3",
        "alan@example.net",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_session(adapter, "session_1", "user_1").await?;
    seed_session(adapter, "session_2", "user_1").await?;

    let insensitive_in = adapter
        .count(
            Count::new("user").where_clause(
                Where::new(
                    "email",
                    DbValue::StringArray(vec!["ada@example.com".to_owned()]),
                )
                .operator(WhereOperator::In)
                .insensitive(),
            ),
        )
        .await?;
    let empty_in = adapter
        .count(Count::new("user").where_clause(
            Where::new("email", DbValue::StringArray(Vec::new())).operator(WhereOperator::In),
        ))
        .await?;
    let empty_not_in = adapter
        .count(Count::new("user").where_clause(
            Where::new("email", DbValue::StringArray(Vec::new())).operator(WhereOperator::NotIn),
        ))
        .await?;
    let no_update = adapter.update(Update::new("user")).await?;
    let no_update_many = adapter.update_many(UpdateMany::new("user")).await?;
    adapter
        .delete(
            Delete::new("session")
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned()))),
        )
        .await?;

    assert_eq!(insensitive_in, 1);
    assert_eq!(empty_in, 0);
    assert_eq!(empty_not_in, 3);
    assert!(no_update.is_none());
    assert_eq!(no_update_many, 0);
    assert_eq!(
        adapter
            .count(
                Count::new("session")
                    .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned())))
            )
            .await?,
        1
    );
    Ok(())
}

pub async fn assert_supports_native_and_fallback_joins<A>(adapter: &A) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    seed_user(
        adapter,
        "user_1",
        "ada@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_user(
        adapter,
        "user_2",
        "grace@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_account(adapter, "account_1", "user_1").await?;
    seed_account(adapter, "account_2", "user_1").await?;
    seed_session(adapter, "session_1", "user_1").await?;
    seed_session(adapter, "session_2", "user_1").await?;

    let user = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned())))
                .join("account", JoinOption::enabled().limit(1)),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing joined user".to_owned()))?;
    assert!(matches!(
        user.get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
    ));

    let users = adapter
        .find_many(
            FindMany::new("user")
                .join("account", JoinOption::enabled().limit(1))
                .join("session", JoinOption::enabled()),
        )
        .await?;
    let joined = users
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("user_1".to_owned())))
        .ok_or_else(|| OpenAuthError::Adapter("missing fallback joined user".to_owned()))?;
    assert!(matches!(
        joined.get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
    ));
    assert!(matches!(
        joined.get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.len() == 2
    ));

    let account = adapter
        .find_one(
            FindOne::new("account")
                .where_clause(Where::new("id", DbValue::String("account_1".to_owned())))
                .join("user", JoinOption::enabled()),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing joined account".to_owned()))?;
    assert!(matches!(
        account.get("user"),
        Some(DbValue::Record(user)) if user.get("id") == Some(&DbValue::String("user_1".to_owned()))
    ));
    Ok(())
}

pub async fn assert_returns_empty_or_null_for_missing_join_rows<A>(
    adapter: &A,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    seed_user(
        adapter,
        "user_without_children",
        "without@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_user(
        adapter,
        "user_with_children",
        "with@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_session(adapter, "session_1", "user_with_children").await?;

    let users = adapter
        .find_many(FindMany::new("user").join("session", JoinOption::enabled().limit(1)))
        .await?;
    let without = users
        .iter()
        .find(|record| {
            record.get("id") == Some(&DbValue::String("user_without_children".to_owned()))
        })
        .ok_or_else(|| OpenAuthError::Adapter("missing user without children".to_owned()))?;
    assert!(matches!(
        without.get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.is_empty()
    ));

    let session = adapter
        .find_one(
            FindOne::new("session")
                .where_clause(Where::new("id", DbValue::String("session_1".to_owned())))
                .join("user", JoinOption::enabled()),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing joined session".to_owned()))?;
    assert!(matches!(
        session.get("user"),
        Some(DbValue::Record(user)) if user.get("id") == Some(&DbValue::String("user_with_children".to_owned()))
    ));
    Ok(())
}

pub async fn assert_rolls_back_failed_transactions<A>(adapter: &A) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let result = adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                seed_user(
                    tx.as_ref(),
                    "user_1",
                    "ada@example.com",
                    OffsetDateTime::now_utc(),
                )
                .await?;
                Err(OpenAuthError::Adapter("force rollback".to_owned()))
            })
        }))
        .await;

    assert!(result.is_err());
    assert_eq!(adapter.count(Count::new("user")).await?, 0);
    Ok(())
}

pub async fn assert_commits_successful_transactions<A>(adapter: &A) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                seed_user(
                    tx.as_ref(),
                    "user_1",
                    "ada@example.com",
                    OffsetDateTime::now_utc(),
                )
                .await
            })
        }))
        .await?;

    assert_eq!(adapter.count(Count::new("user")).await?, 1);
    Ok(())
}

pub async fn assert_rolls_back_after_sql_error_in_transaction<A>(
    adapter: &A,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let result = adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                seed_user(
                    tx.as_ref(),
                    "user_1",
                    "ada@example.com",
                    OffsetDateTime::now_utc(),
                )
                .await?;
                seed_user(
                    tx.as_ref(),
                    "user_1",
                    "duplicate@example.com",
                    OffsetDateTime::now_utc(),
                )
                .await
            })
        }))
        .await;

    let Err(error) = result else {
        return Err(OpenAuthError::Adapter(
            "duplicate insert unexpectedly succeeded".to_owned(),
        ));
    };
    let message = error.to_string();
    assert!(message.contains("23505"), "{message}");
    assert_eq!(adapter.count(Count::new("user")).await?, 0);
    Ok(())
}

pub async fn assert_rejects_nested_transactions<A>(adapter: &A) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let result = adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                tx.transaction(Box::new(|_| Box::pin(async { Ok(()) })))
                    .await
            })
        }))
        .await;

    let Err(error) = result else {
        return Err(OpenAuthError::Adapter(
            "nested transaction unexpectedly succeeded".to_owned(),
        ));
    };
    assert!(error.to_string().contains("nested"));
    Ok(())
}

pub async fn assert_transaction_multi_join_uses_fallback<A>(
    adapter: &A,
    schema: DbSchema,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    adapter
        .transaction(Box::new(move |tx| {
            let schema = schema.clone();
            Box::pin(async move {
                seed_user(
                    tx.as_ref(),
                    "user_1",
                    "ada@example.com",
                    OffsetDateTime::now_utc(),
                )
                .await?;
                seed_account(tx.as_ref(), "account_1", "user_1").await?;
                seed_session(tx.as_ref(), "session_1", "user_1").await?;

                let joined = JoinAdapter::new(schema, tx, true)
                    .find_many(
                        FindMany::new("user")
                            .join("account", JoinOption::enabled())
                            .join("session", JoinOption::enabled()),
                    )
                    .await?;
                let user = joined
                    .into_iter()
                    .next()
                    .ok_or_else(|| OpenAuthError::Adapter("missing joined user".to_owned()))?;
                assert!(matches!(
                    user.get("account"),
                    Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
                ));
                assert!(matches!(
                    user.get("session"),
                    Some(DbValue::RecordArray(sessions)) if sessions.len() == 1
                ));
                Ok(())
            })
        }))
        .await
}

pub async fn seed_user<A>(
    adapter: &A,
    id: &str,
    email: &str,
    created_at: OffsetDateTime,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
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
        .await?;
    Ok(())
}

pub async fn seed_account<A>(adapter: &A, id: &str, user_id: &str) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let now = OffsetDateTime::now_utc();
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
        .await?;
    Ok(())
}

pub async fn seed_session<A>(adapter: &A, id: &str, user_id: &str) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let now = OffsetDateTime::now_utc();
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
        .await?;
    Ok(())
}

async fn create_user_with_json_and_arrays<A>(
    adapter: &A,
    id: &str,
    email: &str,
    profile: DbValue,
    tags: DbValue,
    scores: DbValue,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String(id.to_owned()))
                .data("email", DbValue::String(email.to_owned()))
                .data("email_verified", DbValue::Boolean(false))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("profile", profile)
                .data("tags", tags)
                .data("scores", scores),
        )
        .await?;
    Ok(())
}

async fn find_required<A>(
    adapter: &A,
    model: &str,
    field: &str,
    value: &str,
) -> Result<DbRecord, OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    adapter
        .find_one(
            FindOne::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned()))),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter(format!("missing {model} record `{value}`")))
}
