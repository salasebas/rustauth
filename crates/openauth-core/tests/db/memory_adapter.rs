use openauth_core::db::{
    auth_schema, AdapterCapabilities, Count, Create, DbAdapter, DbValue, DeleteMany, FindMany,
    FindOne, JoinAdapter, JoinOption, MemoryAdapter, Sort, SortDirection, Update, Where, WhereMode,
    WhereOperator,
};
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use time::OffsetDateTime;

#[tokio::test]
async fn memory_adapter_clones_share_inserted_records() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let clone = adapter.clone();
    let now = OffsetDateTime::now_utc();

    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("created_at", DbValue::Timestamp(now)),
        )
        .await?;

    let record = clone
        .find_one(FindOne::new("user").where_clause(Where::new(
            "email",
            DbValue::String("ada@example.com".to_owned()),
        )))
        .await?
        .ok_or("missing user inserted through cloned adapter")?;

    assert_eq!(
        record.get("id"),
        Some(&DbValue::String("user_1".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn memory_adapter_filters_sorts_limits_and_counts_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    for (id, email, created_at) in [
        ("user_1", "ada@example.com", 1),
        ("user_2", "grace@example.com", 3),
        ("user_3", "alan@example.net", 2),
    ] {
        adapter
            .create(
                Create::new("user")
                    .data("id", DbValue::String(id.to_owned()))
                    .data("email", DbValue::String(email.to_owned()))
                    .data("created_at", DbValue::Number(created_at)),
            )
            .await?;
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
                .limit(1),
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
        Some(&DbValue::String("user_2".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn memory_adapter_updates_and_deletes_matching_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    for (id, user_id) in [
        ("session_1", "user_1"),
        ("session_2", "user_1"),
        ("session_3", "user_2"),
    ] {
        adapter
            .create(
                Create::new("session")
                    .data("id", DbValue::String(id.to_owned()))
                    .data("user_id", DbValue::String(user_id.to_owned()))
                    .data("active", DbValue::Boolean(true)),
            )
            .await?;
    }

    let updated = adapter
        .update(
            Update::new("session")
                .where_clause(Where::new("id", DbValue::String("session_1".to_owned())))
                .data("active", DbValue::Boolean(false)),
        )
        .await?
        .ok_or("missing updated session")?;
    let deleted = adapter
        .delete_many(
            DeleteMany::new("session")
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned()))),
        )
        .await?;
    let remaining = adapter.find_many(FindMany::new("session")).await?;

    assert_eq!(updated.get("active"), Some(&DbValue::Boolean(false)));
    assert_eq!(deleted, 2);
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0].get("id"),
        Some(&DbValue::String("session_3".to_owned()))
    );
    Ok(())
}

#[test]
fn memory_adapter_reports_public_capabilities() {
    let capabilities = MemoryAdapter::new().capabilities();

    assert_eq!(
        capabilities,
        AdapterCapabilities::new("memory")
            .named("Memory Adapter")
            .with_json()
            .with_arrays()
    );
}

#[tokio::test]
async fn memory_adapter_supports_or_connectors_and_in_operators(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    for (id, provider) in [
        ("account_1", "credential"),
        ("account_2", "github"),
        ("account_3", "google"),
    ] {
        adapter
            .create(
                Create::new("account")
                    .data("id", DbValue::String(id.to_owned()))
                    .data("provider_id", DbValue::String(provider.to_owned())),
            )
            .await?;
    }

    let records = adapter
        .find_many(
            FindMany::new("account")
                .where_clause(
                    Where::new(
                        "provider_id",
                        DbValue::StringArray(vec!["github".to_owned(), "google".to_owned()]),
                    )
                    .operator(WhereOperator::In),
                )
                .where_clause(Where {
                    mode: WhereMode::Sensitive,
                    ..Where::new("id", DbValue::String("account_1".to_owned())).or()
                }),
        )
        .await?;

    assert_eq!(records.len(), 3);
    Ok(())
}

#[tokio::test]
async fn memory_adapter_supports_verification_store_lifecycle(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let store = DbVerificationStore::new(&adapter);

    let verification = store
        .create_verification(CreateVerificationInput::new(
            "reset-password:token",
            "user_1",
            OffsetDateTime::now_utc() + time::Duration::minutes(10),
        ))
        .await?;
    let found = store
        .find_verification("reset-password:token")
        .await?
        .ok_or("missing verification")?;
    store.delete_verification("reset-password:token").await?;
    let deleted = store.find_verification("reset-password:token").await?;

    assert_eq!(verification.identifier, "reset-password:token");
    assert_eq!(found.value, "user_1");
    assert!(deleted.is_none());
    Ok(())
}

#[tokio::test]
async fn join_adapter_fallback_composes_forward_and_reverse_joins(
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = MemoryAdapter::new();
    seed_user(&inner, "user_1", "ada@example.com").await?;
    seed_user(&inner, "user_2", "grace@example.com").await?;
    seed_account(&inner, "account_1", "user_1").await?;
    seed_account(&inner, "account_2", "user_1").await?;
    seed_session(&inner, "session_1", "user_1").await?;

    let adapter = JoinAdapter::new(
        auth_schema(Default::default()),
        std::sync::Arc::new(inner),
        false,
    );
    let user = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned())))
                .select(["email"])
                .join("account", JoinOption::enabled())
                .join("session", JoinOption::enabled()),
        )
        .await?
        .ok_or("missing joined user")?;

    assert_eq!(
        user.get("email"),
        Some(&DbValue::String("ada@example.com".to_owned()))
    );
    assert!(!user.contains_key("id"));
    assert!(matches!(
        user.get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.len() == 2
    ));
    assert!(matches!(
        user.get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.len() == 1
    ));

    let account = adapter
        .find_one(
            FindOne::new("account")
                .where_clause(Where::new("id", DbValue::String("account_1".to_owned())))
                .join("user", JoinOption::enabled()),
        )
        .await?
        .ok_or("missing joined account")?;

    assert!(matches!(
        account.get("user"),
        Some(DbValue::Record(user)) if user.get("id") == Some(&DbValue::String("user_1".to_owned()))
    ));
    Ok(())
}

#[tokio::test]
async fn join_adapter_fallback_batches_find_many_and_applies_join_limits(
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = MemoryAdapter::new();
    seed_user(&inner, "user_1", "ada@example.com").await?;
    seed_user(&inner, "user_2", "grace@example.com").await?;
    seed_session(&inner, "session_1", "user_1").await?;
    seed_session(&inner, "session_2", "user_1").await?;
    seed_session(&inner, "session_3", "user_2").await?;

    let adapter = JoinAdapter::new(
        auth_schema(Default::default()),
        std::sync::Arc::new(inner),
        false,
    );
    let users = adapter
        .find_many(
            FindMany::new("user")
                .sort_by(Sort::new("id", SortDirection::Asc))
                .join("session", JoinOption::enabled().limit(1)),
        )
        .await?;

    assert_eq!(users.len(), 2);
    assert!(matches!(
        users[0].get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.len() == 1
    ));
    assert!(matches!(
        users[1].get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.len() == 1
    ));
    Ok(())
}

async fn seed_user(
    adapter: &MemoryAdapter,
    id: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await?;
    Ok(())
}

async fn seed_account(
    adapter: &MemoryAdapter,
    id: &str,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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

async fn seed_session(
    adapter: &MemoryAdapter,
    id: &str,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
