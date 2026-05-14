use std::sync::Arc;

use openauth_core::db::{
    run_transaction_without_native_support, AdapterCapabilities, AdapterFuture, Connector, Count,
    Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, JoinConfig,
    JoinOption, JoinRelation, SchemaCreation, Sort, SortDirection, TransactionCallback, Update,
    UpdateMany, Where, WhereMode, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use tokio::sync::Mutex;

#[test]
fn where_clause_defaults_to_eq_and_and_connector() {
    let clause = Where::new("email", DbValue::String("USER@example.com".to_owned()));

    assert_eq!(clause.operator, WhereOperator::Eq);
    assert_eq!(clause.connector, Connector::And);
    assert_eq!(clause.mode, WhereMode::Sensitive);
}

#[test]
fn where_clause_supports_case_insensitive_pattern_matching() {
    let clause = Where::new("email", DbValue::String("example.com".to_owned()))
        .operator(WhereOperator::EndsWith)
        .insensitive();

    assert_eq!(clause.operator, WhereOperator::EndsWith);
    assert_eq!(clause.mode, WhereMode::Insensitive);
}

#[test]
fn where_clause_supports_or_connector() {
    let clause = Where::new("name", DbValue::String("Ada".to_owned())).or();

    assert_eq!(clause.connector, Connector::Or);
}

#[test]
fn find_many_defaults_to_no_limit_or_offset() {
    let query = FindMany::new("user");

    assert_eq!(query.model, "user");
    assert_eq!(query.limit, None);
    assert_eq!(query.offset, None);
}

#[test]
fn find_many_supports_sort_limit_offset_and_select() {
    let query = FindMany::new("user")
        .where_clause(Where::new(
            "email",
            DbValue::String("a@example.com".to_owned()),
        ))
        .limit(25)
        .offset(50)
        .sort_by(Sort::new("created_at", SortDirection::Desc))
        .select(["id", "email"]);

    assert_eq!(query.where_clauses.len(), 1);
    assert_eq!(query.limit, Some(25));
    assert_eq!(query.offset, Some(50));
    assert_eq!(
        query.sort_by.as_ref().map(|sort| sort.direction),
        Some(SortDirection::Desc)
    );
    assert_eq!(query.select, vec!["id".to_owned(), "email".to_owned()]);
}

#[test]
fn find_queries_support_join_options() {
    let find_one = FindOne::new("user").join("accounts", JoinOption::enabled().limit(1));
    let find_many = FindMany::new("user").join("sessions", JoinOption::enabled().limit(5));

    assert_eq!(
        find_one.joins.get("accounts").and_then(|join| join.limit),
        Some(1)
    );
    assert_eq!(
        find_many.joins.get("sessions").and_then(|join| join.limit),
        Some(5)
    );
}

#[test]
fn create_captures_data_select_and_id_policy_hint() {
    let query = Create::new("user")
        .data("email", DbValue::String("a@example.com".to_owned()))
        .select(["id", "email"])
        .force_allow_id();

    assert_eq!(query.model, "user");
    assert_eq!(
        query.data.get("email"),
        Some(&DbValue::String("a@example.com".to_owned()))
    );
    assert_eq!(query.select, vec!["id".to_owned(), "email".to_owned()]);
    assert!(query.force_allow_id);
}

#[test]
fn find_one_requires_where_clauses_and_supports_select() {
    let query = FindOne::new("session")
        .where_clause(Where::new(
            "token",
            DbValue::String("session-token".to_owned()),
        ))
        .select(["id", "user_id"]);

    assert_eq!(query.model, "session");
    assert_eq!(query.where_clauses.len(), 1);
    assert_eq!(query.select, vec!["id".to_owned(), "user_id".to_owned()]);
}

#[test]
fn count_update_and_delete_share_where_contract() {
    let count = Count::new("session")
        .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned())));
    let update = Update::new("user")
        .where_clause(Where::new("id", DbValue::String("user_1".to_owned())))
        .data("name", DbValue::String("Ada".to_owned()));
    let update_many = UpdateMany::new("session")
        .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned())))
        .data("revoked", DbValue::Boolean(true));
    let delete = Delete::new("verification").where_clause(Where::new(
        "identifier",
        DbValue::String("email".to_owned()),
    ));
    let delete_many =
        DeleteMany::new("session").where_clause(Where::new("expires_at", DbValue::Null));

    assert_eq!(count.where_clauses.len(), 1);
    assert_eq!(
        update.data.get("name"),
        Some(&DbValue::String("Ada".to_owned()))
    );
    assert_eq!(
        update_many.data.get("revoked"),
        Some(&DbValue::Boolean(true))
    );
    assert_eq!(delete.where_clauses.len(), 1);
    assert_eq!(delete_many.where_clauses.len(), 1);
}

#[test]
fn join_config_captures_resolved_relation_metadata() {
    let config = JoinConfig::new("user_id", "id")
        .limit(100)
        .relation(JoinRelation::OneToMany);

    assert_eq!(config.on.from, "user_id");
    assert_eq!(config.on.to, "id");
    assert_eq!(config.limit, Some(100));
    assert_eq!(config.relation, JoinRelation::OneToMany);
}

#[test]
fn adapter_capabilities_default_to_core_safe_values() {
    let capabilities = AdapterCapabilities::new("custom");

    assert_eq!(capabilities.adapter_id, "custom");
    assert!(capabilities.supports_numeric_ids);
    assert!(capabilities.supports_dates);
    assert!(capabilities.supports_booleans);
    assert!(!capabilities.supports_uuid_ids);
    assert!(!capabilities.supports_json);
    assert!(!capabilities.supports_arrays);
    assert!(!capabilities.supports_joins);
    assert!(!capabilities.supports_transactions);
    assert!(!capabilities.disable_id_generation);
}

#[test]
fn adapter_capabilities_can_describe_sql_style_databases() {
    let capabilities = AdapterCapabilities::new("sqlx-postgres")
        .named("SQLx Postgres")
        .with_uuid_ids()
        .with_json()
        .with_arrays()
        .with_joins()
        .with_transactions()
        .without_id_generation();

    assert_eq!(capabilities.adapter_name.as_deref(), Some("SQLx Postgres"));
    assert!(capabilities.supports_uuid_ids);
    assert!(capabilities.supports_json);
    assert!(capabilities.supports_arrays);
    assert!(capabilities.supports_joins);
    assert!(capabilities.supports_transactions);
    assert!(capabilities.disable_id_generation);
}

#[test]
fn db_value_supports_nested_join_records() -> Result<(), Box<dyn std::error::Error>> {
    let mut user = DbRecord::new();
    user.insert("id".to_owned(), DbValue::String("user_1".to_owned()));

    let mut account = DbRecord::new();
    account.insert("id".to_owned(), DbValue::String("account_1".to_owned()));

    let value = DbValue::RecordArray(vec![account.clone()]);
    let serialized = serde_json::to_value(&value)?;
    let deserialized: DbValue = serde_json::from_value(serialized)?;

    assert_eq!(deserialized, DbValue::RecordArray(vec![account]));
    assert_eq!(DbValue::Record(user.clone()), DbValue::Record(user));
    Ok(())
}

#[test]
fn schema_creation_describes_file_write_intent_without_writing() {
    let creation = SchemaCreation::new("src/schema.rs", "schema contents")
        .append()
        .overwrite();

    assert_eq!(creation.path, "src/schema.rs");
    assert_eq!(creation.code, "schema contents");
    assert!(creation.append);
    assert!(creation.overwrite);
}

#[tokio::test]
async fn adapter_trait_is_async_and_object_safe() -> Result<(), OpenAuthError> {
    struct MockAdapter {
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl MockAdapter {
        fn new(calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self { calls }
        }

        fn record<'a, T: Send + 'a>(
            &'a self,
            name: &'static str,
            value: T,
        ) -> AdapterFuture<'a, T> {
            Box::pin(async move {
                self.calls.lock().await.push(name);
                Ok(value)
            })
        }
    }

    impl DbAdapter for MockAdapter {
        fn id(&self) -> &str {
            "mock"
        }

        fn create<'a>(&'a self, _query: Create) -> AdapterFuture<'a, DbRecord> {
            self.record("create", DbRecord::new())
        }

        fn find_one<'a>(&'a self, _query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
            self.record("find_one", None)
        }

        fn find_many<'a>(&'a self, _query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
            self.record("find_many", Vec::new())
        }

        fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
            self.record("count", 0)
        }

        fn update<'a>(&'a self, _query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
            self.record("update", None)
        }

        fn update_many<'a>(&'a self, _query: UpdateMany) -> AdapterFuture<'a, u64> {
            self.record("update_many", 0)
        }

        fn delete<'a>(&'a self, _query: Delete) -> AdapterFuture<'a, ()> {
            self.record("delete", ())
        }

        fn delete_many<'a>(&'a self, _query: DeleteMany) -> AdapterFuture<'a, u64> {
            self.record("delete_many", 0)
        }

        fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
            run_transaction_without_native_support(self, callback)
        }
    }

    let calls = Arc::new(Mutex::new(Vec::new()));
    let adapter: Box<dyn DbAdapter> = Box::new(MockAdapter::new(Arc::clone(&calls)));

    assert_eq!(adapter.capabilities().adapter_id, "mock");
    adapter.create(Create::new("user")).await?;
    adapter.find_one(FindOne::new("user")).await?;
    adapter.find_many(FindMany::new("user")).await?;
    adapter.count(Count::new("user")).await?;
    adapter.update(Update::new("user")).await?;
    adapter.update_many(UpdateMany::new("user")).await?;
    adapter.delete(Delete::new("user")).await?;
    adapter.delete_many(DeleteMany::new("user")).await?;

    let calls = calls.lock().await;
    assert_eq!(
        calls.as_slice(),
        [
            "create",
            "find_one",
            "find_many",
            "count",
            "update",
            "update_many",
            "delete",
            "delete_many"
        ]
    );

    Ok(())
}

#[tokio::test]
async fn adapter_transaction_falls_back_to_current_adapter() -> Result<(), OpenAuthError> {
    struct FallbackAdapter;

    impl DbAdapter for FallbackAdapter {
        fn id(&self) -> &str {
            "fallback"
        }

        fn create<'a>(&'a self, _query: Create) -> AdapterFuture<'a, DbRecord> {
            Box::pin(async {
                let mut record = DbRecord::new();
                record.insert("adapter".to_owned(), DbValue::String("fallback".to_owned()));
                Ok(record)
            })
        }

        fn find_one<'a>(&'a self, _query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
            Box::pin(async { Ok(None) })
        }

        fn find_many<'a>(&'a self, _query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
            Box::pin(async { Ok(0) })
        }

        fn update<'a>(&'a self, _query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
            Box::pin(async { Ok(None) })
        }

        fn update_many<'a>(&'a self, _query: UpdateMany) -> AdapterFuture<'a, u64> {
            Box::pin(async { Ok(0) })
        }

        fn delete<'a>(&'a self, _query: Delete) -> AdapterFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn delete_many<'a>(&'a self, _query: DeleteMany) -> AdapterFuture<'a, u64> {
            Box::pin(async { Ok(0) })
        }

        fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
            run_transaction_without_native_support(self, callback)
        }
    }

    let adapter: Box<dyn DbAdapter> = Box::new(FallbackAdapter);
    let observed = Arc::new(Mutex::new(None));
    let observed_for_callback = Arc::clone(&observed);
    let callback: TransactionCallback<'_> = Box::new(move |trx| {
        Box::pin(async move {
            let record = trx.create(Create::new("user")).await?;
            observed_for_callback
                .lock()
                .await
                .replace(record.get("adapter").cloned());
            Ok(())
        })
    });

    adapter.transaction(callback).await?;

    assert_eq!(
        observed.lock().await.as_ref(),
        Some(&Some(DbValue::String("fallback".to_owned())))
    );

    Ok(())
}

#[tokio::test]
async fn adapter_transaction_can_be_overridden_by_real_adapter() -> Result<(), OpenAuthError> {
    struct TransactionAdapter;

    impl DbAdapter for TransactionAdapter {
        fn id(&self) -> &str {
            "transactional"
        }

        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities::new(self.id()).with_transactions()
        }

        fn create<'a>(&'a self, _query: Create) -> AdapterFuture<'a, DbRecord> {
            Box::pin(async {
                let mut record = DbRecord::new();
                record.insert("adapter".to_owned(), DbValue::String("base".to_owned()));
                Ok(record)
            })
        }

        fn find_one<'a>(&'a self, _query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
            Box::pin(async { Ok(None) })
        }

        fn find_many<'a>(&'a self, _query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
            Box::pin(async { Ok(0) })
        }

        fn update<'a>(&'a self, _query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
            Box::pin(async { Ok(None) })
        }

        fn update_many<'a>(&'a self, _query: UpdateMany) -> AdapterFuture<'a, u64> {
            Box::pin(async { Ok(0) })
        }

        fn delete<'a>(&'a self, _query: Delete) -> AdapterFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn delete_many<'a>(&'a self, _query: DeleteMany) -> AdapterFuture<'a, u64> {
            Box::pin(async { Ok(0) })
        }

        fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
            struct TransactionHandle;

            impl DbAdapter for TransactionHandle {
                fn id(&self) -> &str {
                    "transaction"
                }

                fn create<'a>(&'a self, _query: Create) -> AdapterFuture<'a, DbRecord> {
                    Box::pin(async {
                        let mut record = DbRecord::new();
                        record.insert(
                            "adapter".to_owned(),
                            DbValue::String("transaction".to_owned()),
                        );
                        Ok(record)
                    })
                }

                fn find_one<'a>(&'a self, _query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
                    Box::pin(async { Ok(None) })
                }

                fn find_many<'a>(&'a self, _query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
                    Box::pin(async { Ok(Vec::new()) })
                }

                fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
                    Box::pin(async { Ok(0) })
                }

                fn update<'a>(&'a self, _query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
                    Box::pin(async { Ok(None) })
                }

                fn update_many<'a>(&'a self, _query: UpdateMany) -> AdapterFuture<'a, u64> {
                    Box::pin(async { Ok(0) })
                }

                fn delete<'a>(&'a self, _query: Delete) -> AdapterFuture<'a, ()> {
                    Box::pin(async { Ok(()) })
                }

                fn delete_many<'a>(&'a self, _query: DeleteMany) -> AdapterFuture<'a, u64> {
                    Box::pin(async { Ok(0) })
                }

                fn transaction<'a>(
                    &'a self,
                    callback: TransactionCallback<'a>,
                ) -> AdapterFuture<'a, ()> {
                    run_transaction_without_native_support(self, callback)
                }
            }

            Box::pin(async move {
                let trx = TransactionHandle;
                callback(Box::new(trx)).await
            })
        }
    }

    let adapter = TransactionAdapter;
    let observed = Arc::new(Mutex::new(None));
    let observed_for_callback = Arc::clone(&observed);
    let callback: TransactionCallback<'_> = Box::new(move |trx| {
        Box::pin(async move {
            let record = trx.create(Create::new("user")).await?;
            observed_for_callback
                .lock()
                .await
                .replace(record.get("adapter").cloned());
            Ok(())
        })
    });

    adapter.transaction(callback).await?;

    assert_eq!(
        observed.lock().await.as_ref(),
        Some(&Some(DbValue::String("transaction".to_owned())))
    );

    Ok(())
}
