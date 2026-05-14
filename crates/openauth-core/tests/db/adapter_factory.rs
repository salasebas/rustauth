use std::sync::{Arc, Mutex as StdMutex};

use openauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, DbValue,
    Delete, DeleteMany, FindMany, FindOne, HookedAdapter, JoinAdapter, JoinOption, SchemaAdapter,
    TransactionCallback, Update, UpdateMany, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{
    PluginDatabaseBeforeAction, PluginDatabaseBeforeInput, PluginDatabaseHook,
};
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct CapturingAdapter {
    capabilities: Option<AdapterCapabilities>,
    create: Arc<Mutex<Option<Create>>>,
    find_one: Arc<Mutex<Option<FindOne>>>,
    find_many: Arc<Mutex<Option<FindMany>>>,
    find_many_result: Arc<Mutex<Vec<DbRecord>>>,
    count: Arc<Mutex<Option<Count>>>,
    update: Arc<Mutex<Option<Update>>>,
    update_many: Arc<Mutex<Option<UpdateMany>>>,
    delete: Arc<Mutex<Option<Delete>>>,
    delete_many: Arc<Mutex<Option<DeleteMany>>>,
    create_result: Arc<Mutex<DbRecord>>,
    update_result: Arc<Mutex<Option<DbRecord>>>,
    update_many_result: Arc<Mutex<u64>>,
    delete_many_result: Arc<Mutex<u64>>,
    transaction_count: Arc<Mutex<u64>>,
    transaction_should_fail: Arc<Mutex<bool>>,
}

impl DbAdapter for CapturingAdapter {
    fn id(&self) -> &str {
        "capture"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.capabilities
            .clone()
            .unwrap_or_else(|| AdapterCapabilities::new(self.id()))
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            self.create.lock().await.replace(query);
            Ok(self.create_result.lock().await.clone())
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.find_one.lock().await.replace(query);
            Ok(None)
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            self.find_many.lock().await.replace(query);
            Ok(self.find_many_result.lock().await.clone())
        })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.count.lock().await.replace(query);
            Ok(0)
        })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.update.lock().await.replace(query);
            Ok(self.update_result.lock().await.clone())
        })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.update_many.lock().await.replace(query);
            Ok(*self.update_many_result.lock().await)
        })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.delete.lock().await.replace(query);
            Ok(())
        })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.delete_many.lock().await.replace(query);
            Ok(*self.delete_many_result.lock().await)
        })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            *self.transaction_count.lock().await += 1;
            if *self.transaction_should_fail.lock().await {
                return Err(OpenAuthError::Adapter("transaction failed".to_owned()));
            }
            callback(Box::new(self)).await
        })
    }
}

#[tokio::test]
async fn hooked_adapter_before_create_can_modify_data() -> Result<(), OpenAuthError> {
    let inner = CapturingAdapter::default();
    let adapter = HookedAdapter::new(
        Arc::new(inner.clone()),
        vec![PluginDatabaseHook::before_create(
            "tag-user",
            |_context, mut query| {
                query
                    .data
                    .insert("role".to_owned(), DbValue::String("admin".to_owned()));
                Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Create(query),
                ))
            },
        )],
    );

    adapter
        .create(Create::new("user").data("email", DbValue::String("a@example.com".to_owned())))
        .await?;

    let captured = inner
        .create
        .lock()
        .await
        .clone()
        .ok_or_else(|| OpenAuthError::Adapter("create query was not delegated".to_owned()))?;

    assert_eq!(
        captured.data.get("role"),
        Some(&DbValue::String("admin".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn hooked_adapter_before_update_and_update_many_can_modify_data() -> Result<(), OpenAuthError>
{
    let inner = CapturingAdapter::default();
    let adapter = HookedAdapter::new(
        Arc::new(inner.clone()),
        vec![
            PluginDatabaseHook::before_update("touch-one", |_context, mut query| {
                query.data.insert(
                    "updated_by".to_owned(),
                    DbValue::String("plugin".to_owned()),
                );
                Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Update(query),
                ))
            }),
            PluginDatabaseHook::before_update_many("touch-many", |_context, mut query| {
                query.data.insert(
                    "updated_many_by".to_owned(),
                    DbValue::String("plugin".to_owned()),
                );
                Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::UpdateMany(query),
                ))
            }),
        ],
    );

    adapter
        .update(Update::new("user").data("name", DbValue::String("Ada".to_owned())))
        .await?;
    adapter
        .update_many(UpdateMany::new("session").data("active", DbValue::Boolean(false)))
        .await?;

    let captured_update = inner
        .update
        .lock()
        .await
        .clone()
        .ok_or_else(|| OpenAuthError::Adapter("update query was not delegated".to_owned()))?;
    let captured_update_many =
        inner.update_many.lock().await.clone().ok_or_else(|| {
            OpenAuthError::Adapter("update_many query was not delegated".to_owned())
        })?;

    assert_eq!(
        captured_update.data.get("updated_by"),
        Some(&DbValue::String("plugin".to_owned()))
    );
    assert_eq!(
        captured_update_many.data.get("updated_many_by"),
        Some(&DbValue::String("plugin".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn hooked_adapter_before_delete_can_cancel() {
    let inner = CapturingAdapter::default();
    let adapter = HookedAdapter::new(
        Arc::new(inner.clone()),
        vec![PluginDatabaseHook::before_delete(
            "block-delete",
            |_context, _query, _snapshots| {
                Ok(PluginDatabaseBeforeAction::Cancel(OpenAuthError::Api(
                    "delete blocked".to_owned(),
                )))
            },
        )],
    );

    let result = adapter.delete(Delete::new("user")).await;

    assert!(matches!(result, Err(OpenAuthError::Api(message)) if message == "delete blocked"));
    assert!(inner.delete.lock().await.is_none());
}

#[tokio::test]
async fn hooked_adapter_after_hooks_receive_results() -> Result<(), OpenAuthError> {
    let inner = CapturingAdapter::default();
    inner
        .create_result
        .lock()
        .await
        .insert("id".to_owned(), DbValue::String("user_1".to_owned()));
    inner.update_result.lock().await.replace({
        let mut record = DbRecord::new();
        record.insert("id".to_owned(), DbValue::String("user_2".to_owned()));
        record
    });
    *inner.update_many_result.lock().await = 2;
    *inner.delete_many_result.lock().await = 3;

    let events = Arc::new(StdMutex::new(Vec::<String>::new()));
    let adapter = HookedAdapter::new(
        Arc::new(inner),
        vec![
            PluginDatabaseHook::after_create("after-create", {
                let events = Arc::clone(&events);
                move |_context, _query, result| {
                    let id = db_value_as_str(result.get("id")).unwrap_or_default();
                    events
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                        .push(format!("create:{id}"));
                    Ok(())
                }
            }),
            PluginDatabaseHook::after_update("after-update", {
                let events = Arc::clone(&events);
                move |_context, _query, result| {
                    let id = result
                        .as_ref()
                        .and_then(|record| record.get("id"))
                        .and_then(|value| db_value_as_str(Some(value)))
                        .unwrap_or_default();
                    events
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                        .push(format!("update:{id}"));
                    Ok(())
                }
            }),
            PluginDatabaseHook::after_update_many("after-update-many", {
                let events = Arc::clone(&events);
                move |_context, _query, result| {
                    events
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                        .push(format!("update_many:{result}"));
                    Ok(())
                }
            }),
            PluginDatabaseHook::after_delete("after-delete", {
                let events = Arc::clone(&events);
                move |_context, _query, snapshots| {
                    events
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                        .push(format!("delete:{}", snapshots.len()));
                    Ok(())
                }
            }),
            PluginDatabaseHook::after_delete_many("after-delete-many", {
                let events = Arc::clone(&events);
                move |_context, _query, snapshots, result| {
                    events
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                        .push(format!("delete_many:{result}:{}", snapshots.len()));
                    Ok(())
                }
            }),
        ],
    );

    adapter.create(Create::new("user")).await?;
    adapter.update(Update::new("user")).await?;
    adapter.update_many(UpdateMany::new("user")).await?;
    adapter.delete(Delete::new("user")).await?;
    adapter.delete_many(DeleteMany::new("user")).await?;

    let events = events
        .lock()
        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
        .clone();
    assert_eq!(
        events,
        vec![
            "create:user_1",
            "update:user_2",
            "update_many:2",
            "delete:0",
            "delete_many:3:0"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn hooked_adapter_hooks_run_in_order_and_inside_native_transactions(
) -> Result<(), OpenAuthError> {
    let inner = CapturingAdapter::default();
    let order = Arc::new(StdMutex::new(Vec::<String>::new()));
    let adapter = HookedAdapter::new(
        Arc::new(inner.clone()),
        vec![
            PluginDatabaseHook::before_create("first", {
                let order = Arc::clone(&order);
                move |_context, query| {
                    order
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("order lock poisoned".to_owned()))?
                        .push("first".to_owned());
                    Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Create(query),
                    ))
                }
            }),
            PluginDatabaseHook::before_create("second", {
                let order = Arc::clone(&order);
                move |_context, query| {
                    order
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("order lock poisoned".to_owned()))?
                        .push("second".to_owned());
                    Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Create(query),
                    ))
                }
            }),
        ],
    );

    adapter
        .transaction(Box::new(|transaction| {
            Box::pin(async move {
                transaction.create(Create::new("user")).await?;
                Ok(())
            })
        }))
        .await?;

    assert_eq!(*inner.transaction_count.lock().await, 1);
    assert_eq!(
        order
            .lock()
            .map_err(|_| OpenAuthError::Adapter("order lock poisoned".to_owned()))?
            .as_slice(),
        ["first", "second"]
    );
    Ok(())
}

#[tokio::test]
async fn hooked_adapter_queues_after_hooks_until_transaction_success() -> Result<(), OpenAuthError>
{
    let inner = CapturingAdapter::default();
    let events = Arc::new(StdMutex::new(Vec::<String>::new()));
    let adapter = HookedAdapter::new(
        Arc::new(inner),
        vec![PluginDatabaseHook::after_create("after-create", {
            let events = Arc::clone(&events);
            move |_context, _query, _result| {
                events
                    .lock()
                    .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                    .push("after".to_owned());
                Ok(())
            }
        })],
    );

    adapter
        .transaction(Box::new({
            let events = Arc::clone(&events);
            move |transaction| {
                Box::pin(async move {
                    transaction.create(Create::new("user")).await?;
                    assert!(events
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                        .is_empty());
                    Ok(())
                })
            }
        }))
        .await?;

    assert_eq!(
        events
            .lock()
            .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
            .as_slice(),
        ["after"]
    );
    Ok(())
}

#[tokio::test]
async fn hooked_adapter_does_not_run_after_hooks_when_transaction_fails() {
    let inner = CapturingAdapter::default();
    *inner.transaction_should_fail.lock().await = true;
    let events = Arc::new(StdMutex::new(Vec::<String>::new()));
    let adapter = HookedAdapter::new(
        Arc::new(inner),
        vec![PluginDatabaseHook::after_create("after-create", {
            let events = Arc::clone(&events);
            move |_context, _query, _result| {
                events
                    .lock()
                    .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                    .push("after".to_owned());
                Ok(())
            }
        })],
    );

    let result = adapter
        .transaction(Box::new(|transaction| {
            Box::pin(async move {
                transaction.create(Create::new("user")).await?;
                Ok(())
            })
        }))
        .await;

    assert!(
        matches!(result, Err(OpenAuthError::Adapter(message)) if message == "transaction failed")
    );
    assert!(events
        .lock()
        .map(|events| events.is_empty())
        .unwrap_or(false));
}

#[tokio::test]
async fn hooked_adapter_delete_hooks_receive_snapshots() -> Result<(), OpenAuthError> {
    let inner = CapturingAdapter::default();
    inner.find_many_result.lock().await.push({
        let mut record = DbRecord::new();
        record.insert("id".to_owned(), DbValue::String("user_1".to_owned()));
        record
    });
    let snapshots = Arc::new(StdMutex::new(Vec::<String>::new()));
    let adapter = HookedAdapter::new(
        Arc::new(inner),
        vec![
            PluginDatabaseHook::before_delete("before-delete", {
                let snapshots = Arc::clone(&snapshots);
                move |_context, query, records| {
                    snapshots
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("snapshots lock poisoned".to_owned()))?
                        .push(format!("before:{}:{}", query.model, records.len()));
                    Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Delete {
                            query,
                            snapshots: records,
                        },
                    ))
                }
            }),
            PluginDatabaseHook::after_delete("after-delete", {
                let snapshots = Arc::clone(&snapshots);
                move |_context, query, records| {
                    snapshots
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("snapshots lock poisoned".to_owned()))?
                        .push(format!("after:{}:{}", query.model, records.len()));
                    Ok(())
                }
            }),
        ],
    );

    adapter.delete(Delete::new("user")).await?;

    assert_eq!(
        snapshots
            .lock()
            .map_err(|_| OpenAuthError::Adapter("snapshots lock poisoned".to_owned()))?
            .as_slice(),
        ["before:user:1", "after:user:1"]
    );
    Ok(())
}

#[tokio::test]
async fn hooked_adapter_find_and_count_do_not_execute_hooks() -> Result<(), OpenAuthError> {
    let inner = CapturingAdapter::default();
    let calls = Arc::new(StdMutex::new(0_u64));
    let adapter = HookedAdapter::new(
        Arc::new(inner),
        vec![PluginDatabaseHook::before_create("count", {
            let calls = Arc::clone(&calls);
            move |_context, query| {
                *calls
                    .lock()
                    .map_err(|_| OpenAuthError::Adapter("calls lock poisoned".to_owned()))? += 1;
                Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Create(query),
                ))
            }
        })],
    );

    adapter.find_one(FindOne::new("user")).await?;
    adapter.find_many(FindMany::new("user")).await?;
    adapter.count(Count::new("user")).await?;

    assert_eq!(
        *calls
            .lock()
            .map_err(|_| OpenAuthError::Adapter("calls lock poisoned".to_owned()))?,
        0
    );
    Ok(())
}

fn db_value_as_str(value: Option<&DbValue>) -> Option<&str> {
    match value {
        Some(DbValue::String(value)) => Some(value),
        _ => None,
    }
}

#[tokio::test]
async fn join_adapter_falls_back_without_passing_joins_to_inner_adapter(
) -> Result<(), OpenAuthError> {
    let inner = CapturingAdapter::default();
    let adapter = JoinAdapter::new(
        auth_schema(Default::default()),
        Arc::new(inner.clone()),
        false,
    );

    adapter
        .find_one(FindOne::new("user").join("account", JoinOption::enabled()))
        .await?;

    let captured = inner
        .find_one
        .lock()
        .await
        .clone()
        .ok_or_else(|| OpenAuthError::Adapter("find_one query was not delegated".to_owned()))?;

    assert!(captured.joins.is_empty());
    Ok(())
}

#[tokio::test]
async fn join_adapter_passes_joins_when_experimental_and_supported() -> Result<(), OpenAuthError> {
    let inner =
        CapturingAdapter::with_capabilities(AdapterCapabilities::new("capture").with_joins());
    let adapter = JoinAdapter::new(
        auth_schema(Default::default()),
        Arc::new(inner.clone()),
        true,
    );

    adapter
        .find_many(FindMany::new("user").join("account", JoinOption::enabled()))
        .await?;

    let captured =
        inner.find_many.lock().await.clone().ok_or_else(|| {
            OpenAuthError::Adapter("find_many query was not delegated".to_owned())
        })?;

    assert!(captured.joins.contains_key("account"));
    Ok(())
}

impl CapturingAdapter {
    fn with_capabilities(capabilities: AdapterCapabilities) -> Self {
        Self {
            capabilities: Some(capabilities),
            ..Self::default()
        }
    }
}

#[tokio::test]
async fn schema_adapter_transforms_create_before_delegating() -> Result<(), OpenAuthError> {
    let inner = CapturingAdapter::default();
    let adapter = SchemaAdapter::new(auth_schema(Default::default()), inner.clone());

    adapter
        .create(Create::new("user").data("email", DbValue::String("a@example.com".to_owned())))
        .await?;

    let captured = inner
        .create
        .lock()
        .await
        .clone()
        .ok_or_else(|| OpenAuthError::Adapter("create query was not delegated".to_owned()))?;

    assert_eq!(captured.model, "users");
    assert_eq!(
        captured.data.get("email"),
        Some(&DbValue::String("a@example.com".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn schema_adapter_transforms_find_many_before_delegating() -> Result<(), OpenAuthError> {
    let inner = CapturingAdapter::default();
    let adapter = SchemaAdapter::new(auth_schema(Default::default()), inner.clone());

    adapter
        .find_many(
            FindMany::new("session")
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned())))
                .select(["id", "user_id"]),
        )
        .await?;

    let captured =
        inner.find_many.lock().await.clone().ok_or_else(|| {
            OpenAuthError::Adapter("find_many query was not delegated".to_owned())
        })?;

    assert_eq!(captured.model, "sessions");
    assert_eq!(captured.where_clauses[0].field, "user_id");
    assert_eq!(captured.select, vec!["id".to_owned(), "user_id".to_owned()]);

    Ok(())
}

#[tokio::test]
async fn schema_adapter_applies_inner_adapter_capabilities() -> Result<(), OpenAuthError> {
    let inner =
        CapturingAdapter::with_capabilities(AdapterCapabilities::new("capture").without_booleans());
    let adapter = SchemaAdapter::new(auth_schema(Default::default()), inner.clone());

    adapter
        .create(Create::new("user").data("email_verified", DbValue::Boolean(true)))
        .await?;

    let captured = inner
        .create
        .lock()
        .await
        .clone()
        .ok_or_else(|| OpenAuthError::Adapter("create query was not delegated".to_owned()))?;

    assert_eq!(
        captured.data.get("email_verified"),
        Some(&DbValue::Number(1))
    );

    Ok(())
}
