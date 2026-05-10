use std::sync::Arc;

use openauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, DbValue,
    Delete, DeleteMany, FindMany, FindOne, SchemaAdapter, TransactionCallback, Update, UpdateMany,
    Where,
};
use openauth_core::error::OpenAuthError;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
struct CapturingAdapter {
    capabilities: Option<AdapterCapabilities>,
    create: Arc<Mutex<Option<Create>>>,
    find_many: Arc<Mutex<Option<FindMany>>>,
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
            Ok(DbRecord::new())
        })
    }

    fn find_one<'a>(&'a self, _query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async { Ok(None) })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            self.find_many.lock().await.replace(query);
            Ok(Vec::new())
        })
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
        callback(self)
    }
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
