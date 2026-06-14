mod join_support;

use super::{
    transform_count_query_with_capabilities, transform_create_query_with_capabilities,
    transform_delete_many_query_with_capabilities, transform_delete_query_with_capabilities,
    transform_find_many_query_with_capabilities, transform_find_one_query_with_capabilities,
    transform_update_many_query_with_capabilities, transform_update_query_with_capabilities,
    AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, DbSchema, Delete,
    DeleteMany, FindMany, FindOne, SchemaCreation, TransactionCallback, Update, UpdateMany,
};
use crate::error::RustAuthError;
use join_support::{
    attach_joins, extend_select_for_joins, resolve_fallback_joins, trim_joined_record,
};
use std::sync::Arc;

/// Adapter wrapper that maps RustAuth logical schema names to database names.
#[derive(Debug, Clone)]
pub struct SchemaAdapter<A> {
    schema: DbSchema,
    inner: A,
}

impl<A> SchemaAdapter<A> {
    pub fn new(schema: DbSchema, inner: A) -> Self {
        Self { schema, inner }
    }

    pub fn schema(&self) -> &DbSchema {
        &self.schema
    }

    pub fn inner(&self) -> &A {
        &self.inner
    }
}

impl<A> DbAdapter for SchemaAdapter<A>
where
    A: DbAdapter,
{
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.inner.capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            let capabilities = self.inner.capabilities();
            let query =
                transform_create_query_with_capabilities(&self.schema, &capabilities, query)?;
            self.inner.create(query).await
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            let capabilities = self.inner.capabilities();
            let query =
                transform_find_one_query_with_capabilities(&self.schema, &capabilities, query)?;
            self.inner.find_one(query).await
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            let capabilities = self.inner.capabilities();
            let query =
                transform_find_many_query_with_capabilities(&self.schema, &capabilities, query)?;
            self.inner.find_many(query).await
        })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let capabilities = self.inner.capabilities();
            let query =
                transform_count_query_with_capabilities(&self.schema, &capabilities, query)?;
            self.inner.count(query).await
        })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            let capabilities = self.inner.capabilities();
            let query =
                transform_update_query_with_capabilities(&self.schema, &capabilities, query)?;
            self.inner.update(query).await
        })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let capabilities = self.inner.capabilities();
            let query =
                transform_update_many_query_with_capabilities(&self.schema, &capabilities, query)?;
            self.inner.update_many(query).await
        })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let capabilities = self.inner.capabilities();
            let query =
                transform_delete_query_with_capabilities(&self.schema, &capabilities, query)?;
            self.inner.delete(query).await
        })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let capabilities = self.inner.capabilities();
            let query =
                transform_delete_many_query_with_capabilities(&self.schema, &capabilities, query)?;
            self.inner.delete_many(query).await
        })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        let schema = self.schema.clone();
        self.inner.transaction(Box::new(move |transaction| {
            let adapter = SchemaAdapter::new(schema, transaction);
            callback(Box::new(adapter))
        }))
    }

    fn create_schema<'a>(
        &'a self,
        _schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        self.inner.create_schema(&self.schema, file)
    }

    fn run_migrations<'a>(&'a self, _schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        self.inner.run_migrations(&self.schema)
    }
}

/// Adapter wrapper that resolves RustAuth join options at runtime.
#[derive(Clone)]
pub struct JoinAdapter<A = Arc<dyn DbAdapter>> {
    schema: DbSchema,
    inner: A,
    experimental_joins: bool,
}

impl<A> JoinAdapter<A> {
    pub fn new(schema: DbSchema, inner: A, experimental_joins: bool) -> Self {
        Self {
            schema,
            inner,
            experimental_joins,
        }
    }
}

impl<A> JoinAdapter<A>
where
    A: DbAdapter,
{
    fn should_delegate_joins(&self) -> bool {
        let caps = self.inner.capabilities();
        if caps.supports_native_joins {
            return true;
        }
        self.experimental_joins && caps.supports_joins
    }

    async fn fallback_find_one(
        &self,
        mut query: FindOne,
    ) -> Result<Option<DbRecord>, RustAuthError> {
        let joins = resolve_fallback_joins(&self.schema, &query.model, &query.joins, 100)?;
        let original_select = query.select.clone();
        extend_select_for_joins(&mut query.select, &joins);
        query.joins.clear();

        let Some(mut record) = self.inner.find_one(query).await? else {
            return Ok(None);
        };
        attach_joins(&self.inner, &mut [&mut record], &joins).await?;
        trim_joined_record(&mut record, &original_select, &joins);
        Ok(Some(record))
    }

    async fn fallback_find_many(
        &self,
        mut query: FindMany,
    ) -> Result<Vec<DbRecord>, RustAuthError> {
        let joins = resolve_fallback_joins(&self.schema, &query.model, &query.joins, 100)?;
        let original_select = query.select.clone();
        extend_select_for_joins(&mut query.select, &joins);
        query.joins.clear();

        let mut records = self.inner.find_many(query).await?;
        let mut record_refs = records.iter_mut().collect::<Vec<_>>();
        attach_joins(&self.inner, &mut record_refs, &joins).await?;
        for record in &mut records {
            trim_joined_record(record, &original_select, &joins);
        }
        Ok(records)
    }
}

impl<A> std::fmt::Debug for JoinAdapter<A>
where
    A: DbAdapter,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JoinAdapter")
            .field("schema", &self.schema)
            .field("inner", &self.inner.id())
            .field("experimental_joins", &self.experimental_joins)
            .finish()
    }
}

impl<A> DbAdapter for JoinAdapter<A>
where
    A: DbAdapter,
{
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.inner.capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        self.inner.create(query)
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            if query.joins.is_empty() || self.should_delegate_joins() {
                self.inner.find_one(query).await
            } else {
                self.fallback_find_one(query).await
            }
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            if query.joins.is_empty() || self.should_delegate_joins() {
                self.inner.find_many(query).await
            } else {
                self.fallback_find_many(query).await
            }
        })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        self.inner.count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        self.inner.update(query)
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        self.inner.update_many(query)
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        self.inner.delete(query)
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        self.inner.delete_many(query)
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        let schema = self.schema.clone();
        let experimental_joins = self.experimental_joins;
        self.inner.transaction(Box::new(move |transaction| {
            let adapter = JoinAdapter::new(schema, transaction, experimental_joins);
            callback(Box::new(adapter))
        }))
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        self.inner.create_schema(schema, file)
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        self.inner.run_migrations(schema)
    }
}
