use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::db::schema::DbSchema;
use crate::error::RustAuthError;
use crate::plugin::PluginMigration;

use super::capabilities::{AdapterCapabilities, SchemaCreation};
use super::query::{Count, Create, Delete, DeleteMany, FindMany, FindOne, Update, UpdateMany};
use super::value::DbRecord;

pub type AdapterResult<T> = Result<T, RustAuthError>;

/// Boxed async result returned by database adapter methods.
pub type AdapterFuture<'a, T> = Pin<Box<dyn Future<Output = AdapterResult<T>> + Send + 'a>>;

/// Adapter handle passed to transaction callbacks.
pub type TransactionAdapter<'tx> = Box<dyn DbAdapter + 'tx>;

/// Callback executed inside an adapter transaction.
pub type TransactionCallback<'a> =
    Box<dyn for<'tx> FnOnce(TransactionAdapter<'tx>) -> AdapterFuture<'tx, ()> + Send + 'a>;

/// Execute a transaction callback directly when native transactions are unavailable.
pub fn run_transaction_without_native_support<'a, A>(
    adapter: &'a A,
    callback: TransactionCallback<'a>,
) -> AdapterFuture<'a, ()>
where
    A: DbAdapter,
{
    callback(Box::new(adapter))
}

/// Async database adapter contract used by core authentication behavior.
///
/// Concrete database integrations should live outside `rustauth-core` and
/// implement this trait without forcing their driver or ORM dependencies into
/// the core crate.
pub trait DbAdapter: Send + Sync {
    fn id(&self) -> &str;

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord>;

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>>;

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>>;

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64>;

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>>;

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64>;

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()>;

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64>;

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()>;

    fn create_schema<'a>(
        &'a self,
        _schema: &'a DbSchema,
        _file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        Box::pin(async { Ok(None) })
    }

    fn run_migrations<'a>(&'a self, _schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        Box::pin(async {
            Err(RustAuthError::InvalidConfig(
                "adapter does not support explicit migrations".to_owned(),
            ))
        })
    }

    fn run_plugin_migrations<'a>(
        &'a self,
        _migrations: &'a [PluginMigration],
    ) -> AdapterFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

impl<A> DbAdapter for &A
where
    A: DbAdapter + ?Sized,
{
    fn id(&self) -> &str {
        (**self).id()
    }

    fn capabilities(&self) -> AdapterCapabilities {
        (**self).capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        (**self).create(query)
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        (**self).find_one(query)
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        (**self).find_many(query)
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        (**self).count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        (**self).update(query)
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        (**self).update_many(query)
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        (**self).delete(query)
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        (**self).delete_many(query)
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        (**self).transaction(callback)
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        (**self).create_schema(schema, file)
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        (**self).run_migrations(schema)
    }

    fn run_plugin_migrations<'a>(
        &'a self,
        migrations: &'a [PluginMigration],
    ) -> AdapterFuture<'a, ()> {
        (**self).run_plugin_migrations(migrations)
    }
}

impl<A> DbAdapter for Box<A>
where
    A: DbAdapter + ?Sized,
{
    fn id(&self) -> &str {
        (**self).id()
    }

    fn capabilities(&self) -> AdapterCapabilities {
        (**self).capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        (**self).create(query)
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        (**self).find_one(query)
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        (**self).find_many(query)
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        (**self).count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        (**self).update(query)
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        (**self).update_many(query)
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        (**self).delete(query)
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        (**self).delete_many(query)
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        (**self).transaction(callback)
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        (**self).create_schema(schema, file)
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        (**self).run_migrations(schema)
    }

    fn run_plugin_migrations<'a>(
        &'a self,
        migrations: &'a [PluginMigration],
    ) -> AdapterFuture<'a, ()> {
        (**self).run_plugin_migrations(migrations)
    }
}

impl<A> DbAdapter for Arc<A>
where
    A: DbAdapter + ?Sized,
{
    fn id(&self) -> &str {
        (**self).id()
    }

    fn capabilities(&self) -> AdapterCapabilities {
        (**self).capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        (**self).create(query)
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        (**self).find_one(query)
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        (**self).find_many(query)
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        (**self).count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        (**self).update(query)
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        (**self).update_many(query)
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        (**self).delete(query)
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        (**self).delete_many(query)
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        (**self).transaction(callback)
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        (**self).create_schema(schema, file)
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        (**self).run_migrations(schema)
    }

    fn run_plugin_migrations<'a>(
        &'a self,
        migrations: &'a [PluginMigration],
    ) -> AdapterFuture<'a, ()> {
        (**self).run_plugin_migrations(migrations)
    }
}
