use std::future::Future;
use std::pin::Pin;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::schema::DbSchema;
use crate::error::OpenAuthError;
use std::sync::Arc;

/// Result type returned by database adapters.
pub type AdapterResult<T> = Result<T, OpenAuthError>;

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

/// Dynamic record payload exchanged between core auth logic and adapters.
pub type DbRecord = IndexMap<String, DbValue>;

/// Database adapter capability metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterCapabilities {
    pub adapter_id: String,
    pub adapter_name: Option<String>,
    pub supports_numeric_ids: bool,
    pub supports_uuid_ids: bool,
    pub supports_json: bool,
    pub supports_dates: bool,
    pub supports_booleans: bool,
    pub supports_arrays: bool,
    pub supports_joins: bool,
    pub supports_transactions: bool,
    pub disable_id_generation: bool,
}

impl AdapterCapabilities {
    pub fn new(adapter_id: impl Into<String>) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            adapter_name: None,
            supports_numeric_ids: true,
            supports_uuid_ids: false,
            supports_json: false,
            supports_dates: true,
            supports_booleans: true,
            supports_arrays: false,
            supports_joins: false,
            supports_transactions: false,
            disable_id_generation: false,
        }
    }

    pub fn named(mut self, adapter_name: impl Into<String>) -> Self {
        self.adapter_name = Some(adapter_name.into());
        self
    }

    pub fn without_numeric_ids(mut self) -> Self {
        self.supports_numeric_ids = false;
        self
    }

    pub fn with_uuid_ids(mut self) -> Self {
        self.supports_uuid_ids = true;
        self
    }

    pub fn with_json(mut self) -> Self {
        self.supports_json = true;
        self
    }

    pub fn without_dates(mut self) -> Self {
        self.supports_dates = false;
        self
    }

    pub fn without_booleans(mut self) -> Self {
        self.supports_booleans = false;
        self
    }

    pub fn with_arrays(mut self) -> Self {
        self.supports_arrays = true;
        self
    }

    pub fn with_joins(mut self) -> Self {
        self.supports_joins = true;
        self
    }

    pub fn with_transactions(mut self) -> Self {
        self.supports_transactions = true;
        self
    }

    pub fn without_id_generation(mut self) -> Self {
        self.disable_id_generation = true;
        self
    }
}

/// Schema file content produced by an adapter or migration generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaCreation {
    pub path: String,
    pub code: String,
    pub append: bool,
    pub overwrite: bool,
}

impl SchemaCreation {
    pub fn new(path: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code: code.into(),
            append: false,
            overwrite: false,
        }
    }

    pub fn append(mut self) -> Self {
        self.append = true;
        self
    }

    pub fn overwrite(mut self) -> Self {
        self.overwrite = true;
        self
    }
}

/// Primitive value accepted by adapter query predicates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DbValue {
    String(String),
    Number(i64),
    Boolean(bool),
    Timestamp(OffsetDateTime),
    Json(serde_json::Value),
    StringArray(Vec<String>),
    NumberArray(Vec<i64>),
    Record(DbRecord),
    RecordArray(Vec<DbRecord>),
    Null,
}

/// Predicate operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhereOperator {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
}

/// Connector between predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Connector {
    And,
    Or,
}

/// Case sensitivity for string predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WhereMode {
    Sensitive,
    Insensitive,
}

/// Adapter query predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Where {
    pub field: String,
    pub value: DbValue,
    pub operator: WhereOperator,
    pub connector: Connector,
    pub mode: WhereMode,
}

impl Where {
    pub fn new(field: impl Into<String>, value: DbValue) -> Self {
        Self {
            field: field.into(),
            value,
            operator: WhereOperator::Eq,
            connector: Connector::And,
            mode: WhereMode::Sensitive,
        }
    }

    pub fn operator(mut self, operator: WhereOperator) -> Self {
        self.operator = operator;
        self
    }

    pub fn or(mut self) -> Self {
        self.connector = Connector::Or;
        self
    }

    pub fn insensitive(mut self) -> Self {
        self.mode = WhereMode::Insensitive;
        self
    }
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortDirection {
    Asc,
    Desc,
}

/// Sort clause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sort {
    pub field: String,
    pub direction: SortDirection,
}

impl Sort {
    pub fn new(field: impl Into<String>, direction: SortDirection) -> Self {
        Self {
            field: field.into(),
            direction,
        }
    }
}

/// User-facing join request before schema relation metadata has been resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinOption {
    pub enabled: bool,
    pub limit: Option<usize>,
}

impl JoinOption {
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            limit: None,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            limit: None,
        }
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Resolved join column pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinOn {
    pub from: String,
    pub to: String,
}

impl JoinOn {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }
}

/// Resolved relation kind for joined output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinRelation {
    OneToOne,
    OneToMany,
    ManyToMany,
}

/// Adapter-facing join configuration after relation metadata is resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinConfig {
    pub on: JoinOn,
    pub limit: Option<usize>,
    pub relation: JoinRelation,
}

impl JoinConfig {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            on: JoinOn::new(from, to),
            limit: None,
            relation: JoinRelation::OneToMany,
        }
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn relation(mut self, relation: JoinRelation) -> Self {
        self.relation = relation;
        self
    }
}

/// Resolved join metadata plus any base select fields required to execute it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResolution {
    pub joins: IndexMap<String, JoinConfig>,
    pub select: Vec<String>,
}

impl JoinResolution {
    pub fn new(select: Vec<String>) -> Self {
        Self {
            joins: IndexMap::new(),
            select,
        }
    }
}

/// Create query contract for adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Create {
    pub model: String,
    pub data: DbRecord,
    pub select: Vec<String>,
    pub force_allow_id: bool,
}

impl Create {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            data: DbRecord::new(),
            select: Vec::new(),
            force_allow_id: false,
        }
    }

    pub fn data(mut self, field: impl Into<String>, value: DbValue) -> Self {
        self.data.insert(field.into(), value);
        self
    }

    pub fn select<const N: usize>(mut self, fields: [&str; N]) -> Self {
        self.select = fields.into_iter().map(str::to_owned).collect();
        self
    }

    pub fn force_allow_id(mut self) -> Self {
        self.force_allow_id = true;
        self
    }
}

/// Find-one query contract for adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindOne {
    pub model: String,
    pub where_clauses: Vec<Where>,
    pub select: Vec<String>,
    pub joins: IndexMap<String, JoinOption>,
}

impl FindOne {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            where_clauses: Vec::new(),
            select: Vec::new(),
            joins: IndexMap::new(),
        }
    }

    pub fn where_clause(mut self, where_clause: Where) -> Self {
        self.where_clauses.push(where_clause);
        self
    }

    pub fn select<const N: usize>(mut self, fields: [&str; N]) -> Self {
        self.select = fields.into_iter().map(str::to_owned).collect();
        self
    }

    pub fn join(mut self, model: impl Into<String>, option: JoinOption) -> Self {
        self.joins.insert(model.into(), option);
        self
    }
}

/// Find-many query contract for adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindMany {
    pub model: String,
    pub where_clauses: Vec<Where>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<Sort>,
    pub select: Vec<String>,
    pub joins: IndexMap<String, JoinOption>,
}

impl FindMany {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            where_clauses: Vec::new(),
            limit: None,
            offset: None,
            sort_by: None,
            select: Vec::new(),
            joins: IndexMap::new(),
        }
    }

    pub fn where_clause(mut self, where_clause: Where) -> Self {
        self.where_clauses.push(where_clause);
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn sort_by(mut self, sort: Sort) -> Self {
        self.sort_by = Some(sort);
        self
    }

    pub fn select<const N: usize>(mut self, fields: [&str; N]) -> Self {
        self.select = fields.into_iter().map(str::to_owned).collect();
        self
    }

    pub fn join(mut self, model: impl Into<String>, option: JoinOption) -> Self {
        self.joins.insert(model.into(), option);
        self
    }
}

/// Count query contract for adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Count {
    pub model: String,
    pub where_clauses: Vec<Where>,
}

impl Count {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            where_clauses: Vec::new(),
        }
    }

    pub fn where_clause(mut self, where_clause: Where) -> Self {
        self.where_clauses.push(where_clause);
        self
    }
}

/// Single-row update query contract for adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Update {
    pub model: String,
    pub where_clauses: Vec<Where>,
    pub data: DbRecord,
}

impl Update {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            where_clauses: Vec::new(),
            data: DbRecord::new(),
        }
    }

    pub fn where_clause(mut self, where_clause: Where) -> Self {
        self.where_clauses.push(where_clause);
        self
    }

    pub fn data(mut self, field: impl Into<String>, value: DbValue) -> Self {
        self.data.insert(field.into(), value);
        self
    }
}

/// Multi-row update query contract for adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateMany {
    pub model: String,
    pub where_clauses: Vec<Where>,
    pub data: DbRecord,
}

impl UpdateMany {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            where_clauses: Vec::new(),
            data: DbRecord::new(),
        }
    }

    pub fn where_clause(mut self, where_clause: Where) -> Self {
        self.where_clauses.push(where_clause);
        self
    }

    pub fn data(mut self, field: impl Into<String>, value: DbValue) -> Self {
        self.data.insert(field.into(), value);
        self
    }
}

/// Single-row delete query contract for adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Delete {
    pub model: String,
    pub where_clauses: Vec<Where>,
}

impl Delete {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            where_clauses: Vec::new(),
        }
    }

    pub fn where_clause(mut self, where_clause: Where) -> Self {
        self.where_clauses.push(where_clause);
        self
    }
}

/// Multi-row delete query contract for adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeleteMany {
    pub model: String,
    pub where_clauses: Vec<Where>,
}

impl DeleteMany {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            where_clauses: Vec::new(),
        }
    }

    pub fn where_clause(mut self, where_clause: Where) -> Self {
        self.where_clauses.push(where_clause);
        self
    }
}

/// Async database adapter contract used by core authentication behavior.
///
/// Concrete database integrations should live outside `openauth-core` and
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
            Err(OpenAuthError::InvalidConfig(
                "adapter does not support explicit migrations".to_owned(),
            ))
        })
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
}
