//! Database contracts, model metadata, and SQL naming defaults.

mod adapter;
#[doc(hidden)]
pub mod adapter_harness;
mod factory;
mod hooks;
mod id;
mod memory;
mod models;
mod output;
mod schema;
pub mod sql;
mod transform;

pub use adapter::{
    run_transaction_without_native_support, AdapterCapabilities, AdapterFuture, AdapterResult,
    Connector, Count, Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne,
    JoinConfig, JoinOn, JoinOption, JoinRelation, JoinResolution, SchemaCreation, Sort,
    SortDirection, TransactionAdapter, TransactionCallback, Update, UpdateMany, Where, WhereMode,
    WhereOperator,
};
pub use factory::JoinAdapter;
pub use factory::SchemaAdapter;
pub use hooks::HookedAdapter;
pub use id::{IdGeneration, IdPolicy, IdValue};
pub use memory::MemoryAdapter;
pub use models::{Account, RateLimit, Session, User, Verification};
pub use output::filter_output_fields;
pub use schema::{
    auth_schema, AuthSchemaOptions, DbField, DbFieldType, DbSchema, DbTable, ForeignKey, OnDelete,
    RateLimitStorage, TableOptions,
};
pub use sql::{
    consume_sql_rate_limit_record, count_statement, create_statement, delete_many_statement,
    delete_one_statement, ensure_executable_migration_plan, execute_schema_migration_plan,
    find_many_statement, find_many_with_joins_statement, find_one_statement, plan_schema_migration,
    rate_limit_consume_statements, rate_limit_count_from_i64, rate_limit_count_to_i64,
    update_many_statement, update_one_plan, ColumnToAdd, DeleteOneStrategy, IndexToCreate,
    MigrationStatement, MigrationStatementKind, SchemaMigrationPlan, SchemaMigrationWarning,
    SqlAdapterRunner, SqlColumnSnapshot, SqlDeleteOnePlan, SqlDialect, SqlExecutor, SqlFragment,
    SqlJoinReadStatement, SqlParam, SqlRateLimitNames, SqlRateLimitPlan, SqlReadStatement,
    SqlRowReader, SqlSchemaSnapshot, SqlSelectedField, SqlStatement, SqlUpdateOnePlan,
    TableToCreate,
};
pub use transform::{
    resolve_join_options, transform_count_query, transform_count_query_with_capabilities,
    transform_create_query, transform_create_query_with_capabilities, transform_delete_many_query,
    transform_delete_many_query_with_capabilities, transform_delete_query,
    transform_delete_query_with_capabilities, transform_find_many_query,
    transform_find_many_query_with_capabilities, transform_find_one_query,
    transform_find_one_query_with_capabilities, transform_update_many_query,
    transform_update_many_query_with_capabilities, transform_update_query,
    transform_update_query_with_capabilities,
};
