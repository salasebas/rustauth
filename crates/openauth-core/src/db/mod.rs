//! Database contracts, model metadata, and SQL naming defaults.

mod adapter;
mod factory;
mod hooks;
mod id;
mod memory;
mod models;
mod output;
mod schema;
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
