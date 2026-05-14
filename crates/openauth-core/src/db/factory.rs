use super::{
    transform_count_query_with_capabilities, transform_create_query_with_capabilities,
    transform_delete_many_query_with_capabilities, transform_delete_query_with_capabilities,
    transform_find_many_query_with_capabilities, transform_find_one_query_with_capabilities,
    transform_update_many_query_with_capabilities, transform_update_query_with_capabilities,
    AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, DbSchema, DbValue,
    Delete, DeleteMany, FindMany, FindOne, JoinRelation, SchemaCreation, TransactionCallback,
    Update, UpdateMany, Where, WhereOperator,
};
use crate::error::OpenAuthError;
use std::sync::Arc;

/// Adapter wrapper that maps OpenAuth logical schema names to database names.
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

/// Adapter wrapper that resolves OpenAuth join options at runtime.
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
        self.experimental_joins && self.inner.capabilities().supports_joins
    }

    async fn fallback_find_one(
        &self,
        mut query: FindOne,
    ) -> Result<Option<DbRecord>, OpenAuthError> {
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
    ) -> Result<Vec<DbRecord>, OpenAuthError> {
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

#[derive(Debug, Clone)]
struct FallbackJoin {
    model: String,
    from: String,
    to: String,
    relation: JoinRelation,
    limit: usize,
}

async fn attach_joins<A>(
    adapter: &A,
    records: &mut [&mut DbRecord],
    joins: &[FallbackJoin],
) -> Result<(), OpenAuthError>
where
    A: DbAdapter,
{
    for join in joins {
        for record in records.iter_mut() {
            initialize_join_value(record, join);
        }

        let values = records
            .iter()
            .filter_map(|record| record.get(&join.from))
            .cloned()
            .collect::<Vec<_>>();
        let Some(where_value) = in_value(values) else {
            continue;
        };

        let related =
            adapter
                .find_many(FindMany::new(join.model.clone()).where_clause(
                    Where::new(join.to.clone(), where_value).operator(WhereOperator::In),
                ))
                .await?;

        for record in records.iter_mut() {
            let Some(base_value) = record.get(&join.from).cloned() else {
                continue;
            };
            let mut matching = related
                .iter()
                .filter(|related| related.get(&join.to) == Some(&base_value))
                .cloned()
                .collect::<Vec<_>>();

            if join.relation == JoinRelation::OneToOne {
                let value = matching
                    .into_iter()
                    .next()
                    .map(DbValue::Record)
                    .unwrap_or(DbValue::Null);
                record.insert(join.model.clone(), value);
            } else {
                matching.truncate(join.limit);
                record.insert(join.model.clone(), DbValue::RecordArray(matching));
            }
        }
    }

    Ok(())
}

fn initialize_join_value(record: &mut DbRecord, join: &FallbackJoin) {
    let value = if join.relation == JoinRelation::OneToOne {
        DbValue::Null
    } else {
        DbValue::RecordArray(Vec::new())
    };
    record.insert(join.model.clone(), value);
}

fn in_value(values: Vec<DbValue>) -> Option<DbValue> {
    let mut strings = Vec::new();
    let mut numbers = Vec::new();

    for value in values {
        match value {
            DbValue::String(value) if !strings.contains(&value) => strings.push(value),
            DbValue::Number(value) if !numbers.contains(&value) => numbers.push(value),
            _ => {}
        }
    }

    if !strings.is_empty() {
        Some(DbValue::StringArray(strings))
    } else if !numbers.is_empty() {
        Some(DbValue::NumberArray(numbers))
    } else {
        None
    }
}

fn trim_joined_record(record: &mut DbRecord, original_select: &[String], joins: &[FallbackJoin]) {
    if original_select.is_empty() {
        return;
    }
    record.retain(|field, _| {
        original_select.contains(field) || joins.iter().any(|join| join.model == *field)
    });
}

fn extend_select_for_joins(select: &mut Vec<String>, joins: &[FallbackJoin]) {
    if select.is_empty() {
        return;
    }
    for join in joins {
        if !select.contains(&join.from) {
            select.push(join.from.clone());
        }
    }
}

fn resolve_fallback_joins(
    schema: &DbSchema,
    base_model: &str,
    joins: &indexmap::IndexMap<String, super::JoinOption>,
    default_limit: usize,
) -> Result<Vec<FallbackJoin>, OpenAuthError> {
    let (_, base_table) =
        find_table(schema, base_model).ok_or_else(|| OpenAuthError::TableNotFound {
            table: base_model.to_owned(),
        })?;
    let mut resolved = Vec::new();

    for (join_model, option) in joins {
        if !option.enabled {
            continue;
        }
        let (join_logical, join_table) =
            find_table(schema, join_model).ok_or_else(|| OpenAuthError::TableNotFound {
                table: join_model.clone(),
            })?;

        let mut foreign_keys = foreign_keys_to_table(join_table, &base_table.name);
        let is_forward_join = !foreign_keys.is_empty();
        if foreign_keys.is_empty() {
            foreign_keys = foreign_keys_to_table(base_table, &join_table.name);
        }

        let [(foreign_key, field)] =
            foreign_keys
                .as_slice()
                .try_into()
                .map_err(|_| match foreign_keys.len() {
                    0 => OpenAuthError::JoinForeignKeyNotFound {
                        base_model: base_model.to_owned(),
                        join_model: join_model.clone(),
                    },
                    _ => OpenAuthError::JoinForeignKeyAmbiguous {
                        base_model: base_model.to_owned(),
                        join_model: join_model.clone(),
                    },
                })?;
        let reference =
            field
                .foreign_key
                .as_ref()
                .ok_or_else(|| OpenAuthError::JoinForeignKeyNotFound {
                    base_model: base_model.to_owned(),
                    join_model: join_model.clone(),
                })?;

        let (from, to, relation_field) = if is_forward_join {
            (
                logical_field_name(base_table, &reference.field)?,
                (*foreign_key).to_owned(),
                field,
            )
        } else {
            (
                (*foreign_key).to_owned(),
                logical_field_name(join_table, &reference.field)?,
                field,
            )
        };
        let relation = if to == "id" || relation_field.unique {
            JoinRelation::OneToOne
        } else {
            JoinRelation::OneToMany
        };
        let limit = if relation == JoinRelation::OneToOne {
            1
        } else {
            option.limit.unwrap_or(default_limit)
        };

        resolved.push(FallbackJoin {
            model: join_logical.to_owned(),
            from,
            to,
            relation,
            limit,
        });
    }

    Ok(resolved)
}

fn find_table<'a>(schema: &'a DbSchema, model: &str) -> Option<(&'a str, &'a super::DbTable)> {
    schema
        .tables()
        .find(|(logical_name, table)| *logical_name == model || table.name == model)
}

fn foreign_keys_to_table<'a>(
    table: &'a super::DbTable,
    target_table: &str,
) -> Vec<(&'a str, &'a super::DbField)> {
    table
        .fields
        .iter()
        .filter_map(|(logical_name, field)| {
            field
                .foreign_key
                .as_ref()
                .filter(|foreign_key| foreign_key.table == target_table)
                .map(|_| (logical_name.as_str(), field))
        })
        .collect()
}

fn logical_field_name(table: &super::DbTable, field: &str) -> Result<String, OpenAuthError> {
    table
        .fields
        .iter()
        .find_map(|(logical_name, metadata)| {
            (logical_name == field || metadata.name == field).then(|| logical_name.clone())
        })
        .ok_or_else(|| OpenAuthError::FieldNotFound {
            table: table.name.clone(),
            field: field.to_owned(),
        })
}
