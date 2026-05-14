//! In-memory database adapter for local development and tests.

use std::cmp::Ordering;
use std::sync::Arc;

use indexmap::IndexMap;
use tokio::sync::Mutex;

use super::{
    auth_schema, run_transaction_without_native_support, AdapterCapabilities, AdapterFuture, Count,
    Create, DbAdapter, DbRecord, DbSchema, DbValue, Delete, DeleteMany, FindMany, FindOne,
    JoinAdapter, SchemaCreation, SortDirection, TransactionCallback, Update, UpdateMany, Where,
    WhereMode, WhereOperator,
};
use crate::error::OpenAuthError;

/// Async-safe in-memory adapter backed by shared state.
#[derive(Debug, Clone, Default)]
pub struct MemoryAdapter {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Debug, Default)]
struct MemoryState {
    records: IndexMap<String, Vec<DbRecord>>,
}

impl MemoryAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a snapshot of all records stored for a model.
    pub async fn records(&self, model: &str) -> Vec<DbRecord> {
        self.state
            .lock()
            .await
            .records
            .get(model)
            .cloned()
            .unwrap_or_default()
    }

    /// Return the number of records stored for a model.
    pub async fn len(&self, model: &str) -> usize {
        self.state
            .lock()
            .await
            .records
            .get(model)
            .map(Vec::len)
            .unwrap_or_default()
    }

    /// Return true when no records are stored for a model.
    pub async fn is_empty(&self, model: &str) -> bool {
        self.len(model).await == 0
    }
}

impl DbAdapter for MemoryAdapter {
    fn id(&self) -> &str {
        "memory"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("Memory Adapter")
            .with_json()
            .with_arrays()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            state
                .records
                .entry(query.model)
                .or_default()
                .push(query.data.clone());
            Ok(select_record(query.data, &query.select))
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            if !query.joins.is_empty() {
                let adapter = JoinAdapter::new(
                    auth_schema(Default::default()),
                    Arc::new(self.clone()),
                    false,
                );
                return adapter.find_one(query).await;
            }
            let state = self.state.lock().await;
            Ok(state.records.get(&query.model).and_then(|records| {
                records
                    .iter()
                    .find(|record| matches_where(record, &query.where_clauses))
                    .map(|record| select_record(record.clone(), &query.select))
            }))
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            if !query.joins.is_empty() {
                let adapter = JoinAdapter::new(
                    auth_schema(Default::default()),
                    Arc::new(self.clone()),
                    false,
                );
                return adapter.find_many(query).await;
            }
            let state = self.state.lock().await;
            let mut records = state
                .records
                .get(&query.model)
                .map(|records| {
                    records
                        .iter()
                        .filter(|record| matches_where(record, &query.where_clauses))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if let Some(sort) = &query.sort_by {
                records.sort_by(|left, right| compare_records(left, right, &sort.field));
                if sort.direction == SortDirection::Desc {
                    records.reverse();
                }
            }

            let offset = query.offset.unwrap_or(0);
            let iter = records.into_iter().skip(offset);
            let records: Vec<DbRecord> = match query.limit {
                Some(limit) => iter.take(limit).collect(),
                None => iter.collect(),
            };

            Ok(records
                .into_iter()
                .map(|record| select_record(record, &query.select))
                .collect())
        })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let state = self.state.lock().await;
            let count = state
                .records
                .get(&query.model)
                .map(|records| {
                    records
                        .iter()
                        .filter(|record| matches_where(record, &query.where_clauses))
                        .count()
                })
                .unwrap_or_default();
            Ok(count as u64)
        })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(records) = state.records.get_mut(&query.model) else {
                return Ok(None);
            };
            let Some(record) = records
                .iter_mut()
                .find(|record| matches_where(record, &query.where_clauses))
            else {
                return Ok(None);
            };
            apply_update(record, query.data);
            Ok(Some(record.clone()))
        })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(records) = state.records.get_mut(&query.model) else {
                return Ok(0);
            };
            let mut updated = 0;
            for record in records
                .iter_mut()
                .filter(|record| matches_where(record, &query.where_clauses))
            {
                apply_update(record, query.data.clone());
                updated += 1;
            }
            Ok(updated)
        })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(records) = state.records.get_mut(&query.model) else {
                return Ok(());
            };
            if let Some(index) = records
                .iter()
                .position(|record| matches_where(record, &query.where_clauses))
            {
                records.remove(index);
            }
            Ok(())
        })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(records) = state.records.get_mut(&query.model) else {
                return Ok(0);
            };
            let before = records.len();
            records.retain(|record| !matches_where(record, &query.where_clauses));
            Ok((before - records.len()) as u64)
        })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        run_transaction_without_native_support(self, callback)
    }

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
                "MemoryAdapter does not support migrations".to_owned(),
            ))
        })
    }
}

fn apply_update(record: &mut DbRecord, data: DbRecord) {
    for (field, value) in data {
        record.insert(field, value);
    }
}

fn select_record(record: DbRecord, select: &[String]) -> DbRecord {
    if select.is_empty() {
        return record;
    }
    select
        .iter()
        .filter_map(|field| {
            record
                .get(field)
                .cloned()
                .map(|value| (field.clone(), value))
        })
        .collect()
}

fn matches_where(record: &DbRecord, where_clauses: &[Where]) -> bool {
    let Some((first, rest)) = where_clauses.split_first() else {
        return true;
    };
    let mut result = matches_clause(record, first);
    for clause in rest {
        if clause.connector == super::Connector::Or {
            result = result || matches_clause(record, clause);
        } else {
            result = result && matches_clause(record, clause);
        }
    }
    result
}

fn matches_clause(record: &DbRecord, clause: &Where) -> bool {
    let Some(actual) = record.get(&clause.field) else {
        return false;
    };
    match clause.operator {
        WhereOperator::Eq => values_equal(actual, &clause.value, clause.mode),
        WhereOperator::Ne => !values_equal(actual, &clause.value, clause.mode),
        WhereOperator::Lt => compare_values(actual, &clause.value, clause.mode)
            .is_some_and(|ordering| ordering == Ordering::Less),
        WhereOperator::Lte => compare_values(actual, &clause.value, clause.mode)
            .is_some_and(|ordering| ordering != Ordering::Greater),
        WhereOperator::Gt => compare_values(actual, &clause.value, clause.mode)
            .is_some_and(|ordering| ordering == Ordering::Greater),
        WhereOperator::Gte => compare_values(actual, &clause.value, clause.mode)
            .is_some_and(|ordering| ordering != Ordering::Less),
        WhereOperator::In => value_in(actual, &clause.value, clause.mode),
        WhereOperator::NotIn => !value_in(actual, &clause.value, clause.mode),
        WhereOperator::Contains => {
            string_predicate(actual, &clause.value, clause.mode, contains_string)
        }
        WhereOperator::StartsWith => {
            string_predicate(actual, &clause.value, clause.mode, starts_with_string)
        }
        WhereOperator::EndsWith => {
            string_predicate(actual, &clause.value, clause.mode, ends_with_string)
        }
    }
}

fn values_equal(left: &DbValue, right: &DbValue, mode: WhereMode) -> bool {
    match (left, right) {
        (DbValue::String(left), DbValue::String(right)) => strings_equal(left, right, mode),
        _ => left == right,
    }
}

fn compare_records(left: &DbRecord, right: &DbRecord, field: &str) -> Ordering {
    match (left.get(field), right.get(field)) {
        (Some(left), Some(right)) => {
            compare_values(left, right, WhereMode::Sensitive).unwrap_or(Ordering::Equal)
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn compare_values(left: &DbValue, right: &DbValue, mode: WhereMode) -> Option<Ordering> {
    match (left, right) {
        (DbValue::String(left), DbValue::String(right)) => Some(compare_strings(left, right, mode)),
        (DbValue::Number(left), DbValue::Number(right)) => Some(left.cmp(right)),
        (DbValue::Boolean(left), DbValue::Boolean(right)) => Some(left.cmp(right)),
        (DbValue::Timestamp(left), DbValue::Timestamp(right)) => left
            .unix_timestamp_nanos()
            .partial_cmp(&right.unix_timestamp_nanos()),
        _ => None,
    }
}

fn value_in(actual: &DbValue, expected: &DbValue, mode: WhereMode) -> bool {
    match expected {
        DbValue::StringArray(values) => values
            .iter()
            .any(|value| values_equal(actual, &DbValue::String(value.clone()), mode)),
        DbValue::NumberArray(values) => values
            .iter()
            .any(|value| values_equal(actual, &DbValue::Number(*value), mode)),
        DbValue::Json(serde_json::Value::Array(values)) => values.iter().any(|value| {
            json_value_to_db_value(value)
                .as_ref()
                .is_some_and(|candidate| values_equal(actual, candidate, mode))
        }),
        _ => false,
    }
}

fn json_value_to_db_value(value: &serde_json::Value) -> Option<DbValue> {
    match value {
        serde_json::Value::String(value) => Some(DbValue::String(value.clone())),
        serde_json::Value::Number(value) => value.as_i64().map(DbValue::Number),
        serde_json::Value::Bool(value) => Some(DbValue::Boolean(*value)),
        serde_json::Value::Null => Some(DbValue::Null),
        _ => None,
    }
}

fn string_predicate(
    actual: &DbValue,
    expected: &DbValue,
    mode: WhereMode,
    predicate: fn(&str, &str) -> bool,
) -> bool {
    let (DbValue::String(actual), DbValue::String(expected)) = (actual, expected) else {
        return false;
    };
    if mode == WhereMode::Insensitive {
        return predicate(&actual.to_ascii_lowercase(), &expected.to_ascii_lowercase());
    }
    predicate(actual, expected)
}

fn strings_equal(left: &str, right: &str, mode: WhereMode) -> bool {
    if mode == WhereMode::Insensitive {
        return left.eq_ignore_ascii_case(right);
    }
    left == right
}

fn compare_strings(left: &str, right: &str, mode: WhereMode) -> Ordering {
    if mode == WhereMode::Insensitive {
        return left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase());
    }
    left.cmp(right)
}

fn contains_string(value: &str, pattern: &str) -> bool {
    value.contains(pattern)
}

fn starts_with_string(value: &str, pattern: &str) -> bool {
    value.starts_with(pattern)
}

fn ends_with_string(value: &str, pattern: &str) -> bool {
    value.ends_with(pattern)
}
