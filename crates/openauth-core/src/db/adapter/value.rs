use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Dynamic record payload exchanged between core auth logic and adapters.
pub type DbRecord = indexmap::IndexMap<String, DbValue>;

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
