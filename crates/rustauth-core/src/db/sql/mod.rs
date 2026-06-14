//! Shared SQL planning helpers for SQL-speaking database adapters.

use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};

use super::{
    AdapterFuture, Connector, Count, Create, DbField, DbFieldType, DbRecord, DbSchema, DbTable,
    DbValue, Delete, DeleteMany, FindMany, FindOne, ForeignKey, IdGeneration, JoinOption,
    JoinRelation, OnDelete, Sort, SortDirection, Update, UpdateMany, Where, WhereMode,
    WhereOperator,
};
use crate::error::RustAuthError;
use crate::options::{RateLimitConsumeInput, RateLimitDecision, RateLimitRecord};

mod common;
mod dialect;
mod executor;
mod joins;
mod migrations;
mod rate_limit;
mod statements;
mod types;

pub use common::*;
pub use executor::*;
pub use joins::*;
pub use migrations::*;
pub use rate_limit::*;
pub use statements::*;
pub use types::*;
