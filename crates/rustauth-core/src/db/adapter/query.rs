use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::join::JoinOption;
use super::value::{DbRecord, DbValue};

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
