use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

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
