use std::collections::{BTreeMap, BTreeSet};

/// Connector used to combine resource or action checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Connector {
    /// Every requested item must be allowed.
    And,
    /// At least one requested item must be allowed.
    Or,
}

/// Resource-to-actions access statements.
pub type Statements = BTreeMap<String, BTreeSet<String>>;

/// Resource-to-action request map.
pub type AccessRequest = BTreeMap<String, ResourceRequest>;

/// Permission request for a single resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRequest {
    pub(crate) actions: BTreeSet<String>,
    pub(crate) connector: Connector,
}

impl ResourceRequest {
    /// Require all listed actions for the resource.
    pub fn all<I, S>(actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            actions: actions.into_iter().map(Into::into).collect(),
            connector: Connector::And,
        }
    }

    /// Require any listed action for the resource.
    pub fn any<I, S>(actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            actions: actions.into_iter().map(Into::into).collect(),
            connector: Connector::Or,
        }
    }

    pub(crate) fn actions(&self) -> &BTreeSet<String> {
        &self.actions
    }

    pub(crate) fn connector(&self) -> Connector {
        self.connector
    }
}

/// Access role with its allowed statements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Role {
    pub(crate) statements: Statements,
}

impl Role {
    pub(crate) fn new(statements: Statements) -> Self {
        Self { statements }
    }

    /// Return the role's allowed statements.
    pub fn statements(&self) -> &Statements {
        &self.statements
    }
}
