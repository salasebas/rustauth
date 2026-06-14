//! Default organization access-control roles.

use crate::access::{
    create_access_control, statements, AccessControl, AccessError, Role, Statements,
};
use std::collections::BTreeMap;

/// Default organization plugin permission statements.
pub fn default_statements() -> Statements {
    statements([
        ("organization", vec!["update", "delete"]),
        ("member", vec!["create", "update", "delete"]),
        ("invitation", vec!["create", "cancel"]),
        ("team", vec!["create", "update", "delete"]),
        ("ac", vec!["create", "read", "update", "delete"]),
        ("apiKey", vec!["create", "read", "update", "delete"]),
    ])
}

/// Default organization plugin access-control policy.
pub fn default_access_control() -> Result<AccessControl, AccessError> {
    create_access_control(default_statements())
}

/// Default organization admin role.
pub fn admin_role() -> Result<Role, AccessError> {
    default_access_control()?.new_role(statements([
        ("organization", vec!["update"]),
        ("invitation", vec!["create", "cancel"]),
        ("member", vec!["create", "update", "delete"]),
        ("team", vec!["create", "update", "delete"]),
        ("ac", vec!["create", "read", "update", "delete"]),
        ("apiKey", vec!["create", "read", "update", "delete"]),
    ]))
}

/// Default organization owner role.
pub fn owner_role() -> Result<Role, AccessError> {
    default_access_control()?.new_role(statements([
        ("organization", vec!["update", "delete"]),
        ("member", vec!["create", "update", "delete"]),
        ("invitation", vec!["create", "cancel"]),
        ("team", vec!["create", "update", "delete"]),
        ("ac", vec!["create", "read", "update", "delete"]),
        ("apiKey", vec!["create", "read", "update", "delete"]),
    ]))
}

/// Default organization member role.
pub fn member_role() -> Result<Role, AccessError> {
    default_access_control()?.new_role(statements([
        ("organization", Vec::<&str>::new()),
        ("member", Vec::<&str>::new()),
        ("invitation", Vec::<&str>::new()),
        ("team", Vec::<&str>::new()),
        ("ac", vec!["read"]),
        ("apiKey", Vec::<&str>::new()),
    ]))
}

/// Default organization plugin role map.
pub fn default_roles() -> Result<BTreeMap<String, Role>, AccessError> {
    Ok(BTreeMap::from([
        ("admin".to_string(), admin_role()?),
        ("owner".to_string(), owner_role()?),
        ("member".to_string(), member_role()?),
    ]))
}
