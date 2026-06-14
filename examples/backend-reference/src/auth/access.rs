//! Access-control helpers (`rustauth_plugins::access`).
//!
//! The `access` upstream plugin is a **library** for roles and statements, not
//! an HTTP plugin. Use it in your own authorization layer after RustAuth
//! authenticates the session.

use rustauth::plugins::access::{create_access_control, statements, AccessControl, AccessError};

/// Example RBAC model for a B2B SaaS: owner, admin, member.
pub fn example_access_control() -> Result<AccessControl, AccessError> {
    create_access_control(statements([
        (
            "organization",
            vec!["create", "read", "update", "delete", "invite"],
        ),
        ("billing", vec!["read", "manage"]),
        ("api_key", vec!["create", "read", "revoke"]),
    ]))
}

/// Owner role with full organization and billing permissions.
pub fn owner_role(control: &AccessControl) -> Result<rustauth::plugins::access::Role, AccessError> {
    control.new_role(statements([
        (
            "organization",
            vec!["create", "read", "update", "delete", "invite"],
        ),
        ("billing", vec!["read", "manage"]),
        ("api_key", vec!["create", "read", "revoke"]),
    ]))
}

/// Member role with read-only organization access.
pub fn member_role(
    control: &AccessControl,
) -> Result<rustauth::plugins::access::Role, AccessError> {
    control.new_role(statements([
        ("organization", vec!["read"]),
        ("api_key", vec!["read"]),
    ]))
}
