use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::access::Role;

use super::options::OrganizationOptions;
use super::OrganizationRoleRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationRole {
    Owner,
    Admin,
    Member,
}

impl OrganizationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrganizationPermission {
    OrganizationUpdate,
    OrganizationDelete,
    MemberCreate,
    MemberUpdate,
    MemberDelete,
    InvitationCreate,
    InvitationCancel,
    TeamCreate,
    TeamUpdate,
    TeamDelete,
    AcCreate,
    AcRead,
    AcUpdate,
    AcDelete,
    ApiKeyCreate,
    ApiKeyRead,
    ApiKeyUpdate,
    ApiKeyDelete,
}

impl OrganizationPermission {
    pub(crate) fn resource_action(self) -> (&'static str, &'static str) {
        match self {
            Self::OrganizationUpdate => ("organization", "update"),
            Self::OrganizationDelete => ("organization", "delete"),
            Self::MemberCreate => ("member", "create"),
            Self::MemberUpdate => ("member", "update"),
            Self::MemberDelete => ("member", "delete"),
            Self::InvitationCreate => ("invitation", "create"),
            Self::InvitationCancel => ("invitation", "cancel"),
            Self::TeamCreate => ("team", "create"),
            Self::TeamUpdate => ("team", "update"),
            Self::TeamDelete => ("team", "delete"),
            Self::AcCreate => ("ac", "create"),
            Self::AcRead => ("ac", "read"),
            Self::AcUpdate => ("ac", "update"),
            Self::AcDelete => ("ac", "delete"),
            Self::ApiKeyCreate => ("apiKey", "create"),
            Self::ApiKeyRead => ("apiKey", "read"),
            Self::ApiKeyUpdate => ("apiKey", "update"),
            Self::ApiKeyDelete => ("apiKey", "delete"),
        }
    }
}

pub fn has_permission(
    role: &str,
    options: &OrganizationOptions,
    permission: OrganizationPermission,
) -> bool {
    role.split(',').map(str::trim).any(|role| {
        if role == options.creator_role {
            return true;
        }
        if configured_role_has_permission(role, options, permission) {
            return true;
        }
        if custom_role_has_permission(role, options, permission) {
            return true;
        }
        match role {
            "owner" => true,
            "admin" => !matches!(permission, OrganizationPermission::OrganizationDelete),
            "member" => matches!(permission, OrganizationPermission::AcRead),
            _ => false,
        }
    })
}

pub(crate) fn role_has_resource_action(
    role: &str,
    options: &OrganizationOptions,
    resource: &str,
    action: &str,
) -> bool {
    role.split(',').map(str::trim).any(|role| {
        if role == options.creator_role {
            return true;
        }
        if options
            .roles
            .as_ref()
            .and_then(|roles| roles.get(role))
            .is_some_and(|role| role_has_resource_action_statement(role, resource, action))
        {
            return true;
        }
        if options.custom_roles.get(role).is_some_and(|permission| {
            permission_value_has_resource_action(permission, resource, action)
        }) {
            return true;
        }
        resolve_permission(resource, action)
            .map(|permission| match role {
                "owner" => true,
                "admin" => !matches!(permission, OrganizationPermission::OrganizationDelete),
                "member" => matches!(permission, OrganizationPermission::AcRead),
                _ => false,
            })
            .unwrap_or(false)
    })
}

pub(crate) fn role_has_resource_action_with_dynamic(
    role: &str,
    options: &OrganizationOptions,
    dynamic_roles: &[OrganizationRoleRecord],
    resource: &str,
    action: &str,
) -> bool {
    role_has_resource_action(role, options, resource, action)
        || role.split(',').map(str::trim).any(|role| {
            dynamic_roles.iter().any(|record| {
                record.role == role
                    && permission_value_has_resource_action(&record.permission, resource, action)
            })
        })
}

pub(crate) fn missing_permissions(
    role: &str,
    options: &OrganizationOptions,
    dynamic_roles: &[OrganizationRoleRecord],
    permission: &serde_json::Value,
) -> BTreeMap<String, Vec<String>> {
    let Some(object) = permission.as_object() else {
        return BTreeMap::new();
    };
    let mut missing = BTreeMap::new();
    for (resource, actions) in object {
        let Some(actions) = actions.as_array() else {
            continue;
        };
        let missing_actions = actions
            .iter()
            .filter_map(serde_json::Value::as_str)
            .filter(|action| {
                !role_has_resource_action_with_dynamic(
                    role,
                    options,
                    dynamic_roles,
                    resource,
                    action,
                )
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !missing_actions.is_empty() {
            missing.insert(resource.clone(), missing_actions);
        }
    }
    missing
}

pub(crate) fn parse_roles(role: impl AsRef<str>) -> String {
    role.as_ref()
        .split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn is_known_static_role(role: &str, options: &OrganizationOptions) -> bool {
    role == options.creator_role
        || options.custom_roles.contains_key(role)
        || options
            .roles
            .as_ref()
            .is_some_and(|roles| roles.contains_key(role))
        || matches!(role, "owner" | "admin" | "member")
}

pub(crate) fn permission_value_has_permission(
    permission: &serde_json::Value,
    required: OrganizationPermission,
) -> bool {
    let (resource, action) = required.resource_action();
    permission_value_has_resource_action(permission, resource, action)
}

pub(crate) fn permission_value_has_resource_action(
    permission: &serde_json::Value,
    resource: &str,
    action: &str,
) -> bool {
    permission
        .get(resource)
        .or_else(|| {
            (resource == "apiKey")
                .then(|| permission.get("api_key"))
                .flatten()
        })
        .and_then(serde_json::Value::as_array)
        .map(|actions| actions.iter().any(|value| value.as_str() == Some(action)))
        .unwrap_or(false)
}

pub(crate) fn validate_permission_with_access_control(
    permission: &serde_json::Value,
    options: &OrganizationOptions,
) -> Result<(), rustauth_core::error::RustAuthError> {
    let Some(ac) = options.access_control.as_ref() else {
        return Err(rustauth_core::error::RustAuthError::Api(
            "MISSING_AC_INSTANCE".to_owned(),
        ));
    };
    let statements = permission_value_to_statements(permission)?;
    ac.new_role(statements)
        .map(|_| ())
        .map_err(|error| rustauth_core::error::RustAuthError::InvalidConfig(error.to_string()))
}

fn configured_role_has_permission(
    role: &str,
    options: &OrganizationOptions,
    permission: OrganizationPermission,
) -> bool {
    options
        .roles
        .as_ref()
        .and_then(|roles| roles.get(role))
        .map(|role| role_has_permission(role, permission))
        .unwrap_or(false)
}

fn role_has_resource_action_statement(role: &Role, resource: &str, action: &str) -> bool {
    role.statements()
        .get(resource)
        .or_else(|| {
            (resource == "apiKey")
                .then(|| role.statements().get("api_key"))
                .flatten()
        })
        .is_some_and(|actions| actions.contains(action))
}

fn custom_role_has_permission(
    role: &str,
    options: &OrganizationOptions,
    permission: OrganizationPermission,
) -> bool {
    options
        .custom_roles
        .get(role)
        .map(|value| permission_value_has_permission(value, permission))
        .unwrap_or(false)
}

fn role_has_permission(role: &Role, permission: OrganizationPermission) -> bool {
    let (resource, action) = permission.resource_action();
    role_has_resource_action_statement(role, resource, action)
}

fn permission_value_to_statements(
    permission: &serde_json::Value,
) -> Result<crate::access::Statements, rustauth_core::error::RustAuthError> {
    let Some(object) = permission.as_object() else {
        return Err(rustauth_core::error::RustAuthError::Api(
            "permission must be an object".to_owned(),
        ));
    };
    let mut statements = crate::access::Statements::new();
    for (resource, actions) in object {
        let Some(actions) = actions.as_array() else {
            return Err(rustauth_core::error::RustAuthError::Api(
                "permission actions must be arrays".to_owned(),
            ));
        };
        statements.insert(
            resource.clone(),
            actions
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect(),
        );
    }
    Ok(statements)
}

pub(crate) fn resolve_permission(resource: &str, action: &str) -> Option<OrganizationPermission> {
    match (resource, action) {
        ("organization", "update") => Some(OrganizationPermission::OrganizationUpdate),
        ("organization", "delete") => Some(OrganizationPermission::OrganizationDelete),
        ("member", "create") => Some(OrganizationPermission::MemberCreate),
        ("member", "update") => Some(OrganizationPermission::MemberUpdate),
        ("member", "delete") => Some(OrganizationPermission::MemberDelete),
        ("invitation", "create") => Some(OrganizationPermission::InvitationCreate),
        ("invitation", "cancel") => Some(OrganizationPermission::InvitationCancel),
        ("team", "create") => Some(OrganizationPermission::TeamCreate),
        ("team", "update") => Some(OrganizationPermission::TeamUpdate),
        ("team", "delete") => Some(OrganizationPermission::TeamDelete),
        ("ac", "create") => Some(OrganizationPermission::AcCreate),
        ("ac", "read") => Some(OrganizationPermission::AcRead),
        ("ac", "update") => Some(OrganizationPermission::AcUpdate),
        ("ac", "delete") => Some(OrganizationPermission::AcDelete),
        ("apiKey" | "api_key", "create") => Some(OrganizationPermission::ApiKeyCreate),
        ("apiKey" | "api_key", "read") => Some(OrganizationPermission::ApiKeyRead),
        ("apiKey" | "api_key", "update") => Some(OrganizationPermission::ApiKeyUpdate),
        ("apiKey" | "api_key", "delete") => Some(OrganizationPermission::ApiKeyDelete),
        _ => None,
    }
}
