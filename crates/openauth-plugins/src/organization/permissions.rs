use serde::{Deserialize, Serialize};

use super::options::OrganizationOptions;

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
        || matches!(role, "owner" | "admin" | "member")
}

pub(crate) fn permission_value_has_permission(
    permission: &serde_json::Value,
    required: OrganizationPermission,
) -> bool {
    let (resource, action) = required.resource_action();
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
