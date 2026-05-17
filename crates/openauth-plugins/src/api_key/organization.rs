use openauth_core::db::{DbRecord, DbValue, FindOne, Where};
use openauth_core::error::OpenAuthError;
use serde_json::Value;

use super::errors;
use super::options::ApiKeyReference;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyAction {
    Create,
    Read,
    Update,
    Delete,
}

impl ApiKeyAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

pub async fn ensure_organization_permission(
    context: &openauth_core::context::AuthContext,
    user_id: &str,
    organization_id: &str,
    action: ApiKeyAction,
) -> Result<(), OpenAuthError> {
    if !context.has_plugin("organization") {
        return Err(OpenAuthError::Api(
            errors::message(errors::ORGANIZATION_PLUGIN_REQUIRED).to_owned(),
        ));
    }
    let adapter = context.adapter().ok_or_else(|| {
        OpenAuthError::Adapter("organization API keys require a database adapter".to_owned())
    })?;
    let Some(member) = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )),
        )
        .await?
    else {
        return Err(OpenAuthError::Api(
            errors::message(errors::USER_NOT_MEMBER_OF_ORGANIZATION).to_owned(),
        ));
    };
    let role = string_field(&member, "role")?.to_owned();
    if role_has_permission(context, &adapter, organization_id, &role, action).await? {
        return Ok(());
    }
    Err(OpenAuthError::Api(
        errors::message(errors::INSUFFICIENT_API_KEY_PERMISSIONS).to_owned(),
    ))
}

pub fn owns_user_key(reference: ApiKeyReference, record_reference_id: &str, user_id: &str) -> bool {
    reference == ApiKeyReference::User && record_reference_id == user_id
}

async fn role_has_permission(
    context: &openauth_core::context::AuthContext,
    adapter: &std::sync::Arc<dyn openauth_core::db::DbAdapter>,
    organization_id: &str,
    role: &str,
    action: ApiKeyAction,
) -> Result<bool, OpenAuthError> {
    let action = action.as_str();
    let creator_role = organization_plugin_options(context)
        .and_then(|options| options.get("creatorRole"))
        .and_then(Value::as_str)
        .unwrap_or("owner");
    for role in role.split(',').map(str::trim) {
        if role == creator_role || role == "owner" || role == "admin" {
            return Ok(true);
        }
        if matches!(role, "api_key_admin" | "apiKeyAdmin") {
            return Ok(true);
        }
        if matches!(role, "api_key_reader" | "apiKeyReader") && action == "read" {
            return Ok(true);
        }
        if custom_role_has_permission(context, role, action) {
            return Ok(true);
        }
        if dynamic_role_has_permission(adapter, organization_id, role, action).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn organization_plugin_options(context: &openauth_core::context::AuthContext) -> Option<&Value> {
    context
        .plugins
        .iter()
        .find(|plugin| plugin.id == "organization")
        .and_then(|plugin| plugin.options.as_ref())
}

fn custom_role_has_permission(
    context: &openauth_core::context::AuthContext,
    role: &str,
    action: &str,
) -> bool {
    organization_plugin_options(context)
        .and_then(|options| options.get("customRoles"))
        .and_then(|roles| roles.get(role))
        .is_some_and(|permissions| api_key_permission_allows(permissions, action))
}

async fn dynamic_role_has_permission(
    adapter: &std::sync::Arc<dyn openauth_core::db::DbAdapter>,
    organization_id: &str,
    role: &str,
    action: &str,
) -> Result<bool, OpenAuthError> {
    let Some(record) = adapter
        .find_one(
            FindOne::new("organization_role")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .where_clause(Where::new("role", DbValue::String(role.to_owned()))),
        )
        .await?
    else {
        return Ok(false);
    };
    Ok(match record.get("permission") {
        Some(DbValue::Json(permissions)) => api_key_permission_allows(permissions, action),
        Some(DbValue::String(raw)) => serde_json::from_str::<Value>(raw)
            .ok()
            .is_some_and(|permissions| api_key_permission_allows(&permissions, action)),
        _ => false,
    })
}

fn api_key_permission_allows(permissions: &Value, action: &str) -> bool {
    permissions
        .get("apiKey")
        .or_else(|| permissions.get("api_key"))
        .and_then(Value::as_array)
        .is_some_and(|actions| actions.iter().any(|value| value.as_str() == Some(action)))
}

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "organization member field `{field}` has invalid type"
        ))),
    }
}
