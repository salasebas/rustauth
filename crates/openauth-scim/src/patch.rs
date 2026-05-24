//! SCIM PatchOp support for user resources.

use indexmap::IndexMap;
use openauth_core::db::User;
use serde_json::Value;

use crate::errors::ScimError;
use crate::mappings::{user_full_name, ScimEmail, ScimName};

#[derive(Debug, Clone, PartialEq)]
pub struct PatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: Value,
}

impl PatchOperation {
    pub fn new(op: &str, path: Option<&str>, value: &str) -> Self {
        Self {
            op: op.to_owned(),
            path: path.map(str::to_owned),
            value: Value::String(value.to_owned()),
        }
    }

    pub fn replace_json(path: Option<&str>, value: Value) -> Self {
        Self {
            op: "replace".to_owned(),
            path: path.map(str::to_owned),
            value,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserPatch {
    pub user: IndexMap<String, Value>,
    pub account: IndexMap<String, Value>,
    pub profile: IndexMap<String, Value>,
    pub emails: Option<Vec<ScimEmail>>,
}

pub fn build_user_patch(
    user: &User,
    operations: &[PatchOperation],
) -> Result<UserPatch, ScimError> {
    let mut patch = UserPatch {
        user: IndexMap::new(),
        account: IndexMap::new(),
        profile: IndexMap::new(),
        emails: None,
    };

    for operation in operations {
        let op = operation.op.to_ascii_lowercase();
        match op.as_str() {
            "add" | "replace" => {
                apply_patch_value(
                    user,
                    &mut patch,
                    operation.path.as_deref(),
                    &operation.value,
                    op.as_str(),
                )?;
            }
            "remove" => apply_remove_value(&mut patch, operation.path.as_deref())?,
            _ => {
                return Err(ScimError::bad_request("Invalid PatchOp operation")
                    .with_scim_type("invalidSyntax"));
            }
        }
    }

    if patch.user.is_empty()
        && patch.account.is_empty()
        && patch.profile.is_empty()
        && patch.emails.is_none()
    {
        return Err(ScimError::bad_request("No valid fields to update"));
    }

    Ok(patch)
}

fn apply_patch_value(
    user: &User,
    patch: &mut UserPatch,
    path: Option<&str>,
    value: &Value,
    op: &str,
) -> Result<(), ScimError> {
    if let Some(path) = path {
        if normalize_path(path) == "/emails" {
            ensure_mutable_path(path)?;
            patch.emails = Some(emails_from_patch_value(value)?);
            return Ok(());
        }
    }
    if let Some(object) = value.as_object() {
        if let Some(path) = path {
            ensure_mutable_path(path)?;
            if path.starts_with("urn:ietf:params:scim:schemas:") {
                patch.profile.insert(path.to_owned(), value.clone());
                return Ok(());
            }
            if is_profile_container_path(path) {
                patch.profile.insert(path.to_owned(), value.clone());
                return Ok(());
            }
        }
        for (key, nested) in object {
            if path.is_none() && key.starts_with("urn:ietf:params:scim:schemas:") {
                patch.profile.insert(key.clone(), nested.clone());
                continue;
            }
            let nested_path = match path {
                Some(path) if !path.is_empty() => format!("{path}.{key}"),
                _ => key.clone(),
            };
            apply_patch_value(user, patch, Some(&nested_path), nested, op)?;
        }
        return Ok(());
    }

    let Some(path) = path else {
        return Ok(());
    };
    ensure_mutable_path(path)?;
    if is_profile_path(path) && !value.is_null() && !value.is_string() {
        patch.profile.insert(path.to_owned(), value.clone());
        return Ok(());
    }
    let Some(value) = value.as_str() else {
        return Ok(());
    };
    apply_mapping(user, patch, path, value, op);
    Ok(())
}

fn apply_remove_value(patch: &mut UserPatch, path: Option<&str>) -> Result<(), ScimError> {
    let Some(path) = path else {
        return Ok(());
    };
    ensure_mutable_path(path)?;
    let normalized = normalize_path(path);
    match normalized.as_str() {
        "/id" | "/meta" | "/schemas" | "/groups" => {}
        "/active" | "/displayName" | "/emails" => {}
        "/externalId" => {
            patch.account.insert("account_id".to_owned(), Value::Null);
        }
        "/userName" | "/name/formatted" | "/name/givenName" | "/name/familyName" => {}
        _ => {
            patch
                .profile
                .insert(path.trim_start_matches('/').to_owned(), Value::Null);
        }
    }
    Ok(())
}

fn apply_mapping(user: &User, patch: &mut UserPatch, path: &str, value: &str, op: &str) {
    match normalize_path(path).as_str() {
        "/externalId" => {
            patch
                .account
                .insert("account_id".to_owned(), Value::String(value.to_owned()));
        }
        "/userName" => {
            let value = value.to_ascii_lowercase();
            if op == "add" && user.email == value {
                return;
            }
            patch.user.insert("email".to_owned(), Value::String(value));
        }
        "/name/formatted" => {
            if op == "add" && user.name == value {
                return;
            }
            patch
                .user
                .insert("name".to_owned(), Value::String(value.to_owned()));
        }
        "/name/givenName" => {
            let current = patch
                .user
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(&user.name);
            let family_name = current
                .split(' ')
                .skip(1)
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_owned();
            let name = user_full_name(
                &user.email,
                Some(&ScimName {
                    formatted: None,
                    given_name: Some(value.to_owned()),
                    family_name: (!family_name.is_empty()).then_some(family_name),
                }),
            );
            patch.user.insert("name".to_owned(), Value::String(name));
        }
        "/name/familyName" => {
            let current = patch
                .user
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(&user.name);
            let given_name = current
                .split(' ')
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or(current)
                .to_owned();
            let name = user_full_name(
                &user.email,
                Some(&ScimName {
                    formatted: None,
                    given_name: Some(given_name),
                    family_name: Some(value.to_owned()),
                }),
            );
            patch.user.insert("name".to_owned(), Value::String(name));
        }
        _ if is_core_user_path(path) => {}
        _ => apply_profile_mapping(patch, path, value),
    }
}

fn emails_from_patch_value(value: &Value) -> Result<Vec<ScimEmail>, ScimError> {
    if value.is_array() {
        return serde_json::from_value(value.clone()).map_err(|error| {
            ScimError::bad_request(format!("Invalid emails value: {error}"))
                .with_scim_type("invalidValue")
        });
    }
    if value.is_object() {
        return serde_json::from_value::<ScimEmail>(value.clone())
            .map(|email| vec![email])
            .map_err(|error| {
                ScimError::bad_request(format!("Invalid emails value: {error}"))
                    .with_scim_type("invalidValue")
            });
    }
    Err(
        ScimError::bad_request("emails must be an array of email objects")
            .with_scim_type("invalidValue"),
    )
}

fn normalize_path(path: &str) -> String {
    let path = path.trim_start_matches('/');
    format!("/{}", path.replace('.', "/"))
}

fn apply_profile_mapping(patch: &mut UserPatch, path: &str, value: &str) {
    let path = path.trim_start_matches('/');
    if let Some((schema, attribute)) = path.rsplit_once(':') {
        if schema.starts_with("urn:ietf:params:scim:schemas:") {
            let entry = patch
                .profile
                .entry(schema.to_owned())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(object) = entry.as_object_mut() {
                object.insert(attribute.to_owned(), Value::String(value.to_owned()));
                return;
            }
        }
    }
    patch
        .profile
        .insert(path.to_owned(), Value::String(value.to_owned()));
}

fn is_profile_path(path: &str) -> bool {
    !matches!(
        normalize_path(path).as_str(),
        "/externalId"
            | "/userName"
            | "/name/formatted"
            | "/name/givenName"
            | "/name/familyName"
            | "/emails"
    ) && !is_core_user_path(path)
}

fn is_profile_container_path(path: &str) -> bool {
    is_profile_path(path) && normalize_path(path) != "/name"
}

fn ensure_mutable_path(path: &str) -> Result<(), ScimError> {
    let normalized = normalize_path(path);
    if matches!(
        normalized.as_str(),
        "/id" | "/meta" | "/schemas" | "/groups" | "/active" | "/displayName"
    ) {
        Err(ScimError::bad_request("Attribute is readOnly").with_scim_type("mutability"))
    } else if normalized.starts_with("/emails/") {
        Err(
            ScimError::bad_request("PATCH supports replacing emails as a whole attribute")
                .with_scim_type("invalidPath"),
        )
    } else {
        Ok(())
    }
}

fn is_core_user_path(path: &str) -> bool {
    matches!(
        normalize_path(path).as_str(),
        "/id"
            | "/meta"
            | "/schemas"
            | "/groups"
            | "/active"
            | "/displayName"
            | "/name"
            | "/emails/value"
            | "/emails/type"
            | "/emails/display"
            | "/emails/primary"
    )
}
