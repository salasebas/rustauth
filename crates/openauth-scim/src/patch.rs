//! SCIM PatchOp support for user resources.

use indexmap::IndexMap;
use openauth_core::db::User;
use serde_json::Value;

use crate::errors::ScimError;
use crate::mappings::{user_full_name, ScimName};

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
}

pub fn build_user_patch(
    user: &User,
    operations: &[PatchOperation],
) -> Result<UserPatch, ScimError> {
    let mut patch = UserPatch {
        user: IndexMap::new(),
        account: IndexMap::new(),
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
                );
            }
            "remove" => {}
            _ => return Err(ScimError::bad_request("Invalid PatchOp operation")),
        }
    }

    if patch.user.is_empty() && patch.account.is_empty() {
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
) {
    if let Some(object) = value.as_object() {
        for (key, nested) in object {
            let nested_path = match path {
                Some(path) if !path.is_empty() => format!("{path}.{key}"),
                _ => key.clone(),
            };
            apply_patch_value(user, patch, Some(&nested_path), nested, op);
        }
        return;
    }

    let Some(path) = path else {
        return;
    };
    let Some(value) = value.as_str() else {
        return;
    };
    apply_mapping(user, patch, path, value, op);
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
        _ => {}
    }
}

fn normalize_path(path: &str) -> String {
    let path = path.trim_start_matches('/');
    format!("/{}", path.replace('.', "/"))
}
