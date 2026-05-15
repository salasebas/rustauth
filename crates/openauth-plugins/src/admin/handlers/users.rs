use http::StatusCode;
use openauth_core::api::{parse_request_body, ApiRequest, ApiResponse};
use openauth_core::context::AuthContext;
use openauth_core::db::{DbRecord, DbValue};
use openauth_core::error::OpenAuthError;
use serde_json::json;

use crate::admin::access::has_permission;
use crate::admin::errors;
use crate::admin::models::{
    BanUserBody, CreateUserBody, SetPasswordBody, SetRoleBody, UpdateUserBody, UserIdBody,
};
use crate::admin::options::AdminOptions;
use crate::admin::response;
use crate::admin::store::{
    ban_expires_from_now, json_to_db_value, role_value, AdminStore, ListUsersQuery,
};

use super::{current_admin, permission, query_usize, query_value, require_adapter};

pub async fn set_role(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "set-role"),
    ) {
        return errors::forbidden(errors::not_allowed_to_change_role());
    }
    let body = parse_request_body::<SetRoleBody>(&request)?;
    if let Some(error) = validate_roles(&options, &body.role.roles()) {
        return error;
    }
    let adapter = require_adapter(context)?;
    let Some(user) = AdminStore::new(adapter.as_ref())
        .update_role(&body.user_id, body.role.joined())
        .await?
    else {
        return errors::not_found_user();
    };
    response::json(StatusCode::OK, &json!({ "user": user }))
}

pub async fn get_user(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "get"),
    ) {
        return errors::forbidden(errors::not_allowed_to_get_user());
    }
    let Some(user_id) = query_value(&request, "id") else {
        return errors::error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "id is required",
        );
    };
    let adapter = require_adapter(context)?;
    let Some(user) = AdminStore::new(adapter.as_ref())
        .find_user_by_id(&user_id)
        .await?
    else {
        return errors::not_found_user();
    };
    response::json(StatusCode::OK, &user)
}

pub async fn create_user(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let adapter = require_adapter(context)?;
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "create"),
    ) {
        return errors::forbidden(errors::not_allowed_to_create_users());
    }
    let body = parse_request_body::<CreateUserBody>(&request)?;
    if !is_valid_email(&body.email) {
        return errors::error_response(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email");
    }
    if let Some(error) = validate_custom_data(&body.data) {
        return error;
    }
    if let Some(role) = &body.role {
        if let Some(error) = validate_roles(&options, &role.roles()) {
            return error;
        }
    }
    let store = AdminStore::new(adapter.as_ref());
    if store.find_user_by_email(&body.email).await?.is_some() {
        return errors::bad_request(errors::user_already_exists_use_another_email());
    }
    let role = body
        .role
        .as_ref()
        .map(|role| role.joined())
        .unwrap_or_else(|| options.default_role.clone());
    let password_hash = match &body.password {
        Some(password) => Some((context.password.hash)(password)?),
        None => None,
    };
    let user = store.create_user(body, role, password_hash).await?;
    response::json(StatusCode::OK, &json!({ "user": user }))
}

pub async fn update_user(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "update"),
    ) {
        return errors::forbidden(errors::not_allowed_to_update_users());
    }
    let body = parse_request_body::<UpdateUserBody>(&request)?;
    if body.data.is_empty() {
        return errors::bad_request(errors::no_data_to_update());
    }
    let mut data = DbRecord::new();
    for (field, value) in body.data {
        let field = camel_to_snake(&field);
        if field == "role" {
            if !has_permission(
                Some(&admin.id),
                admin.role.as_deref(),
                &options,
                &permission("user", "set-role"),
            ) {
                return errors::forbidden(errors::not_allowed_to_change_role());
            }
            let role = role_value(value)?;
            if let DbValue::String(roles) = &role {
                if let Some(error) = validate_roles(
                    &options,
                    &roles.split(',').map(str::to_owned).collect::<Vec<_>>(),
                ) {
                    return error;
                }
            }
            data.insert(field, role);
        } else {
            data.insert(field, json_to_db_value(value));
        }
    }
    let adapter = require_adapter(context)?;
    let Some(user) = AdminStore::new(adapter.as_ref())
        .update_user_fields(&body.user_id, data)
        .await?
    else {
        return errors::not_found_user();
    };
    response::json(StatusCode::OK, &user)
}

pub async fn list_users(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "list"),
    ) {
        return errors::forbidden(errors::not_allowed_to_list_users());
    }
    let adapter = require_adapter(context)?;
    let result = AdminStore::new(adapter.as_ref())
        .list_users(ListUsersQuery {
            search_value: query_value(&request, "searchValue"),
            search_field: query_value(&request, "searchField"),
            search_operator: query_value(&request, "searchOperator"),
            limit: query_usize(&request, "limit"),
            offset: query_usize(&request, "offset"),
            sort_by: query_value(&request, "sortBy"),
            sort_direction: query_value(&request, "sortDirection"),
            filter_field: query_value(&request, "filterField"),
            filter_value: query_value(&request, "filterValue")
                .map(|value| parse_filter_value(&value)),
            filter_operator: query_value(&request, "filterOperator"),
        })
        .await?;
    response::json(
        StatusCode::OK,
        &json!({
            "users": result.users,
            "total": result.total,
            "limit": result.limit,
            "offset": result.offset
        }),
    )
}

pub async fn ban_user(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "ban"),
    ) {
        return errors::forbidden(errors::not_allowed_to_ban_users());
    }
    let body = parse_request_body::<BanUserBody>(&request)?;
    if body.user_id == admin.id {
        return errors::bad_request(errors::cannot_ban_yourself());
    }
    let adapter = require_adapter(context)?;
    let store = AdminStore::new(adapter.as_ref());
    if store.find_user_by_id(&body.user_id).await?.is_none() {
        return errors::not_found_user();
    }
    let reason = body
        .ban_reason
        .or(options.default_ban_reason)
        .unwrap_or_else(|| "No reason".to_owned());
    let expires = body
        .ban_expires_in
        .or(options.default_ban_expires_in)
        .and_then(ban_expires_from_now);
    let Some(user) = store.ban_user(&body.user_id, reason, expires).await? else {
        return errors::not_found_user();
    };
    response::json(StatusCode::OK, &json!({ "user": user }))
}

pub async fn unban_user(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "ban"),
    ) {
        return errors::forbidden(errors::not_allowed_to_ban_users());
    }
    let body = parse_request_body::<UserIdBody>(&request)?;
    let adapter = require_adapter(context)?;
    let Some(user) = AdminStore::new(adapter.as_ref())
        .unban_user(&body.user_id)
        .await?
    else {
        return errors::not_found_user();
    };
    response::json(StatusCode::OK, &json!({ "user": user }))
}

pub async fn remove_user(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "delete"),
    ) {
        return errors::forbidden(errors::not_allowed_to_delete_users());
    }
    let body = parse_request_body::<UserIdBody>(&request)?;
    if body.user_id == admin.id {
        return errors::bad_request(errors::cannot_remove_yourself());
    }
    let adapter = require_adapter(context)?;
    let store = AdminStore::new(adapter.as_ref());
    if store.find_user_by_id(&body.user_id).await?.is_none() {
        return errors::not_found_user();
    }
    store.delete_user(&body.user_id).await?;
    response::json(StatusCode::OK, &json!({ "success": true }))
}

pub async fn set_user_password(
    options: AdminOptions,
    context: &AuthContext,
    request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    let Some((_session, admin)) = current_admin(context, &request).await? else {
        return errors::unauthorized();
    };
    if !has_permission(
        Some(&admin.id),
        admin.role.as_deref(),
        &options,
        &permission("user", "set-password"),
    ) {
        return errors::forbidden(errors::not_allowed_to_set_password());
    }
    let body = parse_request_body::<SetPasswordBody>(&request)?;
    if body.user_id.trim().is_empty() {
        return errors::error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "userId is required",
        );
    }
    if body.new_password.is_empty() {
        return errors::error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "newPassword cannot be empty",
        );
    }
    if body.new_password.len() < context.password.config.min_password_length {
        return errors::error_response(
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_SHORT",
            "Password is too short",
        );
    }
    if body.new_password.len() > context.password.config.max_password_length {
        return errors::error_response(
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_LONG",
            "Password is too long",
        );
    }
    let hash = (context.password.hash)(&body.new_password)?;
    let adapter = require_adapter(context)?;
    AdminStore::new(adapter.as_ref())
        .set_password(&body.user_id, hash)
        .await?;
    response::json(StatusCode::OK, &json!({ "status": true }))
}

fn validate_roles(
    options: &AdminOptions,
    roles: &[String],
) -> Option<Result<ApiResponse, OpenAuthError>> {
    for role in roles {
        if !options.roles.contains_key(role) {
            return Some(errors::bad_request(
                errors::not_allowed_to_set_unknown_role(),
            ));
        }
    }
    None
}

fn validate_custom_data(
    data: &serde_json::Map<String, serde_json::Value>,
) -> Option<Result<ApiResponse, OpenAuthError>> {
    for field in data.keys() {
        if is_reserved_create_user_field(field) {
            return Some(errors::error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                format!("custom data field `{field}` is reserved"),
            ));
        }
    }
    None
}

fn is_reserved_create_user_field(field: &str) -> bool {
    matches!(
        field,
        "id" | "email"
            | "name"
            | "role"
            | "banned"
            | "banReason"
            | "banExpires"
            | "emailVerified"
            | "createdAt"
            | "updatedAt"
            | "image"
    )
}

fn is_valid_email(email: &str) -> bool {
    if email.len() > 254 || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn parse_filter_value(value: &str) -> DbValue {
    match value {
        "true" => return DbValue::Boolean(true),
        "false" => return DbValue::Boolean(false),
        _ => {}
    }
    if let Ok(number) = value.parse::<i64>() {
        return DbValue::Number(number);
    }
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(value) {
        return json_filter_value(json);
    }
    DbValue::String(value.to_owned())
}

fn json_filter_value(value: serde_json::Value) -> DbValue {
    match value {
        serde_json::Value::Bool(value) => DbValue::Boolean(value),
        serde_json::Value::Number(value) => value
            .as_i64()
            .map(DbValue::Number)
            .unwrap_or_else(|| DbValue::Json(serde_json::Value::Number(value))),
        serde_json::Value::Array(values) => {
            let strings = values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>();
            if let Some(strings) = strings {
                return DbValue::StringArray(strings);
            }
            let numbers = values
                .iter()
                .map(serde_json::Value::as_i64)
                .collect::<Option<Vec<_>>>();
            numbers
                .map(DbValue::NumberArray)
                .unwrap_or_else(|| DbValue::Json(serde_json::Value::Array(values)))
        }
        serde_json::Value::String(value) => DbValue::String(value),
        other => DbValue::Json(other),
    }
}

fn camel_to_snake(field: &str) -> String {
    match field {
        "emailVerified" => "email_verified".to_owned(),
        "banReason" => "ban_reason".to_owned(),
        "banExpires" => "ban_expires".to_owned(),
        other => other.to_owned(),
    }
}
