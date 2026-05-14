use std::sync::Arc;

use http::{header, StatusCode};
use openauth_core::api::{parse_request_body, ApiRequest};
use openauth_core::db::{Create, DbRecord, DbValue, Update};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{
    PluginBeforeHookAction, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
    PluginDatabaseHook,
};
use serde_json::Value;

use super::errors;
use super::options::{UsernameOptions, UsernameValidationError};

pub fn normalize_create_user_hook(options: Arc<UsernameOptions>) -> PluginDatabaseHook {
    PluginDatabaseHook::before_create("username-normalize-create", move |_context, query| {
        Ok(PluginDatabaseBeforeAction::Continue(
            PluginDatabaseBeforeInput::Create(normalize_create_query(&options, query)),
        ))
    })
}

pub fn normalize_update_user_hook(options: Arc<UsernameOptions>) -> PluginDatabaseHook {
    PluginDatabaseHook::before_update("username-normalize-update", move |_context, query| {
        Ok(PluginDatabaseBeforeAction::Continue(
            PluginDatabaseBeforeInput::Update(normalize_update_query(&options, query)),
        ))
    })
}

pub fn sign_up_before_hook(
    options: Arc<UsernameOptions>,
) -> impl Fn(
    &openauth_core::context::AuthContext,
    ApiRequest,
) -> Result<PluginBeforeHookAction, OpenAuthError>
       + Send
       + Sync
       + 'static {
    move |_context, request| validate_and_rewrite_body(&options, request, true)
}

pub fn update_user_before_hook(
    options: Arc<UsernameOptions>,
) -> impl Fn(
    &openauth_core::context::AuthContext,
    ApiRequest,
) -> Result<PluginBeforeHookAction, OpenAuthError>
       + Send
       + Sync
       + 'static {
    move |_context, request| validate_and_rewrite_body(&options, request, false)
}

fn normalize_create_query(options: &UsernameOptions, mut query: Create) -> Create {
    if query.model != "user" {
        return query;
    }
    normalize_record(options, &mut query.data);
    query
}

fn normalize_update_query(options: &UsernameOptions, mut query: Update) -> Update {
    if query.model != "user" {
        return query;
    }
    normalize_record(options, &mut query.data);
    query
}

fn normalize_record(options: &UsernameOptions, data: &mut DbRecord) {
    if let Some(DbValue::String(username)) = data.get_mut("username") {
        *username = options.normalize_username(username);
    }
    if let Some(DbValue::String(display_username)) = data.get_mut("display_username") {
        *display_username = options.normalize_display_username(display_username);
    }
}

fn validate_and_rewrite_body(
    options: &UsernameOptions,
    request: ApiRequest,
    apply_sign_up_fallbacks: bool,
) -> Result<PluginBeforeHookAction, OpenAuthError> {
    let mut body: Value = parse_request_body(&request)?;
    let Some(object) = body.as_object_mut() else {
        return Ok(PluginBeforeHookAction::Continue(request));
    };

    if apply_sign_up_fallbacks {
        let username = string_value(object.get("username")).map(str::to_owned);
        let display_username = string_value(object.get("displayUsername"))
            .map(str::to_owned)
            .or_else(|| string_value(object.get("display_username")).map(str::to_owned));
        if username.is_some() && display_username.is_none() {
            object.insert(
                "displayUsername".to_owned(),
                Value::String(username.unwrap_or_default()),
            );
        } else if username.is_none() {
            if let Some(display_username) = display_username {
                object.insert("username".to_owned(), Value::String(display_username));
            }
        }
    }

    if let Some(username) = string_value(object.get("username")) {
        let username_for_validation = options.username_for_validation(username);
        if let Err(error) =
            options.validate_username(&username_for_validation, options.validation_order.username)
        {
            return validation_error(error, StatusCode::BAD_REQUEST)
                .map(PluginBeforeHookAction::Respond);
        }
        object.insert(
            "username".to_owned(),
            Value::String(options.normalize_username(username)),
        );
    }

    let display_username = string_value(object.get("displayUsername"))
        .or_else(|| string_value(object.get("display_username")));
    if let Some(display_username) = display_username {
        let display_username_for_validation =
            options.display_username_for_validation(display_username);
        if let Err(error) = options.validate_display_username(&display_username_for_validation) {
            return validation_error(error, StatusCode::BAD_REQUEST)
                .map(PluginBeforeHookAction::Respond);
        }
        object.insert(
            "displayUsername".to_owned(),
            Value::String(options.normalize_display_username(display_username)),
        );
        object.remove("display_username");
    }

    let (mut parts, _) = request.into_parts();
    parts.headers.insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    let next_body =
        serde_json::to_vec(&body).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    Ok(PluginBeforeHookAction::Continue(http::Request::from_parts(
        parts, next_body,
    )))
}

pub fn validation_error(
    error: UsernameValidationError,
    status: StatusCode,
) -> Result<openauth_core::api::ApiResponse, OpenAuthError> {
    match error {
        UsernameValidationError::TooShort => {
            errors::error_response(status, errors::USERNAME_TOO_SHORT, "Username is too short")
        }
        UsernameValidationError::TooLong => {
            errors::error_response(status, errors::USERNAME_TOO_LONG, "Username is too long")
        }
        UsernameValidationError::Invalid => {
            errors::error_response(status, errors::INVALID_USERNAME, "Username is invalid")
        }
        UsernameValidationError::InvalidDisplay => errors::error_response(
            status,
            errors::INVALID_DISPLAY_USERNAME,
            "Display username is invalid",
        ),
    }
}

fn string_value(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}
