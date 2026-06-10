use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::shared::{
    auth_session_cookies, current_session, error_response, invalid_additional_field_response,
    json_openapi_response, json_response, unauthorized,
};
use crate::api::additional_fields::{json_to_db_value, update_values, AdditionalFieldError};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use crate::db::DbAdapter;
use crate::error::OpenAuthError;
use crate::session::SessionStore;
use crate::user::{DbUserStore, UpdateUserInput};

#[derive(Debug, Deserialize)]
struct UpdateUserBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    image: Option<Value>,
    #[serde(default)]
    username: Option<Value>,
    #[serde(default, alias = "displayUsername")]
    display_username: Option<Value>,
    #[serde(default)]
    email: Option<Value>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Serialize)]
struct UpdateUserResponse {
    status: bool,
}

pub(super) fn update_user_endpoint(adapter: Arc<dyn DbAdapter>) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/update-user",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("updateUser")
            .openapi(
                OpenApiOperation::new("updateUser")
                    .description("Update the current user")
                    .request_body(update_user_request_body())
                    .response("200", update_user_response()),
            ),
        move |context, request| {
            let adapter = Arc::clone(&adapter);
            Box::pin(async move {
                let Some((session, user, mut cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let raw_body: Value = parse_request_body(&request)?;
                let Some(body_object) = raw_body.as_object() else {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "INVALID_REQUEST_BODY",
                        "Body must be an object",
                    );
                };
                let body: UpdateUserBody =
                    serde_json::from_value(raw_body.clone()).map_err(|error| {
                        crate::error::OpenAuthError::InvalidRequestBody {
                            encoding: "JSON",
                            message: error.to_string(),
                        }
                    })?;
                if body.email.is_some() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "EMAIL_CAN_NOT_BE_UPDATED",
                        "Email can not be updated",
                    );
                }

                let mut input = UpdateUserInput::new();
                if let Some(name) = body.name {
                    input = input.name(name);
                }
                if let Some(image) = body.image {
                    input = input.image(match image {
                        Value::Null => None,
                        Value::String(value) => Some(value),
                        _ => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "INVALID_REQUEST_BODY",
                                "image must be a string or null",
                            )
                        }
                    });
                }
                if let Some(username) = body.username {
                    input = input.username(match username {
                        Value::Null => None,
                        Value::String(value) => Some(value),
                        _ => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "INVALID_REQUEST_BODY",
                                "username must be a string or null",
                            )
                        }
                    });
                }
                if context.has_plugin("username") {
                    if let Some(Some(username)) = input.username.as_ref() {
                        if let Some(existing_user) = DbUserStore::new(adapter.as_ref())
                            .find_user_by_username(username)
                            .await?
                        {
                            if existing_user.id != user.id {
                                return error_response(
                                    StatusCode::BAD_REQUEST,
                                    "USERNAME_IS_ALREADY_TAKEN",
                                    "Username is already taken. Please try another.",
                                );
                            }
                        }
                    }
                }
                if let Some(display_username) = body.display_username {
                    input = input.display_username(match display_username {
                        Value::Null => None,
                        Value::String(value) => Some(value),
                        _ => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "INVALID_REQUEST_BODY",
                                "displayUsername must be a string or null",
                            )
                        }
                    });
                }
                let additional_fields =
                    match update_values(&context.options.user.additional_fields, body_object) {
                        Ok(fields) => fields,
                        Err(error) => return invalid_additional_field_response(error),
                    };
                for (field, value) in body.extra {
                    if is_core_field(&field)
                        || context.options.user.additional_fields.contains_key(&field)
                    {
                        continue;
                    }
                    let logical_field = camel_to_snake(&field);
                    if context
                        .options
                        .user
                        .additional_fields
                        .contains_key(&logical_field)
                    {
                        continue;
                    }
                    let Ok(db_field) = context.db_schema.field("user", &logical_field) else {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "INVALID_REQUEST_BODY",
                            format!("unknown user field `{field}`"),
                        );
                    };
                    if !db_field.input {
                        return invalid_additional_field_response(AdditionalFieldError::NotInput(
                            field.clone(),
                        ));
                    }
                    let db_value =
                        match json_to_db_value(&logical_field, &db_field.field_type, &value) {
                            Ok(value) => value,
                            Err(message) => {
                                return invalid_additional_field_response(
                                    AdditionalFieldError::InvalidType(message),
                                );
                            }
                        };
                    input = input.field(db_field.name.clone(), db_value);
                }
                input = input.additional_fields_with(additional_fields);
                if input.is_empty() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "NO_FIELDS_TO_UPDATE",
                        "No fields to update",
                    );
                }

                let updated = DbUserStore::new(adapter.as_ref())
                    .update_user(&user.id, input)
                    .await?
                    .ok_or_else(|| OpenAuthError::Api("user not found".to_owned()))?;
                SessionStore::new(adapter.as_ref(), context)
                    .refresh_user_sessions(&user.id)
                    .await?;
                if context.options.session.cookie_cache.enabled {
                    cookies.extend(auth_session_cookies(context, &session, &updated, false)?);
                }
                json_response(
                    StatusCode::OK,
                    &UpdateUserResponse { status: true },
                    cookies,
                )
            })
        },
    )
}

fn is_core_field(field: &str) -> bool {
    matches!(
        field,
        "name" | "image" | "username" | "displayUsername" | "email"
    )
}

fn camel_to_snake(field: &str) -> String {
    let mut output = String::with_capacity(field.len());
    for (index, ch) in field.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                output.push('_');
            }
            output.push(ch.to_ascii_lowercase());
        } else {
            output.push(ch);
        }
    }
    output
}

fn update_user_request_body() -> Value {
    serde_json::json!({
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The name of the user",
                        },
                        "image": {
                            "type": "string",
                            "description": "The image of the user",
                            "nullable": true,
                        },
                        "username": {
                            "type": "string",
                            "description": "The username of the user",
                            "nullable": true,
                        },
                        "displayUsername": {
                            "type": "string",
                            "description": "The display username of the user",
                            "nullable": true,
                        },
                    },
                    "additionalProperties": true,
                },
            },
        },
    })
}

fn update_user_response() -> Value {
    json_openapi_response(
        "Success",
        serde_json::json!({
            "type": "object",
            "properties": {
                "user": {
                    "$ref": "#/components/schemas/User",
                },
            },
        }),
    )
}
