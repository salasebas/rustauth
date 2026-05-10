use std::sync::Arc;

use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shared::{
    current_session, error_response, json_openapi_response, json_response, unauthorized,
};
use crate::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions,
    OpenApiOperation,
};
use crate::db::DbAdapter;
use crate::user::{DbUserStore, UpdateUserInput};

#[derive(Debug, Deserialize)]
struct UpdateUserBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    image: Option<Value>,
    #[serde(default)]
    email: Option<Value>,
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
                let Some((_, user, cookies)) =
                    current_session(adapter.as_ref(), context, &request).await?
                else {
                    return unauthorized();
                };
                let body: UpdateUserBody = parse_request_body(&request)?;
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
                if input.is_empty() {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "NO_FIELDS_TO_UPDATE",
                        "No fields to update",
                    );
                }

                let _updated = DbUserStore::new(adapter.as_ref())
                    .update_user(&user.id, input)
                    .await?;
                json_response(
                    StatusCode::OK,
                    &UpdateUserResponse { status: true },
                    cookies,
                )
            })
        },
    )
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
                    },
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
