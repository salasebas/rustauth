use std::collections::BTreeMap;

use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::endpoint::AsyncAuthEndpoint;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiOperation {
    pub operation_id: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub parameters: Vec<Value>,
    pub request_body: Option<Value>,
    pub responses: BTreeMap<String, Value>,
}

impl OpenApiOperation {
    pub fn new(operation_id: impl Into<String>) -> Self {
        Self {
            operation_id: Some(operation_id.into()),
            description: None,
            tags: Vec::new(),
            parameters: Vec::new(),
            request_body: None,
            responses: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub fn request_body(mut self, request_body: Value) -> Self {
        self.request_body = Some(request_body);
        self
    }

    #[must_use]
    pub fn parameter(mut self, parameter: Value) -> Self {
        self.parameters.push(parameter);
        self
    }

    #[must_use]
    pub fn response(mut self, status: impl Into<String>, response: Value) -> Self {
        self.responses.insert(status.into(), response);
        self
    }
}

pub(super) fn openapi_operation_for_endpoint(endpoint: &AsyncAuthEndpoint) -> Value {
    let operation = endpoint
        .options
        .openapi
        .clone()
        .unwrap_or_else(|| OpenApiOperation {
            operation_id: endpoint.options.operation_id.clone(),
            description: None,
            tags: Vec::new(),
            parameters: Vec::new(),
            request_body: None,
            responses: BTreeMap::new(),
        });
    let request_body = operation.request_body.or_else(|| {
        endpoint
            .options
            .body_schema
            .as_ref()
            .map(|schema| {
                json!({
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": schema.openapi_schema(),
                        },
                    },
                })
            })
            .or_else(|| {
                method_uses_request_body(&endpoint.method).then(|| {
                    json!({
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {},
                                },
                            },
                        },
                    })
                })
            })
    });
    let mut responses = default_openapi_responses();
    for (status, response) in operation.responses {
        responses.insert(status, response);
    }
    let mut tags = vec!["Default".to_owned()];
    for tag in operation.tags {
        if !tags.iter().any(|existing| existing == &tag) {
            tags.push(tag);
        }
    }

    let mut value = serde_json::Map::new();
    value.insert(
        "tags".to_owned(),
        Value::Array(tags.into_iter().map(Value::String).collect()),
    );
    if let Some(description) = operation.description {
        value.insert("description".to_owned(), Value::String(description));
    }
    if let Some(operation_id) = operation
        .operation_id
        .or_else(|| endpoint.options.operation_id.clone())
    {
        value.insert("operationId".to_owned(), Value::String(operation_id));
    }
    value.insert(
        "security".to_owned(),
        json!([
            {
                "bearerAuth": [],
            },
        ]),
    );
    value.insert("parameters".to_owned(), Value::Array(operation.parameters));
    if let Some(request_body) = request_body {
        value.insert("requestBody".to_owned(), request_body);
    }
    value.insert("responses".to_owned(), Value::Object(responses));
    Value::Object(value)
}

fn method_uses_request_body(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PATCH | Method::PUT)
}

pub(super) fn to_openapi_path(path: &str) -> String {
    path.split('/')
        .map(|part| {
            part.strip_prefix(':')
                .map(|name| format!("{{{name}}}"))
                .unwrap_or_else(|| part.to_owned())
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn default_openapi_responses() -> serde_json::Map<String, Value> {
    let mut responses = serde_json::Map::new();
    responses.insert(
        "400".to_owned(),
        openapi_error_response(
            "Bad Request. Usually due to missing parameters, or invalid parameters.",
            true,
        ),
    );
    responses.insert(
        "401".to_owned(),
        openapi_error_response(
            "Unauthorized. Due to missing or invalid authentication.",
            true,
        ),
    );
    responses.insert(
        "403".to_owned(),
        openapi_error_response(
            "Forbidden. You do not have permission to access this resource or to perform this action.",
            false,
        ),
    );
    responses.insert(
        "404".to_owned(),
        openapi_error_response("Not Found. The requested resource was not found.", false),
    );
    responses.insert(
        "429".to_owned(),
        openapi_error_response(
            "Too Many Requests. You have exceeded the rate limit. Try again later.",
            false,
        ),
    );
    responses.insert(
        "500".to_owned(),
        openapi_error_response(
            "Internal Server Error. This is a problem with the server that you cannot fix.",
            false,
        ),
    );
    responses
}

fn openapi_error_response(description: &str, require_message: bool) -> Value {
    let required = require_message.then(|| json!(["message"]));
    let mut schema = serde_json::Map::new();
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    schema.insert(
        "properties".to_owned(),
        json!({
            "message": {
                "type": "string",
            },
        }),
    );
    if let Some(required) = required {
        schema.insert("required".to_owned(), required);
    }
    json!({
        "content": {
            "application/json": {
                "schema": Value::Object(schema),
            },
        },
        "description": description,
    })
}

pub(super) fn openapi_model_schemas() -> Value {
    json!({
        "User": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "email": { "type": "string", "format": "email" },
                "name": { "type": "string" },
                "image": { "type": "string", "format": "uri", "nullable": true },
                "emailVerified": { "type": "boolean" },
                "createdAt": { "type": "string", "format": "date-time" },
                "updatedAt": { "type": "string", "format": "date-time" },
            },
            "required": ["id", "email", "name", "emailVerified", "createdAt", "updatedAt"],
        },
        "Session": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "userId": { "type": "string" },
                "expiresAt": { "type": "string", "format": "date-time" },
                "token": { "type": "string" },
                "ipAddress": { "type": "string", "nullable": true },
                "userAgent": { "type": "string", "nullable": true },
                "createdAt": { "type": "string", "format": "date-time" },
                "updatedAt": { "type": "string", "format": "date-time" },
            },
            "required": ["id", "userId", "expiresAt", "token", "createdAt", "updatedAt"],
        },
        "Account": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "providerId": { "type": "string" },
                "accountId": { "type": "string" },
                "userId": { "type": "string" },
                "accessToken": { "type": "string", "nullable": true },
                "refreshToken": { "type": "string", "nullable": true },
                "idToken": { "type": "string", "nullable": true },
                "scope": { "type": "string", "nullable": true },
                "password": { "type": "string", "nullable": true },
                "createdAt": { "type": "string", "format": "date-time" },
                "updatedAt": { "type": "string", "format": "date-time" },
            },
            "required": ["id", "providerId", "accountId", "userId", "createdAt", "updatedAt"],
        },
        "Verification": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "identifier": { "type": "string" },
                "value": { "type": "string" },
                "expiresAt": { "type": "string", "format": "date-time" },
                "createdAt": { "type": "string", "format": "date-time" },
                "updatedAt": { "type": "string", "format": "date-time" },
            },
            "required": ["id", "identifier", "value", "expiresAt", "createdAt", "updatedAt"],
        },
    })
}
