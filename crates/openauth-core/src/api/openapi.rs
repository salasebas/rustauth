use std::collections::BTreeMap;

use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::context::AuthContext;

use super::endpoint::AsyncAuthEndpoint;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiOperation {
    pub operation_id: Option<String>,
    pub summary: Option<String>,
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
            summary: None,
            description: None,
            tags: Vec::new(),
            parameters: Vec::new(),
            request_body: None,
            responses: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
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
    let mut operation = endpoint
        .options
        .openapi
        .clone()
        .unwrap_or_else(|| OpenApiOperation {
            operation_id: endpoint.options.operation_id.clone(),
            summary: None,
            description: None,
            tags: Vec::new(),
            parameters: Vec::new(),
            request_body: None,
            responses: BTreeMap::new(),
        });
    let operation_id = operation
        .operation_id
        .clone()
        .or_else(|| endpoint.options.operation_id.clone());
    if operation.summary.is_none() {
        operation.summary = operation_id.as_deref().map(humanize_operation_id);
    }
    if operation.description.is_none() {
        operation.description = operation
            .summary
            .as_ref()
            .map(|summary| format!("{summary} endpoint"));
    }
    add_missing_path_parameters(&mut operation.parameters, &endpoint.path);
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
    if !responses
        .keys()
        .any(|status| status.starts_with('2') || status.starts_with('3'))
    {
        responses.insert(
            "200".to_owned(),
            json_openapi_response(
                "Success",
                json!({
                    "type": "object",
                    "properties": {},
                }),
            ),
        );
    }
    let mut tags = if operation.tags.is_empty() {
        vec![tag_for_endpoint(endpoint, operation_id.as_deref())]
    } else {
        Vec::new()
    };
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
    if let Some(summary) = operation.summary {
        value.insert("summary".to_owned(), Value::String(summary));
    }
    if let Some(operation_id) = operation_id {
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

fn add_missing_path_parameters(parameters: &mut Vec<Value>, path: &str) {
    for name in path
        .split('/')
        .filter_map(|part| part.strip_prefix(':'))
        .filter(|name| !name.is_empty())
    {
        let exists = parameters.iter().any(|parameter| {
            parameter.get("name").and_then(Value::as_str) == Some(name)
                && parameter.get("in").and_then(Value::as_str) == Some("path")
        });
        if !exists {
            parameters.push(path_param(name, &format!("Path parameter `{name}`")));
        }
    }
}

fn humanize_operation_id(operation_id: &str) -> String {
    let mut words = Vec::new();
    let mut current = String::new();
    for character in operation_id.chars() {
        if character == '_' || character == '-' {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        if character.is_uppercase() && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }

    let mut summary = words.join(" ");
    if let Some(first) = summary.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    summary
}

fn tag_for_endpoint(endpoint: &AsyncAuthEndpoint, operation_id: Option<&str>) -> String {
    if let Some(tag) = tag_for_operation_id(operation_id.unwrap_or_default()) {
        return tag.to_owned();
    }
    let first_segment = endpoint
        .path
        .split('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or_default();
    tag_for_path_segment(first_segment)
        .unwrap_or("Default")
        .to_owned()
}

fn tag_for_operation_id(operation_id: &str) -> Option<&'static str> {
    if operation_id.starts_with("mcp") || operation_id.starts_with("getMcp") {
        Some("MCP")
    } else if operation_id.contains("JWT")
        || operation_id.contains("JSONWeb")
        || operation_id.ends_with("JWT")
    {
        Some("JWT")
    } else if operation_id.contains("OAuth2") {
        Some("Generic OAuth")
    } else if operation_id.contains("Siwe") {
        Some("SIWE")
    } else if operation_id.contains("PhoneNumber") {
        Some("Phone Number")
    } else if operation_id.contains("TwoFactor")
        || operation_id.contains("BackupCode")
        || operation_id.contains("Otp")
    {
        Some("Two Factor")
    } else if operation_id.starts_with("organization") || operation_id.contains("Organization") {
        Some("Organization")
    } else {
        None
    }
}

fn tag_for_path_segment(segment: &str) -> Option<&'static str> {
    match segment {
        ".well-known" | "mcp" => Some("MCP"),
        "admin" => Some("Admin"),
        "anonymous" | "delete-anonymous-user" => Some("Anonymous"),
        "device" | "device-authorization" => Some("Device Authorization"),
        "email-otp" => Some("Email OTP"),
        "oauth2" => Some("Generic OAuth"),
        "jwt" | "jwks" | "token" => Some("JWT"),
        "magic-link" => Some("Magic Link"),
        "multi-session" => Some("Multi Session"),
        "oauth-proxy" => Some("OAuth Proxy"),
        "one-tap" => Some("One Tap"),
        "one-time-token" => Some("One Time Token"),
        "open-api" => Some("Open API"),
        "organization" => Some("Organization"),
        "phone-number" => Some("Phone Number"),
        "siwe" => Some("SIWE"),
        "two-factor" => Some("Two Factor"),
        "username" => Some("Username"),
        _ => None,
    }
}

pub fn build_openapi_schema(context: &AuthContext, async_endpoints: &[AsyncAuthEndpoint]) -> Value {
    let mut paths = serde_json::Map::new();
    for endpoint in async_endpoints {
        if endpoint.options.server_only || endpoint.options.hide_from_openapi {
            continue;
        }
        let path = paths
            .entry(to_openapi_path(&endpoint.path))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let Value::Object(methods) = path else {
            continue;
        };
        methods.insert(
            endpoint.method.as_str().to_ascii_lowercase(),
            openapi_operation_for_endpoint(endpoint),
        );
    }
    json!({
        "openapi": "3.1.1",
        "info": {
            "title": "OpenAuth",
            "description": "API Reference for your OpenAuth instance",
            "version": crate::VERSION,
        },
        "components": {
            "schemas": openapi_model_schemas(),
            "securitySchemes": {
                "apiKeyCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "apiKeyCookie",
                    "description": "API Key authentication via cookie",
                },
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Bearer token authentication",
                },
            },
        },
        "security": [
            {
                "apiKeyCookie": [],
                "bearerAuth": [],
            },
        ],
        "servers": [
            {
                "url": context.base_url,
            },
        ],
        "tags": [
            {
                "name": "Default",
                "description": "Default endpoints that are included with OpenAuth by default. These endpoints are not part of any plugin.",
            },
        ],
        "paths": paths,
    })
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

pub fn json_openapi_response(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": schema,
            },
        },
    })
}

pub fn empty_openapi_response(description: &str) -> Value {
    json!({
        "description": description,
    })
}

pub fn redirect_openapi_response(description: &str) -> Value {
    json!({
        "description": description,
        "headers": {
            "Location": {
                "description": "Redirect target",
                "schema": {
                    "type": "string",
                    "format": "uri",
                },
            },
        },
    })
}

pub fn query_param(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "description": description,
        "schema": {
            "type": "string",
        },
    })
}

pub fn path_param(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": {
            "type": "string",
        },
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
