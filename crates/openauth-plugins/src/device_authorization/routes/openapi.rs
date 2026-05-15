use openauth_core::api::OpenApiOperation;
use serde_json::{json, Value};

const TAG: &str = "Device Authorization";

pub fn device_code_operation() -> OpenApiOperation {
    OpenApiOperation::new("deviceCode")
        .description("Create an OAuth 2.0 device authorization request.")
        .tag(TAG)
        .request_body(request_body(json!({
            "type": "object",
            "properties": {
                "client_id": { "type": "string" },
                "scope": { "type": "string" },
            },
            "required": ["client_id"],
        })))
        .response(
            "200",
            response("Device authorization code response.", device_code_schema()),
        )
        .response(
            "400",
            response("OAuth device-flow error response.", error_schema()),
        )
}

pub fn device_token_operation() -> OpenApiOperation {
    OpenApiOperation::new("deviceToken")
        .description("Exchange an approved OAuth 2.0 device code for a bearer token.")
        .tag(TAG)
        .request_body(request_body(json!({
            "type": "object",
            "properties": {
                "grant_type": { "type": "string" },
                "device_code": { "type": "string" },
                "client_id": { "type": "string" },
            },
            "required": ["grant_type", "device_code", "client_id"],
        })))
        .response(
            "200",
            response("OAuth bearer token response.", token_schema()),
        )
        .response(
            "400",
            response("OAuth device-flow error response.", error_schema()),
        )
}

pub fn device_verify_operation() -> OpenApiOperation {
    OpenApiOperation::new("deviceVerify")
        .description("Look up a device authorization request by user code.")
        .tag(TAG)
        .parameter(json!({
            "name": "user_code",
            "in": "query",
            "required": true,
            "schema": { "type": "string" },
        }))
        .response(
            "200",
            response("Device verification response.", verification_schema()),
        )
        .response(
            "400",
            response("OAuth device-flow error response.", error_schema()),
        )
}

pub fn device_decision_operation(operation_id: &str, description: &str) -> OpenApiOperation {
    OpenApiOperation::new(operation_id)
        .description(description)
        .tag(TAG)
        .request_body(request_body(json!({
            "type": "object",
            "properties": {
                "userCode": { "type": "string" },
            },
            "required": ["userCode"],
        })))
        .response(
            "200",
            response("Device authorization decision response.", success_schema()),
        )
        .response(
            "400",
            response("OAuth device-flow error response.", error_schema()),
        )
        .response(
            "401",
            response("OAuth device-flow error response.", error_schema()),
        )
        .response(
            "403",
            response("OAuth device-flow error response.", error_schema()),
        )
}

fn request_body(schema: Value) -> Value {
    json!({
        "required": true,
        "content": {
            "application/json": {
                "schema": schema,
            },
            "application/x-www-form-urlencoded": {
                "schema": schema,
            },
        },
    })
}

fn response(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": schema,
            },
        },
    })
}

fn device_code_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "device_code": { "type": "string" },
            "user_code": { "type": "string" },
            "verification_uri": { "type": "string" },
            "verification_uri_complete": { "type": "string" },
            "expires_in": { "type": "integer" },
            "interval": { "type": "integer" },
        },
        "required": [
            "device_code",
            "user_code",
            "verification_uri",
            "verification_uri_complete",
            "expires_in",
            "interval"
        ],
    })
}

fn token_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "access_token": { "type": "string" },
            "token_type": { "type": "string" },
            "expires_in": { "type": "integer" },
            "scope": { "type": "string" },
        },
        "required": ["access_token", "token_type", "expires_in", "scope"],
    })
}

fn verification_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "user_code": { "type": "string" },
            "status": { "type": "string" },
        },
        "required": ["user_code", "status"],
    })
}

fn success_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "success": { "type": "boolean" },
        },
        "required": ["success"],
    })
}

fn error_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "error": { "type": "string" },
            "error_description": { "type": "string" },
        },
        "required": ["error", "error_description"],
    })
}
