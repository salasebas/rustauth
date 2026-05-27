use openauth_core::api::{BodyField, BodySchema, JsonSchemaType};
use serde_json::{json, Value};

pub fn verify_registration_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("response", JsonSchemaType::Object)
            .description("WebAuthn registration response from the client"),
        BodyField::optional("name", JsonSchemaType::String).description("Name of the passkey"),
    ])
}

pub fn verify_authentication_body_schema() -> BodySchema {
    BodySchema::object([BodyField::new("response", JsonSchemaType::Object)
        .description("WebAuthn authentication response from the client")])
}

pub fn id_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("id", JsonSchemaType::String).description("ID of the passkey")
    ])
}

pub fn update_passkey_body_schema() -> BodySchema {
    BodySchema::object([
        BodyField::new("id", JsonSchemaType::String).description("ID of the passkey"),
        BodyField::new("name", JsonSchemaType::String).description("New passkey name"),
    ])
}

pub fn query_parameter(name: &str, description: &str) -> Value {
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

pub fn webauthn_options_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "challenge": { "type": "string" },
            "rp": { "type": "object" },
            "rpId": { "type": "string" },
            "user": { "type": "object" },
            "pubKeyCredParams": { "type": "array" },
            "allowCredentials": { "type": "array" },
            "userVerification": { "type": "string" },
            "extensions": { "type": "object" },
        },
    })
}

pub fn passkey_openapi_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "name": { "type": "string", "nullable": true },
            "publicKey": { "type": "string" },
            "userId": { "type": "string" },
            "credentialID": { "type": "string" },
            "counter": { "type": "number" },
            "deviceType": { "type": "string" },
            "backedUp": { "type": "boolean" },
            "transports": { "type": "string", "nullable": true },
            "createdAt": { "type": "string", "format": "date-time", "nullable": true },
            "aaguid": { "type": "string", "nullable": true },
        },
        "required": ["id", "publicKey", "userId", "credentialID", "counter", "deviceType", "backedUp"],
    })
}
