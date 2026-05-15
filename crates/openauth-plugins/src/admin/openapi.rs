use http::Method;
use openauth_core::api::OpenApiOperation;
use serde_json::{json, Value};

pub struct EndpointDoc {
    pub path: &'static str,
    pub method: Method,
    pub operation_id: &'static str,
    pub description: &'static str,
    pub request_schema: Option<Value>,
    pub parameters: Vec<Value>,
    pub response_200: Value,
}

impl EndpointDoc {
    pub fn operation(&self) -> OpenApiOperation {
        let mut operation = OpenApiOperation::new(self.operation_id)
            .description(self.description)
            .tag("Admin")
            .response("200", self.response_200.clone());
        for parameter in &self.parameters {
            operation = operation.parameter(parameter.clone());
        }
        if let Some(schema) = &self.request_schema {
            operation = operation.request_body(json!({
                "required": true,
                "content": {
                    "application/json": {
                        "schema": schema
                    }
                }
            }));
        }
        operation
    }
}

pub fn user_id_body() -> Value {
    schema(&[("userId", "string", true, "The user id.")])
}

pub fn create_user_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "email": {
                "type": "string",
                "format": "email",
                "description": "The user's email address.",
            },
            "name": {
                "type": "string",
                "description": "The user's display name.",
            },
            "password": {
                "type": "string",
                "minLength": 8,
                "description": "Optional credential password. Must satisfy the configured core password policy.",
            },
            "role": role_schema("Optional role or role list for the new user."),
            "data": {
                "type": "object",
                "description": "Optional custom additional user fields. Core/admin reserved fields are rejected.",
                "additionalProperties": true,
            },
        },
        "required": ["email", "name"],
    })
}

pub fn set_role_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "userId": {
                "type": "string",
                "description": "The user id to update.",
            },
            "role": role_schema("The role or roles to assign."),
        },
        "required": ["userId", "role"],
    })
}

pub fn list_user_parameters() -> Vec<Value> {
    vec![
        query_parameter("searchValue", "string", false, "Search value."),
        query_parameter(
            "searchField",
            "string",
            false,
            "Search field, usually `email` or `name`.",
        ),
        query_parameter(
            "searchOperator",
            "string",
            false,
            "Search operator: contains, starts_with, or ends_with.",
        ),
        query_parameter("limit", "number", false, "Maximum number of users to return."),
        query_parameter("offset", "number", false, "Offset for pagination."),
        query_parameter("sortBy", "string", false, "Field to sort by."),
        query_parameter("sortDirection", "string", false, "Sort direction: asc or desc."),
        query_parameter("filterField", "string", false, "Field to filter by."),
        query_parameter(
            "filterValue",
            "string",
            false,
            "Filter value. Booleans, integers, and JSON arrays are parsed when possible.",
        ),
        query_parameter(
            "filterOperator",
            "string",
            false,
            "Filter operator, including eq, ne, in, not_in, lt, lte, gt, gte, contains, starts_with, or ends_with.",
        ),
    ]
}

pub fn schema(fields: &[(&str, &str, bool, &str)]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, schema_type, is_required, description) in fields {
        properties.insert(
            (*name).to_owned(),
            json!({
                "type": schema_type,
                "description": description,
            }),
        );
        if *is_required {
            required.push(Value::String((*name).to_owned()));
        }
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

pub fn query_parameter(name: &str, schema_type: &str, required: bool, description: &str) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": required,
        "description": description,
        "schema": { "type": schema_type },
    })
}

pub fn ref_schema(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

pub fn ref_response(description: &str, schema_name: &str) -> Value {
    json_response(description, ref_schema(schema_name))
}

pub fn success_response(description: &str) -> Value {
    object_response(description, &[("success", json!({ "type": "boolean" }))])
}

pub fn object_response(description: &str, fields: &[(&str, Value)]) -> Value {
    let mut properties = serde_json::Map::new();
    for (name, schema) in fields {
        properties.insert((*name).to_owned(), schema.clone());
    }
    json_response(
        description,
        json!({
            "type": "object",
            "properties": properties,
            "required": fields.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        }),
    )
}

fn role_schema(description: &str) -> Value {
    json!({
        "description": description,
        "oneOf": [
            { "type": "string" },
            { "type": "array", "items": { "type": "string" } }
        ],
    })
}

fn json_response(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": schema,
            },
        },
    })
}
