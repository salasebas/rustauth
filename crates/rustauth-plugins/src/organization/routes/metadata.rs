use rustauth_core::api::{AuthEndpointOptions, BodyField, BodySchema, JsonSchemaType};

pub(super) fn options(operation_id: &str, fields: Vec<BodyField>) -> AuthEndpointOptions {
    let options = AuthEndpointOptions::new().operation_id(operation_id);
    if fields.is_empty() {
        options
    } else {
        options.body_schema(BodySchema::object(fields))
    }
}

pub(super) fn string(name: &str) -> BodyField {
    BodyField::new(name, JsonSchemaType::String)
}

pub(super) fn optional_string(name: &str) -> BodyField {
    BodyField::optional(name, JsonSchemaType::String)
}

pub(super) fn optional_bool(name: &str) -> BodyField {
    BodyField::optional(name, JsonSchemaType::Boolean)
}

pub(super) fn object(name: &str) -> BodyField {
    BodyField::new(name, JsonSchemaType::Object)
}

pub(super) fn optional_object(name: &str) -> BodyField {
    BodyField::optional(name, JsonSchemaType::Object)
}
